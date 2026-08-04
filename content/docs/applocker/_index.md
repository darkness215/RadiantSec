---
title: "AppLocker"
date: 2026-05-12
weight: 5
icon: "lock-closed"
description: "Every AppLocker bypass technique from a red team perspective, paired with the telemetry each one generates and the hardening that closes the gap."
---

AppLocker is Microsoft's application whitelisting solution, built into Windows and widely deployed across enterprise environments. When misconfigured, or relying entirely on default rules, it becomes an attack surface rather than a control.

This series covers AppLocker bypass techniques from a red team perspective alongside the detection and hardening guidance a blue teamer needs to close each gap. Each post documents a specific bypass, explains why it works at a technical level, and covers the telemetry it generates and how to detect or prevent it.

Every technique here defeats one of four assumptions AppLocker makes. The map below groups the bypasses by the assumption they break:

```mermaid
graph LR
    A["A signed / trusted binary\nis safe to run"] --> A1["Regasm & Regsvcs"]
    A --> A2["Regsvr32 (Squiblydoo)"]
    A --> A3["Reflective Assembly Load"]
    A --> A4["BgInfo VBScript"]
    B["Only certain file types\nneed evaluating"] --> B1["File Extension Blind Spots"]
    C["A trusted path\nimplies a trusted writer"] --> C1["Trusted Folder Abuse"]
    C --> C2["DLL Hijacking & Side-Loading"]
    D["Checking a process at launch\nis enough"] --> D1["Process Injection"]
    D --> D2["UAC Bypass (auto-elevate)"]
```

{{< cards >}}
  {{< card link="/docs/applocker/bypass-regasm-regsvcs" title="Regasm and Regsvcs" icon="shield-exclamation" subtitle="Abusing trusted .NET COM registration utilities to execute arbitrary code." >}}
  {{< card link="/docs/applocker/bypass-regsvr32" title="Regsvr32 (Squiblydoo)" icon="shield-exclamation" subtitle="Loading COM scriptlets via a signed Microsoft binary to execute arbitrary JScript or VBScript." >}}
  {{< card link="/docs/applocker/bypass-assembly-load" title="Reflective Assembly Load" icon="shield-exclamation" subtitle="Executing .NET payloads in-memory via Assembly.Load(), InstallUtil, and MSBuild inline tasks." >}}
  {{< card link="/docs/applocker/bypass-bginfo" title="BgInfo VBScript Execution" icon="shield-exclamation" subtitle="Embedding VBScript payloads in OLE .bgi files executed by a Microsoft-signed binary." >}}
  {{< card link="/docs/applocker/bypass-file-extension" title="File Extension Blind Spots" icon="shield-exclamation" subtitle="Six extension-based vectors AppLocker never evaluates — HTA, WSF, XSL, INF, CPL, and ADS." >}}
  {{< card link="/docs/applocker/bypass-trusted-folders" title="Trusted Folder Abuse" icon="shield-exclamation" subtitle="Dropping payloads into writable AppLocker-trusted directories such as C:\\Windows\\Tasks." >}}
  {{< card link="/docs/applocker/dll-hijacking" title="DLL Hijacking and Side-Loading" icon="shield-exclamation" subtitle="Planting malicious DLLs inside trusted application directories to hijack the search order." >}}
  {{< card link="/docs/applocker/process-injection" title="Process Injection" icon="shield-exclamation" subtitle="DLL injection, PE injection, APC injection, and process hollowing into AppLocker-trusted processes." >}}
  {{< card link="/docs/applocker/uac-bypass" title="UAC Bypass" icon="shield-exclamation" subtitle="Escalating from medium to high integrity via auto-elevating binaries and COM object hijacking." >}}
{{< /cards >}}
