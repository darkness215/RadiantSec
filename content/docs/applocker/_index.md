---
title: "AppLocker"
weight: 4
---

AppLocker is Microsoft's application whitelisting solution, built into Windows and widely deployed across enterprise environments. When misconfigured, or relying entirely on default rules, it becomes an attack surface rather than a control.

This series covers AppLocker bypass techniques from a red team perspective alongside the detection and hardening guidance a blue teamer needs to close each gap. Each post documents a specific bypass, explains why it works at a technical level, and covers the telemetry it generates and how to detect or prevent it.

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
