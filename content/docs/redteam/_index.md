---
title: "Red Team"
date: 2026-06-11
weight: 3
icon: "shield-exclamation"
description: "Offensive techniques for constrained environments: AMSI and Defender bypasses, credential dumping, and EDR evasion, each with detection considerations."
---

Offensive techniques for constrained environments where standard tooling gets flagged, EDR is watching, or application controls are enforced. Each note documents the technique, why it works at a technical level, and detection considerations where relevant.

These notes chain in a natural order: blind the defensive stack first, then act. Defender and AMSI bypasses clear the way; credential dumping is what you do once the process is no longer watched.

```mermaid
graph LR
    F["Foothold\n(constrained, EDR watching)"] --> D["Disable Defender\nblind real-time engine + telemetry"]
    F --> A["AMSI Bypass\nrun blocked PowerShell / .NET"]
    D --> C["Credential Dumping\nLSASS, SAM, NTDS, LSA secrets"]
    A --> C
    C --> M["Lateral movement\n(Pass-the-Hash / Ticket)"]
```

{{< cards >}}
  {{< card link="/docs/redteam/defender-bypass" title="Disabling Windows Defender" icon="shield-exclamation" subtitle="Five in-memory techniques to blind and disable Defender without touching disk." >}}
  {{< card link="/docs/redteam/bypass-amsi" title="AMSI Bypass Techniques" icon="shield-exclamation" subtitle="Patching, corrupting, and suppressing AMSI to execute blocked PowerShell and .NET content." >}}
  {{< card link="/docs/redteam/credential-dumping" title="Credential Dumping" icon="shield-exclamation" subtitle="LSASS, SAM, NTDS, LSA secrets, and Credential Manager — dumping credentials while evading EDR." >}}
{{< /cards >}}