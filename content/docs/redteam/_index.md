---
title: "Red Team"
weight: 2
---

Offensive techniques for constrained environments where standard tooling gets flagged, EDR is watching, or application controls are enforced. Each note documents the technique, why it works at a technical level, and detection considerations where relevant.

{{< cards >}}
  {{< card link="/docs/redteam/defender-bypass" title="Disabling Windows Defender" icon="shield-exclamation" subtitle="Five in-memory techniques to blind and disable Defender without touching disk." >}}
  {{< card link="/docs/redteam/bypass-amsi" title="AMSI Bypass Techniques" icon="shield-exclamation" subtitle="Patching, corrupting, and suppressing AMSI to execute blocked PowerShell and .NET content." >}}
  {{< card link="/docs/redteam/credential-dumping" title="Credential Dumping" icon="shield-exclamation" subtitle="LSASS, SAM, NTDS, LSA secrets, and Credential Manager — dumping credentials while evading EDR." >}}
{{< /cards >}}