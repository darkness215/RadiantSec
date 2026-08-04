---
title: "Start Here"
date: 2026-08-02
weight: 1
icon: "map"
description: "An ordered path through the Radiant Sec docs: what to read first for Kerberos, AppLocker and evasion, and what each note assumes you already know."
---

<!--
  MAINTENANCE NOTE

  This page is hand-ordered. Every new note needs slotting into a path, or the
  page stops reflecting what is published.

  Note counts and reading times are NOT hand-maintained. The path-stats
  shortcode derives them at build time from RegularPagesRecursive and Hugo's own
  .ReadingTime, so adding a note updates them automatically.

  (Do not write that shortcode's name in call syntax inside this comment.
  Shortcodes are expanded before markdown rendering, so one inside an HTML
  comment still executes — an argument-less call here failed the whole build.)

  The sidebar order in each section is set by explicit `weight` front matter
  matching the sequences below. If you reorder a path here, reorder the weights
  too, or the two disagree.

  Four ordering calls that are judgement rather than fact, recorded so they can
  be revisited deliberately:

    1. AS-REP Roasting before Kerberoasting. Ordered by prerequisite (AS-REP
       needs no credentials at all). Kerberoasting is more common in the wild,
       so the opposite order is equally defensible.
    2. Timeroasting grouped with roasting. It targets machine accounts over NTP
       and shares little with the other three beyond the name.
    3. AppLocker sequenced by tooling demanded, not by publication order.
       Reflective Assembly Load is the first note assuming .NET comfort.
    4. Bronze Bit last in delegation, as a patch-dependent special case rather
       than a core primitive.
-->

The docs here are a knowledge base, not a course. Individually the notes are self-contained; collectively they have no obvious front door. This page is the reading order.

Each path is sequenced so nothing assumes knowledge you have not met yet. Follow one end to end, or use it as a lookup: if a note references something unfamiliar, the path is where that something gets explained.

{{< callout type="warning" >}}
**Scope:** everything here is written for authorized testing, meaning your own lab, a CTF, or an engagement with a signed scope. Several techniques will trip AV and EDR by design. Build the lab before running any of them.
{{< /callout >}}

---

## What Does This Site Assume?

Across every section:

- You are comfortable in a terminal, on both Linux and Windows.
- You can build and revert VMs. Most notes assume a throwaway lab you can break.
- You know what a hash is and roughly how offline cracking works.

**Active Directory knowledge is not assumed.** Path 1 starts from the protocol itself, which is why it opens with what a ticket actually contains rather than with an attack.

Every note carries a **Last verified** line in its header giving the environment and month it was tested against. Techniques in this field decay, so check it before trusting a bypass.

---

## Path 1: Active Directory and Kerberos

{{< path-stats sections="/docs/kerberos" >}} No prerequisites. The largest section on the site, and the one with a genuine beginning.

By the end you can go from zero credentials to domain compromise in a lab, and explain which key signed what at every step.

### Foundations

1. **[Kerberos Tickets](/docs/kerberos/tickets/)** — what a TGT and a Service Ticket actually contain, how the PAC carries group membership, and which key encrypts what. Every attack below is a manipulation of something described here.
2. **[Lab Setup](/docs/kerberos/lab-setup/)** — the three-VM `radiant.local` domain every other Kerberos note assumes. Build this before going further.

### Roasting: Getting Crackable Material

Cheapest attacks first. Each recovers a password offline, without ever touching the target service.

3. **[AS-REP Roasting](/docs/kerberos/asreproast/)** — needs no credentials at all, only an account with pre-authentication disabled. The gentlest starting point on the site.
4. **[Kerberoasting](/docs/kerberos/kerberoast/)** — needs any valid domain user. Request tickets for service accounts, crack them offline.
5. **[AS-REQ Roasting](/docs/kerberos/asreqroast/)** — the variant that harvests material from the request side.
6. **[Timeroasting](/docs/kerberos/timeroast/)** — machine accounts over NTP, no credentials required. Related to the three above in spirit rather than mechanism.

### Ticket Attacks: Using and Forging

Assumes you have credentials or a key from the roasting stage.

7. **[Pass-the-Ticket](/docs/kerberos/ticket-attacks/pass-the-ticket/)** — reuse a stolen ticket instead of cracking anything. First, because forgery makes more sense once you have injected a real ticket.
8. **[Silver Ticket](/docs/kerberos/ticket-attacks/silver-ticket/)** — forge a Service Ticket from one service account's hash. Narrow scope, low noise.
9. **[Golden Ticket](/docs/kerberos/ticket-attacks/golden-ticket/)** — forge a TGT with the `krbtgt` key. Domain-wide, and the reference point for both notes below.
10. **[Diamond Ticket](/docs/kerberos/ticket-attacks/diamond-ticket/)** — modify a real TGT rather than forging one, so the logs show an ordinary logon.
11. **[Sapphire Ticket](/docs/kerberos/ticket-attacks/sapphire-ticket/)** — the refinement that sources a legitimate PAC.

### Delegation

The hardest group. Read the ticket attacks first: delegation is mostly about who may request tickets on whose behalf.

12. **[Unconstrained Delegation](/docs/kerberos/delegation/unconstrained-delegation/)** — the original, most permissive model.
13. **[Constrained Delegation](/docs/kerberos/delegation/constrained-delegation/)** — the restricted replacement, and the S4U extensions it introduced.
14. **[Resource-Based Constrained Delegation](/docs/kerberos/delegation/rbcd/)** — control moves to the target resource, which is exactly what makes it attacker-writable.
15. **[S4U2Self Abuse](/docs/kerberos/delegation/s4u2self-abuse/)** — the protocol transition primitive on its own.
16. **[Bronze Bit (CVE-2020-17049)](/docs/kerberos/delegation/bronze-bit/)** — a patch-dependent special case. Last, not because it is hardest, but because it only makes sense once you know what the bit does.

### Relays and Edge Cases

17. **[Kerberos Relay Attacks](/docs/kerberos/relays/)** — MITM6, KrbRelayUp and ADCS ESC8.
18. **[User-to-User Authentication Abuse](/docs/kerberos/user-to-user/)** — the U2U case, and why it exists.

---

## Path 2: Application Whitelisting

{{< path-stats sections="/docs/applocker" >}} No prerequisites, though Path 3 pairs well with it. Sequenced by the tooling each note demands, not by publication order.

By the end you can get code running on a host where AppLocker is supposed to prevent exactly that, and say what each method leaves in the logs.

**Read the definition first.** The shortest explanation of what AppLocker is and how it evaluates a process opens the [Regsvr32 note](/docs/applocker/bypass-regsvr32/). Read that section before anything else here.

1. **[File Extension Blind Spots](/docs/applocker/bypass-file-extension/)** — which extensions the default rules never cover. Concept-heavy, tooling-light.
2. **[Regsvr32 (Squiblydoo)](/docs/applocker/bypass-regsvr32/)** — the classic trusted-binary bypass, and the note carrying the AppLocker primer.
3. **[Trusted Folder Abuse](/docs/applocker/bypass-trusted-folders/)** — path rules trust a location, not the files inside it.
4. **[Regasm and Regsvcs](/docs/applocker/bypass-regasm-regsvcs/)** — .NET tooling persuaded to run your assembly.
5. **[Reflective Assembly Load](/docs/applocker/bypass-assembly-load/)** — loading bytes straight into a trusted process. First note assuming .NET comfort.
6. **[BgInfo VBScript Execution](/docs/applocker/bypass-bginfo/)** — a signed Sysinternals binary that evaluates script from its own config file.
7. **[DLL Hijacking](/docs/applocker/dll-hijacking/)** — search-order abuse, phantom DLLs and proxying.
8. **[Process Injection](/docs/applocker/process-injection/)** — seven techniques, and the point where C# and the Win32 API become unavoidable.
9. **[UAC Bypass](/docs/applocker/uac-bypass/)** — a separate control from AppLocker, usually the last step in the chain.

---

## Path 3: Evasion and Credential Access

{{< path-stats sections="/docs/redteam,/docs/blueteam" >}} No prerequisites. Short, but the order matters.

By the end you can land a payload on a defended Windows host, pull credentials from it, and describe the telemetry you generated doing so.

1. **[AMSI Bypass Techniques](/docs/redteam/bypass-amsi/)** — first, because AMSI is the first thing to block a payload. Almost everything else assumes you can get past it.
2. **[Disabling Defender Without Touching Disk](/docs/redteam/defender-bypass/)** — ETW patching, registry manipulation and PPL process termination.
3. **[Credential Dumping](/docs/redteam/credential-dumping/)** — LSASS, SAM, and the offline parsing that follows. This is where Path 1 gets its keys.

Then the same ground from the defender's side:

4. **[Hunting LOLBins in Windows Event Logs](/docs/blueteam/lolbins-hunting/)** — what the three techniques above actually leave behind.

---

## Path 4: Tooling

{{< path-stats sections="/docs/tools" >}} Not a sequence. Read whichever you need.

- **[Ligolo-ng](/docs/tools/ligolo-ng/)** — Layer 3 tunneling and multi-hop pivoting. The most broadly useful of the three, and the one to read first if you are picking one.
- **[Sliver C2](/docs/tools/sliver/)** — implants, beacons, execute-assembly and post-exploitation.
- **[bloodyAD](/docs/tools/bloodyad/)** — Active Directory privilege escalation. Pairs directly with Path 1; several of its chains reuse RBCD and shadow credentials.

---

## Just Want to See an Attack End to End?

The [HTB writeups](/docs/htb/) are complete attack paths on retired machines, recon through root. {{< path-stats sections="/docs/htb" >}} Easiest first:

| Machine | Difficulty | Why start here |
|---|---|---|
| [Expressway](/docs/htb/expressway/) | Easy · Linux | A clean enumeration-to-root path with no unusual tooling. |
| [Conversor](/docs/htb/conversor/) | Easy · Linux | Two clearly separated stages, both turning on `sudo`. |
| [Remote](/docs/htb/remote/) | Easy · Windows | The Windows counterpart, and the closest of the four to the Path 1 material. |
| [Gavel](/docs/htb/gavel/) | Medium · Linux | A SQL injection `sqlmap` cannot find. Read the Easy boxes first. |

---

## If You Only Read One Thing

[Kerberos Tickets](/docs/kerberos/tickets/). It is the foundation for the rest of the Kerberos section, and the page most likely to make everything else on this site click.
