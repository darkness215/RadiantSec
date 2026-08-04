# Kerberos Section: Writing Conventions

> Authoring guide for `content/docs/kerberos/`. Repo doc, not published.
> Moved out of `content/` so a front-matter slip can never publish it.

## Project

Technical security notes for [radiantsec.io](https://radiantsec.io), a Hugo site using the **Hextra** theme. This folder is the Kerberos section. Notes target a **beginner to intermediate** audience — always write and patch with that in mind.

## File Structure

``` {linenos=table}
kerberos/
├── _index.md                    # Section landing page (overview, attack map embed, all topic summaries)
├── tickets.md                   # Deep-dive reference: ticket internals, PAC, encryption types, storage formats
├── lab-setup.md                 # Windows Server 2022 AD lab setup guide (DC01, WS01, Kali attacker)
├── ASREProast.md                # ✅ Complete
├── ASREQroast.md                # ✅ Complete
├── Kerberoast.md                # ✅ Complete
├── Timeroast.md                 # ✅ Complete
├── relays.md                    # ✅ Complete (MITM6+krbrelayx, KrbRelayUp, ADCS ESC8)
├── user-to-user.md              # ✅ Complete (U2U+S4U2Self RBCD chain, PAC enumeration)
├── kerberos-attack-map.svg      # 1640×870 dark-theme SVG attack map (embedded in _index.md)
├── delegation/
│   ├── _index.md                # Delegation landing page: type comparison + attack map
│   ├── unconstrained-delegation.md  # ✅ Complete
│   ├── constrained-delegation.md    # ✅ Complete
│   ├── rbcd.md                  # ✅ Complete
│   ├── s4u2self-abuse.md        # ✅ Complete
│   └── bronze-bit.md            # ✅ Complete (CVE-2020-17049)
└── ticket-attacks/
    ├── _index.md                # Subsection landing page: attack comparison table + decision flowchart
    ├── pass-the-ticket.md       # ✅ Complete
    ├── silver-ticket.md         # ✅ Complete
    ├── golden-ticket.md         # ✅ Complete
    ├── diamond-ticket.md        # ✅ Complete
    └── sapphire-ticket.md       # ✅ Complete
```

All planned notes complete. ✅

## Hugo / Hextra Conventions

**Tabs shortcode** — used in every attack note for Linux vs Windows split:
```
{{< tabs >}}
  {{< tab name="Linux" >}}
  Linux content here
  {{< /tab >}}
  {{< tab name="Windows" >}}
  Windows content here
  {{< /tab >}}
{{< /tabs >}}
```

**Branch bundles** — any folder with an `_index.md` is a Hugo branch bundle (renders as a section, not a leaf page).

**Mermaid diagrams** — use fenced code blocks with `mermaid` language tag. Hextra renders them natively.

**SVG images** — stored alongside the markdown in `content/docs/kerberos/` as page-bundle resources, referenced as `/docs/kerberos/filename.svg`. Do not use `/images/kerberos/...`; that path resolves to `static/images/kerberos/`, which does not exist, and produces a 404.

**Footnotes** — Hugo goldmark with `unsafe: true` enabled. Use standard markdown footnote syntax `[^id]` with definitions at the bottom of the file.

## Attack Note Structure

Every attack note follows this section order. **Headings are question-shaped and
name the attack explicitly** — substitute the attack name for `<Attack>` below,
adjusting articles and plurals so the heading reads as natural English
(`What Is a Golden Ticket?`, not `What Is Golden Ticket?`).

1. **`## What Is <Attack>?`** — what the attack is, one plain-English paragraph (or numbered steps for multi-stage attacks)
2. **`## How Does <Attack> Work?`** — mechanism + mermaid sequence diagram
3. **`## What Does <Attack> Require?`** — what the attacker needs before starting
4. **[Named action sections]** — tabbed Linux/Windows (names vary by attack: "Obtaining Tickets", "Preparation", "Getting the krbtgt Hash", "Forging the Ticket", etc.)
5. **Using the Ticket** — tabbed Linux/Windows (for ticket attacks)
6. **Verification** — tabbed Linux/Windows, confirming the attack worked
7. **Operational Notes** — expiry, limitations, edge cases, RC4 vs AES tradeoffs
8. **`## How Do You Detect and Defend Against <Attack>?`** — four subsections:
   - `### What Logs Does <Attack> Generate?` — specific Event IDs and where they fire
   - `### What Logs Does <Attack> Not Generate?` — the silence that defines the attack's stealth
   - `### How Do You Mitigate <Attack>?` — defensive controls
   - `### Detection Tools` — MDI, Sentinel/Splunk queries, Sysmon, Zeek, EDR

**Why question form.** Generative answer engines (ChatGPT, Perplexity, Google AI
Overviews) retrieve by matching question intent against passages. A heading that
names the attack matches a real query; the previous generic `## How It Works`
appeared identically on all 16 notes and matched nothing. The paragraph directly
under each of these headings must be a **self-contained answer** — it is the
chunk a model lifts, so it cannot depend on the sentence before it for meaning.

Section names not listed above (`## Operational Notes`, `### Detection Tools`,
`## Verification`, `## Using the Ticket`) stay as scannable noun labels. Do not
convert them; not every heading benefits, and over-converting reads as spam.

## Writing Rules

- **Never give lazy writing.** Every section must be substantive.
- **Beginner-first language.** Define every acronym inline on first use. Explain why a thing exists before explaining how it works.
- **No jargon without a lifeline.** Every unexplained term is a reader lost. Add parentheticals for: tool flags, Windows privilege names, encryption type names, AD concepts, Windows admin shares, PowerShell remoting commands, hash formats, file formats.
- **Commands must be copy-paste ready.** Show expected output blocks after every command. Beginners need to know what success looks like.
- **Flag lists after every command block.** For commands with multiple flags, follow each block with a bullet list explaining every flag — including `\` and `` ` `` line continuation characters.
- **Both platforms always.** Every attack covers Linux (Impacket-based) and Windows (Rubeus + mimikatz) in separate tabs.
- **Call out confusion points explicitly.** If a command has two hash flags for two different purposes, bold the warning and label each one.
- **After writing any new file, run 3 assessment rounds and patch proactively.** Don't ask — find the gaps and fix them. Only declare a file done after 3 clean passes.

## Recurring Beginner Gaps to Watch For

These patterns have appeared repeatedly across notes — always check for them:

- `\` (bash line continuation) and `` ` `` (PowerShell line continuation) — explain on first use in each file
- `-hashes :NThash` Impacket format — the colon prefix and empty LM field confuses beginners every time
- Two hash flags in the same command (e.g., `-hashes` for user auth + `-nthash` for krbtgt) — always label explicitly
- `C$` administrative share — explain as hidden share exposing full C: drive
- `Enter-PSSession` — explain as PowerShell SSH equivalent
- `ACCOUNTDISABLE` on krbtgt — always clarify it's intentional and doesn't prevent Kerberos from working
- `lsadump::lsa /patch` — explain `/patch` as LSASS memory patching, note it's more invasive than DCSync
- `(Get-ADDomain)` — requires RSAT, warn it fails on non-DC machines
- PAW — always define inline as "dedicated hardened machine for admin tasks only"
- PAC verification — always explain as "service calls KDC via NETLOGON to validate PAC against AD"
- `NTDS.DIT` — AD database file on every DC
- `in-flight tickets` — legitimate tickets already issued and still within their lifetime window
- S4U2Self output "forwardable ticket for X" — X is the account performing S4U2Self, not the impersonation target

## Domain & Lab Standards

**Domain:** `radiant.local` / `RADIANT.LOCAL` / `RADIANT` (NetBIOS) — use this in every note, every command, every example output block.

**DC hostname:** `dc01.radiant.local`

**Lab accounts:** `jdoe / Password123!`, `svc_sql / Service123!`, `svc_iis / Service456!`, `nopreauth / Roast123!`, `Administrator / Admin@Radiant1!`

**Impacket install:** Always `pipx install impacket` (NOT apt). Scripts are named `getTGT.py`, `secretsdump.py`, `psexec.py`, `GetNPUsers.py`, `GetUserSPNs.py`, `getST.py`, `ticketConverter.py`, `ticketer.py`, `smbclient.py`, `wmiexec.py` — the `.py` suffix is always present, never the `impacket-*` prefix form.

## Tools Referenced

| Tool | Platform | Purpose |
|---|---|---|
| Rubeus | Windows | Ticket dumping, injection, forging (`dump`, `ptt`, `silver`, `golden`, `diamond`, `sapphire`, `asreproast`, `kerberoast`) |
| mimikatz | Windows | Ticket export (`sekurlsa::tickets`), injection (`kerberos::ptt`), hash extraction (`lsadump::dcsync`, `lsadump::lsa`, `sekurlsa::ekeys`) |
| Impacket | Linux | `getTGT.py`, `psexec.py`, `smbclient.py`, `wmiexec.py`, `secretsdump.py`, `ticketConverter.py`, `ticketer.py`, `GetNPUsers.py`, `GetUserSPNs.py`, `getST.py`, `getPac.py`, `lookupsid.py` |
| klist | Both | List tickets in current session or ccache file |
| timeroast.py | Linux | MS-SNTP hash harvesting for machine account cracking |
| PCredz | Linux | Extract credential hashes (including AS-REQ PA-ENC-TIMESTAMP) from pcap files |
| hashcat | Both | GPU-accelerated offline hash cracking (modes: 18200 AS-REP, 13100 TGS RC4, 19700 TGS AES256, 7500 AS-REQ, 31300 MS-SNTP) |

## SVG Notes

The attack map ships as a **dark/light pair**, both 1640×870:

- `kerberos-attack-map.svg` — dark (`#0d1117` background). **This is the source of truth.**
- `kerberos-attack-map-light.svg` — **generated** from the dark file. Never hand-edit it.

Semantic colour scheme (dark file):
- Green (`#166534` / `#bbf7d0`) — key material / hashes
- Purple (`#4c1d95` / `#c4b5fd`) — KDC operations
- Blue (`#1e3a5f` / `#93c5fd`) — tickets
- Yellow (`#fde68a`) — attack primitives
- Orange (`#c8a96a`) — services

### Regenerating the light variant

Edit the dark file, then regenerate the light one. The SVG has ~198 inline
`fill=`/`stroke=` attributes and **no `<style>` block**, so there is nothing for
CSS to restyle — a second file is the only option.

Apply this map in a **single atomic pass** (one regex over `#rrggbb`, one dict
lookup per match). A sequential find-and-replace will double-substitute, because
`#4b5563 → #6b7280` and `#6b7280 → #64748b` would chain.

| Dark | Light | | Dark | Light |
|---|---|---|---|---|
| `#0d1117` | `#ffffff` | | `#0a1f12` | `#f0fdf4` |
| `#161b22` | `#f8fafc` | | `#86efac` | `#15803d` |
| `#111820` | `#f8fafc` | | `#4ade80` | `#16a34a` |
| `#21262d` | `#f1f5f9` | | `#17102e` | `#f5f3ff` |
| `#30363d` | `#e2e8f0` | | `#1a0f4a` | `#ede9fe` |
| `#e6edf3` | `#111827` | | `#3b1d8a` | `#ddd6fe` |
| `#8b949e` | `#6b7280` | | `#c4b5fd` | `#6d28d9` |
| `#7c6fa0` | `#6b7280` | | `#a78bfa` | `#7c3aed` |
| `#4b5563` | `#6b7280` | | `#0a2340` | `#eff6ff` |
| `#6b7280` | `#64748b` | | `#7dd3fc` | `#0369a1` |
| `#fde68a` | `#92400e` | | `#38bdf8` | `#0284c7` |
| `#fbbf24` | `#b45309` | | `#0ea5e9` | `#0284c7` |
| `#c8a96a` | `#b45309` | | `#1a1700` | `#fffbeb` |
| `#fb923c` | `#ea580c` | | `#1f1500` | `#fef3c7` |
| `#f97316` | `#ea580c` | | `#f87171` | `#dc2626` |

Unchanged (already legible on both backgrounds): `#16a34a`, `#22c55e`, `#7c3aed`.

Assert afterwards that no dark surface colour survives into the light file, and
that every `#rrggbb` in the source has a mapping — fail loudly rather than
letting an unmapped colour pass through silently.

**Do not use an SVG-internal `prefers-color-scheme` query.** The site has a
manual theme toggle that sets `.dark` on `<html>`; a media query inside the SVG
would follow the OS and ignore the toggle. The swap is done in `_index.md` with
the same `hx:dark:hidden` / `hx:hidden hx:dark:block` pattern the navbar logo
uses, with each `<img>` in its own `<a>` so the click-through opens the matching
file.

### Editing checklist

When editing either file, always check for text overflow and colour visibility.
Dark text on dark backgrounds has been a recurring issue in the dark file; the
light file has the mirror problem — the greys are the ones to watch. `#6b7280`
is used for 14 **text** fills, so it must get *darker* on white, not lighter
(an earlier `#94a3b8` mapping was ~2.6:1 and failed WCAG at the 8-9px sizes used
in the legend).
