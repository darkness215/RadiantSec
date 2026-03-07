# Radiant Sec

Personal security research site built with Hugo and the Hextra theme.
Published at [radiantsec.io](https://radiantsec.io).

---

## About

This is the source code for radiantsec.io, a blog and knowledge base covering HTB machine writeups, red team techniques, blue team detection, and AppLocker research.

Written by darkness215. CPTS and OSEP certified.

---

## Tech Stack

**Static site generator:** Hugo Extended
**Theme:** Hextra
**Hosting:** Cloudflare Pages
**Domain:** radiantsec.io

---

## Content Areas

**HTB Writeups**
Retired machine walkthroughs from enumeration to root.

**Red Team**
Offensive techniques including AMSI bypass, credential dumping, and AV/EDR evasion.

**Blue Team**
Threat hunting and detection from the attacker's perspective.

**AppLocker**
Bypass techniques and detection for every AppLocker escape.

---

## Running Locally

```bash
git clone https://github.com/darkness215/RadiantSec.git
cd RadiantSec
hugo server
```

The site will be available at `http://localhost:1313`.

---

## Building

```bash
hugo --minify
```

Output is placed in the `public/` directory.

---

## Contact

Discord: `batman.damned`
GitHub: [darkness215](https://github.com/darkness215)
