---
title: "How I Passed OffSec OSEP: PEN-300, AV Evasion, and Exam Strategy"
date: 2026-03-06
description: "A full breakdown of how I prepared for and passed the OffSec Experienced Penetration Tester exam: PEN-300 course, custom payloads, Sliver C2, exam experience, and everything I wish I knew before starting."
tags: ["OSEP", "OffSec", "Certification", "AV Evasion", "Active Directory", "C2"]
---

## Overview

I passed the **OffSec Experienced Penetration Tester (OSEP)** exam in **February 2026** on my first attempt, completing **17 flags including secret.txt** within the 48-hour exam window. Passing requires either **10 flags** or the **secret.txt** flag. I purchased **90 days of PEN-300 access**, which gave me enough time to go through the material thoroughly and spend a full month on the challenge labs without feeling rushed. This post is a full breakdown of how I prepared, what tools I used, what the exam was actually like, and what I would tell anyone currently working through PEN-300 or considering OSEP.

---

## My Background

I came into OSEP off the back of passing **CPTS in July 2025**. Between the two certifications I took some time off and kept my skills sharp with HTB machines and a bit of rest. I did not jump straight from one exam to the next. Having a gap helped me come back to the PEN-300 material with fresh focus.

If you want to read about my CPTS journey first, I wrote a full post on it [here](/blog/htb-cpts-review).

By the time I started OSEP I had a solid foundation in Active Directory attacks, lateral movement, and pivoting from CPTS. What I did not have was deep experience in AV/EDR evasion and C2 framework usage, which is exactly what OSEP is built around.

---

## How I Prepared

### PEN-300 — The Course Material

The PEN-300 course is a significant step up from anything at the OSCP or CPTS level. It covers process injection, custom shellcode runners, AV/EDR evasion, advanced lateral movement techniques, and operating through a C2 framework, among other things. I spent **2 months** working through the material thoroughly, then dedicated a full **third month exclusively to the challenge labs**.

Do not rush through PEN-300. The course is dense and the techniques build on each other. If you skip or skim sections you will feel it in the challenge labs and in the exam. Take notes on every technique, every code snippet, and every concept as you go.

### Challenge Labs — The Most Important Part of Prep

After completing the course material, the **PEN-300 challenge labs** are where real preparation happens. There are **8 challenge lab environments** in total, and the last two, **Challenge Lab 7 and 8, are previous OSEP exams**. They are the closest simulation of the actual exam you will get. These are designed to simulate exactly the kind of chained, multi-machine, evasion-heavy environment you will face on exam day.

I cannot stress this enough. **Solve the challenge labs.** They are almost the exam environment. The skills you build working through them, the methodology you develop, and the evasion techniques you refine will transfer directly to exam day. If I had to point to one thing that made the difference it would be the time I put into the challenge labs.

### Additional Resources

Alongside the course material and challenge labs, here is what I used outside of PEN-300:

- **Sliver HTB Academy Module** — I had chosen Sliver as my C2 framework for the exam and used HTB Academy's dedicated Sliver module to get comfortable with it before touching the labs. Knowing your C2 framework before you need it matters a lot.

- **Solved Zephyr using Sliver** — I had previously completed Zephyr 100% during my CPTS prep. I went through it again using Sliver instead of my usual toolset. This was one of the best decisions I made. It forced me to learn Sliver in a realistic AD environment under pressure, not just in a tutorial.

- **RastaLabs** — I completed 30% of RastaLabs. It is a more advanced evasion-focused AD environment and even partial completion exposed me to the kind of defences I would encounter in OSEP. If you have the budget it is worth starting.

- **Personal VMware Lab** — I set up a simple victim machine in VMware to test payloads locally before using them anywhere else. Build a payload, test it against Defender, iterate. This habit of testing before deploying saved me a lot of time in the exam.

- **GitHub and Community Resources** — A few pages I kept coming back to during prep:
  - [OSEPlayground](https://github.com/Extravenger/OSEPlayground) — a solid collection of OSEP-relevant techniques and tooling
  - [RGB Wiki — Red Cell](https://rgbwiki.com/Red%20Cell/) — well organised red team reference covering a lot of the PEN-300 curriculum
  - [B4l3rI0n/OSEP](https://github.com/B4l3rI0n/OSEP) — OSEP notes and resources
  - [The-Viper-One/OSEP-Notes](https://github.com/The-Viper-One/OSEP-Notes) — another strong set of OSEP notes worth going through
  - [Emmanuel Solis — OSEP](https://www.emmanuelsolis.com/osep.html) — a detailed OSEP review and prep guide that I found useful when planning my approach


---

## Tools I Used During the Exam

I went into the exam with a carefully prepared and thoroughly tested toolkit. Nothing was used for the first time on exam day.

- **Sliver** — My primary C2 framework. I chose Sliver over Cobalt Strike because it is free, actively maintained, and I had spent significant time learning it before the exam. I did not use Metasploit either. Not for any technical reason, I just liked Sliver more. A key observation: a generic out-of-the-box Sliver executable was not getting flagged in the challenge labs. That said, always test your payloads. Do not assume.
- **BloodHound** — Essential as always for mapping the AD environment and identifying attack paths.
- **Impacket suite** — Used throughout for SMB, Kerberos attacks, and credential operations.
- **NetExec** — Lateral movement, credential spraying, and quick access checks across the network.
- **Rubeus** — Kerberos attacks including Kerberoasting, AS-REP roasting, and ticket manipulation.
- **Mimikatz** — Credential dumping where AV permitted, used selectively.
- **Custom shellcode runners** — I wrote 3-4 custom shellcode runners specifically for AV evasion before the exam. Having multiple options ready meant I was never stuck if one got flagged.
- **Custom payloads** — Prepared and tested custom payloads ahead of time rather than relying on defaults.
- **Custom Runspaces (C#)** — Used to escape PowerShell Constrained Language Mode and execute code entirely in memory, avoiding touching disk and reducing detection surface. My malicious HTA file and Word macro both worked the same way: downloading and executing a Custom Runspace which in turn executes two files entirely inside memory, nothing touching disk.
- **Ligolo-ng** — Used for pivoting into internal network segments, same as CPTS.
- **PowerView / PowerUp** — PowerView for AD enumeration, PowerUp for local privilege escalation vectors.
- **GodPotato** — Used for privilege escalation from SeImpersonate privilege. I went with GodPotato specifically over other potato variants and it worked reliably throughout the exam.

Know what each tool does, when to use it, and have it tested before the exam starts.

---

## My Custom Tools

All the custom payloads and shellcode runners I built during my OSEP journey are available on my [GitHub](https://github.com/darkness215/osep-tools). Most are written in **C#**, with the exception of the C shellcode runner.

### [AES Shellcode Loaders](https://github.com/darkness215/osep-tools/tree/main/aes-loaders)
AES-256-CBC encrypted runners, each using a different execution technique. Encrypt your shellcode with `aes-shellcode-encryption` first, then pick the loader.

- [aes-shellcode-encryption](https://github.com/darkness215/osep-tools/tree/main/aes-loaders/aes-shellcode-encryption) — encrypts your shellcode, start here
- [aes-normal-runner](https://github.com/darkness215/osep-tools/tree/main/aes-loaders/aes-normal-runner) — self-injection via VirtualAlloc + CreateThread
- [aes-process-injection](https://github.com/darkness215/osep-tools/tree/main/aes-loaders/aes-process-injection) — remote injection into another process via CreateRemoteThread
- [aes-av-evasion](https://github.com/darkness215/osep-tools/tree/main/aes-loaders/aes-av-evasion) — remote injection with sandbox evasion checks + VirtualAllocExNuma
- [aes-process-hollowing](https://github.com/darkness215/osep-tools/tree/main/aes-loaders/aes-process-hollowing) — process hollowing into svchost.exe via suspended process + PEB walk

### [darkcrypt](https://github.com/darkness215/darkcrypt)
AES-256-CBC shellcode loader written in **C**. Downloads an encrypted payload over HTTP, decrypts it entirely in memory, and injects it via Early Bird APC injection into a suspended process before the entry point runs, bypassing user-mode EDR hooks on ntdll. Uses Hell's Gate direct syscalls instead of standard Windows APIs and includes sandbox detection.

### [HTA Delivery](https://github.com/darkness215/osep-tools/tree/main/hta-delivery)
Two HTA payloads. Pick based on whether AppLocker is present.

- [red.hta](https://github.com/darkness215/osep-tools/blob/main/hta-delivery/red.hta) — PowerShell download cradle, executes entirely in memory, no disk artifacts
- [black.hta](https://github.com/darkness215/osep-tools/blob/main/hta-delivery/black.hta) — bitsadmin + certutil + InstallUtil AppLocker bypass

### [Word Macros](https://github.com/darkness215/osep-tools/tree/main/word-macro)
VBA macro payloads with multiple execution techniques. Run `recon` first to know which technique to deploy.

- [recon](https://github.com/darkness215/osep-tools/tree/main/word-macro/recon) — detects AppLocker status, OS arch, and Office bitness via HTTP exfil
- [xor-shellcode-runner](https://github.com/darkness215/osep-tools/tree/main/word-macro/xor-shellcode-runner) — XOR encrypted runner via VirtualAlloc + CreateThread
- [caesar-cipher](https://github.com/darkness215/osep-tools/tree/main/word-macro/caesar-cipher) — shellcode runner using Caesar cipher (+2 shift)
- [alternative-shellcode-runner](https://github.com/darkness215/osep-tools/tree/main/word-macro/alternative-shellcode-runner) — uses HeapAlloc + EnumSystemGeoID for execution
- [installutil-applocker-bypass](https://github.com/darkness215/osep-tools/tree/main/word-macro/installutil-applocker-bypass) — InstallUtil LOLBin + WMI for AppLocker evasion

### [PowerShell Loaders](https://github.com/darkness215/osep-tools/tree/main/ps-loaders)
In-memory PowerShell execution. Resolves WinAPI via reflection to avoid touching disk.

- [ps-loader.ps1](https://github.com/darkness215/osep-tools/blob/main/ps-loaders/ps-loader.ps1) — downloads and executes a payload over HTTP entirely in memory
- [ps-shellcode-runner.ps1](https://github.com/darkness215/osep-tools/blob/main/ps-loaders/ps-shellcode-runner.ps1) — reflection-based shellcode runner via LookupFunc

### [AMSI Bypass](https://github.com/darkness215/osep-tools/tree/main/amsi-bypass)
PowerShell scripts for AMSI evasion.

### [UAC Bypass](https://github.com/darkness215/osep-tools/tree/main/uac-bypass)
fodhelper.exe registry hijack for privilege escalation from medium to high integrity.

Feel free to use, modify, and learn from them. If you find them useful, a star on the repo is appreciated.

---

## What I Did Differently for OSEP

The biggest shift from CPTS was the focus on **AV evasion from the very beginning**.

In CPTS, evasion is a factor but not the central challenge. In OSEP, getting past defences is often the exam. I spent a significant portion of my preparation time writing and testing custom payloads: shellcode runners, custom Runspaces, in-memory execution techniques. I also tested Metasploit and Sliver extensively in my VMware lab before committing to Sliver as my exam C2.

By the time I sat the exam I had 3-4 working custom payloads that I had personally validated against Windows Defender. I was not improvising evasion under pressure. I had payloads ready to use for the exam. Having multiple options matters more than it sounds: if one payload gets flagged mid-exam you move to the next immediately instead of scrambling to write something new under pressure.

I also built a personal cheatsheet of the most used commands specifically from the challenge labs and used it throughout the exam. Not a generic cheatsheet pulled from the internet. One built from my own hands-on time in the actual OSEP environments. It made a real difference in speed.

---

## The Exam Experience

OSEP is a **48-hour practical exam** followed by a 24-hour report submission window. I completed **17 flags including secret.txt** and ended the exam after **21 hours**.

I started my exam in the evening. Before that I slept well. I knew I would not be sleeping that night and I wanted to go in with a clear head. Despite that, I was nervous when I actually started. That nervousness cost me time early on. I got my first flag after about an hour into the exam, which was slower than it should have been purely because of the anxiety of starting.

After that I picked up pace and worked through to 6 flags. Then I hit a wall and stayed stuck for **4 to 5 hours**. Looking back, the problem was not technical. I was so focused on exploitation that I stopped thinking clearly about where I was in the environment and how to move forward. I was trying to hack my way through without stepping back to assess the bigger picture.

I took a break. Stepped away completely, cleared my head, and came back thinking about the environment as a whole rather than the machine in front of me. I got the 7th flag shortly after. From there the path opened up and the rest of the exam moved much more smoothly.

After reaching 17 flags I took a long break. When I came back I went through the environment methodically and took all the screenshots I needed for the report, and then took extra screenshots on top of that, just in case. Better to have too many than to be missing something critical during the report window. I ended the exam after **21 hours** of starting.

I also took multiple shorter breaks throughout the exam. Do not underestimate how much a 10 or 15 minute break can reset your thinking. The exam is 48 hours. You are not racing against the clock, you are racing against your own tunnel vision.

Once I ended the exam I slept for **12 to 14 hours**. Came back fresh, started writing the report, and finished it in **4 to 5 hours**. The final report was around **48 to 50 pages**. Having thorough notes and screenshots from the exam meant the report window was just writing, no trying to piece together what I had done hours earlier.

---

## Writing the Exam Report

I used the same approach as CPTS, **[SysReptor](https://docs.sysreptor.com/offsec-reporting-with-sysreptor/)** for structure and formatting, and **ChatGPT** to help write the executive summary and clean up finding descriptions.

The OSEP report requires more technical depth than CPTS. Each finding needs to demonstrate not just what you did but how the evasion worked and why it was effective. Document your payloads, your evasion approach, and the reasoning behind your technique choices, not just the commands you ran.

You have a separate **24-hour window after the 48-hour exam** to write and submit your report, so you do not need to be writing while you hack. That said, take detailed notes and screenshots throughout the exam so your 24-hour report window is spent writing, not trying to remember what you did.

---

## Suggestions for Those Preparing

These are the things that made the biggest difference for me:

1. **Complete all of PEN-300 and do every exercise.** The course is the foundation. Do not skip the code-heavy sections even if they feel uncomfortable. That discomfort is exactly where the exam lives. Aim to finish the course material within **1 to 2 months**, then spend the remaining time practising inside the labs and challenge labs.

2. **Get comfortable with C# basics before you start.** PEN-300 involves writing custom tools: shellcode runners, process injection payloads, custom Runspaces, and almost all of it is in C#. I had zero C# experience going in and the course does teach you what you need, but having a basic grasp of the language before you start will make the code-heavy sections significantly less intimidating. You will be able to focus on the security concepts rather than fighting the syntax at the same time.

3. **Solve the challenge labs.** They are the most accurate simulation of the exam environment you will get. Treat each one seriously: take notes, document steps, practice your methodology.

4. **Build and test custom payloads before the exam.** Do not go into the exam relying on default Metasploit or off-the-shelf tools. Write shellcode runners, test them against Defender in your lab, iterate until they work reliably. Have multiple options ready.

5. **Learn your C2 framework before the exam.** Whatever you choose, Sliver, Havoc, Cobalt Strike, or Metasploit, spend real time in it before exam day. Use it in the challenge labs, use it in Zephyr or RastaLabs if you have access. The exam is not the place to learn how your C2 behaves.

6. **When you get stuck, step back and think about the environment, not the machine.** I hit a wall for 4 to 5 hours during the exam. The problem was not technical. I was so focused on the machine in front of me that I stopped thinking about where I was in the environment as a whole. I took a break, stepped away completely, and came back thinking about the bigger picture. I got the next flag shortly after. Know where you are, what you have compromised, and what paths are still open at all times.

7. **Take detailed notes and screenshots throughout the exam.** You have a dedicated 24-hour window after the 48-hour exam to write your report. Use the exam time to hack, but document everything as you go so the report window is spent writing, not reconstructing.

---

## Final Thoughts

OSEP is the most technically demanding certification I have completed. The PEN-300 material is excellent and the challenge labs are genuinely difficult. If you have a solid Active Directory foundation from CPTS or OSCP and you are willing to put serious time into AV evasion and C2 usage, you will be ready for it.

The jump from CPTS to OSEP is significant, but if you respect the material, do the challenge labs properly, and prepare your toolset in advance, you will be ready.

One honest critique: the exam environment is not particularly realistic. That does not mean it is easy, it is genuinely difficult, but if you are looking for an environment that simulates what modern enterprise defences actually look like, I think **HTB CAPE** does a better job of that. The AV in the OSEP exam was running a **2022 patch**, which is not exactly what you will encounter in the real world. I think OffSec should put more focus on keeping the environment current and realistic. The course material is excellent. The exam environment just has not kept pace with it.

I still recommend OSEP. Just go in knowing the environment is not representative of what you will face in the real world, but it does teach you how to evade AV by writing custom tools, and that skill is very real.

If you are preparing for it and have questions, feel free to reach out on Discord — `batman.damned`
