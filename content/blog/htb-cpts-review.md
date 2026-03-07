---
title: "How I Passed HTB CPTS: Preparation, Exam Strategy, and Lessons Learned"
date: 2026-03-06
description: "A full breakdown of how I prepared for and passed the Hack The Box Certified Penetration Testing Specialist exam: study timeline, tools, report writing, and everything I wish I knew before starting."
tags: ["CPTS", "HTB", "Certification", "Penetration Testing", "Active Directory"]
---

## Overview

I passed CPTS in **July 2025**. I am writing this in early 2026, after passing OSEP in February. Even after moving on to other certifications I kept getting messages asking about CPTS preparation and the exam, so I figured it was time to write it all down properly in one place.

The short version: 3 months of study material, 1st attempt, 13 out of 14 flags, report submitted and passed. Here is the full story.

---

## My Background

When I started preparing for CPTS I was in my **third year of a Computer Science degree**. I was not coming in completely cold. I had a **CCNA (Cisco Certified Network Associate)** from the year before which gave me a solid networking foundation, and I had completed the **Junior Penetration Tester path on TryHackMe**, which gave me an introduction to the offensive mindset and basic tooling.

Beyond that I was self-taught, learning through HTB free tier machines, CTFs, and a lot of reading. No OSCP, no prior offensive certifications. CPTS was my first real penetration testing cert.

---

## How I Prepared

### HTB Academy: The Core Material

The CPTS path on HTB Academy is enormous. It covers everything from basic enumeration and web attacks through to full Active Directory domain compromise chains. I completed the entire path in **3 months**, studying consistently every day alongside my degree.

One thing to know upfront: completing the full path is not optional preparation. It is a hard requirement. You cannot sit the CPTS exam until you have completed 100% of the Penetration Tester job-role path, including all hands-on skills assessments at the end of each module. The evaluation does not start when the exam does. It starts on day one of the path.

My biggest piece of advice here is simple: **do not skip modules**. Every section exists for a reason. The exam will find every gap you left. You might hit something from a module you skimmed and have no idea where to go. Complete everything, do all the exercises, and do not just read through passively.

As I went through each module I built notes on every technique and concept. Early on I made the mistake of just copying commands without understanding them. That produced pages of notes I could not actually use under pressure. I fixed that halfway through: instead of copying, I started writing down what each command does and why the arguments matter. By the time I sat the exam I had a cheatsheet I could actually reference, not just read.

### Additional Resources

The HTB Academy material is said to be enough practice on its own. But I think you should also do the following to really solidify what you learn and feel confident going into the exam:

- **[IppSec Youtube Unofficial CPTS Playlist](https://www.youtube.com/playlist?list=PLidcsTyj9JXItWpbRtTg6aDEj10_F17x5):** IppSec covers a specific set of retired machines mapped to the CPTS curriculum. Watching his methodology on machines related to the path is extremely valuable. You see how an experienced person thinks through problems, not just what commands to run.

- **Retired HTB Machines:** I worked through a solid number of retired boxes on the free and VIP tiers. Machines that involve Active Directory, Kerberoasting, AS-REP roasting, and lateral movement were the most relevant.

- **[HTB CPTS Track](https://app.hackthebox.com/tracks/76):** A dedicated machine track on HTB aligned specifically with the CPTS curriculum. This was released after I passed, but if it had been available during my prep I would have used it heavily. If you are currently preparing, this is worth adding to your routine alongside the Academy material.

- **HTB Prolabs:** This was probably the most important preparation I did outside the Academy. I completed **100% of Zephyr** and **50% of Dante**. Prolabs are chained environments where you pivot through multiple machines to reach a final objective, exactly what the CPTS exam simulates. If you want to feel ready for the exam environment, I would suggest doing at least one Prolab if you have the budget. Zephyr is mostly AD-based and very aligned with the CPTS exam style. Dante is more of a mixed environment covering both Linux and Windows machines, which made it useful for rounding out the gaps.

---

## Tools I Used During the Exam

I kept my toolset simple and stuck to what I knew well. The exam is not the place to try tools you have never used before.

`BloodHound` was open from the moment I had a foothold. Active Directory environments have privilege chains you will not find by manually querying LDAP. BloodHound maps them instantly.

`Impacket` covered a huge amount of ground. I used different scripts for very different jobs. Credential dumping, Kerberoasting, and ACL manipulation are not the same problem and Impacket has a tool for each. Go through the suite before the exam and understand what each script does and when you would reach for it.

`PowerView` and `PowerUp` handled Windows enumeration. PowerView for Active Directory recon: users, groups, ACLs, trust relationships. PowerUp for local privilege escalation vectors on Windows hosts. They do different jobs and you will need both.

`NetExec` was how I validated credentials and moved laterally quickly. Once you have a set of credentials in a Windows environment, NetExec tells you immediately where they work and what you can do with them. It saves a lot of time that would otherwise go to manual checking.

`Ligolo-ng` handled all pivoting. If you have only ever used proxychains or SSH tunnelling, learn Ligolo-ng before the exam. It is significantly more stable in multi-hop environments and you will not want to be learning it mid-exam.

`Nmap`, `Evil-WinRM`, and a few privilege escalation scripts filled in the rest. Nothing exotic. The exam rewards knowing your tools well over knowing many tools.

---

## What I Did Differently for the Exam

The biggest change I made from how I worked through labs was **taking detailed notes from the very first minute of the exam**.

In labs you can be lazy about documentation because you can always go back and redo a step. In the exam you cannot. Every shell you get, every credential you find, every service you enumerate, write it down immediately. I documented:

- IP addresses and hostnames the moment I discovered them
- Every credential the moment I found it
- Every command I ran that gave useful output (with screenshots)
- The exact steps from one machine to the next

This meant that when it came to writing the report, I was not trying to reconstruct what I did from memory. I had a complete record of the entire engagement already.

---

## The Exam Experience

The CPTS exam gives you **10 days** to compromise the environment and write your report. That window covers everything, hacking and documentation combined.

When you start the exam you receive a letter of engagement covering scope, objectives, and rules, the same format as a real client engagement. From that point it is fully blackbox. There are no known CVEs handed to you, no obvious exploitation path. The exam expects you to find vulnerabilities, chain them together, and work your way through the environment using the same thinking you would on a real engagement.

One thing worth mentioning before getting into the experience itself: in **June 2025**, just a month before I sat the exam, HTB updated the CPTS exam. No details were published about what changed. Going in I had no idea if the environment had been made significantly harder, if the format had shifted, or if something fundamental was different. That uncertainty added real anxiety before I even started. It turned out not to be dramatically different from what people had described before the update, but not knowing that going in made the early days feel heavier than they needed to.

I started on **15 July 2025 at 1pm**. About an hour in, power outages started hitting my area. At first I assumed it was a one-off but they kept coming. Eventually my Kali VM lost internet connectivity entirely. I did not want to spend exam time troubleshooting a broken VM, so I switched to **Pwnbox**, HTB's browser-based VM. The power outages continued for the next few hours but at least Pwnbox meant I was not losing my environment every time the power flickered. I ended day 1 without a single flag. I felt disappointed in myself.

Day 2 I came back with full hope and spent the entire day enumerating. Nothing. The combination of power issues, an unfamiliar post-update environment, and two days of no progress sent my morale into free fall. It was at this point I dropped the idea of writing the report alongside the hacking. I just needed to find something first.

Day 3 I started with the last bit of hope I had. It paid off. I got my **first flag**, and the relief was significant. A few hours later I got the **2nd flag**, and then the **3rd** came almost immediately after. I pivoted into the internal network using **Ligolo-ng** and the environment started to open up.

Day 4 I got flags **4, 5, and 6**.

Day 5 I got flags **7 and 8**. My confidence was back and I had a real sense of the environment.

Day 6 I tried my Kali VM again and it was working. I switched back to it and stayed on Kali for the rest of the exam. The first half of the day was slower, spent enumerating, but the second half gave me flags **9, 10, and 11**.

Day 7 I got flags **12 and 13**. That was 13 out of 14 total, comfortably above the 12-flag pass threshold. I made the call to stop hacking and move to the report.

Day 8 and day 9 I focused entirely on the report, going back through the environment, taking all the screenshots I needed, and writing everything up. I submitted on day 9. The final report came in at **148 pages**. I got my results **1 day after submitting**.

It was a proper rollercoaster. The first two days were some of the most stressful I have had sitting any exam. The last few days felt completely different. Once the flags started coming the environment made sense and the momentum carried through to the end.

The one flag I missed I have thoughts on, but I will not spoil the environment. 13/14 is enough to pass comfortably.

My advice from all of this: **sort out your power situation before day one**. Not because the exam requires it, but because unexpected issues cause stress and stress costs you time. Also, **take snapshots of your Kali machine** before starting. If something breaks mid-exam you want to roll back instantly rather than spending hours troubleshooting a broken VM.

---

## Writing the Exam Report

The CPTS exam requires a **professional penetration testing report** as part of the submission. This is not optional and it is not trivial. The report is evaluated as part of your pass/fail decision.

I used two tools for this:

**[SysReptor](https://docs.sysreptor.com/htb-reporting-with-sysreptor/):** An open-source penetration testing report tool that structures your report professionally. It handles formatting, section templates, and produces a clean PDF output. I strongly recommend it over writing a report in Word from scratch. HTB even has a dedicated SysReptor reporting guide for exactly this use case.

**ChatGPT:** I used it to help write the executive summary and clean up the language in finding descriptions. Professional pentesters use every tool available to produce good documentation. ChatGPT is useful for turning rough technical notes into clearly written paragraphs, especially for the non-technical executive summary section.

The report should include at least:
- Executive summary for a non-technical audience
- Attack path narrative (how you moved from initial access to the final objective)
- Individual findings with severity, evidence (screenshots), and remediation recommendations

The ideal approach is to write findings as you go, and I still recommend it. But I want to be honest: I did not do it that way. After two days of no flags, writing a report felt impossible. I was too focused on finding something first. Once the flags started coming I kept the momentum going and pushed the report entirely to the end.

It cost me. Days 8 and 9 were spent going back through the environment taking screenshots and reconstructing the narrative of what I had done. Some of it was harder to remember than it should have been. If I had documented as I went it would have been two days of writing, not two days of writing and archaeology.

So: write the report as you go. That is still the right advice. Just know that if the pressure gets to you and you fall behind on documentation, you can catch up. It will just cost you time at the end.

---

## Suggestions for Those Preparing

These are the things that made the difference for me:

1. **Do not rush through the modules.** The goal is not to finish the path as fast as possible. The goal is to understand what you are studying. Speed through a module and you will complete it without retaining anything. Slow down, make sure the topic actually makes sense, then move on.

2. **When you get stuck, get a nudge, not a solution.** If you have been stuck on something for an hour or two with no progress, stop banging your head against it. Look at a writeup, watch IppSec or 0xdf cover a related machine, or ask for a nudge in the HTB Discord. The goal is to understand what you missed, not to be handed the answer. When I solved my first HTB active machine, Code, it took me 2-3 days and I asked for help in the Discord community. That is completely normal. Seeing how experienced people think through problems, through IppSec's videos or 0xdf's blogs, is one of the best ways to improve your methodology, not just your toolset.

3. **Treat AEN like a real exam.** AEN (Attacking Enterprise Networks) is the final module of the CPTS path and it is the closest simulation of the exam you will get during preparation. Do it blind: no hints, no reading ahead. Enumerate properly, take notes from minute one, and write the report as you go through it. The exam is harder than AEN so do not walk in expecting the same difficulty level, but AEN is where you build the habits that carry you through. If you get stuck, go back and read the relevant module. The answer is usually in the material.

4. **Get comfortable being lost.** In the exam you will not always know where to go next. That feeling is part of it. If you only ever practice in environments where the next step is obvious, the exam will feel overwhelming. Train yourself to sit with uncertainty, keep enumerating, and trust that the path forward is there.

5. **Build your methodology while preparing, then use it in the exam.** Every lab, every machine, and every prolab you solve during preparation is a chance to refine how you approach an unknown environment. Pay attention to what works, what order you do things in, and what you keep missing. By the time you sit the exam you should have a personal methodology you trust: how you enumerate, how you prioritise services, how you move laterally, how you escalate. The exam is not the place to figure that out. Build it during preparation so it runs on instinct when the pressure is on.

6. **Take breaks and look after yourself.** This applies during study and during the exam. Short breaks keep your brain focused. The exam is 10 days. You are not racing a clock, you are managing your thinking over a long period. Eat properly, drink water, sleep. It sounds obvious but it is easy to forget when you are deep in an environment and making progress.

---

## Final Thoughts

CPTS is the best entry-level offensive certification available right now. The Academy path does not just show you what commands to run. It explains why things work, how the underlying protocols and systems behave, and what defenders are looking for. That depth is what builds a foundation you can actually use beyond the cert.

The report requirement is something I think gets overlooked when people research CPTS. Passing the exam is not just about getting flags. You have to write a professional penetration testing report and have it evaluated as part of your pass/fail decision. That is a real skill in this field and CPTS takes it seriously.

It is not easy. But do the work properly and the exam will take care of itself.

If you are preparing for it and have questions, feel free to reach out on Discord — `darkness215`

---

## My CPTS Notes and Cheatsheet

Over the course of 3 months studying the Academy path I built a full personal cheatsheet covering every technique, tool syntax, and methodology from the curriculum. I have published my full CPTS notes on Notion, you can find them here: [HTB CPTS Notes — darkness215](https://www.notion.so/HTB-CPTS-Notes-darkness215-3164aa3a9bdc80f198a3d00b1657baec).

If you are on the CPTS path, check the [Red Team](/docs/redteam) and [Blue Team](/docs/blueteam) sections of this site. Some of the techniques covered there overlap directly with the CPTS curriculum.

---

If this post helped you, drop me a respect on HackTheBox, it means a lot. [Give Respect →](https://app.hackthebox.com/users/2187012)
