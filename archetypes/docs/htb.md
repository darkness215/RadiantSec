---
title: "{{ replace .Name "-" " " | title }}"
date: {{ .Date }}
description: ""
tags: ["HackTheBox", "HTB"]
---

## Overview

{{</* htb-meta platform="HackTheBox" difficulty="" os="" ip="" date="{{ now.Format "2006-01-02" }}" status="In Progress" */>}}

## Enumeration

### Port Scan

```bash
nmap -sC -sV -oA nmap/initial 10.129.x.x
```

## Foothold

## Privilege Escalation

## Summary
