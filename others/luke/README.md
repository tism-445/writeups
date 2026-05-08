

Today I will be doing a writeup for Luke, a medium FreeBSD machine from hackthebox.
The machine involves enumerating FTP and multiple HTTP services, pivoting between leaked credentials until gaining access to Ajenti, which provides a root terminal.




## Recon


### Nmap

As always I start with `nmap` to scan for open ports:

```bash
sudo nmap -p- -oA nmap/allports --min-rate=10000 10.129.96.55
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-07 11:53 EDT
Warning: 10.129.96.55 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.96.55
Host is up (0.12s latency).
Not shown: 52256 filtered tcp ports (no-response), 13274 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
8000/tcp open  http-alt
```

The scan shows 5 open ports. I will now perform a service and version detection scan on these ports.


```bash
┌──(10.10.14.154)─(kali@kali)-[~/boxes/luke]
└─ [★]$ sudo nmap -p 21,22,80,3000,8000 -sV -sC -vv 10.129.96.55
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-07 12:01 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:01
Completed NSE at 12:01, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:01
Completed NSE at 12:01, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:01
Completed NSE at 12:01, 0.00s elapsed
Initiating Ping Scan at 12:01
Scanning 10.129.96.55 [4 ports]
Completed Ping Scan at 12:01, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 12:01
Completed Parallel DNS resolution of 1 host. at 12:01, 0.01s elapsed
Initiating SYN Stealth Scan at 12:01
Scanning 10.129.96.55 [5 ports]
Discovered open port 80/tcp on 10.129.96.55
Discovered open port 21/tcp on 10.129.96.55
Discovered open port 22/tcp on 10.129.96.55
Discovered open port 3000/tcp on 10.129.96.55
Discovered open port 8000/tcp on 10.129.96.55
Completed SYN Stealth Scan at 12:01, 0.06s elapsed (5 total ports)
Initiating Service scan at 12:01
Scanning 5 services on 10.129.96.55
Completed Service scan at 12:03, 158.67s elapsed (5 services on 1 host)
NSE: Script scanning 10.129.96.55.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:03
NSE: [ftp-bounce 10.129.96.55:21] PORT response: 500 Illegal PORT command.
Completed NSE at 12:04, 22.85s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 1.11s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Nmap scan report for 10.129.96.55
Host is up, received echo-reply ttl 63 (0.041s latency).
Scanned at 2026-05-07 12:01:19 EDT for 183s

PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.3+ (ext.1)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.14.154
|      Logged in as ftp
|      TYPE: ASCII
|      No session upload bandwidth limit
|      No session download bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3+ (ext.1) - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0             512 Apr 14  2019 webapp
22/tcp   open  ssh?    syn-ack ttl 63
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.38 ((FreeBSD) PHP/7.3.3)
|_http-server-header: Apache/2.4.38 (FreeBSD) PHP/7.3.3
|_http-title: Luke
| http-methods:
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn\'t have a title (application/json; charset=utf-8).
8000/tcp open  http    syn-ack ttl 63 Ajenti http control panel
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Ajenti

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:04
Completed NSE at 12:04, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.14 seconds
           Raw packets sent: 9 (372B) | Rcvd: 6 (248B)
```

The scan shows `ftp` on port 21 with anonymous login enabled, ssh on port 22 and then there are 3 http servers on ports 80, 3000 and 8000.


### FTP - TCP 21


Anonymous login is allowed, so I connect and download all available files.

```
┌──(10.10.14.154)─(kali@kali)-[~/boxes/luke]
└─ [★]$ wget -r ftp://anonymous:anonymous@10.129.96.55

──(10.10.14.154)─(kali@kali)-[~/boxes/luke]
└─ [★]$ find 10.129.96.55/ -type f
10.129.96.55/webapp/for_Chihiro.txt
```


There is only one file: `for_Chihiro.txt`
```
┌──(10.10.14.154)─(kali@kali)-[~/boxes/luke]
└─ [★]$ cat 10.129.96.55/webapp/for_Chihiro.txt
Dear Chihiro !!

As you told me that you wanted to learn Web Development and Frontend, I can give you a little push by showing the sources of 
the actual website I've created .
Normally you should know where to look but hurry up because I will delete them soon because of our security policies ! 

Derry
```

From this note, I get two possible usernames: `Chihiro` and `Derry`. The note also hints there might be some source code available.


### HTTP - TCP 80

Browsing to `http://10.129.96.55` I find a page for Luke LTD:

![](attachments/image01.png)


There is nothing interesting on the page, so I begin brute-forcing directories.


```bash
┌──(10.10.14.154)─(kali@kali)-[~/boxes/luke]
└─ [★]$ ffuf -u http://10.129.96.55/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.96.55/FUZZ 
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 55ms]
LICENSE                 [Status: 200, Size: 1093, Words: 156, Lines: 22, Duration: 45ms]
.hta                    [Status: 403, Size: 213, Words: 16, Lines: 10, Duration: 2031ms]
.htpasswd               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 3061ms]
css                     [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 42ms]
index.html              [Status: 200, Size: 3138, Words: 595, Lines: 109, Duration: 45ms]
js                      [Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 40ms]
management              [Status: 401, Size: 381, Words: 36, Lines: 13, Duration: 74ms]
member                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 71ms]
package.json            [Status: 200, Size: 1033, Words: 239, Lines: 38, Duration: 53ms]
package-lock.json       [Status: 200, Size: 205147, Words: 75277, Lines: 5006, Duration: 46ms] 
vendor                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 56ms]
:: Progress: [4750/4750] :: Job [1/1] :: 784 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```


The most interesting endpoint is `/management`, which requests http auth, no common guesses seem to work

![](attachments/image02.png)

Next I try to brute force files on the server

```bash
┌──(10.10.14.154)─(kali@kali)-[~/boxes/luke]
└─ [★]$ ffuf -u http://10.129.96.55/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.96.55/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

login.php               [Status: 200, Size: 1593, Words: 230, Lines: 40, Duration: 225ms]
index.html              [Status: 200, Size: 3138, Words: 595, Lines: 109, Duration: 58ms]
config.php              [Status: 200, Size: 202, Words: 22, Lines: 7, Duration: 59ms]
.htaccess               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 40ms]
.                       [Status: 200, Size: 3138, Words: 595, Lines: 109, Duration: 41ms]
.html                   [Status: 403, Size: 214, Words: 16, Lines: 10, Duration: 42ms]
.htpasswd               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 401ms]
.htm                    [Status: 403, Size: 213, Words: 16, Lines: 10, Duration: 44ms]
.htpasswds              [Status: 403, Size: 219, Words: 16, Lines: 10, Duration: 50ms]
.htgroup                [Status: 403, Size: 217, Words: 16, Lines: 10, Duration: 44ms]
.htaccess.bak           [Status: 403, Size: 222, Words: 16, Lines: 10, Duration: 41ms]
.htuser       , Words: 16, Lines: 10, Duration: 40ms]
```

The most interesting file is `config.php` which contains the credentials for the connection to the database.

![](attachments/image03.png)

`$dbHost = 'localhost'; $dbUsername = 'root'; $dbPassword = 'Zk6heYCyv6ZE9Xcg'; $db = "login"; $conn = new mysqli($dbHost, $dbUsername, $dbPassword,$db) or die("Connect failed: %s\n". $conn -> error);`

I tried the password on the `/management` login but did not work.

### HTTP - TCP 3000

Visiting `http://10.129.96.55:3000`, it responds with a json saying `Auth token is not supplied`

![](attachments/image04.png)

The response looks like an API for some app. 


### HTTP - TCP 8000

Browsing `http://10.129.96.55:8000` we get to the login page of `Ajenti`

![](attachments/image05.png)


Using common credentials does not work.




## Shell as root

Going back to the API at port 3000, I try to brute-force endpoints.

```bash
┌──(10.10.14.154)─(kali@kali)-[~/boxes/luke]
└─ [★]$ ffuf -u http://10.129.96.55:3000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt 
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.96.55:3000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

Login                   [Status: 200, Size: 13, Words: 2, Lines: 1, Duration: 60ms]
login                   [Status: 200, Size: 13, Words: 2, Lines: 1, Duration: 42ms]
users                   [Status: 200, Size: 56, Words: 5, Lines: 1, Duration: 43ms]
:: Progress: [4750/4750] :: Job [1/1] :: 921 req/sec :: Duration: [0:00:06] :: Errors: 0 :
```

Found `/login` and `/users`.

I then test the login endpoint using the password we got from before. The usernames from the FTP note did not work but `admin` does.

![](attachments/image06.png)


```
Content-Type: application/json
{"user":"admin","password":"Zk6heYCyv6ZE9Xcg"}
```


I got the following response from the API:

```
{"success":true,"message":"Authentication successful!","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNzc4MTc1NzA2LCJleHAiOjE3NzgyNjIxMDZ9.rUgyx6Jmkm6P2JANPlrM8jRsBbSCP9LCmJgvyvaU2WU"}
```

It looks like a JWT token, I might be able to use it to access the other API endpoint.


![](attachments/image07.png)

Using the token against /users, the API returns a list of valid usernames.

![](attachments/image08.png)

I then query each user individually with /users/<username> and get the following credentials:


```
{"name":"Admin","password":"WX5b7)>/rp$U)FW"}
```

```
{"name":"Yuri","password":"bet@tester87"}
```

```
{"name":"Dory","password":"5y:!xa=ybfe)/QD"}
```

```
{"name":"Derry","password":"rZ86wwLvx7jUxtch"}
```


I try these credentials on the `/management` login and I was able to login with `Derry`:`rZ86wwLvx7jUxtch`

After logging in I get access to the file `config.json` which seeappears to be `ajenti` configuration
![](attachments/image09.png)

The config includes a password: `KpMasng6S5EtTy9Z`


I can log into `Ajenti` on port 8000 using `root`:`KpMasng6S5EtTy9Z`
![](attachments/image10.png)


At this point, there are several things i could try, but the terminal option looks the most interesting.

Clicking the `+NEW` button a new black box appears. Then i click on it, and i am presented with a shell logged in as root

![](attachments/image11.png)


