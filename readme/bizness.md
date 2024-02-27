---
description: https://app.hackthebox.com/machines/Bizness
---

# Bizness



```
-[Tue Feb 27-13:52:38]-[table@parrot]-
-[~]$ nmap -sV -sC -T5 10.10.11.252 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-27 13:55 PST
Warning: 10.10.11.252 giving up on port because retransmission cap hit (2).
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.075s latency).
Not shown: 64877 closed tcp ports (conn-refused), 654 filtered tcp ports (no-response)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
|_http-trane-info: Problem with XML parsing of /evox/about
|_ssl-date: TLS randomness does not represent time
|_http-title: BizNess Incorporated
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|_  http/1.1
35339/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 342.32 seconds

```

msf attempts on nginx unsuccessful

```
[msf](Jobs:0 Agents:0) >> search nginx

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/linux/http/nginx_chunked_size           2013-05-07       great      Yes    Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow
   1  auxiliary/scanner/http/nginx_source_disclosure                   normal     No     Nginx Source Code Disclosure/Download
   2  exploit/multi/http/php_fpm_rce                  2019-10-22       normal     Yes    PHP-FPM Underflow RCE
   3  exploit/linux/http/roxy_wi_exec                 2022-07-06       excellent  Yes    Roxy-WI Prior to 6.1.1.0 Unauthenticated Command Injection RCE


Interact with a module by name or index. For example info 3, use 3 or use exploit/linux/http/roxy_wi_exec
```

Cant access the web page at `https://10.10.11.252/`\
Edited `/etc/hosts` to include \
`10.10.11.252            bizness.htb`

Whatweb for services on website

```
-[Tue Feb 27-13:30:41]-[table@parrot]-
-[~]$ whatweb http://bizness.htb/
http://bizness.htb/ [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.252], RedirectLocation[https://bizness.htb/], Title[301 Moved Permanently], nginx[1.18.0]
https://bizness.htb/ [200 OK] Bootstrap, Cookies[JSESSIONID], Country[RESERVED][ZZ], Email[info@bizness.htb], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[JSESSIONID], IP[10.10.11.252], JQuery, Lightbox, Script, Title[BizNess Incorporated], nginx[1.18.0]
```

Gobuster initial

```
-[Tue Feb 27-13:59:23]-[table@parrot]-
-[~]$ gobuster dir -u  http://10.10.11.252 --wordlist /usr/share/dirb/wordlists/common.txt -b 301
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.252
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   301
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

Dirsearch

```
-[Tue Feb 27-14:04:24]-[table@parrot]-
-[~]$ dirsearch -u 10.10.11.252

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/table/.dirsearch/reports/10.10.11.252_24-02-27_14-04-34.txt

Error Log: /home/table/.dirsearch/logs/errors-24-02-27_14-04-34.log

Target: http://10.10.11.252/

[14:04:34] Starting: 
[14:04:53] 301 -  169B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/  ->  https://bizness.htb/examples/jsp/%252e%252e/%252e%252e/manager/html/

Task Completed

```

Nginx in nmap but noticed Apahce OFBiz Powers the website at the footer

