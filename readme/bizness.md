---
description: https://app.hackthebox.com/machines/Bizness
---

# Bizness



```
-[Wed Feb 14-15:46:04]-[table@parrot]-
-[~]$ nmap -sV 10.10.11.252 -p- -T5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 15:46 PST
Warning: 10.10.11.252 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.252
Host is up (0.076s latency).
Not shown: 64399 closed tcp ports (conn-refused), 1132 filtered tcp ports (no-response)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp    open  http       nginx 1.18.0
443/tcp   open  ssl/http   nginx 1.18.0
46589/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 395.69 seconds

```



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

