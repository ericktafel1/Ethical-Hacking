# Lessons Learned

Netcat/socat is GOAT

Dirsearch is better, also use better syntax

* ```
  dirsearch -u 10.10.11.252
  ```
* ```
  dirsearch -u https://bizness.htb/ --exclude-status 403,404,500,502,400,401
  ```

when using a web server (python3 -m http.server \<port>) use it in the directory where you want to `wget` the script

Linpeas is good, but not all the highlighted vulnerabilities are valid pathways

Learn to let go of an attack vector but also learn to not give up on that attack vector. It is a fine balance of not wasting your time and spending more time on certain attacks.

Hints are okay, in moderation

