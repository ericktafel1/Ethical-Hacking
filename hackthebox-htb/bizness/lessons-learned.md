# Lessons Learned

Never forget to use `netcat`/`socat`

* They are fantastic for setting up reverse and bind shells.

Use the better directory enumerator. Maybe it is `dirsearch` after this box. Also use better syntax:

* Bad syntax
* <pre><code><strong>dirsearch -u 10.10.11.252
  </strong></code></pre>
* Good syntax
* ```
  dirsearch -u https://bizness.htb/ --exclude-status 403,404,500,502,400,401
  ```

When using a web server (`python3 -m http.server <port>`) use it in the directory where you want to `wget` the script.

The script `linpeas` is good, but not all the highlighted vulnerabilities are valid pathways. Do a lot of reading and be VERY patient.&#x20;

Learn to let go of an attack vector, but also learn to not give up on that attack vector.

* It is a fine balance of not wasting your time and spending more time on certain attacks.

Hints are okay, in moderation.

## Do not rush box completion.
