# Lessons Learned



* Use `nc` after nmap to banner grab and confirm services
  * then use `-sC` to scan. if nothing, depending on what has been previously identified, use a specific nmap script
* We can use `whatweb` to try to identify the web application in use.
* `curl http://.../.../.xml | xmllint --format -`
  * formats xml to be readable
* Dont stop enumerating
* Gobuster to brute force pages/directories
* Check config.xml files and other interesting ones (users, admin, etc.)
* Uploading a file with `<?php system('id'); ?>` in it checks for code execution.
*
