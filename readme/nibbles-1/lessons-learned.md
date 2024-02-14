# Lessons Learned

* `nc` to grab banners and confirm nmap services
* `whatweb` gets website services
* `$ curl -s http://10.10.10.75/nibbleblog/content/private/config.xml | xmllint --format -`
  * shows in more readable format
* enumartion never stops
* php command execution file upload and using reverse shell cheatsheets
  * `cURL` the image page again or browse to it in `Firefox` at http://nibbleblog/content/private/plugins/my\_image/image.php to execute the reverse shell.
* get a TTY shell using python3:
  * `python3 -c 'import pty; pty.spawn("/bin/bash")'`
