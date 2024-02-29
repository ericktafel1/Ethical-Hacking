# Lessons Learned

Use `dirsearch` instead of `gobuster` for directory enumeration. `Gobuster` usually misses hidden directories in my experience.

Spend more time reading and researching, don't waste time with exploits until I have done so much recon that I understand what all the services and technologies on the target do.

* I wasted time trying exploits when I had more recon to do.

Don't forget to change `GET` to `POST` when submitting fields in a request.

Encode payloads to base64 and then URL when sending the exploit over request headers.

Save the ptty update terminal commands (see my local notes), and the /bin/sh payload commands for future reference ([https://www.revshells.com/](https://www.revshells.com/)).

Use `sudo -l` to check priv esc options on user account.

Use GTFObins for shells too ([https://gtfobins.github.io/](https://gtfobins.github.io/)).
