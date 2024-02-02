---
description: HTB Granny walkthrough used in the last 15% of the attack
---

# Lessons Learned

I learned that I can use the local\_exploit\_suggester module in a Meterpreter session. To do this I run the following command:

```
(Meterpreter 1)(c:\Documents and Settings) > run post/multi/recon/local_exploit_suggester
```

I also learned about migrat ing processes to have higher privileges. It is recommended to migrate to a process running under NT AUTHORITY\NETWORK SERVICE. In this case, davcdata.exe seemed to be the only stable process available. To migrate use the PID:

```
(Meterpreter 1)(c:\Documents and Settings) > migrate 2112
[*] Migrating from 2440 to 2112...
[*] Migration completed successfully.
(Meterpreter 1)(C:\WINDOWS\system32) > getuid
Server username: NT AUTHORITY\NETWORK SERVICE
```

Lastly, I am learning that I tend to jump from exploit to exploit. Even after the first exploit I used worked and got me a Meterpreter session, I jumped backward to see if the others would elevate my privileges somehow.\
\
For these reasons, it was beneficial for me to consult a walkthrough to understand how to proceed.

