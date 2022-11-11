After getting a reverse shell, you can choose to stabilize your shell by generating SSH keys on the victim box.

In this case, I will be demonstrating in the [Squashed](../HackTheBox/Squashed.md) box in HackTheBox.

I will be generating ssh key pairs using `ssh-keygen` for the user `alex`.
```console
alex@squashed:/home/alex$ ssh-keygen
ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/alex/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Created directory '/home/alex/.ssh'.
Your identification has been saved in /home/alex/.ssh/id_rsa
Your public key has been saved in /home/alex/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:4KZlt2nolAc7QIPF1QOdejDth4LDZGA+jOZ8JHMz1iI alex@squashed.htb
The key's randomart image is:
+---[RSA 3072]----+
|  oo..o= .       |
| = o= o *        |
|.E=@oo.= o       |
|+ BoBoo.+ .      |
| o ...*oS.       |
|  .  * * o       |
|    . * =        |
|     o +         |
|      .          |
+----[SHA256]-----+
```

Then in `.ssh/`, copy the public key to a file named 'authorized_keys' with the permission of `644`.
```console
$ cd ~/.ssh/
$ cat id_rsa.pub > authorized_keys
$ chmod 644 authorized_keys 
```
The last step is crucial, if you did not do this, you will not be able to authenticate using the private key.

Then I copied the private key (`id_rsa`) to my box and named it `id_rsa_alex`. The permission of the file needs to be set to `600` in order to use it.
```console
$ ssh -i id_rsa_alex alex@$IP

[REDACTED]
Last login: Mon Oct 31 10:19:35 2022 from 10.10.14.12
alex@squashed:~$
```
Now we have a more stable shell.
