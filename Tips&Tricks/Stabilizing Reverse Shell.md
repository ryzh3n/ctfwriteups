# Stabilizing the reverse shell

After getting a connection from a reverse shell, you can choose to stabilize it in order to use some commands such as `vim`, `nano`, or some database consoles.

I'll be demonstrating this using [SwagShop](../HackTheBox%20Retired%20Machines/SwagShop.md).

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

And that's it, now we can use the arrow keys, tab, and other shortcut keys just like our local shell.
