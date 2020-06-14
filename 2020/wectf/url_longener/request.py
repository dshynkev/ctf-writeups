import requests

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/80.0.3987.162 Safari/537.36",
    #"X-Forwarded-For": "35.232.27.222, 162.158.75.93",
    "Host": "url.w-va.cf",
}
cookies = {
    "url_longener_auth": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0aW1lIjoxNTkyMTUxNTIxLCJ0b2tlbiI6ImI4MmQ4OTIwLTE4MDUtNGVkZC1iNzczLTVkOTAyZGUyYmI2MSJ9.1Ok4jwcK6oVW3RhtpHWTUyMl33DZnY5T7tIb8jw1TOQ",
}
url = "http://url.w-va.cf/"

resp = requests.get(url, headers=headers, cookies=cookies)
print(resp.text)
