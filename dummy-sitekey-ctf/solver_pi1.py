#!/usr/bin/env python3
"""Turnstile 'solver' for hardware too old to run a browser (Pi 1, 2012, ARMv6).

No browser, no JS engine: the target site uses Cloudflare's published testing
sitekey (1x00000000000000000000AA), which always passes and only ever issues
one fixed literal token: XXXX.DUMMY.TOKEN.XXXX. Knowing that from Cloudflare's
own docs is the whole "solve" -- we just POST it directly.
"""
import sys
import urllib.parse
import urllib.request

DUMMY_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "http://192.168.1.41:5050"
    data = urllib.parse.urlencode({"cf-turnstile-response": DUMMY_TOKEN}).encode()
    req = urllib.request.Request(f"{target}/verify", data=data, method="POST")
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(resp.read().decode())


if __name__ == "__main__":
    main()
