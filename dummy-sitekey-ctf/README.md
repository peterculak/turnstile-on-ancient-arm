# Dummy-sitekey no-browser CTF

A genuinely no-browser Turnstile "solve": the server uses Cloudflare's published
testing sitekey `1x00000000000000000000AA`, which always passes and always
produces one fixed, documented token: `XXXX.DUMMY.TOKEN.XXXX`. Knowing that
fact is the entire challenge — see [`../RESEARCH.md`](../RESEARCH.md) for the
full writeup.

## Run it

```
pip install -r requirements.txt
python app.py        # serves the challenge on :5050
```

Solve it from anywhere with only the Python standard library (this is what
runs, unmodified, on the Raspberry Pi 1):

```
python solver_pi1.py http://<server-host>:5050
```

## Testing against a real widget too

Create a real Cloudflare Turnstile widget (see `RESEARCH.md`), then:

```
export CF_REAL_SITE_KEY=<your sitekey>
export CF_REAL_SECRET_KEY=<your secret key>
python app.py
```

This activates `/real` and `/real-verify`, serving the real widget instead of
the dummy one — but solving *that* needs the actual cfsolve binary from the
repo root, not `solver_pi1.py`.
