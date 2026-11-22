import os

import requests
from flask import Flask, render_template_string, request

app = Flask(__name__)

# Cloudflare's published testing keypair: this sitekey always passes client-side,
# and only this matching secret (never a real one) accepts the token it produces.
SITE_KEY = "1x00000000000000000000AA"
SECRET_KEY = "1x0000000000000000000000000000000AA"

FLAG = os.environ.get("CTF_FLAG", "CTF{turnstile_dummy_token_never_lies}")

# The 1x...AA test secret always reports success regardless of what token it's
# given, so it alone can't tell a real solve from random garbage. Requiring the
# exact documented dummy token is what actually makes this a challenge.
DUMMY_TOKEN = "XXXX.DUMMY.TOKEN.XXXX"

# Set these to test against a real Turnstile widget (see RESEARCH.md for how
# to create one). Left unset, only the dummy-sitekey routes below are active.
REAL_SITE_KEY = os.environ.get("CF_REAL_SITE_KEY")
REAL_SECRET_KEY = os.environ.get("CF_REAL_SECRET_KEY")

PAGE = """
<!doctype html>
<title>Pi CTF - Turnstile Gate</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<h1>Solve the Turnstile to get the flag</h1>
<form action="{{ verify_path }}" method="post">
  <div class="cf-turnstile" data-sitekey="{{ sitekey }}"></div>
  <button type="submit">Submit</button>
</form>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, sitekey=SITE_KEY, verify_path="/verify")


@app.route("/verify", methods=["POST"])
def verify():
    token = request.form.get("cf-turnstile-response", "")
    if not token:
        return "Missing token\n", 400
    if token != DUMMY_TOKEN:
        return "Verification failed: not a valid Turnstile response token\n", 403

    resp = requests.post(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data={
            "secret": SECRET_KEY,
            "response": token,
            "remoteip": request.remote_addr,
        },
        timeout=10,
    )
    result = resp.json()

    if result.get("success"):
        return f"Access granted.\nFLAG: {FLAG}\n"
    return f"Verification failed: {result.get('error-codes')}\n", 403


if REAL_SITE_KEY and REAL_SECRET_KEY:

    @app.route("/real")
    def real_index():
        return render_template_string(
            PAGE, sitekey=REAL_SITE_KEY, verify_path="/real-verify"
        )

    @app.route("/real-verify", methods=["POST"])
    def real_verify():
        token = request.form.get("cf-turnstile-response", "")
        if not token:
            return "Missing token\n", 400

        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": REAL_SECRET_KEY,
                "response": token,
                "remoteip": request.remote_addr,
            },
            timeout=10,
        )
        result = resp.json()

        if result.get("success"):
            return f"Access granted (REAL Cloudflare Turnstile).\nFLAG: {FLAG}\n"
        return f"Verification failed: {result.get('error-codes')}\n", 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050)
