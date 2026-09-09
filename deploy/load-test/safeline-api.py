#!/usr/bin/env python3
"""Minimal SafeLine (chaitin) console API client, for benchmarking against it.

Why this exists: SafeLine's login is not a plain POST, and the scheme is only
discoverable by reading the console's minified JS bundle. Re-deriving it costs
an hour, so it is recorded here. Verified against SafeLine 9.4.1 community.

    GET  /api/open/system/key   -> {"data": "<16-char AES key>"}
    GET  /api/open/auth/csrf    -> {"data": {"csrf_token": "..."}}   (sets no cookies)
    POST /api/open/auth/login   {username, password, csrf_token}
                                 + X-CSRF-Token header
      password = base64( iv_ascii + AES-128-CBC/PKCS7(plaintext, key, iv_ascii) )
      iv_ascii = hex(os.urandom(8))  -- 16 ASCII characters, used directly as the
                                        16-byte CBC IV (NOT hex-decoded first)

Sending the plaintext password returns msg "invalid request", which is what makes
this hard to guess: the failure looks like a schema error, not a crypto error.

The bearer token is the returned `jwt`, sent in Authorization with no "Bearer "
prefix.

Usage:
    SL_USER=admin SL_PASS=... python3 safeline-api.py sites
    SL_USER=admin SL_PASS=... python3 safeline-api.py mode strict
Env: SL_BASE (default https://127.0.0.1:9443)

Never put the password in argv — it would land in the process table and shell
history. This reads it from the environment only.
"""
import base64, json, os, ssl, sys, urllib.error, urllib.request

BASE = os.environ.get("SL_BASE", "https://127.0.0.1:9443")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE          # the console ships a self-signed cert
_jwt = None


def call(path, data=None, method=None, timeout=60):
    """One API call. Returns the decoded envelope, or a synthetic one on a
    non-JSON error body (SafeLine answers some 404s in plain text)."""
    req = urllib.request.Request(
        f"{BASE}/api/{path.lstrip('/')}",
        data=json.dumps(data).encode() if data is not None else None,
        method=method or ("POST" if data is not None else "GET"),
    )
    req.add_header("Content-Type", "application/json")
    if _jwt:
        req.add_header("Authorization", _jwt)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {"err": f"http {e.code}", "msg": raw[:120].decode("utf8", "replace")}


def _encrypt_password(pw, key):
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(8).hex().encode()            # 16 ASCII chars == the 16 IV bytes
    p = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key.encode()), modes.CBC(iv)).encryptor()
    ct = enc.update(p.update(pw.encode()) + p.finalize()) + enc.finalize()
    return base64.b64encode(iv + ct).decode()


def login(user, pw):
    global _jwt
    key = call("open/system/key")["data"]
    csrf = call("open/auth/csrf")["data"]["csrf_token"]
    r = call("open/auth/login",
             {"username": user, "password": _encrypt_password(pw, key), "csrf_token": csrf})
    if r.get("err"):
        raise SystemExit(f"login failed: err={r['err']} msg={r.get('msg')}")
    _jwt = r["data"]["jwt"]
    return _jwt


def create_site(port, upstream, server_names=("*",)):
    """A bench site. `port` is a string; suffix it "_ssl" for TLS. tengine runs on
    the host network, so the port is bound on the host."""
    return call("open/site", {
        "server_names": list(server_names),
        "ports": [str(port)],
        "upstreams": [upstream],                  # e.g. "http://172.17.0.2:80"
        "load_balance": {"balance_type": 1},      # 1=round-robin
        "mode": 0,                                # 0=Defense 1=Offline 2=Dryrun
        "type": 0, "cert_id": 0, "email": "", "comment": "bench",
    })


def set_semantics(level):
    """Set every semantic module to one of disable|default|dryrun|strict.
    SafeLine ships m_scanner and m_response disabled; `strict` is its maximum
    detection posture."""
    cur = call("open/global/mode")["data"]["semantics"]
    call("open/global/mode", {"semantics": {k: level for k in cur}}, method="PUT")
    return call("open/global/mode")["data"]["semantics"]


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "sites"
    try:
        login(os.environ["SL_USER"], os.environ["SL_PASS"])
    except KeyError:
        raise SystemExit("set SL_USER and SL_PASS in the environment")
    if cmd == "sites":
        print(json.dumps(call("open/site/1"), indent=1))
    elif cmd == "mksite":
        print(json.dumps(create_site(sys.argv[2], sys.argv[3]), indent=1))
    elif cmd == "mode":
        print(json.dumps(set_semantics(sys.argv[2]), indent=1, sort_keys=True))
    else:
        print(json.dumps(call(cmd), indent=1))
