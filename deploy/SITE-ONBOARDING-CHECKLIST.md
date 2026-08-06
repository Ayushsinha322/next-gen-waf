# Site onboarding checklist — one page per application

Fill this in **with the application owner** before the app goes behind the WAF.
Every line exists because skipping it has broken a real app somewhere.

The WAF's defaults are tuned for a typical web app. They are *not* right for
every app, and nothing warns you when they aren't — the app just returns 413, or
504, or drops SSO. This page is how you find that out before your users do.

> **Scope note.** We are a single-arm reverse proxy: traffic reaches us by
> DNS/VIP, we terminate TLS, inspect, and forward to the origin. We do **not**
> take over the network's L2/L3 role. If the app currently depends on F5 VLAN
> separation, SNAT-pool source addresses, or route domains, that has to be
> re-homed to the network team — it does not move to us.

---

## 1. Collect from the app owner

| | Question | Answer |
|---|---|---|
| 1.1 | Hostnames to protect (all of them, including `www.` and any API subdomain) | |
| 1.2 | Origin host:port, and is the origin HTTP or **HTTPS**? | |
| 1.3 | More than one origin server? If yes, list them | |
| 1.4 | Does the origin have a health endpoint (e.g. `/healthz`) that returns 200 without auth? | |
| 1.5 | **Largest file a user can upload**, in MB | |
| 1.6 | **Slowest endpoint** — what is the longest an origin takes to *start* responding? (report generation, bulk export, payment callback) | |
| 1.7 | Does the app use **SAML or OIDC SSO**? Which binding? | |
| 1.8 | Does the app use **WebSockets** (chat, live notifications, dashboards)? | |
| 1.9 | Does the app use **Server-Sent Events** or long-polling? | |
| 1.10 | Does the app need **session stickiness**? Users behind one corporate NAT? | |
| 1.11 | Does the app serve **large downloads** or video? | |
| 1.12 | Is there PII in **responses** that must be masked (DLP)? | |
| 1.13 | Who owns the app, and who do we call at 2am? | |
| 1.14 | Maintenance window for the cutover | |

---

## 2. Settings that must be chosen, not defaulted

These four are the ones that break apps. Set them in the site wizard
(**Sites → New Site**) or in the API `upstream` / `waf_policy` blocks.

### 2.1 Max Body — default **10 MB**
From answer 1.5. Anything larger gets **413 Request Entity Too Large** from us,
and the app owner will report it as "upload is broken".

- Document portals (KYC, PAN/Aadhaar scans, balance sheets): usually **50 MB**
- Media upload: size it to the real limit, not "generous"

Don't set it far above the true maximum — it is also the memory bound per
in-flight request body.

### 2.2 Read Timeout — default **30 s**
From answer 1.6. This bounds how long the origin may take to return **response
headers**. It does **not** limit download duration or SSE stream lifetime, so
raising it does not weaken protection against slow clients.

- Normal web app: leave at default
- Report / export / batch endpoints: **120–300 s**
- Capped at 600 s by the API — beyond that it is an application bug

Set it **per site**. It used to be a node-wide environment variable, so one slow
app forced every other site on the box to wait as long.

### 2.3 Max URI — default **8192 bytes**
From answer 1.7. **SAML HTTP-Redirect binding** puts a deflated, base64-encoded
`SAMLRequest` in the query string, and it can exceed 8 KB. Symptom: login
redirect returns 403 and nobody can sign in.

- App uses SAML redirect binding: **16384**
- App uses SAML POST binding or OIDC: default is fine

### 2.4 Max Headers — default **100**
Raise to **200** for apps behind corporate SSO that accumulate many cookies.

### Also check

- **Load balancing** (1.3, 1.10): default is round-robin. Choose **IP hash** if
  the app needs stickiness — but note answer 1.10: users behind a single
  corporate NAT all hash to one backend. Cookie-based persistence is not
  available; if the app truly needs it, keep session state in the app.
- **Health check** (1.4): enable it with the real path. Without it, a dead
  origin is only detected reactively by the circuit breaker, after real users
  have already hit errors.
- **Origin TLS** (1.2): set `tls: true` per server for an HTTPS origin.
- **DLP** (1.12): off by default. Turning it on makes the WAF buffer response
  bodies up to 512 KB. Larger responses are forwarded **uninspected** and a
  warning is logged — check the logs, don't assume full coverage.

---

## 3. Deploy

1. Create the site in the dashboard (**Sites → New Site**) or via
   `POST /api/v1/sites`. Takes seconds and needs no restart.
2. **Set `mode: learning`.** Never launch a new site straight into blocking —
   its false-positive rate is unknown until it has seen real traffic. See
   [LEARNING-MODE-PILOT.md](./LEARNING-MODE-PILOT.md).
3. Upload the certificate (**manual**), or set ACME if the domain is publicly
   resolvable. Confirm the cert covers *every* hostname from 1.1.
4. Point DNS (or the VIP) at the WAF.

> On a `PATCH`, send the **full** `waf_policy`. A partial one risks dropping
> sub-objects such as `ml`.

---

## 4. Verify before telling anyone it is live

Run every line. Each maps to a question above.

```bash
HOST=app.customer.com

# 4.1  Clean request reaches the origin
curl -sk -o /dev/null -w '%{http_code}\n' https://$HOST/            # expect 200

# 4.2  An attack is caught (learning mode: 200 + a DETECT event in the console)
curl -sk -G --data-urlencode "q=1' OR '1'='1" \
     -o /dev/null -w '%{http_code}\n' https://$HOST/                # expect 200 (learning) / 403 (blocking)

# 4.3  The origin sees the REAL client IP, not the WAF's
#      Ask the app owner to check their access log for your source IP.

# 4.4  Upload at the real maximum size (1.5)
head -c 45M /dev/urandom > /tmp/big.bin
curl -sk -o /dev/null -w '%{http_code}\n' -F file=@/tmp/big.bin https://$HOST/upload

# 4.5  Slowest endpoint completes (1.6) — must not return 504
curl -sk -o /dev/null -w '%{http_code} in %{time_total}s\n' https://$HOST/<slow-endpoint>

# 4.6  SSO login works end to end (1.7) — do the real login, in a browser

# 4.7  WebSocket connects and stays up (1.8) — exercise the real feature

# 4.8  Large download completes and the byte count matches (1.11)
curl -sk -o /tmp/dl.bin -w '%{size_download}\n' https://$HOST/<large-file>

# 4.9  Certificate covers every hostname from 1.1
echo | openssl s_client -connect $HOST:443 -servername $HOST 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName -dates
```

**Do not skip 4.4–4.8 because "it's just a proxy".** These are precisely the
paths where a WAF changes behaviour, and they are invisible to a homepage check.

---

## 5. Go-live gate

Do not flip a site to `blocking` until:

- [ ] It has run in learning mode over a **full business cycle** (2 weeks target,
      1 week minimum — month-end and payroll traffic look nothing like a Tuesday)
- [ ] `deploy/load-test/fpr-report.sh` reports **under 1%**, and the denominator
      is **real user traffic** — a rate whose denominator you generated yourself
      (health probes, synthetic checks) is not a measurement
- [ ] Every recurring detection has been triaged as attack or false positive,
      and each false positive fixed with the narrowest tool available
- [ ] The app owner has signed off on the verification in §4

Then flip **one site at a time**, and watch it.

---

## 6. Rollback

If the app breaks after cutover:

1. **Fastest** — set the site to `mode: off` in the dashboard. Traffic still
   flows through the proxy, inspection stops. Seconds, no restart.
2. **Full** — point DNS/VIP back at the origin or the old F5.
3. Capture the `request_id` from a failing response and the matching event in
   **Events** before changing anything. Without it the cause is guesswork.

---

## 7. Record

| Field | Value |
|---|---|
| Application | |
| Hostnames | |
| Origin(s) | |
| Max body (MB) | |
| Read timeout (s) | |
| Max URI / headers | |
| LB strategy | |
| Health check path | |
| DLP | on / off |
| Learning mode started | |
| FPR measured | |
| Flipped to blocking | |
| App owner / on-call | |

## Related

- [LEARNING-MODE-PILOT.md](./LEARNING-MODE-PILOT.md) — the go-live gate in detail
- [DEPLOYMENT-CHECKLIST.md](./DEPLOYMENT-CHECKLIST.md) — platform install, not per-app
- [../OPERATIONS.md](../OPERATIONS.md) — day-to-day operation of the box
