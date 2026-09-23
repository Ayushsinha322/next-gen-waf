# Swaraj Kavach — Putting a website behind the WAF

**Who this is for:** SOC / NOC / operations. You do not need developer access.
Everything here is done in the console, plus two commands to test with.

**Time:** about 20 minutes of work, then a waiting period before you switch on
blocking. The waiting is not optional — §8 explains why.

---

## The whole journey

```
Add website  →  Backend  →  TLS  →  DNS  →  Test  →  Monitor  →  Blocking
    §3            §4        §5      §6      §7       §8          §8
```

## First, the one idea you need

The WAF sits **in front of** a website. It is not the website.

```
Visitor
   │
   ▼
www.customer.com   ← DNS name the visitor types
   │
   ▼
Public IP          ← "frontend" — where traffic arrives
   │
   ▼
WAF                ← inspects the request
   │
   ▼
10.20.30.40:443    ← "backend" / origin — the customer's real server
   │
   ▼
The actual website
```

Two things you will configure for every site:

- **Domains** — the names visitors type. The WAF uses these to decide which site
  a request belongs to.
- **Backend (origin)** — the IP and port of the real server to forward to.

One WAF handles many sites at once. It tells them apart by the name in the
request:

```
                     ┌── shop.customer.com   ──> 10.1.1.20:443
Public IP ─── WAF ───┼── portal.customer.com ──> 10.1.1.30:8080
                     └── api.customer.com    ──> 10.1.2.40:443
```

---

## 1. Collect this information first

Get these answers from the application owner **before** you touch the console.
Every line here exists because skipping it has broken a real application.

| | Question | Why you need it |
|---|---|---|
| 1 | **All** hostnames to protect — including `www.` and any API subdomain | A name you miss will not route. Visitors get an error |
| 2 | Origin IP or hostname, and **port** | Where the WAF forwards to |
| 3 | Is the origin **HTTP or HTTPS**? | Wrong answer = handshake failure or 502 |
| 4 | Does the origin have a health URL that returns 200 without a login? | Lets the WAF detect a dead origin before users do |
| 5 | **Largest file a user can upload**, in MB | Too small and uploads fail with `413`. The owner will report "upload is broken" |
| 6 | **Slowest page** — how long can the origin take to start replying? | Too short and you get `504` on reports and exports |
| 7 | Does it use **SAML** single sign-on? | SAML redirect login needs a bigger URL limit, or logins fail with `403` |
| 8 | Does it use **WebSockets** (live chat, live dashboards)? | Off by default. If the app needs it and you do not enable it, that feature silently stops working |
| 9 | Are there **large downloads** or video? | Affects timeout choices |
| 10 | Who owns the app, and who do you call at 2 a.m.? | |
| 11 | Agreed **maintenance window** for the switchover | |

If the origin is HTTPS, also ask: **what name is on its certificate?** You may
need it in §4.

---

## 1b. The one-command way (recommended for a real application)

With the answers above and the certificate files on the WAF host, §2–§5 below
collapse into one command run **on the WAF host**:

```bash
sudo ./onboard-site.sh --domain app.example.com \
     --origin 10.20.30.40:443 --origin-tls \
     --cert /root/app.fullchain.pem --key /root/app.key.pem \
     --health /healthz --websocket --body-limit 52428800
```

It checks the key matches the certificate and the certificate names the domain,
installs the certificate, creates the site in **learning** mode, waits for the
rule engine, and then proves the path from the WAF host itself — the site
answers for the hostname, presents *your* certificate, reaches the origin, and
records a detection — all **before DNS moves**. It ends with the pre-cutover
test for your laptop and the cutover steps in order. `--dry-run` shows exactly
what it would send. If the admin account has MFA on, give it an API key via
`SENTINEL_API_KEY`. The console steps below remain the reference for what each
setting means, and for changing a site later.

---

## 2. Open the console

```bash
ssh -L 9443:127.0.0.1:9443 root@<waf-vm-ip>      # run on your own machine
```

Then browse to **https://127.0.0.1:9443** and log in. (Full explanation of why
the tunnel is needed: [INSTALL-WALKTHROUGH.md](../vm-deploy/INSTALL-WALKTHROUGH.md) §3.)

---

## 3. Add the website

Go to **Sites → New Site**. A wizard opens.

It has two modes. **Easy mode has 5 steps:**

```
Basics  →  Front Service  →  Reverse Proxy  →  Protection  →  Review
```

Advanced mode has 11 steps and adds Request Limits, Proxy Options, API security,
rate limiting, anti-bot, geo/IP filtering, custom headers and ML tuning.

> ### Choose the mode from §1, before you start
>
> Easy mode is genuinely enough for a plain website on default limits. It is
> **not** enough for most real applications, and the settings it omits are
> exactly the ones that break them — body size, timeouts, URI and header limits,
> allowed methods, WebSocket, health checks, origin SNI.
>
> **Use Advanced mode if any of §1 lines 4–8 is not the default.** Switching an
> existing Easy-mode site is not offered; you would recreate it. Deciding once,
> here, costs nothing.

You will notice small tags on the settings:

- **● Enforced** — the WAF acts on this today.
- **◐ Stored** — saved and carried through, but not enforced yet (roadmap).

They are there so you are never guessing which is which. Trust them.

### Step 1 — Basics

| Field | What to enter |
|---|---|
| **Site Name** | Anything recognisable, e.g. `customer-portal`. Internal label only |
| **Security Mode** | ⚠️ **Change this to `Learning`.** See the warning below |
| **Server Names / Domains** | The hostnames from §1 line 1. Bare names only — no `http://`, no port. Press **Enter** after each one |

> ### ⚠️ The most important box on this page
>
> **Security Mode defaults to `Blocking`. Change it to `Learning` for every new
> site.**
>
> Blocking means the WAF rejects requests it dislikes. That sounds like what you
> want, and eventually it is — but **nobody has yet measured how this WAF behaves
> against *your* application's normal traffic.** Switch it on from day one and
> the first thing you may discover is real users being blocked, in production,
> during business hours.
>
> Learning mode inspects everything and records exactly what it *would* have
> blocked — without blocking it. After a couple of weeks you will know, with
> numbers, whether blocking is safe. §8 covers the switch.
>
> Learning mode is **not** "protection off". Some defences still act — bad
> scanners are still rejected. It is the *rule engine* that reports instead of
> blocks.

> ### Learning mode relaxes the four request limits too — size them anyway
>
> In **Learning** mode an over-limit request is **recorded as would-block and
> forwarded**, like every other verdict. In **Blocking** mode it is refused:
>
> | Limit | Refused with (Blocking) | Typical real-user trigger |
> |---|---|---|
> | Max body size | **413** | a large file or image upload |
> | Max URI length | **414** | a SAML/OIDC redirect carrying a long token |
> | Max header count | **431** | a corporate SSO session with many cookies |
> | Allowed methods | **405** | `PUT`/`PATCH`/`DELETE` from a REST or WebDAV client |
>
> **Size these four from §1 before the site takes real traffic anyway.** Nothing
> breaks during the learning window, but every over-limit request lands in the
> learning report — and on the day you switch to Blocking, each one becomes a
> real user's 413. Read the report for limit hits before §8, not after.
>
> *(Earlier editions of this manual said the opposite — that the limits reject in
> every mode except Off. That was true of an early build and has not been since;
> the behaviour is now pinned by an automated test.)*
>
> The console refuses values that cannot be meant — a body limit over 10 GB, a
> URI limit over 128 KB, more than 1000 headers — and warns on risky ones,
> including the **Strict preset's paranoia 4 / threshold 3**, which blocks most
> legitimate traffic until tuned. "Max Body" is in **megabytes**: typing a byte
> count there is the usual mistake, and the console now says so.



**Do not put a bare IP address in the Domains list** if you can avoid it. One of
the standard rule sets flags every request whose host is a numeric IP, so every
single request gets a suspicion score. Your logs fill with noise and you cannot
see real problems. Use a DNS name.

### Step 2 — Front Service

This is the **visitor-facing** side.

> **These four switches record intent. They do not change traffic.** The whole
> Front Service block is stored on the site record and is never sent to the data
> plane — the control plane classifies `frontend` as deliberately stored-only,
> because these are listener-level properties and the listeners are configured
> once for the host, not per site. The wizard shows an amber note saying so; this
> table used to contradict it.

| Setting | Recommended | Effect |
|---|---|---|
| **HTTPS** | On | ◐ Recorded only. The host's `:443` listener already serves every site |
| **Force HTTPS** | On | ◐ **Recorded only — there is no HTTP→HTTPS redirect today.** See the warning below |
| **HTTP/2** | On | ◐ Recorded only. Negotiated by the listener for all sites |
| **HTTP/3** | Off unless you specifically want it | ◐ Recorded only. Enabled host-wide, not per site |
| **TLS / certificate** | Leave as is for now | §5 handles certificates properly — that part *is* per-site and does take effect |

> ### ⚠️ "Force HTTPS" does not force HTTPS
>
> There is no per-site HTTP→HTTPS redirect in this build. With **Force HTTPS on**,
> a visitor who types `http://your-site` is served the site **in full over
> unencrypted HTTP on port 80** — and §6 tells the network team to NAT public
> `:80` through to the WAF, so that path is open by default.
>
> If plain HTTP must not serve this site, the control is at the network edge, not
> in this wizard: **ask the network team not to NAT public `:80`.** Note that
> doing so also disables ACME `http-01` certificate issuance and renewal (§5), so
> use DNS-01 or a manually supplied certificate instead.
>
> Do not record "HTTPS enforced" on the §9 handover sheet on the strength of this
> toggle.

### Step 3 — Reverse Proxy (the backend)

This is where you enter the **origin server** from §1.

> ### ⚠️ Easy mode does not show most of this step
>
> In **Easy** mode the Reverse Proxy screen has exactly three controls:
> **Application Host**, **Port**, and **Upstream uses HTTPS**. Health check path,
> both timeouts, WebSocket, Host-header override and Origin SNI render only in
> **Advanced**; and Max body size / Max URI length / Max header count / Allowed
> methods are not on this screen at all — they live on the **Advanced → Request
> Limits** step.
>
> **If §1 told you to change any of them, create the site in Advanced mode.**
> There is no way to reach them later from an Easy-mode site without switching.
>
> | What you need | Easy mode | Where it actually is |
> |---|---|---|
> | Host, Port, origin HTTPS | ✅ on this screen | — |
> | Health check path | ❌ | Advanced → Reverse Proxy |
> | Read / connect timeout | ❌ | Advanced → Reverse Proxy → Proxy Options |
> | WebSocket, Host override, Origin SNI | ❌ | Advanced → Reverse Proxy → Proxy Options |
> | Max body / URI / headers, Allowed methods | ❌ | Advanced → Request Limits |
> | Security template (Essential/Balanced/Strict) | on **Basics**, not here | Basics → Security Template |

| Field | What to enter |
|---|---|
| **Host** | Origin IP or hostname — e.g. `10.20.30.40`. IP only, **no port here** |
| **Port** | e.g. `443` or `8080` |
| **TLS** | **On if the origin is HTTPS.** Off for plain HTTP — but see the origin-certificate limit below |
| **Health check path** | From §1 line 4, e.g. `/healthz` or `/` — **Advanced mode only** |

> **An HTTPS origin must present a publicly trusted certificate.** The upstream
> connector verifies origin certificates against the public root store with no
> override, so an origin using an internal-CA or self-signed certificate fails
> the handshake on every request and returns **502 forever** — with every item on
> the §2 troubleshooting checklist passing. There is no setting for this today.
> Until there is, reach such an origin over plain **HTTP on a trusted network
> segment** instead.

Then the settings that actually break applications — **all of them Advanced
mode**. Defaults are fine for a normal website; change them only when §1 told
you to:

| Setting | Default | Change it when |
|---|---|---|
| **Max body size** | 10 MB | Users upload bigger files (§1 line 5). Document portals with KYC scans usually need 50 MB. Symptom if too small: **`413`** |
| **Read timeout** | 60 s | The app has slow reports or exports (§1 line 6). Use 120–300 s for those. Symptom if too small: **`504`** |
| **Connect timeout** | 5 s | Rarely. This only covers making the connection |
| **Max URI length** | 8192 | The app uses **SAML redirect login** (§1 line 7) — raise to 16384. Symptom: login returns **`403`** |
| **Max header count** | 100 | Corporate SSO with many cookies — raise to 200 |
| **WebSocket** | **Off** | The app uses live chat / live dashboards (§1 line 8). If you forget this, the feature just stops working with no error |
| **Host header override** | blank | Only when the origin serves a different name than the visitor types |
| **Origin SNI name** | blank | **Required when the origin is HTTPS and you address it by IP.** TLS does not allow an IP as a server name, so without it the origin may answer with the wrong certificate or refuse. Use the name from §1 |

### Step 4 — Protection

Three templates:

| Template | Detection strength | False-positive risk |
|---|---|---|
| 🟢 **Essential** | OWASP Top-10. Suits most applications | Lowest |
| 🔵 **Balanced** | Stronger detection. Labelled "recommended" in the UI | Medium |
| 🔴 **Strict** | Maximum. Also turns on TLS fingerprinting | Highest — the UI itself says tune with Learning first |

**Start with Essential or Balanced.** You can tighten later once you have real
numbers; you cannot un-block a customer's users retroactively.

#### Request inspection — on by default

Thirteen OWASP CRS categories covering what arrives *from* the visitor: SQL
injection, XSS, command execution, file inclusion, protocol abuse and so on. A new
site gets all of them. Leave it that way unless you have a measured reason not to.

#### Response inspection — off by default, and worth turning on

Six more categories inspect what your **origin sends back**, and they catch a
different class of problem: the application disclosing its own internals.

| Category | Catches |
|---|---|
| SQL Error Leakage | MySQL / Oracle / MSSQL / DB2 errors printed to the page |
| PHP Error Leakage | PHP warnings, stack traces, source disclosure |
| Java Error Leakage | Java exceptions and stack traces |
| IIS Error Leakage | ASP.NET error pages and filesystem paths |
| Generic Leakage | Directory listings and similar disclosure |
| Web Shell Detection | Pages served by known web shells (r57, c99, WSO) |

This matters because a leaked `You have an error in your SQL syntax` is how an
attacker learns which database you run and that your input is reaching it. The
request-side rules cannot see any of it — by the time the origin answers, the
request already passed.

**Two costs, and they are the reason it is off by default:**

1. **Responses are buffered, not streamed** for that site — held until scanned,
   up to the scan cap. Large text responses feel slightly slower. Binary and
   media responses are skipped, so downloads and video are unaffected.
2. **A single match blocks the response.** Unlike request rules, these do not add
   to an anomaly score that the threshold moderates — one hit is a decision. A
   page that *legitimately* prints database error text will be blocked.

So: **turn it on in Learning mode first**, exactly as you would for a new site,
and read the report before you let it block. Applications that deliberately show
stack traces to logged-in developers are the usual surprise.

If a response is too large to scan, the WAF forwards it and records
`response exceeds the scan cap` in the data-plane log rather than pretending it
inspected it. Treat that line as a coverage gap you can see.

### Step 5 — Review

Read the summary. Check the domains and the backend address once more, then save.

**A site becomes live in seconds — no restart, no downtime for other sites.**

---

## 4. Check the backend connection before anything else

The site exists now. Test it from the WAF VM before you touch DNS. This proves
WAF → origin works while nothing is pointed at the WAF yet.

```bash
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Host: www.customer.com' https://127.0.0.1/
```

| Result | Meaning |
|---|---|
| **200** (or 301/302) | Working. Move on |
| **502** | The WAF cannot reach the origin. Wrong IP or port, a firewall in between, origin down, or HTTPS/TLS mismatch. See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) §2 |
| **504** | Origin is reachable but too slow. Raise the read timeout |
| **404 from the WAF** | The `Host` name does not match any domain on the site. Check the Domains list for a typo |

**Fix a 502 now.** Every later step assumes this works, and a 502 after DNS is
live is a customer-visible outage instead of a test result.

---

## 5. TLS certificate

Go to **Certificates**. Two tabs:

### Auto SSL (ACME) — free, automatic, renews itself

Use this when the domain is publicly reachable. The WAF speaks ACME natively —
no certbot to install.

**Requirements — check both before you click:**
1. The domain must already resolve to this WAF (so do §6 first for this route).
2. Inbound **port 80** from the internet must actually reach the WAF. Many
   on-premise networks do not permit that — **verify it before promising a
   customer automatic certificates.**

Enter the ACME account email and click **Request Certificate**.

> **Tip:** the first time you use ACME on a new network, enable the *staging*
> option if offered. Let's Encrypt limits how many times you may fail per hour.
> A staging certificate will not be trusted by browsers — that is expected. It
> proves the plumbing works. Then request the real one.

### Manual Upload — for a customer-supplied certificate

Paste the certificate PEM and the private key PEM. Upload once, then assign to as
many sites as you like. Wildcards cover every subdomain.

**Check the certificate covers every hostname from §1 line 1.** A certificate for
`customer.com` does not cover `www.customer.com`.

### The internal certificate

If you skip both, the WAF serves the self-signed certificate created at install.
Fine for testing; visitors get a browser warning. You can download the internal
root CA from this page and import it on trusted machines to remove the warning.

---

## 6. DNS

Now point the world at the WAF. **This is the actual switchover** — the moment
real visitors start going through the WAF.

Ask the network / DNS team for:

```
www.customer.com   →   <WAF public IP>
```

Do it in the agreed maintenance window (§1 line 11).

If the WAF is behind NAT — which is normal — the public IP is not the WAF's own
address. The network team forwards it:

```
Public IP :80 and :443   →   WAF VM private IP :80 and :443
```

**Only ports 80 and 443.** The console on 9443 and SSH on 22 must never be
forwarded from the internet.

---

## 7. Test properly

Run every line. Each one maps to a question in §1, and each covers a way a WAF
changes behaviour that a quick look at the homepage will not reveal.

```bash
HOST=www.customer.com

# 7.1  A normal request reaches the site
curl -sk -o /dev/null -w '%{http_code}\n' https://$HOST/                  # expect 200

# 7.2  An attack is detected (in Learning mode it is allowed through and logged)
curl -sk -G --data-urlencode "q=1' OR '1'='1" \
     -o /dev/null -w '%{http_code}\n' https://$HOST/                      # expect 200 in Learning
#     Then open Events in the console — you should see it recorded as a detection.

# 7.3  The certificate covers every name
echo | openssl s_client -connect $HOST:443 -servername $HOST 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName -dates

# 7.4  A real-size upload works (use the real maximum from §1 line 5)
head -c 45M /dev/urandom > /tmp/big.bin
curl -sk -o /dev/null -w '%{http_code}\n' -F file=@/tmp/big.bin https://$HOST/upload

# 7.5  The slowest page completes and does NOT return 504
curl -sk -o /dev/null -w '%{http_code} in %{time_total}s\n' https://$HOST/<slow-page>
```

Then, by hand, in a browser:

- **Log in to the application.** If it uses SSO, do the full SSO login.
- **Use any live feature** (chat, live dashboard) if the app has WebSockets.
- **Download something large**, if the app offers that.
- Ask the application owner to confirm their access log shows **real visitor IP
  addresses**, not the WAF's. The WAF passes the visitor's address in the
  `X-Forwarded-For` header; the application may need to be told to read it.

**Do not skip 7.4 and 7.5 because "it is only a proxy".** Uploads and slow pages
are exactly where a WAF changes behaviour, and they are invisible to a homepage
check.

---

## 8. Monitor, then switch on blocking

The site is live and protecting nothing yet — it is watching and recording.

### While it learns

- **Overview** — traffic and detection totals at a glance.
- **Events** — every detection. Each has a request ID, the rule that matched,
  the source IP and what the WAF would have done.
- **Traffic** — request volumes.
- **Alerts** — notifications.

Each recurring detection is one of two things:

1. **A real attack** — good, nothing to do.
2. **A false positive** — normal user activity the WAF misread. These must be
   fixed *before* blocking, or you will block those users.

For a false positive, use the narrowest fix available: exclude that one rule for
that one path on that one site, not "turn off the category".

### Measuring

On the WAF VM:

```bash
sudo /opt/sentinel/current/scripts/fpr-report.sh 168      # last 7 days
```

**Read the denominator, not just the percentage.** If the report covers 40
requests and 38 were your own tests, the percentage means nothing. You need real
visitor traffic.

### The go-live gate — all four, no exceptions

Do not switch a site to Blocking until:

- [ ] It has run in Learning mode over a **full business cycle** — 2 weeks
      preferred, 1 week absolute minimum. Month-end and payroll traffic look
      nothing like a Tuesday afternoon.
- [ ] `fpr-report.sh` reports **under 1%**, and the denominator is **real user
      traffic**.
- [ ] **Every** recurring detection has been reviewed and classified as attack or
      false positive, and each false positive fixed.
- [ ] The application owner has signed off on the §7 tests.

### Switching

**Sites → the site → Security Mode → Blocking.** Takes effect in seconds.

Then **watch it.** Stay on the Events page for the first hour of real traffic.
Switch **one site at a time** — never a batch.

If anything looks wrong, set Security Mode to **Off** immediately. Traffic keeps
flowing, inspection stops. That is the emergency brake and it takes seconds —
[ROLLBACK.md](ROLLBACK.md) §1.

---

## 9. Record what you did

Keep this per site. The next person to touch it — possibly you at 2 a.m. — needs
it.

| Field | Value |
|---|---|
| Application | |
| Hostnames | |
| Origin(s) and port | |
| Origin HTTP or HTTPS | |
| Max body (MB) | |
| Read timeout (s) | |
| Max URI / headers | |
| WebSocket | on / off |
| Host header override | |
| Origin SNI name | |
| Health check path | |
| Certificate: ACME or uploaded, expiry | |
| Learning mode started (date) | |
| False-positive rate measured | |
| Switched to Blocking (date) | |
| Application owner / on-call | |

---

## Quick reference

| Symptom | Look at |
|---|---|
| Website will not open | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) §1 |
| `502` | §2 — WAF cannot reach the origin |
| `504` | §3 — origin too slow, raise read timeout |
| `413` | §4 — upload bigger than Max body size |
| `403` on normal use | §5 — likely a false positive; find it in Events |
| Certificate warning | §6 |
| Need to undo something | [ROLLBACK.md](ROLLBACK.md) |
