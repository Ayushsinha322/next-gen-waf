# Next-Gen ESDSWAF — Troubleshooting

**How to use this:** find your symptom in the table, go to that section. Each
section tells you what to check, in order, cheapest check first.

**Two things to do before you start:**

1. **Get the request ID.** Almost every problem is faster to diagnose with one.
   §11 explains how.
2. **Change nothing yet.** Capture the request ID and the matching Events entry
   *first*. Once you have changed a setting, the evidence of what went wrong is
   gone and you are guessing.

---

## Symptom index

| What you see | Go to |
|---|---|
| Website will not open at all | [§1](#1-website-will-not-open) |
| **502** Bad Gateway | [§2](#2-502-bad-gateway) |
| **504** Gateway Timeout | [§3](#3-504-gateway-timeout) |
| **413** Request Entity Too Large — uploads fail | [§4](#4-413--uploads-fail) |
| **403** on normal, legitimate use | [§5](#5-403-on-legitimate-traffic-false-positive) |
| **503** with a Retry-After header | [§6](#6-503-with-retry-after) |
| Certificate / browser security warning | [§7](#7-certificate-warnings) |
| Redirect loop — page keeps reloading | [§8](#8-redirect-loop) |
| Console will not open | [§9](#9-console-will-not-open) |
| A container keeps restarting | [§10](#10-container-restart-loop) |
| Login works but SSO login fails | [§5](#5-403-on-legitimate-traffic-false-positive) |
| Live chat / live dashboard stopped working | [§12](#12-websockets-stopped-working) |
| Application logs show the WAF's IP, not visitors' | [§13](#13-origin-sees-the-wrong-client-ip) |
| Everything returns 502 on a brand-new install | Normal — no sites yet. [INSTALL.md](INSTALL.md) §4 |

---

## 1. Website will not open

Work down this list. Stop at the first failure.

```
1. Does the name resolve?          dig +short www.customer.com
2. Does it resolve to the WAF?     compare with the WAF's public IP
3. Is the WAF alive?               sudo ./verify.sh   on the VM
4. Does the site exist in the console, with that exact hostname?
5. Does the WAF reach the origin?  the curl in §2
6. Is the certificate valid?       §7
```

**Step 4 is the one people miss.** The WAF decides which website a request belongs
to by reading the hostname the visitor's browser sent, and matching it against the
Domains list on each site. If the visitor types `www.customer.com` and the site
only lists `customer.com`, **nothing matches** and the WAF answers 502 — because
there is no site, therefore no origin to forward to.

Test from the WAF VM, which skips DNS entirely:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Host: www.customer.com' https://127.0.0.1/
```

- Works here but not from outside → the problem is **DNS or the firewall**, not the WAF.
- Fails here too → the problem is **the site config or the origin**. Continue to §2.

---

## 2. 502 Bad Gateway

502 means: *the WAF could not get a usable answer from the origin.* There are two
quite different causes.

### Cause A — no site matched the hostname

There is no origin to talk to because no site claimed this name. Check the
Domains list for a typo, a missing `www.`, or a name the visitor uses that you
did not list.

This is also why `curl -H 'Host: 127.0.0.1'` returns 502 on a working WAF — that
is not one of your sites' names. **Correct behaviour, not a fault.**

### Cause B — the origin is not answering

Check, in this order:

| # | Check | Command / where |
|---|---|---|
| 1 | Is the origin actually up? | Ask the app team, or `curl` it directly from the WAF VM |
| 2 | Can the WAF reach the origin's IP and port? | `nc -zv 10.20.30.40 443` from the WAF VM |
| 3 | Is a firewall between WAF and origin blocking it? | Network team. Very common on a first onboarding |
| 4 | Is the **port** right? | Console → the site → Reverse Proxy |
| 5 | Is the **HTTP vs HTTPS** setting right? | If the origin is HTTPS, the server's TLS toggle must be **on**. Plain HTTP to an HTTPS port fails |
| 6 | Origin is HTTPS **and addressed by IP**? | You probably need **Origin SNI name**. TLS forbids an IP as a server name, so without it the origin may answer with the wrong certificate or refuse outright |
| 7 | Is the origin's certificate valid and trusted? | A failed handshake to the origin looks like 502 from outside |

**If you are running the demo/practice profile:** a site pointing at a container
that is not started returns 502. Check the container is actually running.

---

## 3. 504 Gateway Timeout

The origin is reachable but took too long to **start** replying.

- **Which page?** If it is a report, export, batch job or payment callback,
  the origin is genuinely slow and the timeout is too short for it.
- **Fix:** Console → site → Reverse Proxy → **Read timeout**. Use 120–300 s for
  slow endpoints. The ceiling is 600 s; beyond that it is an application problem,
  not a timeout setting.
- **If the homepage 504s**, the origin is unhealthy. Do not raise the timeout to
  hide that — tell the app team.

Read timeout bounds how long the origin may take to send response *headers*. It
does not limit how long a download takes, so raising it does not weaken
protection against slow clients.

---

## 4. 413 — uploads fail

The upload is larger than **Max body size** (default 10 MB).

**Fix:** Console → site → Reverse Proxy → **Max body size**. Set it to the real
maximum the application accepts — ask the app owner, do not guess.

Document portals handling KYC scans, PAN/Aadhaar images or balance sheets usually
need 50 MB.

**Do not set it far above the real maximum.** That value is also the memory limit
per in-flight request, so an unnecessarily large value is a free
memory-amplification target for an attacker.

---

## 5. 403 on legitimate traffic (false positive)

The WAF blocked something it should not have. This is the most common real
problem, and it has a proper procedure.

### Step 1 — get the request ID

The block page shown to the user carries a **Support ID**. Ask them for it, or
reproduce the request yourself. API clients get the same value as JSON
(`support_id` / `request_id`).

### Step 2 — find it

Console → **Events** → search that ID. You now have: the rule that matched, the
part of the request that triggered it, the score, the site, the source IP, and the
action taken.

### Step 3 — decide

Read the matched rule and the request. **Was it actually an attack?** Blocked
attacks look alarming and are the WAF working correctly. Only continue if the
request was genuinely legitimate.

### Step 4 — fix it narrowly

Use the **narrowest** tool that solves it:

| Preferred | Fix |
|---|---|
| **1st** | Exclude **that one rule** for **that one URL path** on **that one site** |
| **2nd** | Exclude that one rule for that whole site |
| **3rd** | Lower the paranoia level, or raise the score threshold, for that site |
| **Last resort** | Disable a whole rule category |

Every step down that list removes protection from more traffic. Do not start at
the bottom because it is quicker.

### Special case — SSO login returns 403

If the application uses **SAML redirect-binding** login, the login URL contains a
long encoded blob that can exceed the 8192-byte URL limit. Symptom: the login
redirect returns 403 and nobody can sign in.

**Fix:** raise **Max URI length** to 16384 on that site.

### If a false positive is urgent and you cannot fix it now

Set the site's Security Mode to **Off**. Traffic flows, inspection stops, takes
seconds. Then fix it properly. [ROLLBACK.md](ROLLBACK.md) §1.

---

## 6. 503 with Retry-After

The WAF is shedding load on purpose — more requests are in flight than it will
accept at once. Health, readiness and metrics endpoints are exempt, so monitoring
keeps working.

Check whether this is:

- **A genuine traffic spike or attack** → the WAF is doing its job. Look at
  Events and Traffic.
- **The WAF undersized for normal load** → escalate to R&D with the numbers from
  `/metrics`.

---

## 7. Certificate warnings

| What the browser says | Cause | Fix |
|---|---|---|
| Untrusted issuer / self-signed | You are using the internal certificate created at install | Expected on internal names. Import `/opt/sentinel-pki/root.crt` (downloadable from Certificates) on client machines, or install a real certificate |
| Name mismatch | The certificate does not cover the hostname the visitor typed | Certificates page — check it covers **every** name, including `www.` |
| Expired | A manually uploaded certificate was not replaced | Upload a new one. ACME certificates renew themselves; manual ones do not |

Check what is actually being served:

```bash
echo | openssl s_client -connect www.customer.com:443 -servername www.customer.com 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName -dates
```

**ACME (automatic) certificate request failed?** The two usual reasons:

1. The domain does not yet resolve to this WAF.
2. Inbound **port 80** from the internet does not reach the WAF. The certificate
   authority must fetch a file over port 80 to prove you control the domain. Many
   on-premise networks block it.

Confirm both with the network team before retrying — repeated failures are
rate-limited by the certificate authority.

---

## 8. Redirect loop

The page reloads forever, or the browser reports too many redirects.

| Cause | Fix |
|---|---|
| **Force HTTPS** is on at the WAF, and the origin also redirects HTTP→HTTPS, and the WAF talks to the origin over plain HTTP | The origin sees "http" and redirects; round and round. Either point the WAF at the origin's HTTPS port, or have the app team make the origin trust the WAF's forwarded-protocol header |
| The application is configured with the **wrong public URL** | Many applications build every link from a configured site URL. If it does not exactly match what visitors type, they get sent somewhere that bounces back. Ask the app team to set it to the real public `https://` name |

---

## 9. Console will not open

**`https://<vm-ip>:9443` not loading is correct behaviour, not a fault.** The
console is bound to `127.0.0.1` only, deliberately.

Open it through a tunnel from your own machine:

```bash
ssh -L 9443:127.0.0.1:9443 root@<vm-ip>
```

then browse to **https://127.0.0.1:9443**.

Still failing? Check on the VM:

```bash
docker compose -p sentinel ps          # is the control plane up?
curl -sk https://127.0.0.1:9443/healthz
```

**Lost the admin password?**

```bash
docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'
```

---

## 10. Container restart loop

```bash
docker compose -p sentinel ps
docker compose -p sentinel logs --tail 100 <service-name>
```

**Check memory first — it is the answer most of the time:**

```bash
free -g
```

The event database (ClickHouse) is capped at 6 GB and **crash-loops indefinitely**
when less than about 2 GB is free on the host. An undersized VM does not produce a
slow WAF; it produces this. The requirement is 16 GB and it is real.

Other causes:

| Symptom in the logs | Cause |
|---|---|
| Cannot connect to database | Postgres not up yet, or a wrong value in `.env` |
| Permission denied on a certificate path | The host is RHEL / Rocky / Alma — **not supported**; SELinux blocks the certificate mounts |
| Port already in use | Something else on the host holds 80, 443 or 9443 |

If it is not memory and not one of those, escalate — §14.

---

## 11. How to get a request ID

This single value turns most investigations from 30 minutes into 30 seconds.

- **From a blocked user:** the block page displays a **Support ID**. Ask for it.
- **From an API client:** the JSON error body contains `support_id` and
  `request_id`.
- **Reproduce it yourself:** run the request with `curl -i` and read the response.

Then: Console → **Events** → search that ID.

---

## 12. WebSockets stopped working

Live chat, live dashboards and notifications use WebSockets, and **the WAF blocks
protocol upgrades by default.** With the gate closed, the WAF strips the upgrade
headers before the request leaves it, so the origin never switches protocol and
the client gets an ordinary HTTP response — a feature that silently does nothing
rather than an error.

**Fix:** Console → site → Reverse Proxy → **WebSocket** → on.

Prove it on the wire:

```bash
curl -isk -N --max-time 5 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
     -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
     https://www.customer.com/<ws-path> | head -1
```

Expect `HTTP/1.1 101 Switching Protocols`. Anything else (200, 404) means the
upgrade is still being refused. Then test the real feature — a 101 proves the
handshake, not that messages flow.

---

## 13. Origin sees the wrong client IP

Expected, and it is how a reverse proxy works. The visitor's connection ends at
the WAF; the WAF makes its own separate connection to the origin. So the origin
sees the **WAF's** address as the client.

The real visitor address is passed in the **`X-Forwarded-For`** header. The
application (or its web server) must be configured to read it — that is an app-side
change, not a WAF setting.

**Note for the app team:** they should trust that header **only** from the WAF's
address, never from arbitrary clients. Otherwise anyone can forge it.

---

## 14. Escalating to R&D

Escalate when:

- `verify.sh` fails and nothing here explains it
- A container restart-loops and it is **not** memory
- A false positive resists a narrow exclusion
- Traffic is blocked in a way you cannot explain from the Events entry
- The fix needs an upgrade, a rollback, or a database restore

**Send all of this — it is the difference between a fast answer and a long
conversation:**

1. What you expected, and what happened
2. The **request ID** from Events or the block page
3. Site name and the exact hostname used
4. Time, with timezone
5. `docker compose -p sentinel ps`
6. Relevant log tail: `docker compose -p sentinel logs --tail 200 <service>`
7. For install problems: `/var/log/sentinel/install.log`
8. Whether anything changed recently — a config edit, an upgrade, a network change

---

## Quick commands

```bash
# Health
cd /path/to/ESDSWAF-v1.0.0 && sudo ./verify.sh    # bundle dir, not /opt/sentinel
docker compose -p sentinel ps
free -g
df -h /opt

# Test a site without DNS
curl -sk -o /dev/null -w '%{http_code}\n' -H 'Host: www.customer.com' https://127.0.0.1/

# Test the origin directly from the WAF VM
nc -zv 10.20.30.40 443

# Logs
docker compose -p sentinel logs --tail 100 <service>

# False-positive rate over the last 7 days
sudo /opt/sentinel/current/scripts/fpr-report.sh 168
```

## Related

- [SITE-ONBOARDING.md](SITE-ONBOARDING.md) — the settings referenced above
- [ROLLBACK.md](ROLLBACK.md) — when the fix is "undo it"
- [ADMIN-GUIDE.md](ADMIN-GUIDE.md) — monitoring and what to alert on
