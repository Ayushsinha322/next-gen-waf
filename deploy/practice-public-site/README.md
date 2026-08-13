# Public-edge practice run — a real site on a public address, behind the WAF

A rehearsal of the thing we have never done: put the WAF on a publicly reachable
address, with a real application behind it, and let the internet arrive. It is a
deployment exercise first. It is also the only way to find out how this product
behaves against traffic nobody generated on purpose.

Everything here is scripted and verified. The one step that is not ours to run is
the firewall change — §3 is the request to send, written so the network team can
act on it without a conversation.

---

## What this is not

**It is not the FPR pilot.** The go-live gate in
[../SITE-ONBOARDING-CHECKLIST.md](../SITE-ONBOARDING-CHECKLIST.md) §5 wants a
false-positive rate whose denominator is *real user traffic*. A public practice
blog's denominator is mostly crawlers, uptime probes and scanners. That is real
traffic, and far better than the six self-generated requests the .71 rehearsal
measured — but a blog's benign traffic does not look like an internal business
application's, so a good number here does not transfer to a customer. It tells
you the WAF survives contact with the open internet, and it will surface real
false positives on crawler and browser traffic, which is worth having.

The pilot still needs a named internal application. This does not replace it.

---

## Why not a free cloud VM

Because none of them can run this. `dist/ESDSWAF-v1.0.0/install.sh:101` gates on
`MIN_RAM_GB=15` and means it — ClickHouse is capped at 6 GB and crash-loops below
roughly 2 GB available, so an undersized box does not produce a slow WAF, it
produces a restart loop. Every free tier is 1 GB (AWS `t3.micro`, GCP `e2-micro`,
Azure `B1s`, Oracle's AMD shapes), and the one genuinely generous free shape —
Oracle's 4-core/24 GB Always Free — is **aarch64**, while our images are amd64
with no `platform:` anywhere in `deploy/docker/`.

So the public address has to come from ESDS, and the WAF stays on `172.16.21.71`,
which is what makes §2 mandatory rather than advisory.

---

## The order of operations

Steps 1, 2 and 5 are safe to do now. **Nothing becomes publicly reachable until
step 4**, and step 4 must not happen before step 2 exits clean.

| | Step | Who |
|---|---|---|
| 1 | Register the DuckDNS name, start the origin, onboard the site | us, now |
| 2 | `pre-exposure-audit.sh` — must exit 0 | us |
| 3 | Send the firewall request | us → network team |
| 4 | Rule goes live; point DuckDNS at the public address | network team, then us |
| 5 | Issue the certificate (staging, then production) | us |
| 6 | Verify per checklist §4; leave it in learning mode | us |

---

## 1. Set it up

### 1.1 The name

DuckDNS needs a browser login (Google/GitHub) — run this bit yourself at
<https://www.duckdns.org>. Pick a subdomain, e.g. `esdswaf-demo.duckdns.org`, and
copy the token from the page.

DuckDNS is on the Public Suffix List, so each `*.duckdns.org` name is its own
registered domain for Let's Encrypt rate-limiting purposes — a mistake here will
not burn a shared quota.

Leave the IP unset for now; there is nothing to point it at until step 4. Once
there is, keep it current from the WAF host — a dynamic public address that
changes silently is a site that goes dark with no error anywhere:

```bash
# /etc/cron.d/duckdns  — token in the file, so chmod 600 it
*/5 * * * * root curl -fsS "https://www.duckdns.org/update?domains=esdswaf-demo&token=<TOKEN>&ip=" -o /var/log/duckdns.log
```

An empty `ip=` tells DuckDNS to use the source address of the request, which is
the public address the WAF is actually reachable on — the correct value, and one
you do not have to hardcode or remember to change.

### 1.2 The origin

Ghost, added to `deploy/docker/compose.prod.yml` behind a `ghost` profile,
alongside the existing `demo` profile that gates Juice Shop. It never starts in a
customer install.

Three variables in `deploy/docker/.env`, all required — compose refuses to render
without them rather than starting a half-configured public site:

```bash
GHOST_PUBLIC_URL=https://esdswaf-demo.duckdns.org
GHOST_DB_PASSWORD=$(openssl rand -base64 24)
GHOST_DB_ROOT_PASSWORD=$(openssl rand -base64 24)
```

`GHOST_PUBLIC_URL` is the one to get right. Ghost builds every absolute URL from
it — canonical links, redirects, asset paths, password-reset mail — and it must be
the **public** `https://` URL, not the container address. Wrong here fails
quietly: the page renders, then stylesheets 404 or the login bounces in a
redirect loop, because Ghost is sending the browser somewhere it cannot reach.

```bash
cd /opt/sentinel-src/deploy/docker
docker compose -f compose.prod.yml --profile ghost up -d ghost-db ghost
docker compose -f compose.prod.yml logs -f ghost   # wait for "Ghost is running"
```

The box has 16 GB and the WAF stack already claims most of it; these two add
about 1 GB (`mem_limit` 512m each). Check `free -g` before starting them, because
the thing that breaks under memory pressure is ClickHouse, and it breaks by
restart-looping rather than by complaining.

### 1.3 Claim the Ghost admin account — before anything is public

**Do this immediately after the container starts.** Ghost's first-run setup at
`/ghost/#/setup` creates the owner account **without authenticating anyone**. It
is unauthenticated because there is nobody to authenticate yet. Whoever loads it
first owns the site, and on a publicly reachable Ghost that is a race you lose in
minutes, not days.

From the WAF host, through the WAF, before DNS exists:

```bash
# Confirm Ghost answers, then claim the owner account in a browser over an SSH
# tunnel — no public exposure required for either.
curl -si -H 'Host: esdswaf-demo.duckdns.org' https://127.0.0.1/ghost/ -k | head -1
# ssh -L 8443:127.0.0.1:443 root@172.16.21.71   then https://127.0.0.1:8443/ghost/
```

Use a real password from a password manager. This account is the administrative
surface of an internet-facing application, and there is no per-path IP
restriction in the product to hide it behind — `path_overrides` tunes mode,
threshold and exclusions per path, not access.

### 1.4 The site

```bash
cd /opt/sentinel-src/deploy/practice-public-site
export SENTINEL_ADMIN_PASSWORD="$(tr -d '\r\n' < /opt/sentinel-src/pswdwaf)"
./onboard-ghost-site.sh esdswaf-demo.duckdns.org --dry-run   # changes nothing
./onboard-ghost-site.sh esdswaf-demo.duckdns.org
```

The script dry-runs `POST /sites/validate` and refuses to create a site the data
plane cannot use, sends only allowlisted `waf_policy` keys, and then verifies
three ways — API read-back, the Postgres row, and the live wire — requiring all
three to agree. It creates the site in **learning** mode. The settings it chooses
and why are documented in the script against checklist §1, and recorded in §7
below.

Note `tr -d '\r\n'` on the password: `pswdwaf` contains an interior newline, so a
plain `$(cat)` yields a string that fails to authenticate.

---

## 2. The pre-exposure audit — the gate

```bash
./pre-exposure-audit.sh --expect-domain esdswaf-demo.duckdns.org
```

**Nothing goes public until this exits 0.** It exists because a WAF host does not
become public one site at a time. It becomes public all at once, for everything
already on it, the moment a firewall rule changes — and site matching is by
**Host header alone** (`site_matches()`,
`crates/sentinel-proxy/src/lib.rs:4787`: exact match, or a `*.` suffix). The
client chooses the Host. So every site on the node is reachable from any address
that reaches the node.

On `172.16.21.71` today that has a specific consequence. The Juice Shop site's
domains include `juice`, `localhost` and `172.16.21.71`. Forward a public address
to this host and

```
curl -H 'Host: juice' https://<public-ip>/
```

reaches a **deliberately vulnerable application** on an internal ESDS subnet,
from the internet, with the WAF as the only thing in the way — and the WAF's
real-world error rate is the unknown this whole exercise exists to measure, so it
cannot also be the assumption that makes the exposure acceptable. `juice` and
`localhost` are first-minute guesses, not thousandth. **Delete the Juice Shop site
before the firewall rule opens** (the teammate demo can come back afterwards on a
name that is not a guess), or keep the practice site on a different host.

The audit also checks that no `default_site` is answering for unmatched Hosts
(with one set, a request matching nothing is *served* rather than refused —
`lib.rs:2673`; a 502 is the safe behaviour), enumerates every non-loopback
listener, and flags port 9443 specifically. `compose.prod.yml` publishes the
admin console on loopback by default and explains why in a comment that ends "and
to the internet the moment the host gets a public IP" — but `.71` sets
`SENTINEL_MGMT_BIND=0.0.0.0:`, so loopback is no longer what is protecting it.
That is fine behind a port forward of 80/443 and fatal under a 1:1 NAT.

---

## 3. The firewall request

Send this as written. The distinction in the first line is the one that matters.

> Please **port-forward tcp/80 and tcp/443 only** from a public address to
> `172.16.21.71`. Please do **not** configure a 1:1 NAT or a static NAT of the
> whole address.
>
> The host also listens on tcp/22 (SSH) and tcp/9443. Port 9443 is the WAF's own
> administrative console and API; its certificate is self-signed with no IP SAN,
> so a browser cannot warn a user that they have reached the wrong one. Neither
> port may be reachable from the internet. A 1:1 NAT would publish both.
>
> Purpose: a controlled internet-exposure test of the Next-Gen ESDSWAF with a
> benign origin application. Requested duration: <n> weeks. The WAF terminates
> TLS on 443 and needs 80 reachable for Let's Encrypt HTTP-01 domain validation.
>
> Please confirm the public address once the rule is in place, and that the
> forward is 80/443 only.

Two things to be straight about when you ask: the host sits on the internal
subnet, and the exposure is deliberate and time-boxed. Someone will ask, and the
honest answer — a port forward of two ports to a reverse proxy, audited first,
with a vulnerable demo app removed — is a good one.

---

## 4. Point DNS

Once the public address exists: set it on DuckDNS (or just let the cron entry in
§1.1 fire, which discovers it). Then confirm from **outside** the network —
phone hotspot, or `curl` from anywhere that is not the office:

```bash
curl -sv https://esdswaf-demo.duckdns.org/ 2>&1 | head -20
curl -si https://<public-ip>/ -H 'Host: juice' | head -1   # must NOT be 200
```

That second line is the one worth running. It is the audit's finding, checked on
the wire, from the internet, after the rule is live.

---

## 5. The certificate

**Staging first.** Let's Encrypt rate-limits failures at 5 per hour per account,
and HTTP-01 has several ways to fail that all look the same from here — port 80
not actually forwarded, DNS not propagated, a firewall answering on 80 before the
WAF does.

```bash
TOKEN=$(curl -sk -X POST https://127.0.0.1:9443/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@sentinel.local\",\"password\":\"$SENTINEL_ADMIN_PASSWORD\"}" \
  | jq -r .access_token)

curl -sk -X POST https://127.0.0.1:9443/api/v1/certs/acme \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"domains":["esdswaf-demo.duckdns.org"],"email":"ayush.sinha@esds.co.in",
       "provider":"letsencrypt_staging","challenge":"http_01","renew_before_days":30}'
```

A staging certificate will not validate in a browser — that is expected, and it
proves the challenge round-trip works. Re-issue with `"provider":"letsencrypt"`
once it does. `http_01` needs port 80 open; `tls_alpn_01` works on 443 alone if
80 is refused.

---

## 6. Verify, then leave it alone

Run [../SITE-ONBOARDING-CHECKLIST.md](../SITE-ONBOARDING-CHECKLIST.md) §4 against
the public name — all of it, including the parts that look unnecessary for a
blog. §4.3 (does the origin see the real client IP) is the one to watch: XFF is
only trusted from a configured trusted-proxy range and the default is empty
(`lib.rs:4077`), which is correct here — a direct public client's `X-Forwarded-For`
must never be believed, or a blocked client escapes its block by forging one.

Then stop touching it. Learning mode, real traffic, and measure with

```bash
/opt/sentinel-src/deploy/load-test/fpr-report.sh 168
```

Read the denominator before the rate. A rate over traffic you generated is not a
measurement — that is what the 16.67% from the .71 rehearsal was.

### Teardown

```bash
# site first, so nothing routes to a dead origin
curl -sk -X DELETE https://127.0.0.1:9443/api/v1/sites/<id> -H "Authorization: Bearer $TOKEN"
cd /opt/sentinel-src/deploy/docker
docker compose -f compose.prod.yml --profile ghost down
# Only if you want the content gone. Find the real names rather than guessing the
# compose project prefix: docker volume ls | grep ghost
docker volume ls --format '{{.Name}}' | grep ghost | xargs -r docker volume rm
```

Ask the network team to remove the forward. An exposure that outlives its purpose
because nobody closed it is the ordinary way this goes wrong.

---

## 7. Record — checklist §7, filled in

| Field | Value |
|---|---|
| Application | Ghost 5 (`ghost:5-alpine`), MySQL 8.4, `ghost` compose profile |
| Hostnames | `esdswaf-demo.duckdns.org` (substitute the name you registered) |
| Origin(s) | `ghost:2368`, plaintext HTTP on the compose network |
| Max body (MB) | 20 — Ghost's image uploads sit well under it; also the per-request memory bound, and a public site is a free amplification target |
| Read timeout (s) | 30 (default) — no report or export endpoints |
| Connect timeout (s) | 5 |
| Max URI / headers | 8192 / 100 (defaults) — no SAML redirect binding |
| WebSocket | off — Ghost admin does not need an upgrade |
| Host header override | none — Ghost vhosts on the client's Host |
| Origin SNI name | n/a — plaintext origin |
| Upstream keep-alive | on |
| LB strategy | round-robin, one server |
| Health check path | `/` — Ghost has no unauthenticated `/healthz` |
| DLP | off — no PII in responses, and it would buffer bodies for nothing |
| Learning mode started | _fill in at step 1.4_ |
| FPR measured | _not yet — this is the point_ |
| Flipped to blocking | not planned; see §5 of the checklist for the gate |
| App owner / on-call | Ayush Sinha, ayush.sinha@esds.co.in |

## Related

- [../SITE-ONBOARDING-CHECKLIST.md](../SITE-ONBOARDING-CHECKLIST.md) — the general procedure this instantiates
- [../LEARNING-MODE-PILOT.md](../LEARNING-MODE-PILOT.md) — the go-live gate in detail
- [../load-test/fpr-report.sh](../load-test/fpr-report.sh) — the measurement half
- [../STANDALONE.md](../STANDALONE.md) — platform install and its real requirements
