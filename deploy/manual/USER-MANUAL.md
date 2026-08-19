# Next-Gen ESDSWAF — User Manual

**Version 1.0.2** · ESDS Software Solution Ltd

---

## About this manual

**Who it is for:** an ESDS NOC engineer or system administrator. Competent with
Linux and SSH. No prior exposure to this product is assumed.

**What it covers:** installing the WAF, putting a website behind it, running it day
to day, and fixing it when it breaks.

> **Every command and every output in this manual came from a real machine.** The
> procedures were executed on a fresh Ubuntu 24.04 VM (`172.16.21.101`) and the
> quoted outputs are that machine's, copied verbatim. Where a step has a trap, it
> is a trap that actually occurred during those runs — not one that might.

**How to read it:** §1–§6 in order for a first install. After that, treat §7–§11 as
reference and open only the section matching your question.

| § | | |
|---|---|---|
| 1 | [What this product is](#1-what-this-product-is) | 5 minutes of reading that saves an hour |
| 2 | [Before you start](#2-before-you-start) | VM sizing, network, which package |
| 3 | [Installing](#3-installing) | 15 minutes |
| 4 | [First login](#4-first-login) | **and the one thing you must not skip** |
| 5 | [Protecting a website](#5-protecting-a-website) | |
| 6 | [Going live safely](#6-going-live-safely) | learning mode → blocking |
| 7 | [Daily operation](#7-daily-operation) | reference |
| 8 | [Users and access](#8-users-and-access) | reference |
| 9 | [Backup and recovery](#9-backup-and-recovery) | reference |
| 10 | [Troubleshooting](#10-troubleshooting) | symptom → cause → fix |
| 11 | [Upgrading and removing](#11-upgrading-and-removing) | reference |
| 12 | [Known limitations](#12-known-limitations-in-102) | **read before promising anything to a customer** |

---

## 1. What this product is

A **reverse-proxy security gateway**. It sits in front of a website. Visitors reach
the WAF, the WAF inspects each request, and only acceptable requests are passed to
the real server.

```
   Visitor  ──►  ESDSWAF  ──►  the customer's web server ("the origin")
                    │
                    └── attacks stopped here, before they reach the application
```

### The two addresses, and why they get confused

This is the single most common source of a broken first install.

| | What it is | Example |
|---|---|---|
| **The site hostname** | What visitors type. The WAF decides which protected site a request belongs to using the **Host header alone**, so this must match exactly. | `portal.example.com` |
| **The origin** | Where the application actually runs today. Must be reachable **from the WAF host**, not from your laptop. | `10.20.30.40:8080` |

If the Host header does not exactly match a site you configured, the WAF has no
idea where to send the request and answers **502**.

### What is running after an install

Eight containers. You do not need to remember these, but they appear in
troubleshooting output:

| Container | Job |
|---|---|
| `dataplane` | the WAF itself — inspects traffic, binds ports 80/443 |
| `controlplane` | the management API behind the console |
| `dashboard` | the web console |
| `postgres` | configuration, users, sites |
| `clickhouse` | traffic and detection events (allocated 6 GB) |
| `redis` | rate-limit and session state |
| `prometheus`, `grafana` | metrics, on loopback only |

A ninth, `migrate`, runs the database migrations once and then exits. **It being
gone is correct.**

---

## 2. Before you start

### 2.1 The virtual machine

| Requirement | Why it matters |
|---|---|
| Ubuntu 22.04 or 24.04 | The installer refuses anything else |
| **4 vCPU** minimum | Enforced |
| **16 GB RAM** | ClickHouse alone is allocated 6 GB. Below this it restarts forever — you get a broken WAF, not a slower one |
| **110 GB disk on `/opt`** | See the warning below |
| Ports **80, 443, 9443** free | The WAF binds all three |
| root or sudo | |

> ### ⚠️ The disk check reads `/opt`, not `/`
>
> Ask for **110 GB, not 100** — a "100 GB" disk formats to about 98 GB usable, and
> the requirement is 100 GB free. On the reference VM this was the layout:
>
> ```
> Filesystem      Size  Used Avail Use% Mounted on
> /dev/sda1       100G  1.6G   98G   2% /
> /dev/sdb1       108G   24K  103G   1% /opt      ← the one that counts
> ```
>
> Note `/` had only 98 GB free and would have **failed**. If `/opt` is not its own
> mount on your VM, the root disk must be large enough by itself.

Also note: a VM provisioned with 16 GB reports as **15 GB**, and the installer's
floor is 15. So 16 GB provisioned passes; anything less does not.

### 2.2 Which package you need

This depends on one thing: **what your VM can reach.** Check both:

```bash
curl -sS -o /dev/null -w 'harbor:     %{http_code}\n' https://hub.enlight.dev/v2/
curl -sS -o /dev/null -w 'dockerhub:  %{http_code}\n' https://registry-1.docker.io/v2/
```

`401` means reachable — that is the normal unauthenticated answer from a registry.
A timeout or `000` means blocked.

| Harbor | Docker Hub | Use | Size |
|---|---|---|---|
| ✅ | either | **`-registry`** | **316 KB** |
| ❌ | ✅ | `-online` | 99 MB |
| ❌ | ❌ | `-offline` | 584 MB, 3 parts |

**Prefer `-registry`.** It downloads no container images at all — the installer
pulls all ten from ESDS's own Harbor registry, which needs no credentials because
the project is public within the ESDS network. This is the normal case for any
ESDS-internal deployment.

Use `-offline` for a customer's own datacentre. Such a site cannot reach Harbor
regardless of whether it has internet, because Harbor is on an internal address
(`172.16.23.2`) that is not routable from outside ESDS.

You cannot pick the wrong one by accident: the installer reads which variant it is
from the package manifest and aborts in preflight with a clear message rather than
failing halfway through.

### 2.3 Getting the package

**Releases page** (preferred — one version, clearly labelled):

> https://git.enlight.dev/research-lab/SIG-CyberSec/sentinel-waf/-/releases

Or **Deploy → Package Registry → esdswaf**. You need the archive **and** its
`.sha256`.

> ⚠️ **Take the version the release page names.** The package registry holds older
> versions too, and **1.0.0 contains a defect that aborts the install at step 9 of
> 10, after `/opt` has already been written.** Do not use it.

---

## 3. Installing

### 3.1 Install Docker

Skip if `docker --version` already answers.

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

Verify — **both** must answer, and the daemon must be running:

```bash
docker --version          # e.g. Docker version 29.7.2
docker compose version    # e.g. Docker Compose version v5.4.0
systemctl is-active docker
```

> A high Compose version is fine. `v5.x` is current. What matters is that
> `docker compose` (a plugin, no hyphen) exists at all — the old separate
> `docker-compose` binary is not a substitute.

### 3.2 Verify and unpack

```bash
cd /root
sha256sum -c ESDSWAF-v1.0.2-registry.tar.gz.sha256    # must print: OK
tar -xzf ESDSWAF-v1.0.2-registry.tar.gz
cd ESDSWAF-v1.0.2
```

**Do not skip the checksum.** A truncated download fails later, during the
install, in a way that looks like a product fault.

> For the **offline** package, join the parts first. The result is byte-identical
> and the checksum proves it:
> ```bash
> cat ESDSWAF-v1.0.2-offline.tar.gz.part-* > ESDSWAF-v1.0.2-offline.tar.gz
> sha256sum -c ESDSWAF-v1.0.2-offline.tar.gz.sha256
> ```

### 3.3 Rehearse

```bash
./install.sh --dry-run
```

This runs **every check the installer makes** and changes nothing. Real output:

```
==> Step 1 of 10 — package
  ✓ package: Next-Gen ESDSWAF v1.0.2
  ✓ images come from hub.enlight.dev/swaraj-kavach (nothing to load)
  ✓ package integrity verified (55 files)

==> Step 3 of 10 — hardware
  ✓ CPU: 8 vCPU (minimum 4)
  ✓ RAM: 15 GB (minimum 15)
  ✓ Disk: 103 GB free on /opt (minimum 100)

==> Step 4 of 10 — prerequisites
  ✓ Docker 29.7.2
  ✓ ports free: 80 443 9443
  ✓ clock synchronised
  ✓ registry reachable — all ten images will be pulled from hub.enlight.dev

  ✓ --dry-run: all checks passed, nothing changed
```

**The dry run stops after step 4, because those four steps are every check there
is.** Nothing after that point is a check — it is all change. So a clean dry run is
genuinely worth having before you commit. It is free; a failed install is not.

### 3.4 Install

```bash
sudo ./install.sh
```

Three questions, then it works unattended:

| Question | Answer |
|---|---|
| Hostname clients will use | the VM's IP or DNS name, e.g. `172.16.21.101` |
| Administrator email | your email |
| Topology | **`1`** — standalone (press Enter) |

Every password, key and certificate is generated for you. **You are never asked to
invent a secret.**

Unattended equivalent:

```bash
sudo WAF_HOSTNAME=172.16.21.101 ADMIN_EMAIL=you@esds.co.in \
     ./install.sh --non-interactive
```

Ten steps, about 6 minutes. Two of them sit quietly for a while — obtaining images
and starting services. **That is normal. Do not press Ctrl+C.**

It ends with:

```
==> Step 10 of 10 — health checks
  ✓ Postgres
  ✓ Redis
  ✓ ClickHouse
  ✓ Control plane → DB
  ✓ Data plane
  ✓ TLS on :443
  ✓ Console :9443

  Installation successful

    Version        Next-Gen ESDSWAF v1.0.2
    Username       admin@sentinel.local
    Password       c7b1206837eea6deb3d530afe57b8057…
```

**All seven health checks must show `✓`.** Look hardest at **`Control plane → DB`**:
if the control plane cannot reach its database it does *not* stop — it keeps running
and serving, and every login then returns `503`. That check is the only thing that
tells the two apart.

### 3.5 Verify

```bash
sudo ./verify.sh
```

```
  18 passed, 0 failed, 2 warnings

  All checks passed. Review the warnings above.
  Note: enforcement was NOT verified — this run proved the stack is running,
  not that it blocks anything.
```

**`0 failed` is the number that matters.** The two warnings are correct at this
point:

- `no sites configured yet — the WAF returns 502 to everything`
- `enforcement not tested — no site configured`

> **A 502 from the WAF before you add a site is right, not broken.** You have a
> working WAF with nothing behind it, so there is no upstream to forward to. §5
> resolves it.

---

## 4. First login

### 4.1 Reaching the console

The console is **bound to `127.0.0.1` only, deliberately.** It is the admin
interface of a security appliance; on `0.0.0.0` it would be exposed to the whole
office network, and to the internet the moment the host got a public address.

**`https://<vm-ip>:9443` will not open. That is correct, not a fault.**

From your own machine:

```bash
ssh -L 9443:127.0.0.1:9443 root@172.16.21.101
```

Leave that open, then browse to **https://127.0.0.1:9443**

- Expect a **certificate warning** — the WAF issued its own certificate.
  Advanced → Proceed.
- Log in as `admin@sentinel.local` with the password from §3.4.
- A **500** on the very first load is usually a cached error from while the console
  was still starting: hard-reload (`Ctrl+Shift+R`) or use a private window.

Ports **80 and 443 *are*** published on all interfaces — that is the traffic path,
and it is what your protected sites are served on.

### 4.2 🔴 The password cannot be changed. Do these three things now.

**This build has no password-change screen and no password-reset endpoint.** The
user API accepts `role` and `status` only. That one credential is the way into this
console for the life of the installation.

**1. Read it back and record it somewhere durable.**

```bash
sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env
```

**2. Back up the secrets file, off this VM.**

```bash
sudo cp /opt/sentinel/current/.env /root/esdswaf-secrets-$(date +%F).env
# then copy it off the machine entirely
```

It holds every secret for the deployment. **Lose it with no backup and the
installation cannot be recovered — it must be rebuilt from scratch.**

**3. Create a second administrator.** It is the only redundancy the product offers.
Settings → Team Members → **Add User**. No email is sent: you set that user's
password (minimum 12 characters) and pass it on out of band. It cannot be changed
later either.

---

## 5. Protecting a website

### 5.1 What to ask the application owner first

Get these before you touch the console. Every one of them prevents a specific
failure:

| Ask | Why |
|---|---|
| The hostname visitors use | The WAF matches on Host header alone; it must be exact |
| The origin address and port | Must be reachable *from the WAF host* |
| Is the origin HTTP or HTTPS? | An HTTPS origin has a hard constraint — see §12 |
| A health-check path | e.g. `/healthz`, or `/` |
| Largest file a user can upload | Over the limit → **413**. Document portals often need 50 MB |
| Slowest legitimate request | Over the timeout → **504**. Reports and exports can need 120–300 s |
| Does login use SAML/OIDC? | Long redirect URLs → **414** |
| Corporate SSO with many cookies? | Many headers → **431** |
| Which HTTP methods does it use? | Anything outside the allowed list → **405** |
| Does it use WebSockets? | Needs enabling explicitly |

### 5.2 The guided way (recommended for a first site)

On the VM, in the package folder:

```bash
sudo ./first-site.sh
```

It asks three things — visitor hostname, origin address, origin port — and then
**checks its own work**:

```
==> Reaching the origin from this host
  ✓ grafana:3000 is accepting connections

==> Validating against the data plane
  ✓ configuration accepted

==> Confirming the data plane loaded it
  ✓ data plane loaded it — now serving 1 site(s), was 0

==> Proving the WAF inspects traffic for this site
  ✓ normal request -> 302 (the origin answered; a redirect counts)

==> Confirming the rule engine inspected it
  ✓ attack request -> 302, and the WAF recorded it:
      rule 942100  score 30/10  SQL Injection Attack Detected via libinjection
```

That last block is the point: a real SQL injection went through the WAF, and the
WAF identified it, scored it 30 against a threshold of 10, and named the rule that
caught it. **You now have a proven WAF, not merely a running one.**

Use `--dry-run` to see exactly what it would create without creating it.

Each of those checks exists because it can fail silently: the origin may be
unreachable from inside the WAF's network; the control plane will happily store a
configuration the data plane rejects; and a site can be stored, listed and echoed
back while the process that inspects traffic never loaded it.

### 5.3 The console way

**Sites → New Site.** Two things will stop you if you do not know them.

> ### ⚠️ Trap 1 — the wizard silently refuses to save
>
> **Turn OFF "Serve HTTPS" on the Front Service step** (or pick the 🚫 No
> certificate card) unless the hostname is publicly resolvable.
>
> New sites default to automatic Let's Encrypt certificates. Leave that on and
> clicking save does nothing except show a red toast: *"An email is required for
> automatic certificates"*. Supplying an email does not help — Let's Encrypt cannot
> issue a certificate for an internal name that does not exist on the public
> internet.

> ### ⚠️ Trap 2 — Easy mode omits the settings that break applications
>
> **Use Advanced mode if any answer in §5.1 was not the default.**
>
> Easy mode's Reverse Proxy step has exactly three controls: Application Host,
> Port, and "Upstream uses HTTPS". Health check path, both timeouts, WebSocket,
> Host-header override and Origin SNI are Advanced-only — and max body size, URI
> length, header count and allowed methods are not on that step at all; they are on
> **Advanced → Request Limits**.
>
> **Switching an existing site to Advanced is not offered.** Decide before you
> create it.

### 5.4 The four request limits

These reject in **every mode, including learning**:

| Limit | Default | Rejects with | Raise it for |
|---|---|---|---|
| Max body size | 20 MB | **413** | document / KYC upload portals |
| Max URI length | 8192 | **414** | SAML / OIDC redirect logins |
| Max header count | 100 | **431** | corporate SSO with many cookies |
| Allowed methods | GET HEAD POST PUT PATCH DELETE OPTIONS | **405** | WebDAV, some REST clients |

**Size these from §5.1 before the site sees real traffic** — not at the go-live
gate in §6. A 413 during a supposedly safe learning period is a genuine outage for
that user, and it will not appear in the false-positive report, because the request
never reached the rule engine that report is built from.

### 5.5 DNS cutover

Only after the site is created, verified, and has run in learning mode:

1. Test through the WAF while DNS still points at the origin:
   ```bash
   curl -H 'Host: portal.example.com' http://<waf-ip>/
   ```
2. Lower the DNS TTL a day ahead, so a rollback is fast.
3. Point DNS at the WAF, or ask the network team to forward 80/443 to it.
4. **Lock the origin down** so it only accepts traffic from the WAF. Otherwise an
   attacker reaches the application directly and the whole deployment is
   decorative. This is the most-skipped step in any WAF rollout.

---

## 6. Going live safely

### 6.1 Leave new sites in LEARNING mode

**Do not switch a customer site to blocking on day one.** Every detection figure
this product publishes comes from a synthetic corpus. Nobody has measured how often
it would wrongly block *that customer's* users.

Learning mode inspects, scores and records — and lets the request through:

```
rule_ids "942100,942180,942330,942390,9900100"
decision "Log"   block_reason "anomaly score 30 >= threshold 10"   status 200
```

Blocking mode, same request:

```
normal: 200    sqli: 403    xss: 403    traversal: 403
```

### 6.2 The go-live sequence

1. **Run in learning for a full business cycle** — one to two weeks, including a
   month-end if traffic looks different then.
2. **Measure what it would have blocked:**
   ```bash
   /opt/sentinel/current/scripts/fpr-report.sh 168
   ```
3. **Review every would-have-blocked request.** For each one that was legitimate,
   add a site exclusion for that rule — do **not** lower the threshold globally,
   which trades away detection everywhere to fix one rule.
4. **Only when that report is clean**, switch the site to Blocking.
5. **Prove it:**
   ```bash
   SENTINEL_VERIFY_HOST=portal.example.com sudo ./verify.sh
   ```
   It must report **`SQL injection -> 403 — blocking is ENFORCED`**.

> ### ⚠️ Wait ten seconds before judging a new or just-changed site
>
> A site becomes reachable slightly **before** its ruleset has compiled. Rules are
> rebuilt on a five-second cycle, so for a few seconds after you create a site or
> change its mode, requests can pass through uninspected. Measured on the reference
> VM, a SQL injection went through unexamined 1.5 s before the log line
> `rule engine loaded  rules=334` appeared.
>
> **Never create a customer site directly in Blocking mode** — it fails open
> through that window. Create in Learning, confirm detection, then switch.

---

## 7. Daily operation

| Task | Command |
|---|---|
| Health check | `sudo ./verify.sh` |
| Health **and** enforcement | `SENTINEL_VERIFY_HOST=<a-site-domain> sudo ./verify.sh` |
| What is running | `docker compose -p sentinel ps` |
| Service logs | `docker compose -p sentinel logs --tail 100 <service>` |
| Live traffic decisions | `docker logs sentinel-dataplane-1 --tail 50` |
| False-positive report | `/opt/sentinel/current/scripts/fpr-report.sh 168` |
| Restart one service | `docker restart sentinel-<service>-1` |

### Reading a traffic decision

Each request produces one line. This is a detection in learning mode:

```json
{"uri":"/login?id=1' OR 1=1--","site":"test-site","status":200,
 "anomaly_score":30,"rule_matches":5,"rule_ids":"942100,942180,942330,942390,9900100",
 "decision":"Log","block_reason":"anomaly score 30 >= threshold 10"}
```

| Field | Meaning |
|---|---|
| `anomaly_score` | cumulative score for this request |
| `rule_matches` / `rule_ids` | which CRS rules fired |
| `decision` | `Allow`, `Log` (would have blocked), `Block` |
| `block_reason` | why, in words |

`decision: Log` with a non-zero score is learning mode working correctly.

---

## 8. Users and access

**Settings → Team Members → Add User.** You set the password (minimum 12
characters); no email is sent, so pass it on out of band.

| Role | Can |
|---|---|
| `viewer` | read dashboards and events |
| `editor` | manage sites and rules |
| `admin` | everything, including users |

**Passwords cannot be changed after creation** — for any user, not just the
administrator. A user who forgets theirs must be deleted and recreated.

---

## 9. Backup and recovery

### What to back up

| | Why |
|---|---|
| **`/opt/sentinel/current/.env`** | **Every secret, including the only admin password. Irreplaceable.** |
| `/opt/sentinel-pki/` | the internal certificate authority |
| The database | sites, users, configuration, event history |

### How

```bash
/opt/sentinel/current/scripts/backup/backup.sh
```

Then **test it**, which is the step everybody skips:

```bash
/opt/sentinel/current/scripts/backup/drill.sh
```

An untested backup is a hope, not a backup.

Schedule it with the shipped systemd timer (see `scripts/backup/RUNBOOK.md`), and
**copy `.env` somewhere off this VM.** A backup that only exists on the machine you
are protecting against losing is not a backup.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| **502 on everything** | No site configured | Expected. Add a site — §5 |
| **502 on one site** | Origin unreachable *from the WAF host*, or Host header does not match the site's domain exactly | `docker exec sentinel-clickhouse-1 nc -z <origin> <port>` |
| **Login returns 503** | Control plane has no database | `sudo ./verify.sh` → check `Control plane → database`, then `docker restart sentinel-controlplane-1` once Postgres is healthy |
| **`https://<vm-ip>:9443` refuses** | Correct — loopback only | Use the SSH tunnel — §4.1 |
| **Console shows 500** | Cached error from startup | Hard reload, or a private window |
| **Wizard will not save** | ACME email required by default | Turn off Serve HTTPS — §5.3 |
| **Attack returns 200** | Site is in learning mode | Correct. Check the event was *recorded* |
| **Attack returns 200 in blocking mode** | Ruleset may not have compiled yet | Wait ten seconds and retry — §6.2 |
| **413 / 414 / 431 / 405** | A request limit, which rejects in every mode | Raise the relevant limit — §5.4 |
| **HTTPS origin always 502** | Origin certificate not publicly trusted | Not supported — §12 |
| **Install aborted at hardware** | Disk measured on `/opt`, not `/` | §2.1 |
| **Cannot pull images** | Registry unreachable | `curl -sS -o /dev/null -w '%{http_code}\n' https://hub.enlight.dev/v2/` — `401` is correct; a timeout means a firewall |
| **Lost the admin password** | | `sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env` |
| **Lost `.env` entirely** | **Unrecoverable** | Rebuild the installation. Back this file up |

Send `/var/log/sentinel/install.log` with any support request.

---

## 11. Upgrading and removing

### Upgrading

```bash
cd /root/ESDSWAF-v<new-version>
sudo ./verify.sh                 # confirm the current install is healthy FIRST
sudo ./upgrade.sh
sudo ./verify.sh                 # and confirm it still is
```

Back up before upgrading. If it goes wrong: `sudo ./rollback.sh`.

### Removing

```bash
sudo ./uninstall.sh          # removes containers; KEEPS data, .env, certificates
sudo ./uninstall.sh --purge  # destroys everything, including the database
```

To reinstall after a **plain** uninstall you must pass `--force`:

```bash
sudo ./install.sh --force
```

This is required, not a workaround. The plain uninstall deliberately keeps your data
and `.env` so a reinstall brings your sites and history back. A normal `install.sh`
sees those existing secrets and **stops rather than generate new ones**, because new
secrets against an existing database would lock you out of your own data. `--force`
means "reuse what is there".

Verified on the reference VM: after `uninstall.sh` then `install.sh --force`, the
same admin password worked, all sites were present, and the site that had been
switched to blocking was still blocking.

---

## 12. Known limitations in 1.0.2

**Read this section before promising anything to a customer.** Each item is a real
constraint of this build, stated here so it is not discovered in production.

| Limitation | What it means in practice |
|---|---|
| **No password change or reset, for any user** | The seeded admin password is permanent. Back up `.env`; create a second admin |
| **"Force HTTPS" does nothing** | The Front Service switches are recorded, not enforced. There is no per-site HTTP→HTTPS redirect. If plain HTTP must not serve a site, control it at the network edge — but note that also disables ACME `http-01` renewal |
| **HTTPS origins must present a publicly trusted certificate** | The upstream connector verifies against the public root store with no override. An internal-CA or self-signed origin certificate fails every handshake and returns 502 forever, with every troubleshooting check passing. Reach such an origin over plain HTTP on a trusted network segment instead |
| **Learning mode does not relax the four request limits** | 413 / 414 / 431 / 405 reject in every mode except Off. Size them before real traffic — §5.4 |
| **A new site is unprotected for a few seconds** | Rulesets compile on a five-second cycle after the site goes live. Never create a site directly in Blocking mode |
| **HTTP/2, HTTP/3 and TLS toggles are host-wide, not per-site** | They are listener properties, configured once for the host |
| **The console is loopback-only** | Reached via SSH tunnel. There is no supported way to expose it directly |

---

## Appendix A — Which install path you used

| | `-registry` | `-online` | `-offline` |
|---|---|---|---|
| Download | 316 KB | 99 MB | 584 MB (3 parts) |
| Needs Harbor (`hub.enlight.dev`) | ✅ | — | — |
| Needs Docker Hub | — | ✅ | — |
| Needs no network at all | — | — | ✅ |
| Registry credentials required | none | none | none |
| Suitable for a customer datacentre | ✗ | ✗ | ✅ |

All three produce an identical installation. Confirmed by installing via `-registry`
on a VM with Docker Hub blackholed: all eight containers came from Harbor,
`verify.sh` reported 18 passed / 0 failed, and blocking mode returned 403 to SQL
injection, XSS and traversal.

## Appendix B — File locations

| Path | Contents |
|---|---|
| `/opt/sentinel/current/.env` | **every secret — back this up** |
| `/opt/sentinel/current/compose.prod.yml` | the deployed topology |
| `/opt/sentinel/current/scripts/` | backup, FPR report, certificate issuers |
| `/opt/sentinel-pki/` | internal certificate authority |
| `/var/log/sentinel/install.log` | full install log |
| `/root/ESDSWAF-v1.0.2/` | **keep this** — `verify.sh`, `first-site.sh`, `upgrade.sh`, `rollback.sh` and `uninstall.sh` live only here |

---

*Next-Gen ESDSWAF 1.0.2 — ESDS Software Solution Ltd*
