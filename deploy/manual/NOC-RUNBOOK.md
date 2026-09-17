# Swaraj Kavach — NOC Runbook

**Audience:** an ESDS NOC engineer, competent with Linux, who has never seen this
product. No prior knowledge is assumed and nothing is left as an exercise.

**Time:** about 40 minutes, most of it waiting for images.

> Every command in this runbook was executed on a fresh Ubuntu 24.04 VM
> (`172.16.21.101`) on 2026-08-14, in this order, and the outputs quoted are the
> real ones. Where a step has a trap, the trap is one that actually occurred.

---

## 0. What you are deploying

A **reverse-proxy security gateway**. It sits in front of a website. Visitors
reach the WAF, the WAF inspects the request, and only acceptable requests reach
the real server.

```
   Visitor  ──►  ESDSWAF  ──►  the customer's web server ("the origin")
                    │
                    └── attacks stopped here
```

Two addresses matter and confusing them is the usual first mistake:

| | |
|---|---|
| **The hostname visitors type** | e.g. `portal.example.com`. The WAF matches sites by **Host header alone**, so this must be exact. |
| **The origin** | e.g. `10.20.30.40:8080`. Where the application runs today. Must be reachable *from the WAF host*. |

---

## 1. Before you start — the VM

| Requirement | Why, and what happens if you ignore it |
|---|---|
| Ubuntu 22.04 or 24.04 | The installer refuses anything else |
| **4 vCPU** | Checked and enforced |
| **16 GB RAM** | ClickHouse alone is allocated 6 GB. Below this it restarts forever — you get a broken WAF, not a slower one |
| **110 GB disk, mounted at `/opt`** | Ask for 110, not 100: a "100 GB" disk formats to ~98 GB and the installer requires 100 GB free **on `/opt`** |
| Ports **80, 443, 9443** free | The WAF binds all three. Anything else listening (nginx, apache) aborts the install |
| Root or sudo | |

> **The disk check looks at `/opt`, not `/`.** On the test VM `/` had 98 GB free
> (which would fail) while `/opt` was a separate 110 GB volume with 103 GB free
> (which passed). If `/opt` is not separate, size the root disk accordingly.

**Which package you need depends on what the VM can reach.** Check both:

```bash
curl -sS -o /dev/null -w 'harbor:     %{http_code}\n' https://hub.enlight.dev/v2/
curl -sS -o /dev/null -w 'dockerhub:  %{http_code}\n' https://registry-1.docker.io/v2/
```

`401` means reachable — that is a registry's normal unauthenticated answer. A
timeout or `000` means blocked.

| Harbor | Docker Hub | Use | Size |
|---|---|---|---|
| `401` | either | **`ESDSWAF-v1.0.2-registry.tar.gz`** | **316 KB**, one file |
| unreachable | `401` | `ESDSWAF-v1.0.2-online.tar.gz` | 99 MB, one file |
| unreachable | unreachable | `ESDSWAF-v1.0.2-offline.tar.gz` | 584 MB, 3 parts |

**Prefer `-registry`** for any ESDS-internal VM. It ships no container images; the
installer pulls all ten from Harbor, needing no credentials because that project is
readable within the ESDS network. Verified on a VM with Docker Hub blackholed: all
eight containers came from Harbor and the install was indistinguishable from the
tarball one.

`-offline` is for a customer datacentre, which cannot reach Harbor regardless of
internet access — it sits on `172.16.23.2`, which does not route from outside ESDS.

---

## 2. Docker

Nothing to do: `install.sh` installs Docker Engine itself when it is missing —
from the packages shipped in the offline bundle (no network), otherwise from
Ubuntu's repositories. If the host already has Docker, **both** of these must
answer, or the installer tells you which part is missing:

```bash
docker --version          # Docker version 29.7.2, build a7dcaa6
docker compose version    # Docker Compose version v5.4.0
```

---

## 3. Get the package onto the VM

Either copy it across (`scp`), or download from GitLab:

> **https://git.enlight.dev/research-lab/SIG-CyberSec/sentinel-waf/-/packages**

You need **both** the archive and its `.sha256`.

```bash
cd /root
sha256sum -c ESDSWAF-v1.0.2-online.tar.gz.sha256    # must print: OK
tar -xzf ESDSWAF-v1.0.2-online.tar.gz
cd ESDSWAF-v1.0.2
```

**Do not skip the checksum.** A truncated download fails later, during image
loading, in a way that looks like a product fault.

> If you were given the **offline** bundle in parts, reassemble first — the
> result is byte-identical and the checksum proves it:
> ```bash
> cat ESDSWAF-v1.0.2-offline.tar.gz.part-* > ESDSWAF-v1.0.2-offline.tar.gz
> sha256sum -c ESDSWAF-v1.0.2-offline.tar.gz.sha256
> ```

---

## 4. Dry run first

```bash
./install.sh --dry-run
```

This runs every check and **changes nothing**. Real output from the test VM:

```
==> Step 3 of 10 — hardware
  ✓ CPU: 8 vCPU (minimum 4)
  ✓ RAM: 15 GB (minimum 15)
  ✓ Disk: 103 GB free on /opt (minimum 100)

==> Step 4 of 10 — prerequisites
  ✓ Docker 29.7.2
  ✓ ports free: 80 443 9443
  ✓ clock synchronised
  ✓ Docker registry reachable (6 third-party images will be pulled)

  ✓ --dry-run: all checks passed, nothing changed
```

**If this fails, fix it before continuing.** The dry run is free; a failed real
install is not.

---

## 5. Install

```bash
sudo ./install.sh
```

It asks three things: the hostname clients will use, an administrator email, and
the topology (choose **1, standalone**). Everything else — every password, key
and certificate — is generated for you. You are never asked to invent a secret.

For an unattended run:

```bash
sudo WAF_HOSTNAME=172.16.21.101 ADMIN_EMAIL=you@esds.co.in ./install.sh --non-interactive
```

Ten steps, roughly six minutes. It ends with:

```
  Installation successful

    Version        Swaraj Kavach v1.0.2
    Username       admin@sentinel.local
    Password       6c1a48cb969314feb230ce64072348d3afba849a67c59f0534ac480437a7786b
```

### 🔴 The single most important thing in this document

**That password cannot be changed. Ever.**

This build has no password-change screen and no reset endpoint — the user API
accepts `role` and `status` only. That credential is the only way into the
console for the life of the installation.

It is saved for you in `/opt/sentinel/current/.env` (mode `0600`), so it survives
container recreates, upgrades and rollbacks:

```bash
sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env
```

**Back that file up today, somewhere outside this VM.** It holds every secret for
the deployment. Lose it and the installation must be rebuilt from scratch.

**Create a second administrator now**, as your only redundancy — Settings →
Team Members → **Add User**. Note that no email is sent: you set the password
(minimum 12 characters) and pass it on yourself, and it cannot be changed later
either.

---

## 6. Verify

```bash
sudo ./verify.sh
```

Real output on a fresh install:

```
  18 passed, 0 failed, 2 warnings

  All checks passed. Review the warnings above.
  Note: enforcement was NOT verified — this run proved the stack is running,
  not that it blocks anything.
```

The two warnings are **expected and correct** before you add a site:

- `no sites configured yet — the WAF returns 502 to everything`
- `enforcement not tested — no site configured`

> **A 502 from the WAF before you add a site is right, not broken.** There is no
> upstream to forward to yet.

`0 failed` is the number that matters. If `Control plane → database` fails, stop:
the control plane runs without a database rather than exiting, and every login
returns 503 while `docker ps` looks perfectly healthy.

---

## 7. Reach the console

The console is **bound to 127.0.0.1 only, deliberately**. It is a security
appliance's admin UI; on `0.0.0.0` it would be exposed to the whole office
network. `https://<vm-ip>:9443` **will not work, and that is correct.**

From your workstation:

```bash
ssh -L 9443:127.0.0.1:9443 root@172.16.21.101
```

then open **https://127.0.0.1:9443**

- Expect a **certificate warning** — the WAF issued its own. Advanced → Proceed.
- Log in with `admin@sentinel.local` and the password from step 5.
- A **500** on first load is usually a cached error: hard-reload
  (`Ctrl+Shift+R`) or use an incognito window.

Ports **80 and 443 are** published on all interfaces — that is the traffic path.

---

## 8. Put a site behind the WAF

The fastest correct way, on the VM:

```bash
sudo ./first-site.sh
```

It asks for the visitor hostname, the origin address and the origin port; checks
the origin is reachable *from inside the WAF's network*; validates the config
against the data plane before storing it; confirms the data plane actually
loaded it; and then proves the WAF inspected a live attack. Real output:

```
==> Confirming the data plane loaded it
  ✓ data plane loaded it — now serving 4 site(s), was 3

==> Proving the WAF inspects traffic for this site
  ✓ normal request -> 302 (the origin answered; a redirect counts)

==> Confirming the rule engine inspected it
  ✓ attack request -> 302, and the WAF recorded it:
      rule 942100  score 30/10  SQL Injection Attack Detected via libinjection
```

Use `--dry-run` to see exactly what it would create without creating it.

### Doing it in the dashboard instead

**Sites → New Site.** Two things will catch you out:

1. **Turn OFF "Serve HTTPS" on the Front Service step** (or pick 🚫 No
   certificate) unless the hostname is publicly resolvable. New sites default to
   automatic Let's Encrypt certificates, and the wizard silently refuses to save
   without a contact email — a red toast reading *"An email is required for
   automatic certificates"*. Let's Encrypt cannot issue for an internal name
   regardless.

2. **Use Advanced mode if the application needs anything non-default.** Easy mode's
   Reverse Proxy step has exactly three controls — host, port, upstream HTTPS.
   Body size, timeouts, URI/header limits, allowed methods, WebSocket, health
   check and origin SNI are all Advanced-only, and switching an existing site is
   not offered. Decide up front.

### Three limits that will break real applications

These reject in **every** mode, including learning:

| Limit | Default | Rejects with | Raise it for |
|---|---|---|---|
| Max body size | 20 MB | **413** | document/KYC upload portals |
| Max URI length | 8192 | **414** | SAML/OIDC redirect logins |
| Max header count | 100 | **431** | corporate SSO with many cookies |
| Allowed methods | GET HEAD POST PUT PATCH DELETE OPTIONS | **405** | WebDAV, some REST clients |

---

## 9. Leave it in LEARNING mode

**Do not switch a customer site to blocking on day one.** Every detection figure
this product publishes comes from a synthetic corpus. Nobody has measured how
often it would wrongly block *that customer's* users.

Learning mode detects, scores and records — and lets the request through:

```
rule_ids "942100,942180,942330,942390,9900100"
decision "Log"   block_reason "anomaly score 30 >= threshold 10"   status 200
```

Blocking mode, same request:

```
sqli: 403    xss: 403    traversal: 403    normal: 200
```

**Going live:**

1. Run for a full business cycle — 1 to 2 weeks, including month-end if traffic
   changes then.
2. Measure: `/opt/sentinel/current/scripts/fpr-report.sh 168`
3. Only when that is clean, switch to blocking, then confirm:
   ```bash
   SENTINEL_VERIFY_HOST=portal.example.com sudo ./verify.sh
   ```
   It must say **`SQL injection -> 403 — blocking is ENFORCED`**.

> ⚠️ **A newly created site is matchable before it is inspected.** Rule engines
> are rebuilt on a 5-second poll and then compiled; until that lands the site
> proxies traffic with `rule_matches=0`. Never conclude "it does not block" from
> a test in the first ~10 seconds, and do not create a site directly in blocking
> mode — it fails open through that window.

---

## 10. Day-to-day

| Task | Command |
|---|---|
| Health check | `sudo ./verify.sh` |
| Health + enforcement | `SENTINEL_VERIFY_HOST=<a-site-domain> sudo ./verify.sh` |
| What is running | `docker compose -p sentinel ps` |
| Logs | `docker compose -p sentinel logs --tail 100 <service>` |
| Live traffic decisions | `docker logs sentinel-dataplane-1 --tail 50` |
| Backup | `/opt/sentinel/current/scripts/backup/backup.sh` |
| False-positive report | `/opt/sentinel/current/scripts/fpr-report.sh 168` |

**Back up `/opt/sentinel/current/.env` separately and off-box.** It is the only
copy of the admin password and of every generated secret.

---

## 11. When something is wrong

| Symptom | Cause | Fix |
|---|---|---|
| **502 on every request** | No site configured yet | Expected. Add a site |
| **502 on one site** | Origin unreachable *from the WAF host*, or Host header does not match the site's domain exactly | `docker exec sentinel-clickhouse-1 nc -z <origin> <port>` |
| **Login returns 503** | Control plane has no database | `sudo ./verify.sh` → check `Control plane → database`, then `docker restart sentinel-controlplane-1` once Postgres is healthy |
| **`https://<vm-ip>:9443` refuses** | Correct — console is loopback-only | Use the SSH tunnel in §7 |
| **Console shows 500** | Cached error from startup | Hard reload, or incognito |
| **Wizard will not save** | ACME email required by default | Turn off Serve HTTPS (§8) |
| **Attack returns 200** | Site is in learning mode | Correct. Check the event was *recorded* |
| **HTTPS origin always 502** | Origin certificate is not publicly trusted | Not supported today — use plain HTTP to the origin on a trusted segment |
| **Lost the admin password** | | `sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env`. If the file is gone, the installation must be rebuilt |

Send `/var/log/sentinel/install.log` with any support request.

---

## 12. Removing it

```bash
sudo ./uninstall.sh          # keeps data volumes, .env and certificates
sudo ./uninstall.sh --purge  # destroys everything, including the database
```

After a plain uninstall the data survives, so reinstalling must reuse the
existing secrets:

```bash
sudo ./install.sh --force
```

`--force` is **required** because the `.env` deliberately survived — a plain
`install.sh` stops rather than regenerate secrets against a database that
already exists, which would lock you out of your own data.

---

## Known limitations in v1.0.2

State these up front rather than letting a customer discover them:

| Limitation | Consequence |
|---|---|
| **No password change or reset** | The seeded admin password is permanent. Back up `.env` |
| **"Force HTTPS" does nothing** | The Front Service switches are recorded, not enforced. There is no per-site HTTP→HTTPS redirect. Control it at the network edge |
| **HTTPS origins need a public certificate** | Internal-CA and self-signed origin certificates are not supported |
| **Learning mode does not relax the 4 request limits** | 413/414/431/405 reject even in learning |
| **New sites are unprotected for a few seconds** | Rule engines load on a 5s poll after the site goes live |
| **HTTP→HTTPS, HTTP/2, HTTP/3 toggles are per-host, not per-site** | Listener-level, configured once for the host |
