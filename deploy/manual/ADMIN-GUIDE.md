# Next-Gen ESDSWAF — Administrator Guide

**Who this is for:** whoever runs the WAF day to day — SOC, NOC, or the platform
team. It assumes the WAF is installed ([INSTALL-WALKTHROUGH.md](../vm-deploy/INSTALL-WALKTHROUGH.md)) and covers
operating it: users, certificates, backups, upgrades, health, and who is
responsible for what.

---

## 1. What you are operating

The WAF is a **reverse-proxy security gateway**. Traffic from the internet
arrives at the WAF, the WAF inspects it, and only acceptable requests are passed
to the real application server behind it.

```
        Internet
           │
           ▼
     Public IP / DNS
           │
           ▼
    ┌─────────────┐
    │     WAF     │   ← inspects every request
    └─────────────┘
           │
           ▼
   Application server
     (the "origin")
```

It is **single-arm**: traffic comes in and goes out the same network interface.
The WAF does **not** take over the network's routing role — no VLAN separation,
no source-NAT pools, no route domains. If an application depends on those today
(on an F5, for example), that stays with the network team; it does not move to
the WAF.

### The two halves

```
        CONTROL PLANE           ← settings, policies, users, certificates
              │                    (the console you log in to)
              │ pushes config
              ▼
         DATA PLANE             ← the traffic path: TLS, inspect, allow/block
              │
              ▼
           Origin
```

Practical consequence: **changing a setting in the console does not restart
anything.** The data plane picks up new configuration within about 5 seconds.
Adding a site, changing a mode, or fixing a false positive is a live operation
with no downtime.

---

## 2. Reaching the console

```bash
ssh -L 9443:127.0.0.1:9443 root@<waf-vm-ip>      # from your own machine
```

Then **https://127.0.0.1:9443**.

The console is bound to loopback deliberately — it is an admin interface for a
security appliance, and exposing it on a network interface would expose it to
everything that network touches, including the internet if the host is ever given
a public IP. Full explanation in [INSTALL-WALKTHROUGH.md](../vm-deploy/INSTALL-WALKTHROUGH.md) §3.

There is also a plain-HTTP break-glass UI on `127.0.0.1:3000` and Grafana on
`127.0.0.1:3001`, both loopback-only, both reachable the same way (`ssh -L
3001:127.0.0.1:3001 …`).

---

## 3. Users and roles

**Do this before anything else: create a personal login for every operator and
stop sharing the `admin@sentinel.local` account.** A shared account means the
audit log can tell you *what* changed but never *who* changed it — which is
exactly the question asked after an incident.

**Settings → Users.**

Five roles:

| Role | Can do |
|---|---|
| **Owner** | Everything, including tenant-level operations |
| **Admin** | Sites, rules, certificates, users. Cannot delete a tenant |
| **Editor** | Change site and rule configuration. No user management |
| **Viewer** | Read-only. Right role for most SOC analysts on day one |
| **Auditor** | Read-only, aimed at audit and compliance review |

Give people the least role that lets them do their job. A SOC analyst
investigating alerts needs **Viewer**. Someone onboarding sites needs **Editor**.

Also available: **OIDC / SSO**, **multi-factor authentication (TOTP)**, and **API
keys** for automation. There is no SAML or LDAP/AD integration — if someone
claims otherwise, that is incorrect.

**Change the installer-generated admin password at first login.** Every secret is
stored in `/opt/sentinel/current/.env`.

---

## 4. The console, page by page

**Daily use — SOC / NOC:**

| Page | What it is for |
|---|---|
| **Overview** | The at-a-glance state: traffic volume, detections, site health. Start here |
| **Events** | Every detection, with the rule that matched, source IP, action taken, and a request ID. This is where you investigate |
| **Sites** | The protected websites. Add, edit, change mode. See [SITE-ONBOARDING.md](SITE-ONBOARDING.md) |
| **Traffic** | Request volumes and patterns |
| **Alerts** | Notifications and their configuration |
| **Certificates** | Request, upload, and check expiry. §5 |
| **Logs** | Log search and export |

**Occasional:**

| Page | What it is for |
|---|---|
| **Rules** | The detection rule sets, and per-site exclusions. Use it to fix a false positive narrowly |
| **Audit** | Who changed what, and when. Needed after any incident |
| **Cluster** | Node health when running more than one node |

**Advanced — usually R&D, not SOC:**
**Threat Intel** (external feed status), **ML** (machine-learning model tuning),
**Plugins**, **Copilot**.

---

## 5. Certificates

**Certificates** page. Two ways to get one:

- **Auto SSL (ACME)** — free, automatic, and **renews itself**. Needs the domain
  to resolve to this WAF and inbound port 80 reachable from the internet. Many
  on-premise networks do not allow that, so check before promising it.
- **Manual Upload** — paste a customer-supplied certificate and key. Upload once,
  assign to many sites. Wildcards cover all subdomains.

**Check the expiry column on this page weekly.** ACME certificates renew
themselves, typically 30 days before expiry. Manually uploaded ones **do not** —
someone has to replace them, and an expired certificate takes a website down
completely for every visitor.

The internal certificate authority created at install lives in
`/opt/sentinel-pki`. Download `root.crt` from this page and import it on trusted
machines to remove browser warnings for internal names.

---

## 6. Backups

**Set this up on day one.** Everything the WAF knows — sites, policies, users,
certificates, attack history — is in two databases. A VM failure without a backup
means rebuilding every site by hand from memory.

```bash
sudo /opt/sentinel/current/scripts/backup/backup.sh
```

It backs up PostgreSQL (all configuration) and ClickHouse (traffic and event
history) into a timestamped directory with a manifest and SHA-256 checksums,
prunes old copies, and pushes the result offsite.

Settings — backup location, retention, offsite target — are in `_common.sh` in
that directory. A systemd timer is provided in `scripts/backup/systemd/` to run
it on a schedule; use it rather than remembering to run it by hand.

**Also back up `/opt/sentinel/current/.env`.** It holds every generated secret.
Without it a restore cannot decrypt or reconnect to anything.

### Test the restore, do not assume it

```bash
sudo /opt/sentinel/current/scripts/backup/drill.sh
```

A backup you have never restored is a hope, not a backup. Run the drill once when
you set it up, and once a quarter after that. Full procedure:
`scripts/backup/RUNBOOK.md`.

Restoring for real: `scripts/backup/restore.sh` — and read
[ROLLBACK.md](ROLLBACK.md) §5 first, because a restore discards everything
written after the backup was taken.

---

## 7. Health monitoring

### Quick check, any time

```bash
cd /path/to/ESDSWAF-v1.0.0      # the directory you extracted at install time
sudo ./verify.sh
```

> ### Keep the extracted bundle directory
>
> `verify.sh`, `upgrade.sh`, `rollback.sh` and `uninstall.sh` live **only** in the
> directory you extracted to install. The installer copies the compose files and
> the operational `scripts/` into `/opt/sentinel/current`, but not these four.
>
> If you delete the extracted directory, you cannot verify, upgrade, roll back or
> cleanly uninstall until you fetch the package again. Keep it somewhere sensible
> — `/opt/ESDSWAF-v1.0.0` is a reasonable home — and note the path in your runbook.

Read-only. Prints PASS or FAIL per area with the evidence used: containers,
backing stores, database schema, data plane, listeners, enforcement,
certificates.

### Container state

```bash
docker compose -p sentinel ps
```

Everything should be `Up`, and the ones with health checks should say `healthy`.

> **A container stuck restarting is nearly always memory.** The event database is
> capped at 6 GB and crash-loops when the host runs short. Check `free -g` before
> looking anywhere else.

### Endpoints for your monitoring system

Point your existing NOC monitoring at these on the WAF's traffic port:

| Endpoint | Meaning |
|---|---|
| `/healthz` | The process is alive |
| `/readyz` | The node can actually protect traffic right now. **This is the one to alert on** — it goes 503 during shutdown *before* the node stops accepting traffic, so a load balancer drains cleanly |
| `/metrics` | Prometheus metrics: request counts, blocks, latency, rule hits |

Prometheus and Grafana ship with the product; Grafana is on `127.0.0.1:3001`
(tunnel to reach it) with a provisioned WAF overview dashboard.

### What to alert on

| Alert | Why |
|---|---|
| `/readyz` failing | The node is not protecting traffic |
| Any container restarting repeatedly | Usually memory, sometimes a bad config |
| Certificate expiring within 14 days | A dead certificate is a total outage |
| Detection volume suddenly 10× normal | Either an attack, or a change that created false positives |
| Disk above 80% on `/opt` | The event store grows; when the disk fills, logging stops |

---

## 8. Upgrades

Run from the **new** package directory:

```bash
sudo ./upgrade.sh --dry-run     # check everything, change nothing
sudo ./upgrade.sh
```

It verifies the package, confirms rollback is possible, backs up the database and
secrets, loads the new images, starts them (database migrations run
automatically), and health-checks the result. **If the health checks fail it rolls
back by itself.**

One honest limit, worth understanding before you rely on it: **database migrations
are forward-only.** If the upgrade applied migrations, restoring the old images
alone can leave old code against a new schema — so a complete rollback then also
needs the database restored, which discards anything written since. The script
detects which case it is in and tells you, rather than reporting a clean rollback
it did not perform. Details in [ROLLBACK.md](ROLLBACK.md) §4.

Upgrade during a maintenance window. Take a manual backup first (§6) even though
the script takes one.

---

## 9. Where things are

| What | Where |
|---|---|
| Installation | `/opt/sentinel/current` |
| **All secrets and settings** | `/opt/sentinel/current/.env` — back it up |
| Installed version | `/opt/sentinel/version` |
| Certificate authority | `/opt/sentinel-pki` |
| Install log | `/var/log/sentinel/install.log` |
| Operational scripts | `/opt/sentinel/current/scripts/` |
| Container logs | `docker compose -p sentinel logs <service>` |

Compose project name is `sentinel` — that is why every `docker compose` command
here uses `-p sentinel`.

---

## 10. Who does what

This is the division that decides whether the WAF can be run without calling the
developers, and it is worth agreeing explicitly rather than discovering it during
an incident.

### SOC / NOC own

- Onboarding a website: collect the details, create the site, verify, cut over DNS
- Watching Events and Alerts; triaging detections as attack or false positive
- Fixing false positives with narrow exclusions
- Switching a site between Learning, Blocking and Off
- Certificates: requesting, uploading, watching expiry
- Backups: that they run, and the quarterly restore drill
- First-line troubleshooting with [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- The emergency brake: setting a site to **Off** ([ROLLBACK.md](ROLLBACK.md) §1)

### Platform / R&D own

- Installing, upgrading, patching the WAF itself
- The data plane, control plane, clustering, databases
- Writing new detection rules; machine-learning tuning
- Performance work and product bugs
- Anything requiring a code change

### Escalate to R&D when

- `verify.sh` fails and [TROUBLESHOOTING.md](TROUBLESHOOTING.md) does not cover it
- A container restart-loops and it is **not** memory
- The same false positive resists a narrow exclusion
- Blocking legitimate traffic in a way you cannot explain from Events
- Anything requiring an upgrade, rollback, or database restore

**When escalating, send:** what you expected, what happened, the **request ID**
from Events or from the block page, the site name, the time, and
`/var/log/sentinel/install.log` if it is install-related. A request ID turns a
30-minute investigation into a 30-second one.

---

## 11. Routine schedule

| How often | Do this |
|---|---|
| Daily | Overview and Alerts. Anything unusual in Events |
| Weekly | Certificate expiry column. Disk usage on `/opt`. Confirm backups ran |
| Monthly | `verify.sh`. Review new false positives. Check user list — remove leavers |
| Quarterly | Backup restore drill (`drill.sh`). Review which sites are still in Learning and why |
| Per release | Upgrade in a maintenance window, backup first |

---

## Related

- [INSTALL-WALKTHROUGH.md](../vm-deploy/INSTALL-WALKTHROUGH.md) — installing on a fresh VM
- [SITE-ONBOARDING.md](SITE-ONBOARDING.md) — putting a website behind the WAF
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — symptom to cause to fix
- [ROLLBACK.md](ROLLBACK.md) — undoing things, at every level
