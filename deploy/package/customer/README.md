# Swaraj Kavach — Installation Package

**Product:** Swaraj Kavach
**Vendor:** ESDS Software Solution Ltd — SIG-CyberSec

The archive and the directory it extracts to keep the `ESDSWAF-v<version>` name;
every command below is unchanged by the product name.

## New to this product? One document, start to finish

### 👉 [`docs/vm-deploy/INSTALL-WALKTHROUGH.md`](docs/vm-deploy/INSTALL-WALKTHROUGH.md)

Empty VM → install → console open → a real attack blocked. Every command can be
copied and pasted, no prior knowledge of this product assumed, and nothing to
cross-reference while you work. It was written by following it on a real machine.

The rest of this page is the condensed version for people who have done it before.

## Operator manual — for after you are running

Reference, not reading. Open the one that matches your question:
[`docs/manual/`](docs/manual/README.md)

| I want to… | Read |
|---|---|
| Put a **real customer** website behind the WAF | [`docs/manual/SITE-ONBOARDING.md`](docs/manual/SITE-ONBOARDING.md) |
| Run it day to day — users, certificates, backups, upgrades | [`docs/manual/ADMIN-GUIDE.md`](docs/manual/ADMIN-GUIDE.md) |
| Fix something broken | [`docs/manual/TROUBLESHOOTING.md`](docs/manual/TROUBLESHOOTING.md) |
| Undo something | [`docs/manual/ROLLBACK.md`](docs/manual/ROLLBACK.md) |

## Deployment references — in this package

| Deploying | Read |
|---|---|
| **One VM** (evaluation, pilot, most deployments) | [`docs/STANDALONE.md`](docs/STANDALONE.md) |
| **Two VMs**, virtual IP, automatic traffic failover | [`docs/ACTIVE-PASSIVE.md`](docs/ACTIVE-PASSIVE.md) |

This page is the short version of the standalone path. The two-VM deployment is a
two-machine sequence with artifacts that must be copied between the nodes in a
specific order — follow `docs/ACTIVE-PASSIVE.md` for it, not this page.

---

## Install

```bash
# 1. Verify the archive you received (do this BEFORE extracting)
BUNDLE=ESDSWAF-v<version>-offline.tar.gz    # or whichever archive you received
sha256sum -c "$BUNDLE.sha256"               # must print: OK

# 2. Extract
tar -xzf "$BUNDLE"
cd ESDSWAF-v<version>

# 3. Install
sudo ./install.sh
```

The installer asks for three things — the hostname clients will use, an
administrator email, and whether your users arrive through a shared NAT or VPN
address (blank if not). **Every password and key is generated for you** with
`openssl rand`; you are never asked to invent a secret.

It sizes itself to the host: the event store's memory limit, the request-log
ceiling and the event spool are derived from the detected RAM and disk and
written into `.env` with the numbers they came from, and a one-page
`/opt/sentinel/install-report.txt` records the host, the sizing and every check
verdict for support.

Flags for an unattended or hardened install:

| Flag | Effect |
|---|---|
| `--console-bind <ip>` | Publish the console (9443) on a **private** address of this host instead of `127.0.0.1`. Public and wildcard addresses are refused — there is no override. |
| `--shared-egress <cidrs>` | Corporate NAT / VPN addresses shared by many users; their block *history* is forgiven so one person's scan cannot get the whole office blocked. Detection is unchanged. |
| `--non-interactive` | Take answers from `WAF_HOSTNAME`, `ADMIN_EMAIL`, `SHARED_EGRESS`, `CONSOLE_BIND`. |
| `--dry-run` | Run every check, change nothing. |
| `--no-harden` | Skip the kernel network profile (`/etc/sysctl.d/99-sentinel-ddos.conf`). |
| `--no-docker-tuning` | Do not enable Docker at boot or set `live-restore`. |
| `--no-docker-install` | If Docker is absent, stop instead of installing it (for hosts where Docker is managed elsewhere). |
| `--force` | Continue over a previous incomplete attempt (keeps `.env` and certificates as they are). |
| `--allow-undersized` | Evaluation only: proceed below the minimum specification. |

```bash
# A production node published through a NAT, console on the management address:
sudo ./install.sh --console-bind 172.16.21.150 --shared-egress 203.0.113.7
```

Every requirement is checked *before* anything is changed, so a host that does not
qualify is rejected rather than half-installed. If a later step fails, the abort
message tells you whether the host was modified and how to clean up; `--force`
resumes over a previous incomplete attempt.

Want to check the host first without installing anything?

```bash
sudo ./install.sh --dry-run
```

---

## Requirements

| | Minimum (enforced) | Production (recommended) |
|---|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS | same |
| CPU | 4 vCPU | **16 vCPU** |
| RAM | **16 GB** | **32 GB** |
| Disk | 100 GB free on `/opt` and on Docker's data-root | **200 GB SSD/NVMe** |
| Software | Docker Engine with the Compose v2 plugin — **installed by the installer if absent** (from the packages in the offline bundle, else from Ubuntu's repositories). The bundled packages need `iptables` and `nftables` on the host, which Ubuntu Server images carry. | same |
| Ports | 80, 443, 9443 free | same |
| Network | Access to Docker Hub — **see below** | same |

The installer reports which tier the host falls in (`minimum`, `recommended`,
`production`) and sizes the deployment to it: on a 32 GB node the event store
gets 9 GB instead of 6, and a 200 GB disk keeps ~4 GB of request history instead
of 1.2 GB. Spinning disks are detected and warned about — the event store falls
behind on them under load.

**RAM is the hard requirement.** ClickHouse crash-loops indefinitely with less
than about 2 GB available to it. The installer refuses to proceed below 15 GB
detected rather than leaving you with a stack that restarts forever.

**Disk is measured where the data lives.** Images and every volume — the
configuration database, the event store, the request logs — are under Docker's
data-root (`/var/lib/docker` by default), not `/opt`. If that is a separate
filesystem it is checked separately.

**RHEL, Rocky and Alma are not supported yet.** SELinux blocks the certificate
bind mounts this deployment needs, so it would fail *after* installing rather
than before. Support will be added once genuinely tested.

### Network access

This package contains the four ESDSWAF images. Six supporting images are pulled
from Docker Hub on first install:

```
postgres:16-alpine
redis:7-alpine
clickhouse/clickhouse-server:24-alpine
prom/prometheus:v2.54.1
haproxy:2.9-alpine                  # only used by the two-VM / HA topology
```

So **the install is not fully offline.** The installer checks registry
reachability up front and tells you plainly if it cannot get there.

If your site has no egress, either:

- configure a registry mirror in `/etc/docker/daemon.json`, or
- pre-pull those six images onto the host, or
- **ask ESDS for the fully offline bundle**, which contains all ten images.

---

## After installing

The installer prints the administrator password and how to reach the console.

1. **Record the password. It cannot be changed.** This build ships no
   password-change screen and no reset endpoint — `/api/v1/admin/users/:id`
   accepts `role` and `status` only. This credential is the only way into the
   console for the life of the installation.

   The installer generates it into `/opt/sentinel/current/.env` (mode `0600`), so
   unlike a container log it survives upgrades, rollbacks and recreates:

   ```bash
   sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env
   ```

   Back that file up. Lose it without a backup and there is no way back in.

2. **The console is loopback-only, on purpose.** `https://<host>:9443` will not
   connect from your workstation. Tunnel to it:

   ```bash
   ssh -L 9443:127.0.0.1:9443 root@<host>     # then open https://127.0.0.1:9443
   ```
3. **Add your first protected site.** Until one exists the WAF returns 502 to
   everything — correct, because there is no upstream to forward to.
4. **Leave new sites in LEARNING mode.**

### Why learning mode matters

Every detection figure published for this product was measured against a
synthetic attack corpus. **None of them predict how often the WAF would wrongly
block *your* legitimate users.** Enabling blocking on unmeasured traffic risks
refusing real customers.

In learning mode the WAF inspects everything and records what it *would* have
blocked, while letting it through. After a full business cycle — two weeks
preferred, one week minimum, including a weekday peak and a weekend — measure:

```bash
sudo /opt/sentinel/current/scripts/fpr-report.sh 168
```

Enable blocking only once the detection rate is below 1% and the remaining
detections have each been judged genuine attacks. Section 7 of the deployment
guide has the full procedure.

**Learning mode is not inert.** Threat-intelligence and DDoS admission control
run before site policy and still return 403. A legitimate user whose address
appears in a threat feed is still refused during the pilot.

---

## Operating

| Task | Command |
|---|---|
| Verify health | `sudo ./verify.sh` |
| Service status | `docker compose -p sentinel ps` |
| Logs | `docker compose -p sentinel logs --tail 100` |
| Back up | `sudo /opt/sentinel/current/scripts/backup/backup.sh` |
| Test a restore | `sudo /opt/sentinel/current/scripts/backup/drill.sh` |
| Upgrade | extract the new package, `sudo ./upgrade.sh` |
| Roll back | `sudo ./rollback.sh` (or `--list` to see targets) |
| Remove, keep data | `sudo ./uninstall.sh` |
| Remove everything | `sudo ./uninstall.sh --purge` |

**Back up `/opt/sentinel/current/.env`.** It holds every generated secret for
this deployment. Without it a restored database cannot be decrypted or
authenticated against.

---

## Package contents

```
install.sh          one-command installer
uninstall.sh        removal (keeps data unless --purge)
verify.sh           health verification with evidence
upgrade.sh          in-place upgrade with automatic rollback
rollback.sh         return to the previous version
README.md           this file
bundle/             pre-built images, manifest, checksums
compose/            deployment topologies
configs/            example environment, TLS material
scripts/            operational scripts (backup, certificates, 2-VM installer)
docs/               full deployment guide (PDF)
```

There is no source code in this package and nothing is compiled on your host.
Images arrive pre-built and load in about a minute.

---

## If installation fails

Everything is logged to **`/var/log/sentinel/install.log`**. Send that file to
ESDS support — it identifies the cause without anyone re-running commands.

| Symptom | Cause |
|---|---|
| "hardware below minimum specification" | Resize the VM; RAM is usually the one |
| "ports must be free" | nginx or apache is usually already on 80/443 |
| "cannot reach the Docker registry" | See *Network access* above |
| "CHECKSUM MISMATCH" | Corrupted transfer — re-download and re-verify |
| Everything returns 502 | No site configured yet, or the upstream is unreachable |

**Support:** ESDS SIG-CyberSec.
