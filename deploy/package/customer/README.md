# Next-Gen ESDSWAF — Installation Package

**Product:** Next-Gen ESDSWAF
**Vendor:** ESDS Software Solution Ltd — SIG-CyberSec

---

## Install

```bash
# 1. Verify the archive you received (do this BEFORE extracting)
sha256sum -c ESDSWAF-v<version>.tar.gz.sha256

# 2. Extract
tar -xzf ESDSWAF-v<version>.tar.gz
cd ESDSWAF-v<version>

# 3. Install
sudo ./install.sh
```

The installer asks for three things — the hostname clients will use, an
administrator email, and the topology. **Every password and key is generated for
you** with `openssl rand`; you are never asked to invent a secret.

It aborts *before* changing anything if the host does not meet requirements, so
there is no half-installed state to clean up.

Want to check the host first without installing anything?

```bash
sudo ./install.sh --dry-run
```

---

## Requirements

| | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS |
| CPU | 4 vCPU (8 recommended) |
| RAM | **16 GB** |
| Disk | 100 GB free on `/opt` (200 GB recommended) |
| Software | Docker Engine 27+ with the Compose v2 plugin |
| Ports | 80, 443, 9443 free |
| Network | Access to Docker Hub — **see below** |

**RAM is the hard requirement.** ClickHouse is memory-limited to 6 GB and
crash-loops indefinitely with less than about 2 GB available to it. The installer
refuses to proceed below 15 GB detected rather than leaving you with a stack that
restarts forever.

**RHEL, Rocky and Alma are not supported yet.** SELinux blocks the certificate
bind mounts this deployment needs, so it would fail *after* installing rather
than before. Support will be added once genuinely tested.

### Network access

This package contains the four ESDSWAF images. Five supporting images are pulled
from Docker Hub on first install:

```
postgres:16-alpine
redis:7-alpine
clickhouse/clickhouse-server:24-alpine
prom/prometheus:v2.54.1
grafana/grafana:11.2.0
```

So **the install is not fully offline.** The installer checks registry
reachability up front and tells you plainly if it cannot get there.

If your site has no egress, either:

- configure a registry mirror in `/etc/docker/daemon.json`, or
- pre-pull those five images onto the host, or
- **ask ESDS for the fully offline bundle**, which contains all nine images.

---

## After installing

The installer prints the dashboard URL and a one-time administrator password.

1. **Log in and change the password.** It is written in plain text in
   `/var/log/sentinel/install.log`.
2. **Add your first protected site.** Until one exists the WAF returns 502 to
   everything — correct, because there is no upstream to forward to.
3. **Leave new sites in LEARNING mode.**

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
