# Next-Gen ESDSWAF — Standalone Installation

One VM. The whole product — data plane, control plane, console, database, event
store — on a single host.

This is the right topology for an evaluation, a pilot, a demo, or any site that can
tolerate the WAF being down while the VM reboots. If you need the WAF to survive
losing a machine, use [ACTIVE-PASSIVE.md](ACTIVE-PASSIVE.md) instead.

**You need two files**, which ESDS supplies — the archive and its checksum:

```
ESDSWAF-v1.0.0-<variant>.tar.gz
ESDSWAF-v1.0.0-<variant>.tar.gz.sha256
```

You do **not** need the source code, a compiler, or a build machine. The images are
pre-built and load in about a minute.

There are two variants. Check which one you were given — the installer reads it
from the bundle and behaves accordingly, so you cannot use the wrong one by
mistake:

| Variant | Size | Needs Docker Hub at install? |
|---|---|---|
| `-offline` | ~2 GB | **No.** All nine images travel inside the bundle |
| `-online` | ~250 MB | **Yes.** Five supporting images are pulled during install |

If the VM has no outbound internet — which is normal for a management network —
you want the **offline** bundle. The online one will abort in preflight with a
clear message rather than failing halfway through.

**Time:** about 10 minutes.

---

## 1. Requirements

The installer checks every one of these **before it changes anything**, and aborts
with a specific message rather than half-installing. Run the dry run in §2.2 to
check a host without touching it.

| | Minimum | Notes |
|---|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS | RHEL / Rocky / Alma are **not** supported — SELinux blocks the certificate bind mounts, so it would fail *after* installing |
| CPU | 4 vCPU | 8 recommended |
| RAM | **16 GB** | Hard requirement. The installer refuses below ~15 GB detected |
| Disk | 100 GB free on `/opt` | 200 GB recommended |
| Docker | Engine 27+ with the Compose v2 plugin | `docker compose version` must work |
| Ports | 80, 443, 9443 free | The WAF binds them |
| Network | Reachable Docker Hub | Unless you were given an offline bundle — see §9 |
| Access | root / sudo | Writes `/opt`, `/etc`, and manages Docker |

**RAM is the one that actually bites.** ClickHouse is memory-limited to 6 GB and
crash-loops indefinitely with less than about 2 GB available to it. An 8 GB VM does
not produce a slow WAF; it produces a restart loop. The installer refuses rather
than leaving you to diagnose that.

If Docker is missing:

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

---

## 2. Install

### 2.1 Verify, then extract

```bash
BUNDLE=ESDSWAF-v1.0.0-offline.tar.gz      # or whichever file you received

sha256sum -c "$BUNDLE.sha256"             # must print: OK
tar -xzf "$BUNDLE"
cd ESDSWAF-v1.0.0
```

Verify first, extract second. If `sha256sum -c` does not print `OK`, stop — the
transfer was truncated or the file was altered. Do not install it.

The installer separately checks every shipped file against `SHA256SUMS` and
refuses to run on a package that does not match.

### 2.2 Check the host without touching it

```bash
sudo ./install.sh --dry-run
```

Runs every gate — OS, CPU, RAM, disk, Docker, ports, clock, registry reachability —
and changes nothing. Run this first. It is the cheapest way to find out the VM has
8 GB of RAM.

### 2.3 Install

```bash
sudo ./install.sh
```

It asks for two things and generates everything else:

1. **Hostname** clients will use (defaults to this host's primary address)
2. **Administrator email**

Every secret — database passwords, session signing key, audit HMAC key, internal
service token, Grafana password — is generated with `openssl rand`. You are never
asked to invent one. They are written to `/opt/sentinel/current/.env`, mode 0600.
**Back that file up; it is not recoverable.**

Non-interactive, for automation:

```bash
sudo WAF_HOSTNAME=waf.company.com ADMIN_EMAIL=ops@company.com \
     ./install.sh --non-interactive
```

| Flag | Effect |
|---|---|
| `--dry-run` | Run all checks, change nothing |
| `--non-interactive` | Take answers from the environment |
| `--force` | Continue over an existing install, keeping its `.env` and certificates |

Everything is logged to `/var/log/sentinel/install.log`. If something fails, send
that file rather than re-running commands by hand.

---

## 3. Log in

### The console is loopback-only — this is deliberate

**Read this before deciding the install failed.** The management console is bound
to `127.0.0.1`. It is a security appliance's admin UI; on `0.0.0.0` it would be
exposed to whatever network the host sits on, and to the internet the moment the
host gets a public IP.

```
https://<host>:9443     ← will NOT connect. Correct behaviour, not a fault.
```

Reach it one of two ways:

```bash
# On the host itself
https://127.0.0.1:9443

# From your workstation — tunnel first, then browse to https://127.0.0.1:9443
ssh -L 9443:127.0.0.1:9443 root@<vm-ip>
```

You will get a certificate warning: the cert is issued by the internal CA the
installer generated. Import `/opt/sentinel-pki/root.crt` on client machines to
clear it.

### Credentials

Username is `admin@sentinel.local`. The password is printed once at the end of the
install. If you missed it:

```bash
docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'
```

It is **not** in `/var/log/sentinel/install.log`. Change it at first login.

**Ports 80 and 443 are published on all interfaces.** That is the WAF's traffic
path and it is unaffected by the above; only the admin console is restricted.

---

## 4. Verify

```bash
sudo ./verify.sh
docker compose -p sentinel ps          # every service Up
```

`verify.sh` will tell you plainly when it could not measure enforcement — a run
with no site configured proves the stack is *running*, not that it *blocks*. Do not
read a green run as more than it claims.

A fresh install with no sites returns **502 to everything on port 80**. That is
correct: there is no upstream to forward to yet.

---

## 5. Add the first protected site

In the console: **Sites → Add Site**. Four things:

| Field | Value | Rules the validator enforces |
|---|---|---|
| Name | `customer-shop` | Must not be empty — the data plane matches sites by name |
| Domain(s) | `shop.customer.com` | Bare hostname. No `https://`, no path, no spaces |
| Upstream host | `10.0.5.20` | Host only — **not** `10.0.5.20:8080` |
| Upstream port | `8080` | 1–65535 |

Both common mistakes (a `host:port` string in the host field, a URL in the domain
field) are rejected with a message naming the fix. Nothing saves silently broken.

The WAF must be able to *reach* the upstream address — private or public makes no
difference to the WAF, only routing does.

### Leave it in LEARNING mode

Every published detection figure for this product comes from a synthetic corpus.
Nobody has measured how often it would wrongly block **your** users. Learning mode
records what it would have blocked, without blocking it.

After a full business cycle:

```bash
/opt/sentinel/current/scripts/fpr-report.sh 168     # last 7 days
```

Then enable blocking. Turning on blocking on day one against real traffic is how
you spend the following week on the phone.

---

## 6. Backups

Not a formality on a single VM — it is the **only** recovery mechanism. There is no
second copy of anything here.

```bash
/opt/sentinel/current/scripts/backup/backup.sh
/opt/sentinel/current/scripts/backup/drill.sh      # prove a restore actually works
```

Run the drill before you call this production. An untested backup is an assumption.

---

## 7. Lifecycle

| Task | Command |
|---|---|
| Upgrade | `sudo ./upgrade.sh` (from the new bundle) |
| Roll back | `sudo ./rollback.sh` |
| Remove | `sudo ./uninstall.sh` |
| Re-run over a failed install | `sudo ./install.sh --force` |

`rollback.sh` restores **images and configuration**. Read its output carefully
regarding database state before relying on it to undo a schema migration.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `https://<host>:9443` refuses to connect | Console is loopback-only by design | Use the SSH tunnel — §3 |
| Password on screen doesn't work | You are on an old build | `docker logs sentinel-controlplane-1 2>&1 \| grep -A1 'GENERATED password'` |
| Aborts on RAM | Below ~15 GB detected | Resize the VM. This is not tunable |
| Aborts on ports | nginx/apache already on 80 | `ss -ltnp \| grep :80`, stop it |
| Aborts: already installed | A previous install exists | `./upgrade.sh`, `./uninstall.sh`, or `--force` |
| Aborts: cannot reach registry | No Docker Hub egress | Allow egress, configure a mirror in `/etc/docker/daemon.json`, or ask ESDS for the offline bundle |
| Aborts: checksum mismatch | Corrupt or altered package | Re-download. Do not install it |
| 502 on every request | No sites configured yet | Expected. Add a site |
| Certificate warning in browser | Internal CA, as designed | Import `/opt/sentinel-pki/root.crt`, or upload your own cert |

Full log: `/var/log/sentinel/install.log`.

---

## 9. Before this carries real traffic

Four things, in the order they will hurt you:

1. **Lock the origin** so it accepts traffic only from the WAF. Otherwise an attacker
   resolves the old IP and walks straight past you, and the entire deployment is
   decorative. This is the most-skipped step in every WAF rollout.
2. **Learning mode first**, then measure, then block.
3. **Test the backup restore**, not just the backup.
4. **Understand the layer.** This is a Layer-7 WAF. A volumetric flood large enough
   to saturate the link has to be handled upstream, at the perimeter. Say so to the
   customer rather than let them assume otherwise.

---

## Appendix — building the bundle (ESDS staff only)

Customers do not do this. It runs on a build machine with Docker and the source
tree, never on the target VM.

```bash
cd /path/to/waf-development
./deploy/package/build-bundle.sh            # version from the VERSION file
./deploy/package/build-bundle.sh 1.0.1      # or state it explicitly
```

| Variant | Effect |
|---|---|
| `BUNDLE_THIRD_PARTY=1` | Bundle all nine images — fully offline, ~2 GB, no Docker Hub needed at install |
| `SKIP_BUILD=1` | Reuse images already built locally (iterating on the script only) |

Output lands in `dist/` as `ESDSWAF-v<version>.tar.gz` plus its `.sha256`. Rename
both to carry the variant before sending, and regenerate the checksum from inside
`dist/` so it records a bare filename:

```bash
cd dist
mv ESDSWAF-v1.0.0.tar.gz ESDSWAF-v1.0.0-offline.tar.gz     # or -online
sha256sum ESDSWAF-v1.0.0-offline.tar.gz > ESDSWAF-v1.0.0-offline.tar.gz.sha256
```

Send the customer **both** files. The checksum file is 90 bytes and is the only way
they can tell a truncated 2 GB transfer from a good one.

The standard bundle ships the four ESDSWAF images; `postgres`, `redis`,
`clickhouse-server`, `prometheus` and `grafana` are pulled from Docker Hub at
install time. That keeps the archive at a few hundred MB instead of ~2 GB. Use
`BUNDLE_THIRD_PARTY=1` for air-gapped sites — the installer reads which kind of
bundle it is from the manifest and only checks registry reachability when it
actually needs it.
