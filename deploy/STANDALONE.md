# Next-Gen ESDSWAF — Standalone Installation

One VM. The whole product — data plane, control plane, console, database, event
store — on a single host.

This is the right topology for an evaluation, a pilot, a demo, or any site that can
tolerate the WAF being down while the VM reboots. If you need the WAF to survive
losing a machine, use [ACTIVE-PASSIVE.md](ACTIVE-PASSIVE.md) instead.

**Time:** about 10 minutes on the target VM, once you have the bundle.
The slow part is building the bundle (~15 minutes), and that happens once, on a
build machine — not on the customer's VM.

---

## 1. Requirements

The installer checks every one of these **before it changes anything**, and aborts
with a specific message rather than half-installing.

| | Minimum | Notes |
|---|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS | RHEL / Rocky / Alma are **not** supported — SELinux blocks the certificate bind mounts, so it would fail *after* installing |
| CPU | 4 vCPU | 8 recommended |
| RAM | **16 GB** | Hard requirement. The installer refuses below ~15 GB detected |
| Disk | 100 GB free on `/opt` | 200 GB recommended |
| Docker | Engine 27+ with the Compose v2 plugin | `docker compose version` must work |
| Ports | 80, 443, 9443 free | The WAF binds them |
| Network | Reachable Docker Hub | Unless you build an offline bundle — see §2 |

**RAM is the one that actually bites.** ClickHouse is memory-limited to 6 GB and
crash-loops indefinitely with less than about 2 GB available to it. A 8 GB VM does
not produce a slow WAF; it produces a restart loop. The installer refuses rather
than leaving you to diagnose that.

### Why Docker Hub

The standard bundle contains the four ESDSWAF images only. Five supporting images —
`postgres`, `redis`, `clickhouse-server`, `prometheus`, `grafana` — are pulled at
install time. This keeps the archive at a few hundred MB instead of ~2 GB.

For a genuinely air-gapped host, build the bundle with `BUNDLE_THIRD_PARTY=1` (§2)
and all nine images ship inside it. The installer reads which case it is from the
bundle manifest and only checks registry reachability when it actually needs it.

---

## 2. Build the bundle (once, on a build machine)

The target VM never sees source code, never runs `docker build`, and never waits for
a Rust compile. It receives one archive.

```bash
cd /path/to/waf-development
./deploy/package/build-bundle.sh            # version comes from the VERSION file
./deploy/package/build-bundle.sh 1.0.1      # or state it explicitly
```

Useful variants:

```bash
BUNDLE_THIRD_PARTY=1 ./deploy/package/build-bundle.sh   # fully offline, all 9 images
SKIP_BUILD=1        ./deploy/package/build-bundle.sh    # reuse images already built locally
```

Output — send the customer **both** files:

```
dist/ESDSWAF-v1.0.0.tar.gz
dist/ESDSWAF-v1.0.0.tar.gz.sha256
```

The build machine needs Docker and enough patience for a Rust release build with LTO.
It does **not** need to be the target VM, and should not be.

---

## 3. Install on the target VM

### 3.1 Verify before extracting

```bash
sha256sum -c ESDSWAF-v1.0.0.tar.gz.sha256
tar -xzf ESDSWAF-v1.0.0.tar.gz
cd ESDSWAF-v1.0.0
```

Verify first, extract second. The installer separately checks every shipped file
against `SHA256SUMS` and refuses to run on a package that does not match.

### 3.2 Check the host without touching it

```bash
sudo ./install.sh --dry-run
```

Runs every gate — OS, CPU, RAM, disk, Docker, ports, clock, registry reachability —
and changes nothing. Run this first. It is the cheapest way to find out that the VM
has 8 GB of RAM.

### 3.3 Install

```bash
sudo ./install.sh
```

It asks for three things and generates everything else:

1. **Hostname** clients will use (defaults to this host's primary IP)
2. **Administrator email**
3. **TLS**: bring your own certificate (recommended) or self-signed for evaluation
4. **Topology**: standalone — choose 2 only if you are building the active/passive
   pair, in which case it stops and points you at the right script

Every secret — database passwords, session signing key, audit HMAC key, internal
service token, Grafana password — is generated with `openssl rand`. You are never
asked to invent one.

Non-interactive, for automation:

```bash
sudo WAF_HOSTNAME=waf.company.com ADMIN_EMAIL=ops@company.com \
     ./install.sh --non-interactive
```

Other flags:

| Flag | Effect |
|---|---|
| `--dry-run` | Run all checks, change nothing |
| `--non-interactive` | Take answers from the environment |
| `--force` | Continue over an existing install, keeping its `.env` and certificates |

Everything is logged to `/var/log/sentinel/install.log`. If something fails, send
that file rather than re-running commands by hand.

---

## 4. Reaching the console

**This is the step people get wrong, so read it before you decide the install
failed.**

The management console is bound to **127.0.0.1 only**, deliberately. It is a
security appliance's admin UI; on `0.0.0.0` it would be exposed to whatever network
the host sits on, and to the internet the moment the host gets a public IP.

```
https://<host>:9443     ← will NOT connect. Correct behaviour, not a fault.
```

Reach it one of two ways:

```bash
# On the host itself
https://127.0.0.1:9443

# From your workstation — tunnel, then browse to https://127.0.0.1:9443
ssh -L 9443:127.0.0.1:9443 root@<vm-ip>
```

Credentials are printed at the end of the install. If you missed them:

```bash
docker logs sentinel-controlplane-1 2>&1 | grep -A2 "GENERATED password"
```

Change the password at first login — it is sitting in a log file until you do.

**Ports 80 and 443 are published on all interfaces.** That is the WAF's traffic
path and it is unaffected by the above; only the admin console is restricted.

---

## 5. Verify the install

```bash
sudo ./verify.sh
docker compose -p sentinel ps          # every service Up
```

A fresh install with no sites configured returns **502 to everything on port 80**.
That is correct: there is no upstream to forward to yet. It is not a fault, and it
resolves the moment you add a site.

---

## 6. Add the first protected site

In the console: **Sites → Add Site**. Four things:

| Field | Value | Rules the validator enforces |
|---|---|---|
| Name | `customer-shop` | Must not be empty — the data plane matches sites by name |
| Domain(s) | `shop.customer.com` | Bare hostname. No `https://`, no path, no spaces |
| Upstream host | `10.0.5.20` | Host only — **not** `10.0.5.20:8080` |
| Upstream port | `8080` | 1–65535 |

Both common mistakes (a `host:port` string in the host field, a URL in the domain
field) are rejected with a message naming the fix. Nothing saves silently broken.

### Leave it in LEARNING mode

Every published detection figure for this product comes from a synthetic corpus.
Nobody has measured how often it would wrongly block **your** users. Learning mode
records what it would have blocked, without blocking it.

After a full business cycle:

```bash
/opt/sentinel/current/scripts/fpr-report.sh 168     # last 7 days
```

Then enable blocking. Turning on blocking mode on day one against real traffic is
how you spend the following week on the phone.

---

## 7. Backups

Not a formality on a single VM — it is the **only** recovery mechanism. There is no
second copy of anything here.

```bash
/opt/sentinel/current/scripts/backup/backup.sh
/opt/sentinel/current/scripts/backup/drill.sh      # prove a restore actually works
```

Run the drill before you call this production. An untested backup is an assumption.

---

## 8. Lifecycle

| Task | Command |
|---|---|
| Upgrade | `sudo ./upgrade.sh` (from the new bundle) |
| Roll back | `sudo ./rollback.sh` |
| Remove | `sudo ./uninstall.sh` |
| Re-run over a failed install | `sudo ./install.sh --force` |

`rollback.sh` restores the **images and configuration**. Read its output carefully
regarding database state before relying on it to undo a schema migration.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `https://<host>:9443` refuses to connect | Console is loopback-only by design | Use the SSH tunnel — §4 |
| Aborts on RAM | Below ~15 GB detected | Resize the VM. This is not tunable |
| Aborts on ports | nginx/apache already on 80 | `ss -ltnp \| grep :80`, stop it |
| Aborts: already installed | A previous install exists | `./upgrade.sh`, `./uninstall.sh`, or `--force` |
| Aborts: cannot reach registry | No Docker Hub egress | Allow egress, configure a mirror in `/etc/docker/daemon.json`, or get the `BUNDLE_THIRD_PARTY=1` bundle |
| Aborts: checksum mismatch | Corrupt or altered package | Re-download. Do not install it |
| 502 on every request | No sites configured yet | Expected. Add a site |
| Install "successful", console dead | — | Should no longer happen: the console is now a gated health check. If it does, `docker compose -p sentinel logs controlplane` |

Full log: `/var/log/sentinel/install.log`.

---

## 10. Before this carries real traffic

Four things, in the order they will hurt you:

1. **Lock the origin** so it accepts traffic only from the WAF. Otherwise an attacker
   resolves the old IP and walks straight past you, and the entire deployment is
   decorative. This is the most-skipped step in every WAF rollout.
2. **Learning mode first**, then measure, then block.
3. **Test the backup restore**, not just the backup.
4. **Understand the layer.** This is a Layer-7 WAF. A volumetric flood large enough
   to saturate the link has to be handled upstream, at the perimeter. Say so to the
   customer rather than let them assume otherwise.
