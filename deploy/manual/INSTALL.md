# Next-Gen ESDSWAF — Installation

**Who this is for:** anyone installing the WAF on a fresh VM. You do not need to
know Rust, Docker, or how the WAF works inside. You need SSH access and about
15 minutes.

**What you are building:**

```
Fresh VM  →  Install  →  Login  →  Add website  →  Backend  →  TLS  →  DNS  →  Test  →  Monitor
   │            │          │
   └── this document ──────┘        └────────── SITE-ONBOARDING.md ──────────┘
```

This document covers the first three boxes. When you finish it, the WAF is
running and you can log in. It is not protecting anything yet — that is
[SITE-ONBOARDING.md](SITE-ONBOARDING.md).

---

## 1. Before you start

### 1.1 The VM

Ask your infrastructure team for a VM with **exactly** this:

| | Required | Why it matters |
|---|---|---|
| OS | **Ubuntu 24.04 LTS** or 22.04 LTS | RHEL / Rocky / Alma are **not supported**. SELinux blocks the certificate mounts, and it fails *after* installing, which is the worst time to find out |
| CPU | 4 vCPU minimum, **8 recommended** | |
| RAM | **16 GB — not negotiable** | See the warning below |
| Disk | 100 GB free **on `/opt`**, 200 GB recommended | All WAF data lives under `/opt` |
| Ports free | **80, 443, 9443** | The WAF binds all three. Nothing else may be using them |
| Access | root, or a user with full `sudo` | The installer writes `/opt`, `/etc`, and manages Docker |
| Network | Outbound HTTPS to Docker Hub | Only for the *online* bundle — see §1.3 |

> ### ⚠️ About the 16 GB
> This is the one requirement people try to shortcut, so here is the honest
> reason. The event database (ClickHouse) is limited to 6 GB and **crash-loops
> forever** when less than about 2 GB is free. An 8 GB VM does not give you a
> slow WAF. It gives you a WAF that restarts every 30 seconds and looks broken.
>
> The installer **refuses to install** below 15 GB rather than leave you
> debugging that. Please do not use `--allow-undersized` to get around it on a
> box that will carry real traffic.

### 1.2 Install Docker (if it is not already there)

```bash
docker compose version     # if this prints a version, skip this step
```

If not:

```bash
curl -fsSL https://get.docker.com | sh
sudo systemctl enable --now docker
```

You need Docker Engine **27 or newer** with the Compose **v2** plugin.

### 1.3 The two files you were given

ESDS supplies two files. Check which variant you have — it matters:

| Variant | Size | Needs internet during install? |
|---|---|---|
| `ESDSWAF-v1.0.0-offline.tar.gz` | ~2 GB | **No.** All nine container images travel inside the file |
| `ESDSWAF-v1.0.0-online.tar.gz` | ~250 MB | **Yes.** Five supporting images are downloaded during install |

**If the VM has no internet access — which is normal for a management network —
you need the offline bundle.** The online one stops during the checks with a
clear message rather than failing halfway.

You also get a matching `.sha256` file. Keep them together.

---

## 2. Install

### Step 1 — Check the file is intact

```bash
sha256sum -c ESDSWAF-v1.0.0-offline.tar.gz.sha256
```

You should see `OK`. If you see `FAILED`, the file was damaged in transfer — get
a fresh copy. Do not try to install it.

### Step 2 — Extract

```bash
tar -xzf ESDSWAF-v1.0.0-offline.tar.gz
cd ESDSWAF-v1.0.0
```

### Step 3 — Check the VM without changing anything

**Always do this first.** It runs every single check and touches nothing:

```bash
sudo ./install.sh --dry-run
```

If a requirement is missing, it tells you exactly which one and stops. Fix it and
run the dry run again. When it ends with

```
✓ --dry-run: all checks passed, nothing changed
```

you are ready.

> **This is worth doing even when you are confident.** Every check runs *before*
> the first change is made, so there is no half-installed state to clean up. A
> failed dry run costs you 20 seconds. A failed install costs you an afternoon.

### Step 4 — Install

```bash
sudo ./install.sh
```

It runs ten steps and asks you only **two questions** — everything else is
generated for you.

**Question 1: "Hostname clients will use"**

The name (or IP) that visitors' browsers will use to reach the WAF. If you have
no DNS name yet, just press Enter to accept the VM's own IP address. You can
change this later.

**Question 2: "Administrator email"**

Your email. Press Enter to accept the suggested default.

**Then it asks about topology:**

```
1) Standalone — this VM only
2) Active/passive pair
```

**Choose 1.** Option 2 is a two-machine procedure that needs a different script
(`scripts/2vm/install-2vm.sh`) — if you pick it, the installer explains what to
do and exits without changing anything.

> **You are never asked to invent a password.** Every secret — database
> passwords, signing keys, service tokens — is generated with `openssl rand`.
> Do not go looking for a password field.

Now wait. It takes about 10 minutes; loading the images is the slow part.

### Step 5 — Save the password immediately

When it finishes you see:

```
  Installation successful

    Version        Next-Gen ESDSWAF v1.0.0
    Username       admin@sentinel.local
    Password       a3f9c2...   ← 48 characters
```

**Copy that password into your password manager now.** It is deliberately
*not* written to the install log.

If you lose it, it can still be recovered — the control plane printed it once to
its own container log:

```bash
docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'
```

Change it at first login.

---

## 3. Log in

This is where most people get stuck for ten minutes, so read this bit carefully.

### The console is not reachable from your laptop, on purpose

The admin console listens on **127.0.0.1 only** — that means "this machine
itself". It is not a bug and not a mistake in your network. It is deliberate:
this is a security appliance's admin interface, and on a normal network
interface it would be exposed to everything that network touches — including the
whole internet, the moment the VM gets a public IP.

So `https://<vm-ip>:9443` **will not open**, and that is correct.

### How to open it

Build a small private tunnel from your laptop to the VM. Run this **on your own
machine**, not on the VM:

```bash
ssh -L 9443:127.0.0.1:9443 root@<vm-ip>
```

Leave that terminal open. Now open your browser to:

```
https://127.0.0.1:9443
```

Log in with `admin@sentinel.local` and the password from Step 5.

```
Your laptop                          The VM
┌──────────────┐                  ┌──────────────┐
│  browser     │                  │              │
│  127.0.0.1   │ ══ SSH tunnel ══>│  console     │
│    :9443     │                  │  127.0.0.1   │
└──────────────┘                  │    :9443     │
                                  └──────────────┘
```

**Your browser will warn that the certificate is untrusted.** Expected — the
installer created its own certificate authority. Click through the warning. To
get rid of the warning permanently, import `/opt/sentinel-pki/root.crt` into
your browser or OS (there is also a download button on the Certificates page).

Ports **80 and 443 are** published normally on all interfaces. Those carry the
protected websites — only the *admin* console is restricted.

---

## 4. Check it really worked

```bash
sudo ./verify.sh
```

This is a read-only health check, safe to run any time. It prints PASS or FAIL
for each area with the evidence it used — containers, backing stores, database
schema, data plane, listeners, enforcement, certificates.

Everything PASS means the install is genuinely good, not just "no errors on
screen".

You can also look directly:

```bash
docker compose -p sentinel ps       # all containers should be Up / healthy
```

### One thing that looks broken but is not

Right now, **every request to the WAF returns `502 Bad Gateway`.**

That is correct. A WAF is a doorway to a website — you have not told it about any
website yet, so there is nothing behind the door. It will start serving as soon
as you add your first site.

---

## 5. Where everything lives

Useful when someone asks, or when you need to back things up:

| What | Where |
|---|---|
| Installation | `/opt/sentinel/current` |
| **All secrets and settings** | `/opt/sentinel/current/.env` — **back this file up** |
| Installed version | `/opt/sentinel/version` |
| Certificate authority | `/opt/sentinel-pki` (`root.crt` is the one to import) |
| Install log | `/var/log/sentinel/install.log` |
| Operational scripts | `/opt/sentinel/current/scripts/` |

> ### Do not delete the directory you extracted
>
> `verify.sh`, `upgrade.sh`, `rollback.sh` and `uninstall.sh` live **only** there.
> The installer copies the compose files and `scripts/` into
> `/opt/sentinel/current`, but not those four — so if you remove the extracted
> folder you cannot verify, upgrade, roll back or cleanly uninstall until you get
> the package again.
>
> Move it somewhere permanent and write the path down:
>
> ```bash
> sudo mv ESDSWAF-v1.0.0 /opt/
> ```

If anything went wrong, **send `/var/log/sentinel/install.log` to ESDS support**
rather than re-running commands by hand and guessing.

---

## 6. What next

1. **Change the admin password**, and create a personal login for each operator —
   see [ADMIN-GUIDE.md](ADMIN-GUIDE.md) §3.
2. **Add your first website** — [SITE-ONBOARDING.md](SITE-ONBOARDING.md).
3. **Set up backups** — `/opt/sentinel/current/scripts/backup/backup.sh`, see
   [ADMIN-GUIDE.md](ADMIN-GUIDE.md) §6.

If something is wrong: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
To undo anything: [ROLLBACK.md](ROLLBACK.md).

---

## Appendix — installer options

| Option | What it does |
|---|---|
| `--dry-run` | Runs every check, changes nothing. Use it first, always |
| `--non-interactive` | Takes answers from environment variables instead of asking. `sudo WAF_HOSTNAME=waf.company.com ADMIN_EMAIL=you@company.com ./install.sh --non-interactive` |
| `--allow-undersized` | Installs on a VM below the requirements. It will warn you. Please do not use this for real traffic |
| `--force` | Skips the "already installed" guard |
| `--help` | Prints usage |

**To remove the WAF:**

```bash
sudo ./uninstall.sh            # removes containers, KEEPS all your data
sudo ./uninstall.sh --purge    # also destroys all data — IRREVERSIBLE
```

Keeping data is the default deliberately, because "I only wanted to reinstall"
is the common case.
