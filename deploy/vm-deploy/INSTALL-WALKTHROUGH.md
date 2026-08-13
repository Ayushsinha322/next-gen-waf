# Installing Next-Gen ESDSWAF — complete walkthrough

A step-by-step guide from an empty virtual machine to a working WAF that blocks a
real attack. Every command can be copied and pasted.

**No prior experience with this product is assumed.** If you can open a terminal
and copy-paste, you can complete this.

**Time:** about 30 minutes, most of it waiting.

> This walkthrough was written by following it on a real VM, start to finish. The
> troubleshooting section contains the actual problems encountered, not
> hypothetical ones.

---

## What you are about to build

A **WAF** (Web Application Firewall) sits in front of a website and inspects every
request before the website sees it. Attacks get blocked; normal visitors pass
through untouched.

```
   Visitor  ─────►  ESDSWAF  ─────►  Your website
                       │
                       └── attacks stopped here
```

By the end you will have the WAF running, a website behind it, and proof that an
attack against that website is caught.

---

## Before you start — what you need

| | |
|---|---|
| **A virtual machine** | Ubuntu 22.04 or 24.04, **16 GB RAM**, 4 CPUs, 110 GB disk |
| **Its IP address** | e.g. `172.16.21.95` |
| **Its root password** | to log in |
| **A GitLab account** | on `git.enlight.dev`, with access to the WAF project |
| **A terminal** | Terminal on Mac/Linux, PowerShell or PuTTY on Windows |

**16 GB RAM is not negotiable.** The installer refuses to run below it, on
purpose: one component (the event database) is allocated 6 GB and restarts forever
if it cannot get it. A smaller VM does not give you a slower WAF — it gives you a
broken one.

**Disk: ask for 110 GB, not 100 GB.** A "100 GB" disk shows about 98 GB usable
once formatted, and the installer requires 100 GB free. This catches people out.

---

# Part 1 — Get your download key

The WAF is stored in a private area of GitLab. You need a personal key to download
it. This takes two minutes and you only do it once.

1. Open **https://git.enlight.dev/-/user_settings/personal_access_tokens**
2. Click **Add new token**
3. Name: `waf-download`
4. Under **Scopes**, tick **`read_api`**
5. Click **Create personal access token**
6. **Copy the token immediately** — GitLab shows it once and never again

It looks like `glpat-xxxxxxxxxxxxxxxxxxxx`. Paste it somewhere safe for the next
few minutes.

> **What is this?** A password specifically for downloading files, instead of using
> your real GitLab password. If it leaks, it can be revoked without touching your
> account.

---

# Part 2 — Connect to your VM

Open a terminal and run this, replacing the IP with yours:

```bash
ssh root@172.16.21.95
```

Type the root password when asked. **The password will not appear as you type** —
no dots, no stars. That is normal. Type it and press Enter.

You should land at a prompt like:

```
root@waf-testing:~#
```

Everything from here until Part 7 is typed **on the VM**.

---

# Part 3 — Check the VM is suitable

Better to find a problem now than halfway through. Paste this whole block:

```bash
echo "── OS ──"; . /etc/os-release; echo "$PRETTY_NAME"
echo "── RAM ──"; free -g | awk '/Mem:/{print $2" GB (need 16)"}'
echo "── CPU ──"; nproc
echo "── DISK ──"; df -h /opt | tail -1
echo "── DOCKER ──"; docker version --format 'server {{.Server.Version}}' 2>/dev/null || echo "MISSING"
echo "── PORTS ──"; ss -ltn 2>/dev/null | grep -E ':(80|443|9443) ' || echo "80/443/9443 free"
echo "── INTERNET ──"; curl -sI -m 8 https://get.docker.com -o /dev/null -w 'internet: %{http_code}\n' 2>/dev/null || echo "NO INTERNET"
```

**What you want to see:**

| Line | Good result | If not |
|---|---|---|
| OS | `Ubuntu 22.04` or `24.04` | Stop. Other systems are not supported |
| RAM | `15 GB` or more | Stop. Ask for a bigger VM |
| CPU | `4` or more | Stop. Ask for more CPUs |
| DISK | over **100G** in the *Avail* column | See "Not enough disk" below |
| DOCKER | a version, or `MISSING` | `MISSING` is fine, Part 4 installs it |
| PORTS | `80/443/9443 free` | See "A port is in use" below |
| INTERNET | `internet: 200` | Without it you cannot install Docker |

### Not enough disk?

Ask whoever manages the VM to increase the disk to 110 GB, then run:

```bash
growpart /dev/sda 1
resize2fs /dev/sda1
df -h /opt | tail -1        # check it now shows over 100G
```

If `growpart` is missing: `apt-get install -y cloud-guest-utils`

### A port is in use?

Something else is already serving web traffic. Find it:

```bash
ss -ltnp | grep -E ':(80|443|9443) '
```

Usually it is `nginx` or `apache`. Stop it (`systemctl stop nginx`) or use a
different VM. The WAF needs those ports — it *is* the web front door.

---

# Part 4 — Install Docker

Docker runs the WAF's components in isolated containers. Skip this if Part 3
already showed a version.

```bash
apt-get update
apt-get install -y curl ca-certificates
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

Check it worked:

```bash
docker version --format 'server {{.Server.Version}}'
docker compose version
```

You need a version **27 or higher**, and `Docker Compose version v2.x`.
If `docker compose` reports an error, stop and ask for help — nothing later will
work.

---

# Part 5 — Download the WAF

Paste your token from Part 1 into the first line:

```bash
export TOKEN=glpat-xxxxxxxxxxxx
BASE=https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.0

mkdir -p /root/waf && cd /root/waf

for i in 00 01 02 03; do
  curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.0-offline.tar.gz.part-$i
done
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.0-offline.tar.gz.sha256

ls -lh
```

You should see four files of roughly **240M, 240M, 240M, 13M**, plus a tiny
`.sha256`.

> **Why four files?** The download is 733 MB and GitLab refuses uploads over about
> 250 MB, so it is stored in four pieces. You join them back together in the next
> step.

**If a file is only a few hundred bytes**, your token is wrong — that is an error
message, not a download. Delete the files and redo Part 1.

---

# Part 6 — Install

### 6.1 Join the pieces and check nothing was corrupted

```bash
cat ESDSWAF-v1.0.0-offline.tar.gz.part-* > ESDSWAF-v1.0.0-offline.tar.gz
sha256sum -c ESDSWAF-v1.0.0-offline.tar.gz.sha256
```

**This must print `OK`.**

```
ESDSWAF-v1.0.0-offline.tar.gz: OK
```

If it says `FAILED`, the download was incomplete. Delete everything and redo
Part 5. **Do not continue** — installing a damaged file wastes an hour and fails
confusingly.

### 6.2 Unpack

```bash
tar -xzf ESDSWAF-v1.0.0-offline.tar.gz
cd ESDSWAF-v1.0.0
```

### 6.3 Rehearse the install

```bash
./install.sh --dry-run
```

This checks everything and **changes nothing**. It should end with:

```
✓ --dry-run: all checks passed, nothing changed
```

If it stops with a red message, it tells you exactly what is wrong. Fix that and
run the dry run again.

### 6.4 Install for real

```bash
./install.sh
```

It asks two questions:

| Question | What to type |
|---|---|
| Hostname clients will use | Your VM's IP, e.g. `172.16.21.95` |
| Administrator email | Your email address |

Everything else — every password and key — is generated automatically. You are
never asked to invent a password.

**This takes about 10 minutes.** The longest part says "loading images"; it can sit
there for 5–10 minutes with no output. **That is normal — do not press Ctrl+C.**

When it finishes you will see:

```
Installation successful

  Version        Next-Gen ESDSWAF v1.0.0
  Username       admin@sentinel.local
  Password       bdbbbf09b0d3d79e9e7d2cb...
```

### 6.5 ⚠️ Save the password now

**Copy that password somewhere safe before you do anything else.**

If you lose it:

```bash
docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'
```

### 6.6 Check it really worked

```bash
./verify.sh
```

This is read-only and safe to run at any time. It prints **PASS** or **FAIL** for
each area — containers, backing stores, database schema, data plane, listeners,
enforcement, certificates — along with the evidence it used. All PASS means the
install is genuinely good, not just "no red text appeared".

You can also look directly:

```bash
docker compose -p sentinel ps
```

All eight rows should say `Up`. (A ninth, `migrate`, runs the database setup once
and then exits — it is *supposed* to be gone.)

### 6.7 ⚠️ Do not delete this folder

You are in `/root/waf/ESDSWAF-v1.0.0`. **Keep it.**

`verify.sh`, `upgrade.sh`, `rollback.sh` and `uninstall.sh` live **only** here. The
installer copies the compose files and the operational `scripts/` into
`/opt/sentinel/current`, but not those four. Delete this folder and you cannot
verify, upgrade, roll back or cleanly uninstall until you download all 733 MB
again.

Move it somewhere permanent and write the path down:

```bash
cd / && mv /root/waf/ESDSWAF-v1.0.0 /opt/ && cd /opt/ESDSWAF-v1.0.0
```

From now on, "run `./verify.sh`" means: `cd /opt/ESDSWAF-v1.0.0` first.

---

# Part 7 — Open the control panel

### The console is only reachable through a secure tunnel — by design

**`https://172.16.21.95:9443` will not open.** That is deliberate, not a fault.

The control panel is the WAF's administration interface. If it were reachable from
the network, anyone who could reach the server could try to log into your security
appliance. So it only accepts connections from the machine itself, and you reach it
through an encrypted SSH tunnel.

### 7.1 Open the tunnel

**On your own computer**, in a **new terminal window** (leave your VM session
open):

```bash
ssh -L 9443:127.0.0.1:9443 root@172.16.21.95
```

Enter the root password. **Leave this window open** — closing it closes the tunnel.

> **What this does:** makes port 9443 on *your computer* behave as if it were port
> 9443 on the VM, with the traffic encrypted in between.

### 7.2 Open it in your browser

> **https://127.0.0.1:9443**

- You will see a **certificate warning**. This is expected — the WAF issued its own
  certificate. Click **Advanced** → **Proceed to 127.0.0.1 (unsafe)**.
- Log in with `admin@sentinel.local` and the password from Part 6.
- **Change the password immediately.** The one you were given is written in your
  terminal history.

### If you see "500 Internal Server Error"

**Press `Ctrl + Shift + R`** (hard reload). If that does not work, open an
**incognito window** (`Ctrl + Shift + N`) and go to `https://127.0.0.1:9443`.

This happens because the browser can cache an error from a moment when the console
was still starting, then keep showing it. The incognito window proves whether the
server is actually fine. It almost always is.

---

# Part 8 — Put a website behind the WAF

In the control panel, go to **Sites → Add Site** and fill in four fields.

For a first test, use the monitoring dashboard that is already installed — no extra
setup, works even with no internet:

| Field | Value |
|---|---|
| Name | `test-site` |
| **Security Mode** | **`Learning`** — set this explicitly, see below |
| Domain | `test.local` |
| Upstream host | `grafana` |
| Upstream port | `3000` |

Click save.

> ### Set Security Mode to `Learning` yourself — do not trust the default
>
> The dropdown may already say `Blocking`. **Change it to `Learning`.**
>
> This matters for the next part: in Learning mode the WAF *identifies* an attack
> and records it without blocking, which is what lets you see the difference
> between the two modes in Part 9. Set it deliberately and you know which state
> you are in, rather than guessing from what the form happened to pre-select.
>
> It is also the right habit for real sites. A new site's false-positive rate
> against *your* traffic is unknown until it has seen some, so Learning first is
> the rule, not the exception.

### What these fields mean

- **Domain** — the web address visitors type. The WAF uses it to decide which
  protected site a request belongs to.
- **Upstream host / port** — where the real website lives. The WAF forwards clean
  traffic here.

### Two mistakes the form will reject

| You type | Problem |
|---|---|
| `10.0.5.20:8080` in *Upstream host* | Host and port are separate fields |
| `https://test.local/` in *Domain* | Domain is a bare name — no `https://`, no `/` |

Both are rejected with a message telling you the fix. Nothing saves silently
broken.

---

# Part 9 — Prove it blocks attacks

**On the VM**, run these two commands:

```bash
# 1. A normal, harmless request
curl -s -o /dev/null -w 'normal: %{http_code}\n' -H 'Host: test.local' http://127.0.0.1/

# 2. A SQL injection attack
curl -s -o /dev/null -w 'sqli:   %{http_code}\n' -H 'Host: test.local' "http://127.0.0.1/?id=1%27+OR+1%3D1--"
```

Expected result:

```
normal: 200
sqli:   200
```

### Got `sqli: 403` instead?

Then the site is in **Blocking** mode, not Learning — the mode dropdown in Part 8
was left on `Blocking`. Nothing is broken: you have just proved the blocking half
first. Set the site to **Learning**, re-run the command to see `200`, and then
carry on — the point is to see *both* modes and understand the difference.

### "The attack returned 200 — did it fail?"

**No. This is correct, and it is the most important idea in the product.**

New sites start in **learning mode**. The WAF *identifies* the attack and *records*
it, but does not block it. Open **Events** in the control panel and you will see the
SQL injection listed.

Learning mode exists because a WAF that blocks too eagerly turns away real
customers. You run it in learning mode first, look at what it *would* have blocked,
confirm none of it was legitimate traffic, and only then switch on blocking.

### Now switch on blocking

In the control panel, open **test-site** and change the mode from **Learning** to
**Blocking**. Save, then run the attack command again:

```bash
curl -s -o /dev/null -w 'sqli: %{http_code}\n' -H 'Host: test.local' "http://127.0.0.1/?id=1%27+OR+1%3D1--"
```

Now you get:

```
sqli: 403
```

**403 means blocked.** The attack never reached the website.

You now have a working WAF that demonstrably stops an attack.

---

# Troubleshooting

Problems actually encountered while writing this guide.

| What you see | What it means | What to do |
|---|---|---|
| `hardware below minimum specification` | Usually disk: 98 GB free vs 100 GB needed | Grow the disk — Part 3 |
| `sha256sum -c` says `FAILED` | Download was truncated | Delete and redo Part 5 |
| Install seems frozen at "loading images" | Normal — unpacking 733 MB | Wait up to 10 minutes. Do not Ctrl+C |
| `https://<VM-IP>:9443` will not connect | Working as designed | Use the tunnel — Part 7 |
| **500 Internal Server Error** in the browser | Cached error page | `Ctrl+Shift+R`, or incognito — Part 7 |
| Every request returns **502** | No site added yet | Add a site — Part 8 |
| Attack returns 200, not 403 | Site is in learning mode | Expected. Switch to blocking — Part 9 |
| Lost the admin password | It is in the container log | `docker logs sentinel-controlplane-1 2>&1 \| grep -A1 'GENERATED password'` |
| Console fonts look plain | Fonts are fetched from Google | Cosmetic only. Expected on offline VMs |

Full install log, useful when asking for help:

```bash
cat /var/log/sentinel/install.log
```

---

# What to do next

1. **Run in learning mode for a full business cycle** before blocking anything real.
   Then measure:
   ```bash
   /opt/sentinel/current/scripts/fpr-report.sh 168
   ```
2. **Lock down the real website** so it only accepts traffic from the WAF. Otherwise
   an attacker can bypass the WAF by going to the website directly — and the whole
   deployment becomes decorative. This is the most-skipped step in any WAF rollout.
3. **Set up and test backups:**
   ```bash
   /opt/sentinel/current/scripts/backup/backup.sh
   /opt/sentinel/current/scripts/backup/drill.sh
   ```
   Run the drill. An untested backup is a hope, not a backup.
4. **Back up `/opt/sentinel/current/.env`** — it holds every secret for this
   installation and cannot be regenerated.

---

# Glossary

| Term | Meaning |
|---|---|
| **WAF** | Web Application Firewall — inspects web traffic and blocks attacks |
| **Upstream / origin** | The real website the WAF protects and forwards traffic to |
| **Learning mode** | Records what it *would* block, without blocking |
| **Blocking mode** | Actually refuses malicious requests |
| **SQL injection** | An attack that manipulates a site's database queries |
| **403** | "Forbidden" — the WAF blocked the request |
| **502** | "Bad Gateway" — the WAF could not reach the website behind it |
| **SSH tunnel** | An encrypted link that lets you reach a service that only accepts local connections |
| **Container** | An isolated package of software; the WAF runs as eight of them |

---

# Reference

- **Download page:** https://git.enlight.dev/research-lab/SIG-CyberSec/sentinel-waf/-/packages
- **Full standalone guide:** `docs/STANDALONE.md` (inside the bundle)
- **Two-VM high availability:** `docs/ACTIVE-PASSIVE.md` (inside the bundle)

### Once this walkthrough is done — the operator manual

You have finished the only document you needed to get running. These four are
**reference**, for when you have a specific question. Open the one that matches it;
there is no need to read them through.

| Question | Document |
|---|---|
| How do I put a **real customer** website behind the WAF? | [`../manual/SITE-ONBOARDING.md`](../manual/SITE-ONBOARDING.md) — what to ask the app owner, the settings that break real apps, certificates, the DNS cutover, and the gate to pass before blocking |
| How do I run this day to day? | [`../manual/ADMIN-GUIDE.md`](../manual/ADMIN-GUIDE.md) — users and roles, certificates, backups, upgrades, monitoring, who owns what |
| Something is broken | [`../manual/TROUBLESHOOTING.md`](../manual/TROUBLESHOOTING.md) — symptom → cause → fix |
| How do I undo something? | [`../manual/ROLLBACK.md`](../manual/ROLLBACK.md) — every level of undo, and what each one costs |
