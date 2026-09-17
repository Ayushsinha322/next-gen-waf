# Installing Swaraj Kavach — complete walkthrough

A step-by-step guide from an empty virtual machine to a working WAF that blocks a
real attack. Every command can be copied and pasted.

**No prior experience with this product is assumed.** If you can open a terminal
and copy-paste, you can complete this.

**Time:** about 40 minutes, most of it waiting.

> **Every command and every output below came from a real run.** This walkthrough
> was executed start to finish on a fresh Ubuntu 24.04 VM (`172.16.21.101`) on
> **2026-08-14** against **v1.0.2**, and the quoted outputs are that machine's,
> copied verbatim. The troubleshooting section lists the problems that actually
> occurred, not ones that might.

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
| **A virtual machine** | Ubuntu 22.04 or 24.04, **16 GB RAM**, 4 CPUs, **110 GB on `/opt`** |
| **Its IP address** | e.g. `172.16.21.101` |
| **Its root password** | to log in |
| **A GitLab account** | on `git.enlight.dev`, with access to the WAF project |
| **A terminal** | Terminal on Mac/Linux, PowerShell or PuTTY on Windows |

**Ask for 16 GB RAM.** The installer's floor is 15 GB, and a VM provisioned with
16 GB reports as 15 — so 16 GB provisioned passes and anything smaller does not.
It is enforced on purpose: one component (the event database) is allocated 6 GB and
restarts forever if it cannot get it. A smaller VM does not give you a slower WAF —
it gives you a broken one.

**Disk: the installer measures `/opt`, not `/`.** This is the single most common
provisioning mistake. Ask for **110 GB, not 100** — a "100 GB" disk formats to about
98 GB usable, and the requirement is 100 GB free.

On the reference VM `/opt` was its own 110 GB volume, which is the cleanest layout:

```
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G  1.6G   98G   2% /
/dev/sdb1       108G   24K  103G   1% /opt      ← this is the one that counts
```

Note that `/` there has only 98 GB free and would have *failed* the check. If `/opt`
is not a separate mount on your VM, the root disk must be large enough on its own.

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
ssh root@172.16.21.101
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
echo "── RAM ──"; free -g | awk '/Mem:/{print $2" GB (need 15 or more)"}'
echo "── CPU ──"; nproc
echo "── DISK ──"; df -h /opt | tail -1
echo "── DOCKER ──"; docker version --format 'server {{.Server.Version}}' 2>/dev/null || echo "MISSING"
echo "── COMPOSE ──"; docker compose version 2>/dev/null || echo "MISSING"
echo "── PORTS ──"; ss -ltn 2>/dev/null | grep -E ':(80|443|9443) ' || echo "80/443/9443 free"
echo "── ESDS HARBOR ──"; curl -sS -m 8 -o /dev/null -w 'harbor:   %{http_code}\n' https://hub.enlight.dev/v2/ 2>/dev/null || echo "NOT REACHABLE"
echo "── DOCKER HUB ──"; curl -sS -m 8 -o /dev/null -w 'registry: %{http_code}\n' https://registry-1.docker.io/v2/ 2>/dev/null || echo "NOT REACHABLE"
echo "── INTERNET ──"; curl -sI -m 8 https://get.docker.com -o /dev/null -w 'internet: %{http_code}\n' 2>/dev/null || echo "NO INTERNET"
```

**What you want to see** — this is the reference VM's actual result:

| Line | Good result | If not |
|---|---|---|
| OS | `Ubuntu 24.04.2 LTS` | Stop. Other systems are not supported |
| RAM | **`15 GB` or more** | Stop. Ask for a bigger VM |
| CPU | `8` — anything **4 or more** passes | Stop. Ask for more CPUs |
| DISK | over **100G** in the *Avail* column, **for `/opt`** | See "Not enough disk" below |
| DOCKER | a version, or `MISSING` | `MISSING` is fine, Part 4 installs it |
| COMPOSE | any version, or `MISSING` | `MISSING` is fine, Part 4 installs it |
| PORTS | `80/443/9443 free` | See "A port is in use" below |
| ESDS HARBOR | `harbor:   401` | See the note below — this decides which download you need |
| DOCKER HUB | `registry: 401` | Only matters if Harbor is unreachable |
| INTERNET | `internet: 200` | Without it you cannot install Docker |

> **`401` is the good answer for both**, not an error. That is what a container
> registry replies to an unauthenticated request, and it proves the VM can reach it.
> A timeout, `NOT REACHABLE` or `000` means it cannot.
>
> **The HARBOR line is the important one.** If it says `401`, you want the tiny
> `-registry` download in Part 5 — 316 KB, because the images come from ESDS's own
> registry rather than travelling with the package. Only if Harbor is unreachable
> does the Docker Hub line matter.

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

Check it worked. **Both** commands must answer:

```bash
docker --version
docker compose version
```

On the reference VM, that produced:

```
Docker version 29.7.2, build a7dcaa6
Docker Compose version v5.4.0
```

You need Docker **27 or higher** and any `docker compose` that answers. Do not be
alarmed by a high Compose version — `v5.x` is current and correct. What matters is
that the command exists at all: `docker compose` (a plugin, no hyphen) is required,
and the old separate `docker-compose` binary is not a substitute.

If `docker compose` reports an error, stop and ask for help — nothing later will
work.

Confirm the daemon is actually running, not merely installed:

```bash
systemctl is-active docker        # must print: active
```

---

# Part 5 — Download the WAF

### 5.1 Which one do you need?

Three downloads. **Part 3's HARBOR and DOCKER HUB lines tell you which.**

| Harbor | Docker Hub | Download | Size | Files |
|---|---|---|---|---|
| `401` | either | **`-registry`** | **316 KB** | **one file** |
| unreachable | `401` | `-online` | 99 MB | one file |
| unreachable | unreachable | `-offline` | 584 MB | three parts to join |

**If Harbor answered, take `-registry`.** It contains no container images at all —
the installer pulls all ten from ESDS's Harbor registry, which needs no login
because that project is readable inside the ESDS network. This is the normal case
for any ESDS-internal VM, and it is 316 KB instead of 99 MB.

Use `-offline` for a customer's own datacentre. Such a site cannot reach Harbor
whether or not it has internet, because Harbor lives on an internal address
(`172.16.23.2`) that does not route from outside ESDS.

The small one pulls six standard images (Postgres, Redis, ClickHouse, Prometheus,
HAProxy) from Docker Hub during the install. The offline one carries all
ten images inside it and needs no internet at all.

**If in doubt, and the VM has internet, use `-online`.** You cannot pick the wrong
one by accident: the installer reads which variant it is from the package manifest
and refuses early and clearly rather than failing halfway.

### 5.2 Download it

Paste your token from Part 1 into the first line:

```bash
export TOKEN=glpat-xxxxxxxxxxxx
BASE=https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.2

mkdir -p /root/waf && cd /root/waf

# ── the small one (VM has internet) ───────────────────────────────────────────
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-online.tar.gz
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-online.tar.gz.sha256

ls -lh
```

You should see one file of about **99M** plus a tiny `.sha256`. That is the whole
product — there is nothing to join.

> **This used to be four files.** The release was 733 MB and GitLab rejects uploads
> over about 250 MB, so it had to be split and reassembled by hand on the VM. The
> dashboard image was 779 MB of that, almost entirely build tooling that never runs
> in production; removing it took the image to 157 MB and the download to 99 MB.
> The join step is gone for this variant.

**For a closed network**, the offline package is still in three parts:

```bash
for i in 00 01 02; do
  curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-offline.tar.gz.part-$i
done
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-offline.tar.gz.sha256
```

**If a downloaded file is only a few hundred bytes**, your token is wrong — you have
saved an error message, not a download. Delete the files and redo Part 1.

---

# Part 6 — Install

### 6.1 Check nothing was corrupted

**Small download** — nothing to join:

```bash
sha256sum -c ESDSWAF-v1.0.2-online.tar.gz.sha256
```

**Offline download** — join the parts first. The result is byte-identical to the
original and the checksum is what proves it:

```bash
cat ESDSWAF-v1.0.2-offline.tar.gz.part-* > ESDSWAF-v1.0.2-offline.tar.gz
sha256sum -c ESDSWAF-v1.0.2-offline.tar.gz.sha256
```

**This must print `OK`.**

```
ESDSWAF-v1.0.2-online.tar.gz: OK
```

If it says `FAILED`, the download was incomplete. Delete everything and redo
Part 5. **Do not continue** — installing a damaged file wastes an hour and fails
confusingly. (The installer checks all 54 shipped files against their checksums
again in its first step, so a bad package is caught either way — but it is quicker
to find out now.)

### 6.2 Unpack

```bash
tar -xzf ESDSWAF-v1.0.2-online.tar.gz
cd ESDSWAF-v1.0.2
ls
```

```
README.md  SHA256SUMS  bundle  compose  configs  docs
first-site.sh  install.sh  rollback.sh  scripts  uninstall.sh  upgrade.sh  verify.sh
```

### 6.3 Rehearse the install

```bash
./install.sh --dry-run
```

This checks everything and **changes nothing**. Real output from the reference VM:

```
==> Step 1 of 10 — package
  ✓ package: Swaraj Kavach v1.0.2
  verifying every shipped file against SHA256SUMS…
  ✓ package integrity verified (54 files)

==> Step 2 of 10 — operating system
  detected: Ubuntu 24.04.2 LTS
  ✓ supported

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

The dry run stops after step 4 — those four steps are every check the installer
makes. **Nothing after this point is a check; it is all change.** So a clean dry run
is genuinely worth having before you commit.

If it stops with a red message, it tells you exactly what is wrong. Fix that and
run the dry run again. It is free.

### 6.4 Install for real

```bash
./install.sh
```

It asks three questions:

| Question | What to type |
|---|---|
| Hostname clients will use | Your VM's IP, e.g. `172.16.21.101` |
| Administrator email | Your email address |
| Topology | **`1`** — standalone (just press Enter) |

Everything else — every password, key and certificate — is generated automatically.
You are never asked to invent a password.

**This takes about 6 minutes.** Two steps sit for a while with no output — "loading
images" and "starting services". **That is normal — do not press Ctrl+C.**

Ten steps, and it ends like this:

```
==> Step 9 of 10 — starting services
  database migrations run automatically before the control plane starts
  ✓ containers started

==> Step 10 of 10 — health checks
  ✓ Postgres
  ✓ Redis
  ✓ ClickHouse
  ✓ Control plane → DB
  ✓ Data plane
  ✓ TLS on :443
  ✓ Console :9443

  Installation successful

    Version        Swaraj Kavach v1.0.2
    Username       admin@sentinel.local
    Password       6c1a48cb969314feb230ce64072348d3afba849a67c59f0534ac480437a7786b
```

**All seven health checks must be `✓`.** `Control plane → DB` is the one to look
hardest at: if the control plane cannot reach its database it does *not* stop — it
keeps running and serving, and every login then returns `503`. That check is the only
thing that distinguishes the two, so a `✗` there means stop and fix, not carry on.

> **Prefer an unattended run?** Same result, no prompts:
> ```bash
> WAF_HOSTNAME=172.16.21.101 ADMIN_EMAIL=you@esds.co.in ./install.sh --non-interactive
> ```

### 6.5 🔴 Save the password now — it cannot be changed later

**Copy that password somewhere safe before you do anything else.**

This is the most consequential paragraph in this document. **There is no
password-change screen and no password-reset endpoint in this build** — the user API
accepts `role` and `status` only. That one credential is the way into the console for
the life of the installation.

The installer writes it into the deployment's secrets file, so unlike a container log
it survives restarts, upgrades and rollbacks. To read it back at any time:

```bash
sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env
```

**Back up that whole file today, somewhere off this VM:**

```bash
cp /opt/sentinel/current/.env  /root/esdswaf-secrets-$(date +%F).env
# then copy it off the machine entirely
```

It holds every secret for the deployment. Lose it with no backup and the installation
cannot be recovered — it has to be rebuilt from scratch.

> **Create a second administrator as soon as you are logged in** (Part 7), via
> Settings → Team Members → **Add User**. It is the only redundancy the product
> offers. No email is sent: you set that user's password yourself (minimum 12
> characters) and pass it on out of band — and it cannot be changed later either.

### 6.6 Check it really worked

```bash
./verify.sh
```

This is read-only and safe to run at any time. Real output on the fresh install:

```
== Control plane → database
  PASS  control plane is connected to its database

== Database schema
  PASS  schema present (20 tables — migrations ran)

== Listeners
  PASS  port 80 bound
  PASS  port 443 bound
  PASS  port 9443 bound

== Enforcement
  WARN  enforcement not tested — no site configured

  18 passed, 0 failed, 2 warnings

  All checks passed. Review the warnings above.
  Note: enforcement was NOT verified — this run proved the stack is running,
  not that it blocks anything. Configure a site and re-run to measure that.
```

**`0 failed` is the number that matters.** The two warnings are correct and expected
at this point:

- `no sites configured yet — the WAF returns 502 to everything`
- `enforcement not tested — no site configured`

> **A 502 from the WAF right now is right, not broken.** You have a working WAF with
> nothing behind it, so there is no upstream to forward a request to. That resolves in
> Part 8. Note also that the script refuses to *claim* enforcement works until it has
> actually measured it — so it says so plainly rather than reassuring you.

You can also look directly:

```bash
docker compose -p sentinel ps
```

All eight rows should say `Up`. (A ninth, `migrate`, runs the database setup once
and then exits — it is *supposed* to be gone.)

### 6.7 ⚠️ Do not delete this folder

You are in `/root/waf/ESDSWAF-v1.0.2`. **Keep it.**

`verify.sh`, `first-site.sh`, `upgrade.sh`, `rollback.sh` and `uninstall.sh` live
**only** here. The installer copies the compose files and the operational `scripts/`
into `/opt/sentinel/current`, but not those five. Delete this folder and you cannot
verify, onboard a site with the guided script, upgrade, roll back or cleanly
uninstall until you download the package again.

Move it somewhere permanent and write the path down:

```bash
cd / && mv /root/waf/ESDSWAF-v1.0.2 /opt/ && cd /opt/ESDSWAF-v1.0.2
```

From now on, "run `./verify.sh`" means: `cd /opt/ESDSWAF-v1.0.2` first.

---

# Part 7 — Open the control panel

### The console is only reachable through a secure tunnel — by design

**`https://172.16.21.101:9443` will not open.** That is deliberate, not a fault.

The control panel is the WAF's administration interface. If it were reachable from
the network, anyone who could reach the server could try to log into your security
appliance. So it only accepts connections from the machine itself, and you reach it
through an encrypted SSH tunnel.

### 7.1 Open the tunnel

**On your own computer**, in a **new terminal window** (leave your VM session
open):

```bash
ssh -L 9443:127.0.0.1:9443 root@172.16.21.101
```

Enter the root password. **Leave this window open** — closing it closes the tunnel.

> **What this does:** makes port 9443 on *your computer* behave as if it were port
> 9443 on the VM, with the traffic encrypted in between.

### 7.2 Open it in your browser

> **https://127.0.0.1:9443**

- You will see a **certificate warning**. This is expected — the WAF issued its own
  certificate. Click **Advanced** → **Proceed to 127.0.0.1 (unsafe)**.
- Log in with `admin@sentinel.local` and the password from Part 6.

> ### ⚠️ That password cannot be changed. Record it now.
>
> This build has no password-change screen and no reset endpoint — the user API
> accepts `role` and `status` only. The password the installer printed is the
> **only** way into this console, permanently.
>
> It is saved in `/opt/sentinel/current/.env` (mode `0600`), which survives
> upgrades and container recreates. Read it back at any time with:
>
> ```bash
> sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env
> ```
>
> **Back that file up today.** It also holds every other secret for the
> deployment. Lose it without a backup and the installation must be rebuilt from
> scratch.

### If you see "500 Internal Server Error"

**Press `Ctrl + Shift + R`** (hard reload). If that does not work, open an
**incognito window** (`Ctrl + Shift + N`) and go to `https://127.0.0.1:9443`.

This happens because the browser can cache an error from a moment when the console
was still starting, then keep showing it. The incognito window proves whether the
server is actually fine. It almost always is.

---

# Part 8 — Put a website behind the WAF

There are two ways. Do the guided script first — it proves the WAF works in one
command — then do the wizard once by hand, because that is what you will use for a
real customer site.

## 8A — The guided script (do this first)

**On the VM**, in the package folder:

```bash
sudo ./first-site.sh
```

It asks three things — the hostname visitors will use, the origin's address, and the
origin's port. For a first test answer `test.local`, `prometheus`, `9090`: that is the
metrics service the installer already put on the VM, so it works even with no
internet.

Then it does the work and, more importantly, checks it:

```
==> Reaching the origin from this host
  ✓ prometheus:9090 is accepting connections

==> Validating against the data plane
  ✓ configuration accepted

==> Creating the site
  ✓ created — id b68b0f09-8106-4156-b6ab-20590824e5d1

==> Confirming the data plane loaded it
  ✓ data plane loaded it — now serving 1 site(s), was 0

==> Proving the WAF inspects traffic for this site
  ✓ normal request -> 302 (the origin answered; a redirect counts)

==> Confirming the rule engine inspected it
  ✓ attack request -> 302, and the WAF recorded it:
      rule 942100  score 30/10  SQL Injection Attack Detected via libinjection
```

That last block is the whole point of the exercise: a real SQL injection was sent
through the WAF, and the WAF identified it, scored it 30 against a threshold of 10,
and recorded which rule caught it. **You now have a working, proven WAF.**

Add `--dry-run` to see exactly what it would create without creating anything.

Every step it checks is one that can fail silently, which is why it checks them:
the origin might not be reachable from inside the WAF's network; the control plane
will happily store a configuration the data plane rejects; and a site can be stored
and listed while the traffic-inspecting process has never loaded it.

## 8B — The wizard, by hand

Now do the same thing through the control panel, because a real customer site needs
settings the script does not ask about.

Go to **Sites → Add Site**.

**Step 1 — Basics**

| Field | Value |
|---|---|
| Name | `test-site` |
| **Security Mode** | **`Learning`** — set this explicitly, see below |
| Domain | `test.local` |

**Step 2 — Front Service: turn OFF "Serve HTTPS"** (or choose the **🚫 No
certificate** TLS card).

> **Do not skip this step — the wizard will not save without it.** New sites
> default to automatic certificates via Let's Encrypt. Leave that on and clicking
> save does nothing except show a red toast reading *"An email is required for
> automatic certificates (Front Service)"*. Supplying an email does not help
> either: Let's Encrypt cannot issue a certificate for `test.local`, a name that
> does not exist on the public internet. This test site is plain HTTP.
>
> The same applies to any real internal-only hostname later — automatic
> certificates need a publicly resolvable name.

**Step 3 — Reverse Proxy**

| Field | Value |
|---|---|
| Upstream host | `prometheus` |
| Upstream port | `3000` |

Leave the remaining steps at their defaults and click save.

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
curl -s -o /dev/null -w 'normal: %{http_code}\n' -H 'Host: test.local' http://127.0.0.1/login

# 2. A SQL injection attack
curl -s -o /dev/null -w 'sqli:   %{http_code}\n' -H 'Host: test.local' "http://127.0.0.1/login?id=1%27+OR+1%3D1--"
```

Expected result:

```
normal: 200
sqli:   200
```

> **Why `/login` and not `/`?** Many apps redirect `/` to a login page, so `/`
> answers **302**, not 200 — which would make both numbers above read `302` and
> leave you unable to tell a working WAF from a broken one. `/login` is the same
> upstream, reached the same way, and answers 200. If you do test `/` and see
> `302`, nothing is wrong: a 302 from the origin still proves the request was
> proxied through the WAF.

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
**Blocking**. Save, wait about ten seconds, then run the attacks again:

```bash
curl -s -o /dev/null -w 'normal:    %{http_code}\n' -H 'Host: test.local' http://127.0.0.1/login
curl -s -o /dev/null -w 'sqli:      %{http_code}\n' -H 'Host: test.local' "http://127.0.0.1/login?id=1%27+OR+1%3D1--"
curl -s -o /dev/null -w 'xss:       %{http_code}\n' -H 'Host: test.local' "http://127.0.0.1/login?q=%3Cscript%3Ealert(1)%3C/script%3E"
curl -s -o /dev/null -w 'traversal: %{http_code}\n' -H 'Host: test.local' "http://127.0.0.1/login?f=../../../../etc/passwd"
```

Real result from the reference VM:

```
normal:    200
sqli:      403
xss:       403
traversal: 403
```

**403 means blocked.** The attacks never reached the website; the normal request went
straight through. You now have a working WAF that demonstrably stops an attack.

And now prove it the way you will prove it on a customer site — by asking the
verifier instead of trusting a `curl`:

```bash
SENTINEL_VERIFY_HOST=test.local sudo ./verify.sh
```

```
== Enforcement
  PASS  legitimate request -> 302 (origin answered)
  PASS  SQL injection -> 403 — blocking is ENFORCED

  21 passed, 0 failed, 0 warnings
```

> ### ⚠️ Wait ten seconds before you judge a brand-new site
>
> A site becomes reachable slightly **before** the WAF has compiled its ruleset. The
> rules are rebuilt on a five-second cycle, so for a few seconds after you create a
> site — or switch its mode — requests can pass through uninspected. On the reference
> VM a SQL injection went through unexamined 1.5 seconds before the log line
> `rule engine loaded  rules=334` appeared.
>
> This is why the test above says "wait about ten seconds", and why **a real customer
> site should never be created directly in Blocking mode** — it would fail open
> through that window. Create it in Learning, confirm detection, then switch.

---

# Troubleshooting

Problems actually encountered while writing this guide.

| What you see | What it means | What to do |
|---|---|---|
| `hardware below minimum specification` | Usually disk — and it measures **`/opt`**, not `/` | Grow the disk — Part 3 |
| `sha256sum -c` says `FAILED` | Download was truncated | Delete and redo Part 5 |
| Install seems frozen at "loading images" | Normal — unpacking and loading four images | Wait a few minutes. Do not Ctrl+C |
| `Docker Compose version v5.x` | Correct and current | Nothing. Only the *absence* of `docker compose` is a problem |
| Health check `✗ Control plane → DB` | The control plane is up **without a database** — every login will return `503` | Wait for Postgres to be healthy, then `docker restart sentinel-controlplane-1` |
| `https://<VM-IP>:9443` will not connect | Working as designed | Use the tunnel — Part 7 |
| **500 Internal Server Error** in the browser | Cached error page | `Ctrl+Shift+R`, or incognito — Part 7 |
| Every request returns **502** | No site added yet | Add a site — Part 8 |
| **502 on a site you just added** | Origin unreachable *from inside the WAF's network*, or the `Host` header does not match the site's domain exactly | `docker exec sentinel-clickhouse-1 nc -z <origin> <port>` |
| The wizard will not save, red toast about an email | New sites default to automatic certificates | Turn **off** Serve HTTPS on Front Service — Part 8B |
| Attack returns 200, not 403 | Site is in learning mode | Expected. Switch to blocking — Part 9 |
| Attack returns 200 **in blocking mode** | The ruleset may not be compiled yet | Wait ten seconds and retry — see the warning in Part 9 |
| Lost the admin password | It is in the deployment's secrets file | `sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env` |
| Lost the whole `.env` file | **Unrecoverable.** There is no password reset | Rebuild the installation. Back this file up |
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

# Starting over

If this was a trial run and you want the VM back:

```bash
sudo ./uninstall.sh          # removes containers, KEEPS data, .env and certificates
sudo ./uninstall.sh --purge  # destroys everything, including the database
```

To reinstall after a **plain** uninstall, you must pass `--force`:

```bash
sudo ./install.sh --force
```

This is not a workaround — it is required, and for a good reason. The plain uninstall
deliberately keeps your `.env` and your data volumes so that reinstalling brings your
sites and history back. A normal `install.sh` sees those existing secrets and **stops
rather than generate new ones**, because new secrets against an existing database would
lock you out of your own data. `--force` says "reuse what is there".

Verified on the reference VM: after `uninstall.sh` then `install.sh --force`, the same
admin password still worked, all four sites were still present, and the site that had
been switched to blocking was still blocking.

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
