# Sentinel WAF — Operator's Guide (run the VM like an expert)

> Plain-English, beginner-friendly playbook for running the Sentinel WAF on the
> demo/MVP VM. If you only remember one section, remember **§9 Cheat Sheet**.
>
> VM: `172.16.21.71` · login user: `root` · SSH key: `~/.ssh/sentinel_deploy`
> All commands live on the VM under `/opt/sentinel-src/deploy/docker`.

---

## 0. The mental model (read this once, everything else makes sense)

Think of it as a building:

- **The VM** (`172.16.21.71`) is the building — a remote Linux computer in the
  ESDS network. You don't sit in front of it; you walk in remotely with **SSH**.
- **Docker** is the building's facilities manager. It runs each part of the WAF
  in its own sealed room called a **container**.
- **docker compose** is the master switch panel that turns all the rooms on/off
  together, wired up by one file: `compose.prod.yml`.

There are **6 containers** (rooms). Their real names on the VM are
`sentinel-<service>-1`:

| Container | What it does | Who talks to it |
|---|---|---|
| `sentinel-dataplane-1` | **The WAF itself** (Rust). Inspects traffic, blocks attacks. | The public — on port **80** (HTTP) and **443** (HTTPS) |
| `sentinel-dashboard-1` | The web UI you log into (Next.js) | You, in a browser — port **3000** |
| `sentinel-controlplane-1` | The brain (Go). Stores sites/policies, feeds the dashboard, pushes config to the WAF. | Dashboard + the WAF — port **9501** |
| `sentinel-postgres-1` | The database (sites, users, settings) | Control plane only (internal) |
| `sentinel-redis-1` | Fast cache | Control plane only (internal) |
| `sentinel-juiceshop-1` | A deliberately-vulnerable demo website the WAF protects | Only reachable **through** the WAF |

**The flow of a request:** Browser → port 80/443 (the WAF) → WAF checks for
attacks → if clean, forwards to Juice Shop → response comes back. Attacks get a
**403 Forbidden** and never reach Juice Shop.

**The two URLs that matter:**
- Dashboard (you manage the WAF here): `http://172.16.21.71:3000`
- Protected site (what a visitor sees, guarded by the WAF): `http://172.16.21.71/`
- Login: `admin@sentinel.local` / `admin123` *(change this — see §8)*

---

## 1. Step 1 — Get into the VM (SSH)

**SSH** = "Secure Shell." It's how you log into a remote computer's command line.
You run it **from your own machine** (your Parrot laptop / build host).

```bash
ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71
```

Breaking that down so it's never mysterious again:
- `ssh` — the remote-login program.
- `-i ~/.ssh/sentinel_deploy` — "use **this private key file** as my ID badge."
  (The matching public key is already installed on the VM, so no password.)
- `root@172.16.21.71` — "log in as the user **root** on the machine at **172.16.21.71**."

**First time only:** it prints a fingerprint and asks
`Are you sure you want to continue connecting?` → type `yes` and Enter. It won't
ask again.

When it works, your prompt changes to something like `root@vm:~#`. **You are now
inside the VM** — every command you type runs there, not on your laptop.

**To leave the VM:** type `exit` (or press `Ctrl-D`). You're back on your laptop.

### Make it one word (do this once — it's the "expert" move)
Typing the full command every time is annoying. On **your laptop**, edit
`~/.ssh/config` and add:

```
Host sentinel
    HostName 172.16.21.71
    User root
    IdentityFile ~/.ssh/sentinel_deploy
```

Now you just type:

```bash
ssh sentinel
```

### Run one command without "going inside"
You can fire a single command on the VM and come straight back — handy for quick
checks:

```bash
ssh sentinel 'cd /opt/sentinel-src/deploy/docker && docker compose -f compose.prod.yml ps'
```

### If SSH won't connect (the 3 usual culprits)
| Message | Meaning | Fix |
|---|---|---|
| `Connection timed out` / `No route to host` | You can't reach the VM's network | Get on the ESDS internal network / VPN; confirm the VM is powered on |
| `Permission denied (publickey)` | Wrong/missing key | Check the path `~/.ssh/sentinel_deploy` exists; you're using `-i` (or the `~/.ssh/config` above) |
| `Host key verification failed` | The VM's identity changed (e.g. rebuilt) | `ssh-keygen -R 172.16.21.71` then reconnect and type `yes` again |

---

## 2. Step 2 — Go to the control room

Everything is driven from one folder on the VM. **Always go there first:**

```bash
cd /opt/sentinel-src/deploy/docker
```

That folder has `compose.prod.yml` — the file that defines all 6 containers.
Every command below uses `-f compose.prod.yml` to point at it.

> **Power tip (optional):** so you never type `-f compose.prod.yml` again, run
> this once per login (or add it to `~/.bashrc` on the VM to make it permanent):
> ```bash
> alias dc='docker compose -f /opt/sentinel-src/deploy/docker/compose.prod.yml'
> ```
> Then `dc ps`, `dc logs -f`, `dc restart`, etc. The guide below spells out the
> full commands so they always work even without the alias.

---

## 3. The 5 commands you'll use 95% of the time

Run these from `/opt/sentinel-src/deploy/docker`.

### 3.1 See what's running (your #1 habit)
```bash
docker compose -f compose.prod.yml ps
```
You want every service to show **`Up`** (and ideally `(healthy)` for postgres/redis).
`Exited` or `Restarting` = something's wrong → go to §6 logs/troubleshooting.

### 3.2 Start everything
```bash
docker compose -f compose.prod.yml up -d
```
`up` = create + start. `-d` = "detached" (runs in the background, gives you your
prompt back). Safe to run even if things are already up — it only changes what's
needed. **This is the normal way to bring the stack up.**

### 3.3 Stop everything (but keep it ready to restart)
```bash
docker compose -f compose.prod.yml stop
```
Containers stop; nothing is deleted. Start them again with:
```bash
docker compose -f compose.prod.yml start
```

### 3.4 Restart
```bash
# restart everything
docker compose -f compose.prod.yml restart

# restart just one service (most common — e.g. after a config change)
docker compose -f compose.prod.yml restart controlplane
```
Use `restart <service>` when only one part is misbehaving — it's faster and
leaves the rest untouched.

### 3.5 Watch the logs (your eyes into "why")
```bash
# follow ALL services live (Ctrl-C to stop watching — does NOT stop the WAF)
docker compose -f compose.prod.yml logs -f

# follow just one service
docker compose -f compose.prod.yml logs -f dataplane

# last 200 lines of one service, no live follow
docker compose -f compose.prod.yml logs --tail 200 controlplane
```
`-f` = "follow" (keep streaming new lines). Pressing `Ctrl-C` only stops the
*watching*; the containers keep running.

---

## 4. The one dangerous command — know the difference

```bash
docker compose -f compose.prod.yml down
```
`down` **stops AND deletes** the containers (the rooms are torn down). Your data
is still safe because it lives in **volumes** (`pgdata`, `sentinel-certs`,
`sentinel-logs`), which `down` keeps. Recreate everything with `up -d`.

```bash
docker compose -f compose.prod.yml down -v      # ⚠️ DO NOT run casually
```
The `-v` also **deletes the volumes** — that wipes your **database** (all sites,
users, settings) and certificates. Only ever use `-v` if you intentionally want a
factory reset (and you'd then have to re-run migrations + re-seed from
`mvpproduction.md`).

**Rule of thumb:** `stop`/`start`/`restart` for daily life. `up -d` to bring up.
`down` rarely. `down -v` almost never.

---

## 5. Is the WAF actually working? (health checks)

Run these any time to prove the system is healthy. The first two run **on the VM**;
the last two you can run from anywhere that can reach the VM.

```bash
# 1) All containers Up?
docker compose -f compose.prod.yml ps

# 2) Is the brain alive? (run on the VM)
curl -fsS http://127.0.0.1:9501/health && echo "  <- control plane OK"

# 3) Does the dashboard load? (expect 200 or 307)
curl -s http://172.16.21.71:3000 -o /dev/null -w "dashboard %{http_code}\n"

# 4) Does the WAF block an attack? (expect 403)
#    Use -G + --data-urlencode: it keeps the SQLi payload readable AND encodes it
#    properly. A raw "?q=1' OR '1'='1" has an unencoded space, so curl sends a
#    malformed request line and you get 000 (not 403) — looks broken but isn't.
curl -s -G "http://172.16.21.71/" --data-urlencode "q=1' OR '1'='1" -o /dev/null -w "SQLi attempt -> %{http_code} (expect 403)\n"

# 5) Does the WAF pass clean traffic? (expect 200 — Juice Shop served through the WAF)
curl -s http://172.16.21.71/ -o /dev/null -w "clean request -> %{http_code} (expect 200)\n"
```

If #4 returns **403** and #5 returns **200**, your WAF is doing its job: blocking
attacks, passing real visitors. **Best proof of all: open the dashboard in a
browser** (`http://172.16.21.71:3000`), log in, and watch the live Logs / Recent
Events panels light up as requests come in.

> ⚠️ **Demo gotcha — the WAF will flag *you* if you fire several attacks.** After
> ~3 blocked requests from the same source IP within 60 seconds, the WAF marks
> that IP a repeat attacker and adds a standing penalty (+3, rising to +8 at ~9
> blocks) to **every** request from it — so even clean traffic from your machine
> then returns **403**. This is the WAF working, not a bug. It **auto-clears ~60s
> after the last request** from that IP (stop hitting it and wait). So when
> demoing, either run the "clean traffic passes" check **before** the attacks, or
> run clean checks from a **different machine** than the one you attack from. (A
> browser tab left open on the protected site keeps polling and keeps the penalty
> alive — close it first.) Last resort: `docker compose -f compose.prod.yml
> restart dataplane` clears the in-memory state instantly.

---

## 6. When something breaks — symptom → cause → fix

**Golden rule of debugging here:** always start with `ps` (what's down?) then
`logs` (why?). 90% of issues are answered by those two.

```bash
docker compose -f compose.prod.yml ps
docker compose -f compose.prod.yml logs --tail 100 <the-unhealthy-service>
```

| Symptom | Likely cause | Fix |
|---|---|---|
| **Dashboard won't load** in browser | `dashboard` container down, or you're not on the ESDS network | `ps`; if `dashboard` isn't `Up` → `up -d`; confirm network access |
| **Login spins / returns 500** | Dashboard can't reach the control plane | `logs --tail 100 dashboard` and check `controlplane` is `Up`; `restart dashboard` |
| **Login returns 503** | Control plane is in "degraded" mode (lost the database) | Check `postgres` is `Up (healthy)`; then `restart controlplane` (it now retries the DB on boot) |
| **Website returns 502 Bad Gateway** through the WAF | Upstream (`juiceshop`) is down, or the WAF has no site config yet | `ps` (is `juiceshop` Up?); `logs --tail 100 dataplane`; ensure a site exists in the dashboard |
| **Attacks are NOT blocked (get 200)** | Site is in "detection" mode, not "blocking", or no policy | In the dashboard, set the site's WAF policy mode to **blocking** |
| **Clean traffic gets 403 right after you tested attacks** | The WAF flagged *your* source IP as a repeat attacker (≥3 blocks in 60s → standing anomaly penalty on every request from that IP) | Expected — it's the WAF working. Stop hitting it from that IP and wait ~60s (the penalty auto-clears), or test clean traffic from another machine. Close any browser tab left open on the protected site (it keeps polling). Last resort: `restart dataplane` clears it instantly. |
| **Logs page stuck "Connecting to log stream…"** | SSE/CORS issue (port 9501 or origin) | Confirm `controlplane` is `Up` and port `9501` is reachable from your browser; this is a known config area — see `mvpproduction.md` §3 |
| **A site change isn't taking effect** | The WAF syncs config every ~5 seconds | Wait 5–10s; if still nothing, `logs --tail 50 controlplane` and `dataplane` |
| **One container keeps `Restarting`** | It crashes on boot (bad config/dependency) | `logs --tail 200 <service>` — the error is almost always in the last lines |

**Useful deeper looks:**
```bash
# get a shell INSIDE a container to poke around (e.g. postgres)
docker exec -it sentinel-postgres-1 sh

# check the WAF's raw access logs (NDJSON) on the shared volume
docker exec -it sentinel-dataplane-1 sh -c 'tail -n 50 /var/log/sentinel/*.log'

# how much disk/CPU/memory each container is using
docker stats --no-stream
```

---

## 7. After a VM reboot

The containers are set to **`restart: unless-stopped`**, so when the VM boots,
Docker starts and the whole stack comes back **on its own**. After a reboot, just
verify:

```bash
ssh sentinel
cd /opt/sentinel-src/deploy/docker
docker compose -f compose.prod.yml ps
```

If they're **not** up, the usual reasons and fixes:

```bash
# Is the Docker engine itself running?
systemctl status docker
# If not:
systemctl start docker

# Then bring the stack up:
cd /opt/sentinel-src/deploy/docker && docker compose -f compose.prod.yml up -d
```

> Historical note: a bad `/etc/fstab` entry once caused the disk to mount
> read-only after reboot, which stopped Docker. That has been **fixed** (root now
> mounts read-write on boot). If you ever see "read-only file system" errors after
> a reboot, that's the area to check — see `mvpproduction.md`.

---

## 8. Routine admin tasks

**Add/edit a protected site:** Do it in the dashboard → *Sites* → *Site Wizard*
(easiest), or via the control-plane API (see `mvpproduction.md` §5e/§6). Changes
hot-sync to the WAF within ~5 seconds — **no restart needed**.

**Change the admin password** (still on the to-do list): log into the dashboard
and change it from the user/settings menu. `admin123` must not survive a real demo.

**Check disk space** (logs and images grow over time):
```bash
df -h /                    # overall disk
docker system df           # how much Docker is using
docker system prune -f     # safe cleanup: removes unused images/build cache (NOT your volumes/data)
```

**Reclaim the space ClickHouse spent logging about itself** (one time, after
deploying `clickhouse-logging.xml`):

```bash
cd /opt/sentinel-src/deploy/docker
./clickhouse-reclaim-logs.sh            # report only, changes nothing
./clickhouse-reclaim-logs.sh --apply    # drop the renamed leftovers
```

ClickHouse writes its own server log into system tables, and the packaged
configuration puts no retention on them at all. Measured on the deploy VM at 75
days of uptime, `system.text_log` alone held **15.26 GiB across 345 million
rows**, against **3.88 MiB** of actual WAF events — 99.9% of an 18 GiB volume
spent describing its own merges. This is not only wasted disk: merges on that
table are what OOM-killed ClickHouse during startup and produced the restart
storm recorded in `compose.prod.yml`.

`clickhouse-logging.xml` fixes the growth going forward, by lowering the server
log level from `trace` to `information` and putting a TTL on every self-log
table. But a TTL only governs a table from the moment it exists. When ClickHouse
starts and finds a table whose definition no longer matches its config — which
is what adding a TTL does — it **renames the old one out of the way** and
creates a fresh one:

```
system.text_log      →  new, with the TTL
system.text_log_0    →  every existing row, still no TTL, for ever
```

So the config alone stops the bleeding and reclaims nothing. The script is what
turns the old table back into free disk. It only ever names ClickHouse's own log
tables in the `system` database; `sentinel_logs` holds the product's data and is
never matched. Run it once per node after the first deploy of the new config;
running it again is harmless and reports nothing to do.

**Update the code and redeploy** (after you change the source):
```bash
# from your laptop — push the latest source to the VM
cd /home/ayush3750/waf-development
deploy/sync-to-host.sh root@172.16.21.71
```

Use the wrapper, not a raw `rsync -a --delete`. The tree contains directories
that hold **runtime** state rather than source, and a bare rsync has destroyed
live state twice: it overwrote the deployment's `.env` (secrets and
`SENTINEL_VERSION`) on 2026-09-06, and on 2026-09-09 it deleted the GeoIP
database, which is a bind mount and gitignored, so the country lookup went
inert with no error anywhere. `sync-to-host.sh` keeps that list; `DRY_RUN=1`
shows what it would do.

Then, on the VM, build the new images and **roll the fleet one node at a time**:

```bash
ssh sentinel 'cd /opt/sentinel-src/deploy/docker && \
  docker compose -f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml \
    build dataplane controlplane dashboard && \
  ./rolling-update.sh'
```

Do **not** use `docker compose up -d` to deploy a new version on the HA fleet.
Compose recreates every changed service at once, so all three WAF nodes stop
together. Measured from the balancer's own log on 2026-09-11: all three went
DOWN at 10:22:18 with "0 active and 0 backup servers left" and the first came
back at 10:22:32 — fourteen seconds in which every request got a 503. The data
plane does drain gracefully, but a drain needs somewhere for the traffic to go.

`rolling-update.sh` replaces one node at a time, waits for the balancer to call
it ready again before touching the next, refuses to take out the last node
standing, and reports the smallest number of servers any backend held during
the roll. Run `./rolling-update.sh --check` first to confirm a safe roll is
possible without changing anything.

`docker compose up -d` is still the right command for a **cold start**, where
nothing is serving yet — see §7 above.

Note that `compose build waf1` builds nothing: the image is built once under the
`dataplane` service and the fleet services reuse it.
(Full from-scratch build/deploy steps, DB migrations, and demo-site seeding are
in `mvpproduction.md` — keep that as the deploy reference; keep **this** file as
the day-to-day operations reference.)

---

## 9. HTTPS / TLS certificates

**What's live:** the WAF serves HTTPS on `:443`. For bare-IP access
(`https://172.16.21.71/` over the VPN) it presents a **real certificate signed by
our own private CA** — *"Swaraj Kavach Internal Root CA"* (nodes installed before 2026-09-17 carry the previous name, "Sentinel WAF Internal Root CA" — a certificate on disk is data, it does not rename itself) — not a throwaway
self-signed one. The cert has the VM's IP in its SAN, so it's a valid,
chain-verifiable cert.

**Why the browser still warns (and why that's fine):** the CA is *ours*, not a
public one (Let's Encrypt etc. can't issue for a private IP). Until a machine
trusts our root, the browser shows the usual "not secure" warning. The traffic is
still fully encrypted — the warning is about *who vouches for the cert*, not the
encryption. Two choices:
- **Accept the warning** (decided for the internal demo) — click through, done.
- **Get the green lock** — import our root CA **once** per client (below).

### Make the lock go green (import the root CA, optional)
**Easiest — from the dashboard:** log in → **Certificates** → the *"🛡️ Trust this
WAF"* panel → **⬇ Download Root CA**. Saves `sentinel-root-ca.crt`.

**Or grab it off the VM:**
```bash
scp -i ~/.ssh/sentinel_deploy root@172.16.21.71:/opt/sentinel-pki/root.crt sentinel-root-ca.crt
```
Either way, install `sentinel-root-ca.crt` as a *trusted root authority*:
- **Windows:** double-click → *Install Certificate* → *Local Machine* → *Place in*
  → *Trusted Root Certification Authorities*. (Or `certutil -addstore -f Root sentinel-root-ca.crt` as admin.)
- **macOS:** double-click → Keychain *System* → set the cert to *Always Trust*.
- **Linux:** `sudo cp sentinel-root-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`.
- **Firefox** (uses its own store): *Settings → Privacy & Security → Certificates →
  View Certificates → Authorities → Import* → tick *Trust for websites*.

After import, `https://172.16.21.71/` shows a normal padlock — no warning.

### Where the cert lives / the trust model
| File (on the VM, `/opt/sentinel-pki/`) | What it is | Sensitivity |
|---|---|---|
| `root.crt` | the public Root CA | **safe to share** — hand it to anyone |
| `root.key` | the Root CA private key | **SECRET** — never copy off the VM; anyone with it can mint trusted certs |
| `leaf.crt` / `leaf.pkcs8.key` | the IP server cert + key | served by the WAF |
| `issue-ip-cert.sh` | the re-issuer script | re-run to rotate |

The served copy lives in the data-plane cert repository (the `sentinel-certs`
volume) under the special **`default`** entry — that's the cert shown to any
client that connects without SNI, i.e. by IP. Dir is `0700`, keys `0600`.

### Re-issue / rotate the cert
The IP cert is valid until **Oct 2028** (~825 days). To rotate it (or after the IP
changes), re-run the issuer on the VM, then reload the WAF:
```bash
ssh sentinel 'bash /opt/sentinel-pki/issue-ip-cert.sh'          # keeps the same Root CA, mints a fresh leaf
ssh sentinel 'cd /opt/sentinel-src/deploy/docker && docker compose -f compose.prod.yml restart dataplane'
# override defaults if needed:  WAF_IP=10.x.x.x LEAF_DAYS=825 bash issue-ip-cert.sh
```
The Root CA (valid to 2036) is created once and reused, so clients that already
trust it keep working across rotations — no re-import needed.

### Verify what's being served
```bash
# what cert is on :443 for a bare-IP (no-SNI) client? — issuer should be the Sentinel Root CA
ssh sentinel 'echo | openssl s_client -connect 127.0.0.1:443 2>/dev/null | openssl x509 -noout -subject -issuer'
# does it validate against our root? — expect "Verify return code: 0 (ok)"
ssh sentinel 'echo | openssl s_client -connect 127.0.0.1:443 -CAfile /opt/sentinel-pki/root.crt 2>/dev/null | grep "Verify return"'
# HTTPS works AND attacks still blocked? — expect 200 then 403
ssh sentinel 'curl -s --cacert /opt/sentinel-pki/root.crt https://172.16.21.71/ -o /dev/null -w "benign=%{http_code}\n"'
ssh sentinel 'curl -s --cacert /opt/sentinel-pki/root.crt -G "https://172.16.21.71/" --data-urlencode "q=1'\'' OR '\''1'\''='\''1" -o /dev/null -w "attack=%{http_code}\n"'
```

> **Per-domain certs** (if you ever front a real hostname): upload them in the
> dashboard → *Certificates*. They're served by SNI for that hostname; the `default`
> IP cert above still covers bare-IP access. Customer-supplied wildcards auto-cover
> all their subdomains via SNI.

### The management console & its certificate (the F5 "device cert" model)

There are **two completely separate certs** (don't confuse them):
- **Customer-website certs** — what visitors of a protected site see. Managed under
  *Certificates* (§9 above). The customer brings their own / ACME.
- **The management certificate** — what *you* (the admin) see when you open the
  Sentinel console itself. This is its own thing, like an F5 appliance's *Device
  Certificate*.

**The console now has a dedicated, TLS-secured endpoint:**

```
https://172.16.21.71:9443/      ← the management console (admin UI + API over HTTPS)
http://172.16.21.71:3000/       ← legacy/break-glass (cleartext; prefer :9443)
```

`:9443` is served by the WAF's **own engine** (not a third-party proxy): one
dedicated listener that reverse-proxies the dashboard + API and presents a
**replaceable management certificate**. It bypasses the WAF rule pipeline (it's the
admin console) and refuses to forward internal endpoints.

Out of the box it serves a **self-signed** cert (browser warning — expected). To
replace it with your own / your company-PKI cert:

**Dashboard → Settings → Management TLS** → paste the **certificate** + **private
key** (+ optional CA bundle) → *Validate & Install*. The upload is fully validated
before anything is written:
- the key must **match** the certificate,
- it must be **in date** (not expired, not yet-valid),
- it must have a **SAN**,
- the **chain** is verified if you supply a CA bundle,
- a **hostname mismatch** is a warning (not a hard stop).

On success it **hot-swaps with zero downtime** (next connection picks it up),
records an **audit event** (old→new fingerprint), and shows issuer / expiry / days
remaining / fingerprint / key type. The private key is stored **only on the WAF
node at mode 0600**, never in the database, never logged, never shown again. Use
*Revert to self-signed* to roll back.

> Tip: to get a green lock on `:9443` for an internal demo, mint a leaf from the
> Sentinel internal CA (`/opt/sentinel-pki/`) for `172.16.21.71`, upload it here,
> and import `root.crt` on the client (§9). Or upload a cert from your company PKI.

---

## 10. Cheat Sheet (print this)

```bash
# ── connect ───────────────────────────────────────────────
ssh sentinel                       # (after ~/.ssh/config setup)
#   or: ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71
cd /opt/sentinel-src/deploy/docker # always work from here
exit                               # leave the VM

# ── everyday (run from the folder above) ──────────────────
docker compose -f compose.prod.yml ps             # what's running?
docker compose -f compose.prod.yml up -d          # start everything
docker compose -f compose.prod.yml stop           # stop (keep)
docker compose -f compose.prod.yml start          # start after stop
docker compose -f compose.prod.yml restart        # restart all
docker compose -f compose.prod.yml restart NAME   # restart one (e.g. controlplane)
docker compose -f compose.prod.yml logs -f        # watch all logs (Ctrl-C to stop watching)
docker compose -f compose.prod.yml logs -f NAME   # watch one service

# ── health checks ─────────────────────────────────────────
curl -fsS http://127.0.0.1:9501/health                 # control plane (on VM)
curl -s -G "http://172.16.21.71/" --data-urlencode "q=1' OR '1'='1" -o /dev/null -w "%{http_code}\n"  # expect 403 (raw ?q=... with a space → 000)
curl -s http://172.16.21.71/ -o /dev/null -w "%{http_code}\n"                   # expect 200

# ── careful ───────────────────────────────────────────────
docker compose -f compose.prod.yml down            # stop + remove containers (data safe)
docker compose -f compose.prod.yml down -v         # ⚠️ ALSO deletes DB + certs — almost never

# ── service names ─────────────────────────────────────────
#   dataplane (the WAF) · dashboard · controlplane · postgres · redis · juiceshop

# ── the URLs ──────────────────────────────────────────────
#   Console:    https://172.16.21.71:9443  (admin console over TLS — preferred; §9)
#               http://172.16.21.71:3000   (legacy/break-glass, cleartext)
#   Protected:  http://172.16.21.71/   ·   https://172.16.21.71/  (real CA cert, see §9)
#   Login:      admin@sentinel.local / Admin@123#
```
