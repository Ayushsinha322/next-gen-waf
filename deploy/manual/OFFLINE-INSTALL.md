# Swaraj Kavach — Offline Installation Guide

**Product:** Swaraj Kavach (ESDS Software Solution Ltd)
**Scope:** single-VM standalone deployment from the offline package, on Ubuntu 22.04 / 24.04

> This guide was first written by the ESDS operator who performed the first
> unassisted installation (UAT, September 2026), from what actually happened —
> including the two places the process fought back. It has been corrected where
> the installer has since been fixed. Where it disagrees with the longer
> [INSTALL-WALKTHROUGH.md](../vm-deploy/INSTALL-WALKTHROUGH.md), this one is the
> field-tested version.

Every step says **which machine** it runs on. The one mistake that cost the most
time was running a copy command *on the VM* that should have run *on the laptop*.

---

## 1. Get a verified offline package onto your laptop

Download the package from the GitLab Package Registry
(`sentinel-waf` → **Deploy → Package Registry** → `esdswaf` → the version you
were told), or from wherever ESDS shared it. Large single files do not survive
every transfer, so the offline archive is published as **parts** plus one
checksum file for the whole:

```
ESDSWAF-v<version>-offline.tar.gz.part-00
ESDSWAF-v<version>-offline.tar.gz.part-01
ESDSWAF-v<version>-offline.tar.gz.part-02        (count depends on the version)
ESDSWAF-v<version>-offline.tar.gz.sha256          checksum of the JOINED archive
```

Ignore `ESDSWAF-v<version>-online.tar.gz` — it needs Docker Hub from the VM and
is not for an offline install.

**On your laptop, before transferring anything, confirm every part is complete**
(file Properties on Windows, `ls -l` on Linux/Mac). A part that is even one byte
short means the download was cut off — download that part again. For **v1.1.0**:

| file | bytes |
|---|---|
| `…offline.tar.gz.part-00` | 251,658,240 |
| `…offline.tar.gz.part-01` | 251,658,240 |
| `…offline.tar.gz.part-02` | 139,085,098 |
| joined `…offline.tar.gz` | 642,401,578 |

For any other version the `.sha256` file is the authority; sizes are a quick
first check, the checksum is the real one.

## 2. Transfer laptop → VM — never VM → itself

Run this **in a terminal on your laptop** (PowerShell, Terminal, or MobaXterm's
local shell), or drag-and-drop in MobaXterm/WinSCP's file panel:

```bash
scp ESDSWAF-v<version>-offline.tar.gz.part-* \
    ESDSWAF-v<version>-offline.tar.gz.sha256 \
    root@<vm-ip>:~/
```

Wait until every file shows `100%`.

> **Important.** If you are already SSH'd into the VM and run `scp … root@<vm-ip>:~/`
> there, you are copying the VM's own (possibly broken) file onto itself. It will
> report `100%` and change nothing. This happened three times on the first install.
> The copy has to start from the machine that holds the good file.

## 3. On the VM — join the parts

```bash
ssh root@<vm-ip>
cd ~
rm -rf ESDSWAF-v<version> ESDSWAF-v<version>-offline.tar.gz     # leftovers from any earlier try
cat ESDSWAF-v<version>-offline.tar.gz.part-0* > ESDSWAF-v<version>-offline.tar.gz
```

## 4. Verify size and checksum BEFORE extracting

```bash
ls -l ESDSWAF-v<version>-offline.tar.gz                # must match the joined size above
sha256sum -c ESDSWAF-v<version>-offline.tar.gz.sha256  # must print:  …tar.gz: OK
```

**If it says FAILED, stop.** The archive is truncated or corrupt. Do not extract,
do not troubleshoot `tar`, do not run the installer — go back to step 1 and find
the short part. `tar` would fail with `Unexpected EOF in archive`, and that error
tells you nothing the checksum did not already say.

## 5. Extract

```bash
tar -xzf ESDSWAF-v<version>-offline.tar.gz && cd ESDSWAF-v<version>
```

## 6. Re-installing over an existing installation

If a WAF is already installed on this VM (a previous attempt, or an install that
ended with a red health check), **do not remove anything**. Run the installer
with `--force`: it keeps the existing secrets and certificates, re-uses the
running containers, and completes whatever the earlier run left unfinished.

> **Bundle v1.1.0 only:** its installer wrongly treated its *own* running
> containers as "port 80 is already in use" under `--force`. If you see that
> message and `docker ps` shows only `sentinel-*` containers on those ports, stop
> the stack gracefully and re-run:
> ```bash
> docker compose -p sentinel -f /opt/sentinel/current/compose.prod.yml down
> ```
> **Never add `-v` to that command, and never run `docker volume rm` or
> `docker volume prune`.** Containers are disposable; the **volumes are the
> WAF** — configuration database, admin password, certificates, event history.
> `docker rm -f` on containers is survivable (the first operator did it and lost
> nothing); anything that touches volumes is not. Fixed in the next bundle.

To move to a **newer version**, use `./upgrade.sh` from the new bundle, not
`install.sh`. To remove the WAF completely, `./uninstall.sh` (keeps data) or
`./uninstall.sh --purge` (destroys it — it asks you to type DESTROY).

## 7. Run the installer

```bash
sudo ./install.sh --dry-run                      # every check, changes nothing
sudo ./install.sh --console-bind <vm-ip>         # the real install
```

`--console-bind <vm-ip>` puts the management console on the VM's **private**
address so you can open it from the management network. Without it the console
is on `127.0.0.1` only and you reach it through an SSH tunnel. Public and
wildcard addresses are refused — there is no override.

You are asked three things; **Enter accepts the default** for each:

1. Hostname clients will use — defaults to the VM's IP
2. Administrator email
3. Shared egress addresses — leave blank unless your users reach the WAF through
   one corporate NAT/VPN address (then list it, so one person's scan cannot get
   the whole office blocked)

Then choose **1** for topology (standalone).

The installer runs **11 steps**: package integrity, OS, hardware (and it tells
you which tier the host is — minimum / recommended / production), prerequisites,
configuration, images, secrets, internal certificates, host (Docker at boot,
live-restore, kernel network profile), start, health checks.

**Docker:** you do not install it. If the VM has no Docker, Step 4 installs
Docker Engine from the packages inside the offline bundle — no network needed.
(The first install pre-dated this and needed a manual Docker install; that step
is gone.)

## 8. Save the bootstrap credentials immediately

On success the installer prints:

```
Username   <the Administrator email you gave the installer>
Password   <generated>
```

Save the password somewhere secure **now** — a password manager, not a chat
message. It is also stored on the VM, so it can be recovered:

```bash
sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env
```

`/opt/sentinel/current/.env` holds every secret of the deployment (mode 0600).
Back it up. Lose it, with no backup and no SMTP configured, and there is no way
back into the console.

## 9. Sign in once, change the password, enable MFA

From the management network: `https://<vm-ip>:9443` (the browser warns about the
certificate — it is self-signed until a real one is uploaded; expected).

1. Sign in with the bootstrap credentials.
2. **Change the password** — account menu → Change password.
3. **Enable MFA** on the admin account — Settings → Users.
4. Fill in the SMTP block in `/opt/sentinel/current/.env` so password recovery
   works, then `docker compose -p sentinel -f /opt/sentinel/current/compose.prod.yml up -d controlplane`.

> **Security:** port **9443 stays on the management network.** Never forward it
> through a NAT or perimeter firewall alongside 80/443.

## 10. Verify, then add the first site

```bash
sudo /opt/sentinel/current/scripts/verify.sh       # everything PASS
cat /opt/sentinel/install-report.txt               # host, sizing, every check of that run
```

Until a protected site exists **the WAF answers 502 to everything** — correct,
because there is no upstream yet. Not a fault.

Add the first site in **LEARNING mode**: it records what it *would* have blocked
without blocking anything, because nobody has measured the false-positive rate
against *your* traffic yet. For a real application follow
[SITE-ONBOARDING.md](SITE-ONBOARDING.md) — what to ask the application owner,
certificate, DNS cutover, and the gate before switching to blocking. After a
full business cycle, measure before you switch:

```bash
/opt/sentinel/current/scripts/fpr-report.sh 168
```

## Reference

| Item | Location |
|---|---|
| Config — all secrets, back this up | `/opt/sentinel/current/.env` |
| Install report | `/opt/sentinel/install-report.txt` |
| Install log | `/var/log/sentinel/install.log` |
| Verify | `/opt/sentinel/current/scripts/verify.sh` |
| Backup | `/opt/sentinel/current/scripts/backup/backup.sh` |
| Upgrade / rollback / uninstall | `upgrade.sh`, `rollback.sh`, `uninstall.sh` in the bundle directory |
| Site onboarding | [SITE-ONBOARDING.md](SITE-ONBOARDING.md) |
| Day-to-day operation | [ADMIN-GUIDE.md](ADMIN-GUIDE.md) |
| Something broken | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |

**Publishing to the internet:** forward **only** tcp/80 and tcp/443 (and udp/443
for HTTP/3) to the VM. Never forward 9443 (console) or 22 (SSH). Never use a
1:1 / full NAT. Port 80 must stay open permanently — Let's Encrypt renewals are
proven on it. Every site on the node answers to its own Host header the moment
the forward opens, so read SITE-ONBOARDING.md before adding a second site to a
public node.
