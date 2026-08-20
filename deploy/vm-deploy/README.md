# Deploy ESDSWAF on a VM — download and install

Everything needed to get the WAF running on a fresh VM. No source code, no
compiler, no build machine.

> ### 👉 First time? Read [**INSTALL-WALKTHROUGH.md**](INSTALL-WALKTHROUGH.md)
>
> A complete step-by-step guide — empty VM to a WAF blocking a real attack, with
> every command spelled out and no prior knowledge of this product assumed. It was
> written by following it on a real machine, so its troubleshooting section lists
> problems that actually happen rather than ones that might.
>
> This page is the condensed reference for people who have done it before.

## Download

**In a browser** (easiest — no token needed once you are logged into GitLab):

> **https://git.enlight.dev/research-lab/SIG-CyberSec/sentinel-waf/-/packages**

Or in the left sidebar of the project: **Deploy → Package Registry → esdswaf**.

**On the VM itself**, with the helper script in this folder:

```bash
export GITLAB_TOKEN=glpat-xxxxxxxxxxxx     # read_api scope is enough
./get-esdswaf.sh --online                   # 99 MB, one file — if the VM has Docker Hub
./get-esdswaf.sh                            # 584 MB offline bundle (script default)
```

It downloads, reassembles any parts, verifies the checksum, and extracts — then
tells you the next command. It does not need root and installs nothing.

> **Use `--online` when the VM can reach Docker Hub.** The script still defaults to
> the offline bundle, which was the right default when the online one was 248 MB and
> the difference was marginal. At 99 MB in a single file it usually is not: prefer
> `--online` unless the VM is on a closed network. See the check below.

## Which bundle?

| Bundle | Size | Files | What the VM must reach |
|---|---|---|---|
| **`-registry`** | **316 KB** | **one** | `hub.enlight.dev` only. Ships no images — the installer pulls all ten from Harbor |
| `-online` | 99 MB | one | Docker Hub. Ships our four; the other six are pulled |
| `-offline` | 584 MB | 3 parts | nothing. All ten images are inside |

**Pick by what the VM can reach, not by preference:**

```bash
curl -sS -o /dev/null -w 'harbor:     %{http_code}\n' https://hub.enlight.dev/v2/
curl -sS -o /dev/null -w 'dockerhub:  %{http_code}\n' https://registry-1.docker.io/v2/
```

`401` means reachable — a registry's normal unauthenticated answer. A timeout or
`000` means blocked.

**Prefer `-registry` for anything ESDS-internal.** No credentials are needed: the
Harbor project is readable inside the ESDS network. Verified by installing on a VM
with Docker Hub blackholed — all eight containers came from Harbor and the result
was indistinguishable from a tarball install.

**`-offline` is the one that travels.** A customer datacentre cannot reach Harbor
whether or not it has internet, because Harbor is on `172.16.23.2` — an internal
address that does not route from outside ESDS. That is a structural fact about the
network, not an "air-gapped edge case", and it is why the offline bundle is not
going away.

The installer reads which variant it is from the package manifest, so you cannot
use the wrong one by accident — it aborts in preflight with a clear message rather
than failing halfway through.

> **These sizes used to be 248 MB and 733 MB in four parts.** The dashboard image
> accounted for 779 MB of the images, almost entirely build tooling (TypeScript,
> ESLint, Tailwind, the webpack cache) that never runs in production. A traced
> standalone build took it to 157 MB, which brought the online bundle under this
> GitLab's ~250 MB upload cap so it became a single file. Registry mode then
> removed the images from the download altogether.
>
> The offline bundle still needs splitting: most of it is the six third-party
> images (ClickHouse, Grafana, Postgres, Prometheus, Redis, HAProxy), which we do
> not build and cannot shrink. `get-esdswaf.sh` reassembles the parts
> automatically; by hand it is one `cat`, and the checksum proves the join is
> lossless.

## Install

```bash
cd ESDSWAF-v1.0.2
sudo ./install.sh --dry-run     # every check, changes nothing
sudo ./install.sh               # ~6 minutes
sudo ./verify.sh                # proves the result
sudo ./first-site.sh            # guided: first protected site, attack proven blocked
```

Full instructions ship inside the bundle:

- `docs/STANDALONE.md` — one VM
- `docs/ACTIVE-PASSIVE.md` — two VMs, virtual IP, automatic traffic failover

## Requirements

| | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS (RHEL/Rocky/Alma not supported) |
| CPU | 4 vCPU (8 recommended) |
| RAM | **16 GB — hard requirement.** A 16 GB VM reports as 15 GB; the floor is 15 |
| Disk | **100 GB free on `/opt`** — measured on `/opt`, not `/`. Ask for 110 GB |
| Docker | Engine 27+ with the `docker compose` plugin (v2 or newer — v5.x is current and fine) |
| Ports | 80, 443, 9443 free |

`--dry-run` checks every one of these in about ten seconds without touching the
host. Run it first.

## Two things that are not faults

**`https://<vm-ip>:9443` will not connect.** The management console is bound to
loopback deliberately — it is an admin UI for a security appliance, and on
`0.0.0.0` it would be exposed to the whole network. Reach it with a tunnel:

```bash
ssh -L 9443:127.0.0.1:9443 root@<vm-ip>     # then open https://127.0.0.1:9443
```

**The WAF returns 502 to everything until you add a site.** Correct — there is no
upstream to forward to yet.

## The admin password cannot be changed — back it up

There is no password-change screen and no reset endpoint in this build. The password
the installer prints is the only way into the console for the life of the
installation. It is written to the deployment's secrets file, so it survives
restarts, upgrades and rollbacks:

```bash
sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD /opt/sentinel/current/.env
```

**Back that file up off the VM.** It holds every secret for the deployment, and
losing it means rebuilding the installation. Create a second administrator
(Settings → Team Members → Add User) as your only redundancy.

---

## Manual download (no script)

Every file is at the same base URL:

```
https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.2/
```

Online bundle:

```bash
TOKEN=glpat-xxxxxxxxxxxx
BASE=https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.2

curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-online.tar.gz
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-online.tar.gz.sha256
sha256sum -c ESDSWAF-v1.0.2-online.tar.gz.sha256      # must print OK
tar -xzf ESDSWAF-v1.0.2-online.tar.gz
```

Offline bundle (three parts at v1.0.2, reassembled with `cat`). **Check the package
registry for the actual part count before copying this** — it follows the archive
size, so a future release may have more or fewer:

```bash
for i in 00 01 02; do
  curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-offline.tar.gz.part-$i
done
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.2-offline.tar.gz.sha256

cat ESDSWAF-v1.0.2-offline.tar.gz.part-* > ESDSWAF-v1.0.2-offline.tar.gz
sha256sum -c ESDSWAF-v1.0.2-offline.tar.gz.sha256     # must print OK
tar -xzf ESDSWAF-v1.0.2-offline.tar.gz
```

**If `sha256sum -c` does not print `OK`, stop.** The transfer was truncated or the
file was altered. Delete it and download again; do not install it.

## Publishing a new version (ESDS staff)

```bash
# 1. Build
BUNDLE_THIRD_PARTY=1 ./deploy/package/build-bundle.sh 1.0.2   # offline
./deploy/package/build-bundle.sh 1.0.2                        # online

# 2. Split the offline one — this GitLab rejects uploads over ~250 MB
cd dist
split -b 240M -d -a 2 ESDSWAF-v1.0.2-offline.tar.gz ESDSWAF-v1.0.2-offline.tar.gz.part-

# 3. Upload every file
TOKEN=glpat-xxxxxxxxxxxx
BASE=https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.2
for f in ESDSWAF-v1.0.2-online.tar.gz \
         ESDSWAF-v1.0.2-*.sha256 \
         ESDSWAF-v1.0.2-offline.tar.gz.part-*; do
  curl --header "PRIVATE-TOKEN: $TOKEN" --upload-file "$f" "$BASE/$f"
done
```

Generate the `.sha256` files from **inside** `dist/` so they record a bare
filename — otherwise `sha256sum -c` fails on the customer's machine looking for a
`dist/` directory that does not exist there.

Raising the GitLab upload limit (`client_max_body_size` in the instance's nginx)
would remove the need to split; that needs a GitLab administrator.
