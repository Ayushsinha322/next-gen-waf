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
./get-esdswaf.sh                            # offline bundle (default)
./get-esdswaf.sh --online                   # smaller, needs Docker Hub
```

It downloads, reassembles the parts, verifies the checksum, and extracts — then
tells you the next command. It does not need root and installs nothing.

## Which bundle?

| Bundle | Size | Needs internet on the VM? |
|---|---|---|
| **`-offline`** | 733 MB (4 parts) | **No.** All ten container images are inside |
| `-online` | 248 MB | **Yes.** Five images are pulled from Docker Hub during install |

If in doubt use **offline**. A management-network VM usually has no outbound
internet, and the online bundle can only abort in preflight there. The installer
reads which variant it is from the bundle manifest, so you cannot use the wrong
one by accident — it fails early and clearly rather than halfway through.

> **Why is the offline bundle in parts?** This GitLab rejects uploads above ~250 MB
> (`413 Request Entity Too Large`), so it is published as 240 MB pieces. The helper
> script reassembles them automatically. Doing it by hand is one command — see
> below. The reassembled file is byte-identical; the checksum proves it.

## Install

```bash
cd ESDSWAF-v1.0.0
sudo ./install.sh --dry-run     # checks the host, changes nothing
sudo ./install.sh               # ~10 minutes
```

Full instructions ship inside the bundle:

- `docs/STANDALONE.md` — one VM
- `docs/ACTIVE-PASSIVE.md` — two VMs, virtual IP, automatic traffic failover

## Requirements

| | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS or 24.04 LTS (RHEL/Rocky/Alma not supported) |
| CPU | 4 vCPU (8 recommended) |
| RAM | **16 GB — hard requirement**, the installer refuses below ~15 GB |
| Disk | 100 GB free on `/opt` |
| Docker | Engine 27+ with the Compose v2 plugin |
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

The admin password is printed once at the end of the install. If you missed it:

```bash
docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'
```

---

## Manual download (no script)

Every file is at the same base URL:

```
https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.0/
```

Online bundle:

```bash
TOKEN=glpat-xxxxxxxxxxxx
BASE=https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.0

curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.0-online.tar.gz
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.0-online.tar.gz.sha256
sha256sum -c ESDSWAF-v1.0.0-online.tar.gz.sha256      # must print OK
tar -xzf ESDSWAF-v1.0.0-online.tar.gz
```

Offline bundle (four parts, reassembled with `cat`):

```bash
for i in 00 01 02 03; do
  curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.0-offline.tar.gz.part-$i
done
curl -fL -H "PRIVATE-TOKEN: $TOKEN" -O $BASE/ESDSWAF-v1.0.0-offline.tar.gz.sha256

cat ESDSWAF-v1.0.0-offline.tar.gz.part-* > ESDSWAF-v1.0.0-offline.tar.gz
sha256sum -c ESDSWAF-v1.0.0-offline.tar.gz.sha256     # must print OK
tar -xzf ESDSWAF-v1.0.0-offline.tar.gz
```

**If `sha256sum -c` does not print `OK`, stop.** The transfer was truncated or the
file was altered. Delete it and download again; do not install it.

## Publishing a new version (ESDS staff)

```bash
# 1. Build
BUNDLE_THIRD_PARTY=1 ./deploy/package/build-bundle.sh 1.0.1   # offline
./deploy/package/build-bundle.sh 1.0.1                        # online

# 2. Split the offline one — this GitLab rejects uploads over ~250 MB
cd dist
split -b 240M -d -a 2 ESDSWAF-v1.0.1-offline.tar.gz ESDSWAF-v1.0.1-offline.tar.gz.part-

# 3. Upload every file
TOKEN=glpat-xxxxxxxxxxxx
BASE=https://git.enlight.dev/api/v4/projects/1301/packages/generic/esdswaf/1.0.1
for f in ESDSWAF-v1.0.1-online.tar.gz \
         ESDSWAF-v1.0.1-*.sha256 \
         ESDSWAF-v1.0.1-offline.tar.gz.part-*; do
  curl --header "PRIVATE-TOKEN: $TOKEN" --upload-file "$f" "$BASE/$f"
done
```

Generate the `.sha256` files from **inside** `dist/` so they record a bare
filename — otherwise `sha256sum -c` fails on the customer's machine looking for a
`dist/` directory that does not exist there.

Raising the GitLab upload limit (`client_max_body_size` in the instance's nginx)
would remove the need to split; that needs a GitLab administrator.
