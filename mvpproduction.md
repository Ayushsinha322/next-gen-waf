# Sentinel WAF — MVP / Production Deployment Record

> Living record of the first real Sentinel WAF deployment. Purpose: MVP + demo
> (clients / CEO) + internal use. Endgame: 7-VM **Kubernetes** in production —
> so we deploy with **Docker images** now (the same artifacts K8s will run later).
>
> Started: 2026-06-26. Owner: Ayush Sinha (ESDS).

---

## 1. Target VM

| | |
|---|---|
| **Host** | `172.16.21.71` (internal ESDS network, ~134 ms latency, KVM guest) |
| **OS** | Ubuntu 24.04.2 LTS (noble), x86_64, kernel 6.8, **glibc 2.39** |
| **Specs** | 8 vCPU · 17 GiB RAM · 297 GB disk (281 GB free) |
| **Access** | `root` via SSH key `~/.ssh/sentinel_deploy` (installed 2026-06-26) |
| **Runtime** | Docker 29.6.0 + Compose v5.2.0 (installed via get.docker.com), overlayfs, cgroup v2 |

> ⚠️ The root **password** was provided once for `ssh-copy-id` — **rotate it**. Key auth is set up, so password login is no longer needed.

SSH in:
```bash
ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71
```

---

## 2. Why Docker (not the systemd/Ansible path)

Both deploy paths exist in the repo. We chose **Docker** because:

1. **K8s on-ramp** — production will be 7-VM Kubernetes; the container images we build here are exactly what K8s pods pull. The systemd/Ansible path (`sentinel deploy`) would be throwaway work.
2. **Reproducible & reliable** for a CEO/client demo — the image that builds is the image that runs; no glibc / `node_modules` portability surprises.
3. **1 Gbps** capacity is a data-plane (Rust proxy) concern, independent of packaging; horizontal scale is the K8s story.

Glibc check that informed this: build host is Debian 13 / glibc **2.41**, VM is **2.39**. The prebuilt `target/release/sentinel-bin` only needs ≤ GLIBC_2.38 and links just libc/libgcc/libm (rustls, no OpenSSL), so it runs on the VM. In Docker we still rebuild in a **bookworm (glibc 2.36) builder** matched to the `distroless/cc-debian12` runtime, eliminating the concern entirely.

---

## 3. Deploy artifacts created (all under `deploy/docker/`)

| File | What it is |
|------|-----------|
| `compose.prod.yml` | **Lean production compose** — 6 services (see topology). New file; `compose.full.yml` left untouched. |
| `Dockerfile` | **Rewritten.** Rust builder pinned to `rust:1.85-slim-bookworm` (glibc-matched), Go control plane built static (`CGO_ENABLED=0`) on `golang:1.24-alpine`, CRS rules baked into the data-plane image, `SENTINEL_*` env defaults set. |
| `sentinel.proxy.yaml` | Data-plane config: HTTP listener `:8080`, `sync_url → http://controlplane:9501`, `sites: []` (control plane is authoritative and hot-syncs sites). |
| `.env` | **Generated secrets** (gitignored, `chmod 600`): `POSTGRES_*`, `SENTINEL_DB_URL`, `SENTINEL_JWT_SECRET` (64-byte). Must be present on the VM for compose interpolation. |
| `dashboard/.dockerignore` | **New.** Excludes `node_modules`, `.next`, `.env*` so the image build is clean and doesn't leak `.env.local`. |

### Why these fixes were needed (bugs found in the original paths)
- `compose.full.yml` mounted `configs/examples/sentinel.yaml`, which requires gRPC+mTLS PKI certs and TLS server certs **that don't exist** → the proxy would fail to start. Our `sentinel.proxy.yaml` uses the simple HTTP `sync_url` polling path instead.
- Original dashboard wiring set `NEXT_PUBLIC_API_URL=http://controlplane:8443` (browser-unreachable). The dashboard calls **relative** `/api/v1` paths proxied server-side by Next.js rewrites to the control plane. **Gotcha:** Next.js evaluates `rewrites()` at **build** time and bakes the destination into `routes-manifest.json` — a runtime env var is ignored. So the dashboard image must be built with `--build-arg NEXT_PUBLIC_CONTROL_PLANE_URL=http://controlplane:9501` (wired in `compose.prod.yml` `build.args` + a matching `ARG` in `Dockerfile.dashboard`). Symptom if missing: proxied login returns **500** (rewrite points at `localhost:9501` inside the dashboard container).
- `compose.full` pulled ClickHouse + MinIO (heavy, optional) — dropped for the MVP. Threat-search/log-analytics features that depend on ClickHouse are degraded until we add it back.
- **Shared log volume** (`sentinel-logs`) mounted on both control plane and data plane at `/var/log/sentinel` — the proxy writes NDJSON access logs there and the control-plane hub reads them to stream live dashboard panels (Recent events / Logs / Top IPs). Without it those panels stay empty.
- **Live log stream (SSE) blank** — the dashboard opens the SSE `EventSource` **directly** to the control plane (the Next.js proxy buffers SSE, so `api.ts` bypasses it using `NEXT_PUBLIC_CONTROL_PLANE_URL`). That URL is **browser-reachable**, not the internal Docker name. Fix: decoupled the two URLs — REST rewrite uses `CONTROL_PLANE_URL=http://controlplane:9501` (internal, `next.config.js` now prefers it), SSE uses `NEXT_PUBLIC_CONTROL_PLANE_URL=http://172.16.21.71:9501` (build arg), and the control-plane port `9501` is published. **Also required — CORS:** the SSE is cross-origin (`:3000` → `:9501`), so the control plane must allow the dashboard origin via env `SENTINEL_CORS_ORIGINS=http://172.16.21.71:3000` (its `DefaultCORS()` only allows localhost). Without it the browser blocks the `EventSource` with no `Access-Control-Allow-Origin` — and **curl still streams, masking the bug** (curl ignores CORS). Symptom if wrong: Logs page stuck on "Connecting to log stream…". ⚠ Exposing `9501` also exposes the unauthed `/api/v1/internal/config` on the internal network — lock down for prod (auth it, or keep the control plane cluster-internal and front SSE via a single non-buffering ingress so everything is same-origin — eliminates the port exposure + CORS entirely; this is the K8s plan).

---

## 4. Service topology (`compose.prod.yml`)

| Service | Image | Host exposure | Notes |
|---------|-------|---------------|-------|
| `postgres` | postgres:16-alpine | internal only | control-plane DB; volume `pgdata` |
| `redis` | redis:7-alpine | internal only | control-plane cache |
| `controlplane` | `sentinel/controlplane` (Go, distroless static) | **`:9501`** (exposed — browser SSE connects here) | REST `:9501`; migrates + seeds DB + admin user on boot |
| `dataplane` | `sentinel/dataplane` (Rust, distroless cc) | **`:80` → container `:8080`** | the WAF; CRS rules baked in; syncs sites from control plane |
| `dashboard` | `sentinel/dashboard` (Next.js) | **`:3000`** | UI; `CONTROL_PLANE_URL=http://controlplane:9501` |
| `juiceshop` | bkimminich/juice-shop | internal only | demo upstream to protect (only reachable *through* the WAF) |

Both app containers run as `user: "0:0"` so they can write the shared log volume (hardened later in K8s via `securityContext`/`fsGroup`).

**Demo URLs:**
- Dashboard → `http://172.16.21.71:3000`
- Protected app (Juice Shop *through* the WAF) → `http://172.16.21.71/`

---

## 5. Build & deploy — reproduce from scratch

### 5a. One-time local prep (build host)
```bash
# SSH key → VM (interactive, once)
ssh-copy-id -i ~/.ssh/sentinel_deploy.pub root@172.16.21.71

# Ansible was installed in a venv earlier for the alt path — NOT needed for Docker.
```

### 5b. Ship source to the VM
```bash
cd /home/ayush3750/waf-development
rsync -az --delete \
  -e "ssh -i ~/.ssh/sentinel_deploy" \
  --exclude 'target/' --exclude '.git/' --exclude '**/node_modules/' \
  --exclude 'dashboard/.next/' --exclude '*.tsbuildinfo' --exclude '.sentinel-deploy/' \
  ./ root@172.16.21.71:/opt/sentinel-src/
```
> `deploy/docker/.env` is NOT excluded — it must ship for compose interpolation.

### 5c. Build images on the VM (~10–20 min, Rust release is the long pole)
```bash
ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71 \
  'cd /opt/sentinel-src/deploy/docker && docker compose -f compose.prod.yml build'
```

### 5d. Bring the stack up
```bash
ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71 \
  'cd /opt/sentinel-src/deploy/docker && docker compose -f compose.prod.yml up -d'
```

### 5d-bis. Apply DB migrations (REQUIRED — the control plane does NOT auto-migrate)
The control plane connects, then `SeedDev` expects the schema to already exist. The
schema lives in **goose** migrations (`control-plane/internal/db/migrations/*.sql`)
that are *not* in the distroless image and are *not* run on startup. Apply the `Up`
sections directly via psql, then restart the control plane so it seeds tenant+admin:
```bash
cd /home/ayush3750/waf-development/control-plane/internal/db/migrations
{ awk '/-- \+goose Up/{u=1;next} /-- \+goose Down/{u=0} u' 0001_init.sql
  awk '/-- \+goose Up/{u=1;next} /-- \+goose Down/{u=0} u' 0002_notifications.sql
} | ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71 \
    'docker exec -i sentinel-postgres-1 psql -U sentinel -d sentinel -v ON_ERROR_STOP=1'
ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71 \
  'cd /opt/sentinel-src/deploy/docker && docker compose -f compose.prod.yml restart controlplane'
```
> ⚠️ Do **not** wrap this in `ssh 'bash -s' <<EOF` — `docker exec -i` would eat the
> heredoc from stdin. Pipe the SQL straight into the remote `docker exec` as above.
>
> **Follow-up (reproducibility / K8s):** make migrations a one-shot `migrate` service
> (`depends_on: service_completed_successfully`) or embed them in the binary
> (`go:embed` + run on boot). In K8s this becomes an initContainer or a Job.

### 5e. Seed the demo site (Juice Shop, blocking + full CRS)
Run **on the VM** (control plane on `127.0.0.1:9501`):
```bash
CP="http://127.0.0.1:9501/api/v1"
TOKEN=$(curl -fsS "$CP/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"admin@sentinel.local","password":"admin123"}' \
  | grep -oP '"access_token":"\K[^"]+')
curl -fsS "$CP/sites" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{
  "name":"Juice Shop",
  "domains":["172.16.21.71","juice","localhost"],
  "upstream":{"load_balancer":"round_robin","servers":[{"host":"juiceshop","port":3000,"weight":1,"tls":false}]},
  "waf_policy":{"mode":"blocking","paranoia_level":2,"anomaly_threshold":5,
    "rule_categories":["sqli","xss","rce","lfi","rfi","php","java","generic","protocol_attack","protocol","method","scanner","session"],
    "allowed_methods":["GET","POST","HEAD","OPTIONS","PUT","PATCH","DELETE"]}
}'
```
(Staged at `…/scratchpad/seed-demo-site.sh`. Alternatively, add the site via the dashboard Site Wizard — also a good live-demo moment.)

---

## 6. Control-plane API reference (used for seeding)

- Base: `/api/v1` (control plane REST on `:9501`)
- `POST /auth/login {email,password}` → `{access_token, user}`  (default: `admin@sentinel.local` / `admin123`)
- `POST /sites {name, domains, upstream, waf_policy}` (Bearer token) — create site
- `GET /sites`, `GET/PUT/DELETE /sites/:id`, `PATCH /sites/:id/status`
- `POST /sites/import {yaml}` — bulk import
- Data-plane site sync: proxy polls `GET {sync_url}/api/v1/internal/config` every `sync_interval_secs` and **replaces** its site list with the control plane's (control plane is authoritative).

---

## 7. Verification checklist
```bash
ssh -i ~/.ssh/sentinel_deploy root@172.16.21.71 '
  cd /opt/sentinel-src/deploy/docker
  docker compose -f compose.prod.yml ps
  curl -fsS http://127.0.0.1:9501/health && echo "  <- control plane OK"
'
# From anywhere that can reach the VM:
curl -s http://172.16.21.71:3000 -o /dev/null -w "dashboard %{http_code}\n"
# -G + --data-urlencode keeps the payload readable AND encodes it. A raw
# "?q=1' OR '1'='1" has an unencoded space → curl sends a bad request line → 000.
curl -s -G "http://172.16.21.71/" --data-urlencode "q=1' OR '1'='1" -o /dev/null -w "SQLi attempt -> %{http_code} (expect 403)\n"
```
> ⚠️ **Repeat-attacker self-flag:** the data-plane correlation engine
> (`CorrelationEngine`, 60s window, escalate at ≥3 blocks) adds a standing
> anomaly penalty (+3, → +8 at ≥9 blocks) to **every** request from an IP that
> was just blocked several times — so after firing a few attacks, *clean* traffic
> from the same IP also 403s. Auto-clears ~60s after the last request from that
> IP, or instantly on `docker compose -f compose.prod.yml restart dataplane`. When
> verifying, run the clean-traffic check before the attacks (or from another host).

---

## 8. Follow-ups (not blockers for the demo)
- [ ] **Rotate the VM root password** (was pasted in plaintext for key setup).
- [ ] **Change `admin123`** dashboard password after first login.
- [x] **TLS** — ✅ DONE. HTTPS on `:443` via the SNI cert resolver. Internal IP (no public domain) rules out Let's Encrypt, so we stood up a **private CA** (*Sentinel WAF Internal Root CA*, on the VM at `/opt/sentinel-pki/`) and issued a **real CA-signed cert for the bare IP** (IP SAN `172.16.21.71`, valid to Oct 2028), staged into the cert repo under the `default` key (served on no-SNI/IP connections). Browsers warn until clients import `root.crt` (then green lock); re-issue with `/opt/sentinel-pki/issue-ip-cert.sh`. Full operator steps in `OPERATIONS.md §9`.
- [ ] **ClickHouse + MinIO** if the demo needs Threat Search / log analytics (add as compose services).
- [ ] **K8s migration** — reuse `sentinel/controlplane`, `sentinel/dataplane`, `sentinel/dashboard` images; translate compose → Deployments/Services; push images to a registry; move secrets to K8s Secrets; harden `securityContext`.

---

## 9. Current status — ✅ LIVE (2026-06-26)
All three images built; all 6 containers up. Verified end-to-end:

| Check | Result |
|-------|--------|
| Control plane `/health` | **200** |
| DB schema + seed | tables created (migrations applied), `admin@sentinel.local` seeded, 6 sites (5 demo + Juice Shop) |
| Data plane site sync | hot-syncs from control plane (HTTP) |
| Dashboard `http://172.16.21.71:3000` | **307** → login (loads) |
| Proxied login `POST /api/v1/auth/login` | **200** + JWT (after dashboard build-arg fix) |
| WAF benign `GET http://172.16.21.71/` | **200** (Juice Shop via proxy) |
| WAF SQLi / XSS / path-traversal | **403 blocked** |
| HTTPS `GET https://172.16.21.71/` (trust via our root, no `-k`) | **200** — cert chain verifies (return code 0) |
| HTTPS SQLi | **403 blocked** over TLS |

**Access:** dashboard `http://172.16.21.71:3000` · login `admin@sentinel.local` / `Admin@123#` · protected app `http://172.16.21.71/` or `https://172.16.21.71/`.

Follow-ups done since: VM root password rotated, admin password changed to `Admin@123#`, TLS live with a real internal-CA cert (§8). Remaining: ClickHouse/MinIO (if Threat Search needed), migrations-as-code, K8s migration.
