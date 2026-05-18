# Sentinel WAF — Terminal Command Reference

> All commands run from the **repo root** (`/home/ayush3750/waf-development`) unless noted.

---

## Table of Contents

- [1. Infrastructure (Docker)](#1-infrastructure-docker)
- [2. Control Plane (Go)](#2-control-plane-go)
- [3. Data Plane — WAF Proxy (Rust)](#3-data-plane--waf-proxy-rust)
- [4. Dashboard (Next.js)](#4-dashboard-nextjs)
- [5. Lab Targets — DVWA & Juice Shop](#5-lab-targets--dvwa--juice-shop)
- [6. sentinelctl CLI](#6-sentinelctl-cli)
- [7. Full Dev Stack — Quick Start (5 Terminals)](#7-full-dev-stack--quick-start-5-terminals)
- [8. Build Commands](#8-build-commands)
- [9. Test & Lint](#9-test--lint)
- [10. Nuclear Reset](#10-nuclear-reset)

---

## 1. Infrastructure (Docker)

Start/stop backing services: **Postgres, Redis, ClickHouse, MinIO, OpenTelemetry, Jaeger**.

```bash
# Start all infra
./scripts/dev/up.sh

# Stop (keep data)
./scripts/dev/down.sh

# Stop + wipe all data
./scripts/dev/down.sh -v
```

| Service            | Address                                         |
|--------------------|-------------------------------------------------|
| Postgres           | `localhost:5432` — user `sentinel` / `sentinel_dev` |
| Redis              | `localhost:6379`                                |
| ClickHouse HTTP    | `localhost:8123`                                |
| ClickHouse native  | `localhost:9000`                                |
| MinIO console      | `http://localhost:9001`                         |
| Jaeger UI          | `http://localhost:16686`                        |

---

## 2. Control Plane (Go)

REST API + gRPC — listens on `:9501`. Streams live logs via SSE to the dashboard.

```bash
# Start (auto hot-reload with air if installed, else go run)
./scripts/dev/run-controlplane.sh

# Or plain go run
cd control-plane && go run ./cmd/controllerd

# Stop
pkill -f controllerd
kill $(lsof -ti :9501)
```

**Login credentials (dev)**

| Field    | Value                    |
|----------|--------------------------|
| Email    | `admin@sentinel.local`   |
| Password | `admin123`               |
| API URL  | `http://localhost:9501`  |

---

## 3. Data Plane — WAF Proxy (Rust)

Reverse proxy with full WAF pipeline. Routes traffic by `Host` header.
Writes real NDJSON logs to `/tmp/sentinel-logs/` → picked up live by the dashboard.

**Proxy listen port: `9080`**

| Host header    | Upstream              | App            |
|----------------|-----------------------|----------------|
| `dvwa.local`   | `127.0.0.1:9095`      | DVWA           |
| `juice.local`  | `127.0.0.1:3000`      | OWASP Juice Shop |

```bash
# Start (recommended — sets all env vars + creates log dir)
./scripts/dev/run-dataplane.sh

# Or plain cargo run
SENTINEL_LOG_DIR=/tmp/sentinel-logs \
SENTINEL_CONFIG=configs/dev/sentinel.yaml \
RUST_LOG=info,sentinel=debug \
cargo run --bin sentinel-bin

# Stop
pkill -f sentinel-bin
kill $(lsof -ti :9080)
```

**Required `/etc/hosts` entries** (add once, for browser access):

```bash
sudo sh -c 'echo "127.0.0.1  dvwa.local" >> /etc/hosts'
sudo sh -c 'echo "127.0.0.1  juice.local" >> /etc/hosts'
```

**Test the proxy is working:**

```bash
# Should return DVWA homepage (proxied through WAF)
curl -s -o /dev/null -w "%{http_code}" -H "Host: dvwa.local" http://localhost:9080/

# Should return Juice Shop homepage
curl -s -o /dev/null -w "%{http_code}" -H "Host: juice.local" http://localhost:9080/
```

**Live log files** (tailed by control-plane → streamed to dashboard):

```bash
tail -f /tmp/sentinel-logs/access.log   # all requests
tail -f /tmp/sentinel-logs/waf.log      # blocked / rule matches
tail -f /tmp/sentinel-logs/error.log    # proxy errors
tail -f /tmp/sentinel-logs/modsec.log   # CRS/ModSec events
tail -f /tmp/sentinel-logs/ml.log       # ML engine verdicts
tail -f /tmp/sentinel-logs/audit.log    # admin audit trail
```

---

## 4. Dashboard (Next.js)

UI at **`http://localhost:2222`** — proxies API calls to control plane at `:9501`.

> ⚠️ Always use **production mode**. `next dev` uses 3.4 GB RAM and crashes on reload. Production uses **96 MB** with instant response.

```bash
# Step 1 — build (only needed after code changes)
cd /home/ayush3750/waf-development/dashboard
NEXT_PUBLIC_CONTROL_PLANE_URL=http://localhost:9501 npm run build

# Step 2 — start
NEXT_PUBLIC_CONTROL_PLANE_URL=http://localhost:9501 PORT=2222 npm start

# Stop
pkill -f "next-server"
fuser -k 2222/tcp
```

| Mode         | RAM    | Reload    |
|--------------|--------|-----------|
| `next dev`   | 3.4 GB | 30s recompile |
| `next start` | 96 MB  | Instant   |

---

## 5. Lab Targets — DVWA & Juice Shop

These apps are the **upstream targets** the WAF protects. Start them before the data plane.

### DVWA (Damn Vulnerable Web Application)

> **Port note:** The WAF takes over port 9095 as a transparent listener.
> DVWA must run on the internal port **9096** (`:9096 → container :80`).

```bash
# Start DVWA via Docker on port 9096 (WAF owns 9095)
docker run -d --name dvwa \
  -p 9096:80 \
  vulnerables/web-dvwa

# Verify DVWA is up (internal port)
curl -s -o /dev/null -w "%{http_code}" http://localhost:9096/
# Expected: 200 or 302

# Access DVWA THROUGH the WAF on the original port (transparent, no Host header)
curl -s -o /dev/null -w "%{http_code}" http://localhost:9095/
# Expected: 200 or 302 (proxied through WAF)

# Stop
docker stop dvwa && docker rm dvwa
```

### OWASP Juice Shop

> **Port note:** The WAF takes over port 3000 as a transparent listener.
> Juice Shop must run on the internal port **3001** (`:3001 → container :3000`).

```bash
# Start Juice Shop via Docker on port 3001 (WAF owns 3000)
docker run -d --name juiceshop \
  -p 3001:3000 \
  bkimminich/juice-shop

# Verify Juice Shop is up (internal port)
curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/
# Expected: 200

# Access Juice Shop THROUGH the WAF on the original port (transparent)
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/
# Expected: 200 (proxied through WAF)

# Stop
docker stop juiceshop && docker rm juiceshop
```

### Access through the WAF

```bash
# Transparent port-based access (no Host header needed — like BunkerWeb):
#   http://localhost:9095   → DVWA through WAF
#   http://localhost:3000   → Juice Shop through WAF

# In browser (just use the original ports — WAF is invisible):
#   http://localhost:9095
#   http://localhost:3000

# OR — Host-header routing via shared port :9080 (for curl/sentinelctl):
curl -H "Host: dvwa.local" http://localhost:9080/
curl -H "Host: juice.local" http://localhost:9080/

# /etc/hosts entries for browser access via Host-header port:
#   http://dvwa.local:9080
#   http://juice.local:9080
```

---

## 6. sentinelctl CLI

Operator CLI for managing the WAF from the terminal.
Binary: `/home/ayush3750/waf-development/sentinelctl`

```bash
# Add to PATH for convenience
export PATH="$PATH:/home/ayush3750/waf-development"
```

### Authentication

```bash
sentinelctl login --email admin@sentinel.local --password admin123
sentinelctl logout
```

### Sites

```bash
sentinelctl sites list
```

### Rules

```bash
sentinelctl rules list
```

### Alerts

```bash
sentinelctl alerts list
sentinelctl alerts list --state active
sentinelctl alerts ack <alert-id>
sentinelctl alerts resolve <alert-id>
```

### Audit Log

```bash
sentinelctl audit list
sentinelctl audit list --limit 100
```

### Live Stats

```bash
sentinelctl stats
```

### OWASP Attack Test Suite ⚡

Fires **25 real attack payloads** through the WAF proxy and shows what got blocked vs passed.
Results appear **live on the dashboard** logs page.

```bash
# Test against DVWA (default)
sentinelctl test --site dvwa

# Test against Juice Shop
sentinelctl test --site juice

# Custom target and host
sentinelctl test --target http://localhost:9080 --host dvwa.local

# Slow down requests (default 120ms between each)
sentinelctl test --site dvwa --delay 500

# Custom API endpoint
SENTINEL_URL=http://localhost:9501 sentinelctl test --site dvwa
```

**Attack categories tested:**

| Category | Examples                                          |
|----------|---------------------------------------------------|
| SQLI     | Classic OR, UNION SELECT, blind time, stacked     |
| XSS      | Reflected, stored, DOM-based                      |
| LFI      | `/etc/passwd`, null byte, directory traversal     |
| CMDI     | Semicolon, backtick, `$(...)` substitution        |
| RCE      | Log4Shell JNDI via header + User-Agent            |
| SSRF     | localhost, AWS metadata, internal IP              |
| XXE      | XML external entity file read                     |
| NoSQLi   | `$gt` operator, prototype pollution               |
| SCANNER  | sqlmap, Nikto user-agent detection                |
| RFI      | Remote file include via HTTP URL                  |

**Expected results when WAF is blocking correctly:**

```
 SENTINEL WAF — OWASP Attack Test Suite
Target: http://localhost:9080   Host: dvwa.local

TEST                         CATEGORY   CODE   VERDICT    RULE
────────────────────────────────────────────────────────────────────────────────
SQLi classic                 SQLI       403    BLOCKED    CRS-942100
SQLi UNION                   SQLI       403    BLOCKED    CRS-942200
XSS reflected                XSS        403    BLOCKED    CRS-941100
LFI /etc/passwd              LFI        403    BLOCKED    CRS-930100
Log4Shell JNDI               RCE        403    BLOCKED    VP-CVE-2021-44228
...

Results:  Total: 25  |  Blocked: 22 (88%)  |  Passed: 3  |  Errors: 0

✓ WAF protection is STRONG — 88% of OWASP attacks blocked
```

---

## 7. Full Dev Stack — Quick Start (3 Terminals)

The WAF proxy **starts automatically** when the control plane starts — no separate command needed.

Open **3 terminal windows** and run one command per terminal in this order:

```bash
# ── Terminal 1 — Lab Targets (DVWA + Juice Shop) ──────────────────────────
# NOTE: ports 9096 and 3001 — the WAF transparently owns 9095 and 3000
docker start dvwa juiceshop 2>/dev/null || \
  (docker run -d --name dvwa -p 9096:80 vulnerables/web-dvwa && \
   docker run -d --name juiceshop -p 3001:3000 bkimminich/juice-shop)
# Wait ~10s for containers to be ready
```

```bash
# ── Terminal 2 — Control Plane + WAF Proxy (auto-starts together) ─────────
cd /home/ayush3750/waf-development
./scripts/dev/run-controlplane.sh
# This starts:  REST API :9501  +  WAF Proxy :9080  (auto-managed)
# If proxy binary not built yet → runs simulator mode (demo data)
# To build proxy:  cargo build -p sentinel-bin
```

```bash
# ── Terminal 3 — Dashboard (Next.js on :2222) ──────────────────────────────
cd /home/ayush3750/waf-development/dashboard
NEXT_PUBLIC_CONTROL_PLANE_URL=http://localhost:9501 PORT=2222 npm start
```

**All services running — URLs:**

| Service                      | URL                             | Notes                        |
|------------------------------|---------------------------------|------------------------------|
| Dashboard                    | `http://localhost:2222`         | Login: `admin@sentinel.local` / `admin123` |
| DVWA via WAF (transparent)   | `http://localhost:9095`         | No Host header needed        |
| Juice Shop via WAF (transparent) | `http://localhost:3000`     | No Host header needed        |
| WAF shared proxy             | `http://localhost:9080`         | Send `Host:` header to route |
| DVWA via WAF (Host header)   | `http://dvwa.local:9080`        | Requires `/etc/hosts` entry  |
| Juice Shop via WAF (Host header) | `http://juice.local:9080`   | Requires `/etc/hosts` entry  |
| Control Plane API            | `http://localhost:9501/api/v1/` |                              |
| Jaeger tracing               | `http://localhost:16686`        |                              |
| MinIO console                | `http://localhost:9001`         |                              |

**Then fire attacks and watch them appear on the dashboard:**

```bash
# From any terminal
cd /home/ayush3750/waf-development
sentinelctl login --email admin@sentinel.local --password admin123
sentinelctl test --site dvwa
sentinelctl test --site juice
```

---

## 8. Build Commands

### Rust (data plane + all crates)

```bash
cargo build                            # debug — fast
cargo build --release                  # release — optimised
cargo build -p sentinel-proxy          # single crate
cargo build --workspace                # all crates
```

### Go (control plane + sentinelctl)

```bash
# Control plane
cd control-plane
go build -o bin/controllerd ./cmd/controllerd

# sentinelctl CLI
cd control-plane
go build -o ../sentinelctl ./cmd/sentinelctl
```

### Dashboard

```bash
cd dashboard
NEXT_PUBLIC_CONTROL_PLANE_URL=http://localhost:9501 npm run build
```

---

## 9. Test & Lint

### Rust

```bash
cargo test --workspace                 # all 226 tests
cargo test -p sentinel-proxy           # single crate
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Go

```bash
cd control-plane
go test ./...                          # 18 tests
go vet ./...
```

### Dashboard

```bash
cd dashboard
npm run lint
npm run typecheck
```

### WAF end-to-end (requires data plane running)

```bash
sentinelctl test --site dvwa           # 25 OWASP attack cases
sentinelctl test --site juice          # same against Juice Shop
```

---

## 10. Nuclear Reset

Wipes everything — Docker volumes, Rust build artefacts, Node modules, log files.

```bash
docker system prune -af
cargo clean
rm -rf control-plane/bin
rm -rf dashboard/.next dashboard/node_modules
rm -f /tmp/sentinel-logs/*.log
```

Then restart from [Section 7](#7-full-dev-stack--quick-start-5-terminals).
