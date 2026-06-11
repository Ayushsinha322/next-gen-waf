# Sentinel WAF — Master Reference

> The definitive guide. After reading this, you can answer ANY question about
> this WAF — from network engineers, SWEs, DevOps, security engineers, or CTOs.

---

## Table of Contents

1. [Architecture at 10,000 feet](#1-architecture-at-10000-feet)
2. [Every Binary and Tool](#2-every-binary-and-tool)
3. [The 7-Phase Request Lifecycle (Deep)](#3-the-7-phase-request-lifecycle)
4. [All REST API Endpoints](#4-all-rest-api-endpoints)
5. [Configuration System (YAML)](#5-configuration-system)
6. [Database & Multi-Tenancy](#6-database--multi-tenancy)
7. [Rule Systems: CRS + SRL DSL](#7-rule-systems-crs--srl-dsl)
8. [WASM Plugin Ecosystem](#8-wasm-plugin-ecosystem)
9. [ML / AI Pipeline](#9-ml--ai-pipeline)
10. [eBPF Layer 4 Protection](#10-ebpf-layer-4-protection)
11. [Dashboard UI (Every Page)](#11-dashboard-ui)
12. [Deployment (Every Method)](#12-deployment)
13. [Operations & Troubleshooting](#13-operations--troubleshooting)
14. [Security Architecture](#14-security-architecture)
15. [Scaling & HA](#15-scaling--ha)
16. [Quick Reference Cards](#16-quick-reference-cards)

---

## 1. Architecture at 10,000 Feet

### The Two-Plane Design

```
┌─────────────────────────────────────────────────────────┐
│                     INTERNET                             │
└─────────────────────────┬───────────────────────────────┘
                          │
          ┌───────────────▼────────────────┐
          │  eBPF/XDP (Linux Kernel)       │  ← L4 DDoS filter
          │  Drops known bad IPs at NIC    │     ~25M pps per core
          └───────────────┬────────────────┘
                          │
┌─────────────────────────▼─────────────────────────────────────────┐
│               DATA PLANE — Rust (every request)                   │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐     │
│  │Ph0   │→│Ph1   │→│Ph2   │→│Ph3   │→│Ph4   │→│Ph5   │→│Ph6  │     │
│  │Conn  │ │Hdrs  │ │Body  │ │Proxy │ │RespHd│ │DLP   │ │Log  │     │
│  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘     │
│       Rust, lock-free, p99 < 1ms, zero-GC                       │
└─────────────────────────┬───────────────────────────────────────┘
                          │ gRPC + REST
┌─────────────────────────▼───────────────────────────────────────┐
│            CONTROL PLANE — Go (Raft cluster, never on path)     │
│   REST API (Gin) · gRPC · Raft · Auth (JWT/OIDC) · RBAC        │
│   Config push · Audit · Multi-tenant · SSE log streaming       │
└─────────────────────────┬───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────┐
│   Dashboard — Next.js 14 + TS  │
└─────────────────────────────────┘
```

**Why two languages?**

| Plane | Language | Reason |
|-------|----------|--------|
| **Data plane** | Rust | Zero-GC, memory-safe, p99 < 1ms. Every microsecond counts on the request path. |
| **Control plane** | Go | Fast dev velocity, rich web ecosystem (Gin, JWT, gRPC), large hiring pool. Never on the request path so GC pauses don't matter. |

**Key insight:** Data plane nodes are **completely stateless**. You can run 1 or 1000 behind any L4 LB. They subscribe to config from the control plane via gRPC and report metrics via OTel. No CARP, no VRRP, no session sync needed.

---

## 2. Every Binary and Tool

You have **5 entry points** into Sentinel. Here is exactly what each one does:

### 2.1 `sentinel` — Rust CLI (node-local admin)

**Binary:** `crates/sentinel-cli/src/main.rs`
**Language:** Rust
**Purpose:** Manage the data-plane WAF node directly (like `nginx` or `systemctl` for nginx).

| Command | What it does |
|---------|-------------|
| `sentinel init` | Creates `~/.config/sentinel/sentinel.yaml` with default config, discovers CRS rules |
| `sentinel site add NAME --domain D --upstream H:PORT` | Adds a protected site to the YAML config |
| `sentinel site rm NAME` | Removes a site from config |
| `sentinel site ls` | Lists all sites with mode/domains/upstreams/rules |
| `sentinel site mode NAME off\|learning\|blocking` | Changes WAF mode for a site |
| `sentinel start` | Daemonizes `sentinel-bin` in background (setsid, nohup-style) |
| `sentinel stop` | SIGTERM → wait 5s → SIGKILL |
| `sentinel reload` | Sends SIGHUP to running proxy for zero-downtime config reload |
| `sentinel restart` | Stop then start |
| `sentinel status` | Shows running/stopped, PID, listeners, protected sites |
| `sentinel logs` | Shows last N log lines (pretty-printed JSON) |
| `sentinel logs -f` | Tails logs live (like `tail -f`) |
| `sentinel test` | Sends 10 attack samples through the WAF via curl, reports blocked/passed |
| `sentinel paths` | Shows all important file paths |
| `sentinel plugin install REF` | Installs WASM plugin from OCI registry |
| `sentinel plugin ls` | Lists installed plugins |
| `sentinel plugin rm NAME` | Removes plugin |
| `sentinel copilot chat --prompt "..."` | One-shot LLM prompt |
| `sentinel copilot explain "alert..."` | Explains why an alert fired |
| `sentinel copilot suggest-rule "block X"` | Generates SRL rule from description |
| `sentinel copilot patch --cve CVE-2024-1234` | Generates virtual patch for CVE |

### 2.2 `sentinel-bin` — Rust Data Plane (the actual proxy)

**Binary:** `crates/sentinel-bin/src/main.rs`
**Language:** Rust
**Purpose:** The WAF engine itself. Listens on ports, runs the 7-phase pipeline, proxies to upstreams.

```bash
# Direct invocation (CLI wrapper does this for you)
sentinel-bin --config configs/dev/sentinel.yaml
sentinel-bin --config config.yaml --check   # validate config, exit
sentinel-bin --config config.yaml --log-level debug
```

**Key behaviors:**
- Registers SIGHUP handler for hot-reload (config reloads from disk atomically via `ArcSwap`)
- Graceful shutdown on SIGTERM/SIGINT
- Binds all configured listeners in parallel tokio tasks
- Polls control plane `GET /api/v1/internal/config` every 5s for site hot-sync
- Auto-restarts background tasks if they panic (watchdog pattern)

### 2.3 `controllerd` — Go Control Plane Daemon

**Binary:** `control-plane/cmd/controllerd/main.go`
**Language:** Go
**Purpose:** REST API, gRPC, auth, DB operations, Raft clustering, SSE log streaming.

**What it starts (in order):**
1. Logger (zap)
2. JWT service (reads `SENTINEL_JWT_SECRET`)
3. PostgreSQL pool (from `SENTINEL_DB_URL`)
4. DB seed (idempotent — creates dev tenant, admin user if not exists)
5. SSE Log Hub (pub/sub for dashboard live streaming)
6. RBAC enforcer
7. Raft cluster (optional, if `SENTINEL_RAFT_ADDR` set)
8. gRPC server (port 9500)
9. Data-plane auto-start (finds `sentinel-bin`, launches as child, auto-restarts on crash)
10. REST API server (Gin, port 9501)
11. Graceful shutdown on SIGINT/SIGTERM

**Key env vars:**
| Var | Default | Description |
|-----|---------|-------------|
| `SENTINEL_DB_URL` | `postgres://sentinel:sentinel_dev@localhost:5432/sentinel` | PostgreSQL DSN |
| `SENTINEL_JWT_SECRET` | random-warning | JWT signing key |
| `SENTINEL_REST_ADDR` | `0.0.0.0:9501` | REST API bind |
| `SENTINEL_GRPC_ADDR` | `0.0.0.0:9500` | gRPC bind |
| `SENTINEL_RAFT_ADDR` | (empty=disabled) | Raft listen addr |
| `SENTINEL_NODE_ID` | required if RAFT_ADDR set | Raft node ID |
| `SENTINEL_RAFT_PEERS` | `"2=host:9602,3=host:9603"` | Comma-separated peers |
| `SENTINEL_DASHBOARD_DIR` | `../dashboard` | Static HTML files path |
| `SENTINEL_PROXY_BIN` | auto-detect | Override data-plane binary path |

**Degraded mode:** If PostgreSQL is unreachable, controllerd still starts and serves mock data for all endpoints. The dashboard works, but changes aren't persisted.

### 2.4 `sentinelctl` — Go Operator CLI

**Binary:** `control-plane/cmd/sentinelctl/main.go`
**Language:** Go
**Purpose:** Remote operator CLI — talks to the control plane REST API. Like `kubectl` for Sentinel.

| Command | API Call | Description |
|---------|----------|-------------|
| `sentinelctl login --email E --password P` | `POST /api/v1/auth/login` | Auth, saves token to `~/.config/sentinel/token` |
| `sentinelctl logout` | — | Deletes saved token |
| `sentinelctl sites list` | `GET /api/v1/sites` | Table: NAME, STATUS, DOMAINS, MODE |
| `sentinelctl rules list` | `GET /api/v1/rules` | Table: ID, NAME, SEVERITY, ENABLED |
| `sentinelctl alerts list` | `GET /api/v1/alerts` | Table: ID, SEVERITY, STATE, SITE, MSG |
| `sentinelctl alerts ack <id>` | `POST /api/v1/alerts/:id/ack` | Acknowledge alert |
| `sentinelctl alerts resolve <id>` | `POST /api/v1/alerts/:id/resolve` | Resolve alert |
| `sentinelctl audit list` | `GET /api/v1/audit` | Table: ID, ACTOR, ACTION, RESOURCE |
| `sentinelctl stats` | `GET /api/v1/dashboard/stats` | All dashboard metrics |
| `sentinelctl test --target URL --host H` | direct HTTP | 26 OWASP attack vectors through proxy |
| `sentinelctl version` | — | Version + API target + token status |

**Test suite (26 attack vectors):**

The `sentinelctl test` command fires these attack categories:
- **SQLi (4):** classic, UNION, blind time, stacked
- **XSS (3):** reflected, stored, DOM-based
- **LFI (3):** /etc/passwd, null byte, directory traversal
- **CMDi (3):** semicolon, backtick, dollar substitution
- **Log4Shell (2):** JNDI header, User-Agent header
- **SSRF (3):** localhost, AWS metadata, internal IP
- **XXE (1):** file read via DOCTYPE
- **Scanner (2):** SQLMap UA, Nikto UA
- **NoSQLi (2):** prototype pollution, $gt injection
- **RFI (1):** remote file include

### 2.5 `sentinel.sh` — Dev Launcher (Bash)

**File:** `sentinel.sh` at repo root
**Purpose:** All-in-one dev environment launcher. Manages Docker infra, lab sites, builds, and all 3 services.

| Command | What it does |
|---------|-------------|
| `sentinel start` | Infra up → start all lab sites → build CP+dashboard if needed → start CP → start proxy → start dashboard |
| `sentinel stop` | Stop CP + dashboard + proxy + all site containers |
| `sentinel restart` | Stop then start |
| `sentinel status` | Shows which ports are listening + site container status |
| `sentinel logs` | Tails CP + dashboard logs |
| `sentinel build` | Force rebuild CP (Go) + dashboard (Next.js) |
| `sentinel install` | Install `sentinel` wrapper in `~/.local/bin` |
| `sentinel deploy <host>` | Build all → generate Ansible inventory → run playbook |
| `sentinel infra up` | Start Docker: Postgres, Redis, ClickHouse, MinIO, Jaeger |
| `sentinel infra down` | Stop Docker infra |
| `sentinel site list` | Show registered sites + container status |
| `sentinel site on <name>` | Start a lab site Docker container |
| `sentinel site off <name>` | Stop a lab site Docker container |
| `sentinel site add <n> <img> <hp> <cp>` | Register new lab site |

**Default ports:**
| Service | Port |
|---------|------|
| Dashboard | 2222 |
| Control Plane REST | 9501 |
| Control Plane gRPC | 9500 |
| WAF Proxy (shared) | 9080 |
| WAF DVWA port | 9095 |
| WAF Juice Shop port | 3000 |

**Default credentials:**
```
Email:    admin@sentinel.local
Password: admin123
```

---

## 3. The 7-Phase Request Lifecycle

Every HTTP request flows through these 7 sequential phases. Any phase can block.

### Phase 0: Connection (Pre-HTTP)

**Runs:** After TCP/TLS accept, before reading HTTP bytes.

| Check | Module | Decision |
|-------|--------|----------|
| Connection rate per IP | `AntiDdos` (token bucket) | Block if >200 conn/sec |
| IP in blocklist | `IpReputation` (trie) | Block if CIDR match |
| IP in suspect feeds | `IpReputation` (loaded from AlienVault OTX, etc.) | Add +2 anomaly score |
| Correlation history | `CorrelationEngine` | Add +3 to +8 score for repeat offenders |

### Phase 1: Request Headers

**Runs:** After HTTP request line + headers parsed.

| Check | Module | Decision |
|-------|--------|----------|
| URI length limit | Config (`max_uri_length`, default 8192) | 414 if exceeded |
| Header count limit | Config (`max_header_count`, default 100) | 431 if exceeded |
| Rate limiting | `RateLimiter` (per-IP, per-site, global token buckets) | 429 if exceeded |
| Bot detection | `BotDetector` (UA regex + JA4 TLS fingerprint) | Block known tools, challenge suspicious |
| GeoIP | `GeoIp` (MaxMind GeoLite2 mmdb) | Block disallowed countries |
| Rule engine (headers) | `RuleEngine` (CRS + SRL VM) | Block if anomaly ≥ threshold |
| WASM plugins | `PluginRuntime` | Plugin decides allow/block/challenge |

### Phase 2: Request Body

**Runs:** After full body buffered (up to `max_body_size`, default 10 MiB).

| Check | Module | Description |
|-------|--------|-------------|
| Body size limit | Config | 413 if exceeded |
| Rule engine (body) | `RuleEngine` | Same VM, now with `REQUEST_BODY` variable populated |
| ML inference | `MlEngine` | 24-dim feature extraction → Isolation Forest + ONNX classifier |
| Anomaly gate | Config threshold | If `anomaly_score >= threshold` → block |

### Phase 3: Upstream Forwarding

| Feature | Detail |
|---------|--------|
| Load balancer selection | RoundRobin, LeastConn, IpHash, Adaptive |
| Circuit breaker | Opens after 5 consecutive failures, half-open probe after 30s |
| Health checks | Active (periodic GET /health) + passive (real failures) |
| WebSocket upgrade | Detects `Upgrade: websocket`, spawns bidirectional relay |

### Phase 4: Response Headers

| Action | Description |
|--------|-------------|
| Strip hop-by-hop headers | `Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Authorization`, etc. |
| Inject security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy`, `X-XSS-Protection`, `Permissions-Policy` |

### Phase 5: Response Body (DLP)

Scans response body (up to 512 KiB) for sensitive data:
- Credit card numbers (Luhn algorithm)
- SSN (`\d{3}-\d{2}-\d{4}`)
- Private keys (`-----BEGIN RSA PRIVATE KEY-----`)
- AWS keys (`AKIA...`)
- API tokens / bearer tokens in JSON
- Passwords leaked in JSON responses

### Phase 6: Logging

- Structured NDJSON access/WAF log
- OpenTelemetry traces (per-phase spans)
- Prometheus metrics exposed
- Correlation engine state update for source IP

### Anomaly Scoring Model

Every rule match adds to a running score:

| Severity | Points |
|----------|--------|
| Critical | +10 |
| Error | +5 |
| Warning | +2 |
| Notice | +1 |

ML can add up to +8. Correlation can add +3 or +8. If total ≥ `anomaly_threshold` (default 5) → block.

### WAF Modes

| Mode | Behavior |
|------|----------|
| `off` | No inspection, pure reverse proxy |
| `learning` | All checks run, blocks are downgraded to Log (no actual blocking) |
| `blocking` | Full enforcement — blocks are real |

---

## 4. All REST API Endpoints

Base URL: `http://localhost:9501`

### Public (no auth)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check → `{"status":"ok"}` |
| `GET` | `/login` | Static login page |
| `GET` | `/dashboard` | Static dashboard HTML |
| `GET` | `/api/v1/internal/config` | **Internal only** — data plane polls this for site config |
| `GET` | `/api/v1/waf/status` | Proxy health probe (forwards to `localhost:9080/healthz`) |

### Auth

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `POST` | `/api/v1/auth/login` | `{"email","password"}` | Returns JWT access + refresh tokens |
| `POST` | `/api/v1/auth/refresh` | `{"refresh_token"}` | Returns new access token |
| `GET` | `/api/v1/auth/oidc/login?provider=URL` | — | Redirects to OIDC provider |
| `GET` | `/api/v1/auth/oidc/callback?code=X` | — | OIDC callback, returns tokens |

### Protected (JWT required, role-based)

| Method | Path | Role | Description |
|--------|------|------|-------------|
| `GET` | `/api/v1/dashboard/stats` | viewer+ | Total sites, rules, alerts count |
| `GET` | `/api/v1/sites` | viewer+ | List all sites |
| `POST` | `/api/v1/sites` | editor+ | Create site → Raft-proposed → DB → configVersion++ |
| `GET` | `/api/v1/sites/:id` | viewer+ | Get single site |
| `PUT/PATCH` | `/api/v1/sites/:id` | editor+ | Update site |
| `DELETE` | `/api/v1/sites/:id` | editor+ | Delete site |
| `PATCH` | `/api/v1/sites/:id/status` | editor+ | Pause/resume (`{"status":"active\|paused"}`) |
| `GET` | `/api/v1/rules` | viewer+ | List rules |
| `POST` | `/api/v1/rules` | editor+ | Create custom rule |
| `PATCH` | `/api/v1/rules/:id` | editor+ | Toggle enable/disable |
| `DELETE` | `/api/v1/rules/:id` | editor+ | Delete rule |
| `POST` | `/api/v1/rules/test` | viewer+ | Dry-run rule DSL against payload |
| `GET` | `/api/v1/ml/stats` | viewer+ | ML model metrics (precision, recall, FP rate) |
| `GET` | `/api/v1/traffic/history` | viewer+ | Time-series traffic data |
| `GET` | `/api/v1/plugins` | viewer+ | Installed WASM plugins |
| `GET` | `/api/v1/alerts` | viewer+ | Alert list (`?state=active`) |
| `POST` | `/api/v1/alerts/:id/ack` | editor+ | Acknowledge alert |
| `POST` | `/api/v1/alerts/:id/resolve` | editor+ | Resolve alert |
| `GET` | `/api/v1/metrics/snapshot` | viewer+ | Live metrics snapshot |
| `GET` | `/api/v1/audit` | viewer+ | Audit log entries |
| `GET` | `/api/v1/cluster/status` | viewer+ | Raft cluster health |
| `GET` | `/api/v1/logs/stream` | viewer+ | **SSE endpoint** — live log streaming (also supports `?token=`) |

### Admin only

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/users` | List users |
| `POST` | `/api/v1/admin/users` | Create user |
| `GET` | `/api/v1/admin/apikeys` | List API keys |
| `POST` | `/api/v1/admin/apikeys` | Create API key |
| `DELETE` | `/api/v1/admin/apikeys/:id` | Revoke API key |

### Internal Config Sync (data plane → control plane)

`GET /api/v1/internal/config` returns:
```json
{
  "version": 42,
  "sites": [
    {
      "id": "dvwa.local",
      "domains": ["dvwa.local"],
      "upstream": {
        "load_balancer": "round_robin",
        "servers": [{"host": "127.0.0.1", "port": 9096, "weight": 1}]
      },
      "waf": {
        "mode": "blocking",
        "paranoia_level": 2,
        "anomaly_threshold": 5,
        "rules": ["rules/owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf", ...]
      },
      "plugins": []
    }
  ]
}
```

The proxy polls this every 5s. When `version` changes, it deserializes the sites and atomically swaps them via `ArcSwap` → zero-downtime site updates.

---

## 5. Configuration System

### File location
`~/.config/sentinel/sentinel.yaml` (or any path via `--config`)

### Full YAML structure

```yaml
cluster:
  name: sentinel-dev
  node_id: auto                # "auto" = hostname+MAC derived
  sync_url: "http://localhost:9501"   # Control plane polling URL
  sync_interval_secs: 5        # How often to poll for site changes

listeners:
  - name: http
    bind: "0.0.0.0:9080"
    protocol: http1            # or http2, http3, or [http1, http2]
    tls: null                  # or { cert, key, ca, min_version, post_quantum }
    default_site: null         # or "site-id" for port-based routing

sites:
  - id: mysite                 # Unique site identifier
    domains: ["app.example.com", "*.example.com"]   # Wildcard supported
    upstream:
      load_balancer: round_robin   # round_robin | least_conn | ip_hash | random | adaptive
      servers:
        - host: "10.0.1.50"
          port: 8080
          weight: 1
          tls: false           # Set true for HTTPS backend
      health_check:
        path: /healthz         # Active health check endpoint
        interval: 10s
        timeout: 3s
    waf:
      mode: blocking           # off | learning | blocking
      paranoia_level: 2        # 1-4, filters rules by tag
      anomaly_threshold: 5     # Block when cumulative score >= this
      rules:                   # Paths to .conf (CRS) or .srl (native) files
        - "rules/owasp-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"
      rule_exclusions:         # Suppress FP on specific rule targets
        - rule_id: 932236
          exclude_targets: ["ARGS_NAMES"]
      max_body_size: 10485760      # 10 MiB
      max_uri_length: 8192
      max_header_count: 100
      ml:
        enable: false
        models: []
        sensitivity: 0.85
      rate_limit:
        global: { rps: 5000, burst: 10000 }
        per_ip: { rps: 100, burst: 50 }
      bot_detection:
        ja4: false              # JA4 TLS fingerprinting
        challenge: "off"        # off | native_pow | hcaptcha | turnstile
      dlp:
        enable: false
        patterns: []            # Custom regex patterns
      geoip:
        db_path: "/usr/share/GeoIP/GeoLite2-Country.mmdb"
        block_countries: ["CN", "RU"]
        allow_countries: []     # If non-empty, ONLY these allowed
      ip_reputation:
        allow: ["10.0.0.0/8"]  # Always-allow CIDRs
        block: ["5.188.0.0/16"] # Always-block CIDRs
        feeds:
          - url: "https://example.com/bad-ips.txt"
            interval: 1h
            format: cidr
      anti_ddos:
        enabled: true
        conn_rate_limit: 200
        burst: 50
        block_duration_secs: 300
      plugins: ["/path/to/sentinel-plugin.toml"]
      api_discovery: false
      graphql: null             # or { enable: true, max_depth: 10, max_complexity: 1000 }
    plugins: []

logging:
  level: info
  format: json                  # json | text
  outputs:
    - type: stdout
    - type: file
      path: /var/log/sentinel/access.log
      rotate: { size: 100MB, keep: 10 }
    - type: otlp
      endpoint: "http://localhost:4318"

storage:
  cache: { backend: memory, size: 64MB }    # memory | redis
  kv: { backend: memory }                   # memory | rocksdb | redis
  timeseries:                               # ClickHouse
    url: "http://localhost:8123"
    database: sentinel

ebpf:
  enable: false                 # Enable XDP L4 filtering
  programs: []                  # XDP program names to load
```

### Config Hot-Reload

Two mechanisms:
1. **SIGHUP:** `sentinel reload` (or `kill -HUP <pid>`) → reloads YAML from disk, atomically swaps via `ArcSwap`
2. **Control plane sync:** Proxy polls `GET /api/v1/internal/config` every 5s → when `version` changes, merges DB sites with file sites → atomically swaps

Both methods preserve in-memory state (rate-limit counters, anti-DDoS state, correlation engine).

---

## 6. Database & Multi-Tenancy

### Storage Stack

| Database | Technology | Purpose | Access Pattern |
|----------|-----------|---------|----------------|
| PostgreSQL 16 | SQL (RDBMS) | Users, tenants, sites, rules, plugins, alerts, audit logs | OLTP — frequent small R/W |
| Redis 7 | In-memory KV | Rate-limit counters, IP correlation state, pub/sub for SSE | µs R/W, TTL expiry |
| ClickHouse 24+ | OLAP (columnar) | Access logs, security events, traffic metrics rollups | Analytical queries |
| S3/MinIO | Object store | ML models (ONNX), WASM plugins, reports, backups | Infrequent large R/W |

### Multi-Tenancy Model (3 Tiers)

| Tier | Method | Use Case |
|------|--------|----------|
| **T1: Shared schema + RLS** | All tenants in same table, PostgreSQL Row-Level Security enforces `tenant_id` isolation | SaaS (default) |
| **T2: Schema-per-tenant** | Each tenant gets `tenant_acme` schema | Enterprise, HIPAA, banking |
| **T3: Dedicated cluster** | Single tenant per Postgres instance, no `tenant_id` column | On-prem |

Connection lifecycle:
```
1. Authenticate → resolve user → resolve tenant_id
2. Acquire DB conn from pool
3. SET LOCAL app.current_tenant = $tenantID
4. SET LOCAL app.current_user = $userID
5. Run business query (RLS auto-filters)
6. On commit, audit triggers write to audit_logs
```

### Core Tables

```
tenants          → top-level org
  users          → members with role (admin|editor|viewer)
  api_keys       → machine credentials
  audit_logs     → append-only, HMAC-signed, tamper-evident
  sites          → protected websites
    upstreams    → backend server configs
    tls_certs    → TLS certificate storage
    waf_policies → per-site WAF settings (JSONB)
  rules          → custom WAF rules (SRL DSL stored as text)
  rule_sets      → bundles of rules attached to sites
  plugins        → installed WASM plugin metadata
  ml_profiles    → per-site ML baselines
  ip_lists       → allow/deny CIDR lists
  alerts         → triggered alerts with ack/resolve workflow
  reports        → scheduled report definitions
```

---

## 7. Rule Systems: CRS + SRL DSL

Sentinel supports TWO rule formats, compiled to the same bytecode VM.

### 7.1 OWASP CRS (ModSecurity SecRule syntax)

**Location:** `rules/owasp-crs/rules/`
**Format:** `.conf` files with `SecRule` directives
**Compat layer:** `crates/sentinel-rules/src/crs_compat/`

```
SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" \
    "id:913100,phase:1,block,msg:'Scanner User-Agent Detected'"
```

The CRS compat layer:
1. Parses `SecRule` directives → extracts variables, operators, actions
2. Translates to the internal SRL AST
3. Compiles to bytecode via the same compiler
4. Runs through the same stack VM

**Supported operators:** `@rx`, `@pm`, `@pmFromFile`, `@contains`, `@beginsWith`, `@endsWith`, `@streq`, `@within`, `@eq`, `@gt`, `@lt`, `@ge`, `@le`

**Supported transformations:** `t:lowercase`, `t:urlDecode`, `t:htmlEntityDecode`, `t:removeNulls`, `t:compressWhitespace`, `t:removeWhitespace`, `t:base64Decode`, `t:urlDecodeUni`, `t:normalizePath`

**Bundled CRS rules (13 files loaded by default):**

| File | Category |
|------|----------|
| `REQUEST-911-METHOD-ENFORCEMENT.conf` | Method whitelist |
| `REQUEST-913-SCANNER-DETECTION.conf` | Scanner UA/headers |
| `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` | Protocol violations |
| `REQUEST-921-PROTOCOL-ATTACK.conf` | HTTP parameter pollution |
| `REQUEST-930-APPLICATION-ATTACK-LFI.conf` | Local File Inclusion |
| `REQUEST-931-APPLICATION-ATTACK-RFI.conf` | Remote File Inclusion |
| `REQUEST-932-APPLICATION-ATTACK-RCE.conf` | Remote Code Execution |
| `REQUEST-933-APPLICATION-ATTACK-PHP.conf` | PHP injection |
| `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` | Node.js/Generic attacks |
| `REQUEST-941-APPLICATION-ATTACK-XSS.conf` | Cross-Site Scripting |
| `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` | SQL Injection |
| `REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf` | Session fixation |
| `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` | Java attacks |

**NOTE:** `REQUEST-901-INITIALIZATION.conf` and `REQUEST-949-BLOCKING-EVALUATION.conf` are intentionally omitted:
- 901 blocks all traffic if `TX:crs_setup_version` is absent (our engine handles this natively)
- 949 is redundant — our `anomaly_threshold` handles the blocking decision natively

### 7.2 SRL (Sentinel Rule Language) — Native DSL

**Location:** `crates/sentinel-rules/src/dsl/`
**Parser:** `dsl/parser.rs` → produces AST
**Compiler:** `compiler/` → AST → bytecode → `RuleEngine`
**VM:** `compiler/vm.rs` → stack-based bytecode interpreter

Example SRL rule:
```srl
rule BlockSQLInjection
    when REQUEST_ARGS matches r"(\bselect\b.*\bfrom\b|union\s+select|--)"
    phase 1
    severity critical
    action deny(403)
    msg "SQL injection attempt detected"
    tag "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"
    tag "paranoia-level/2"
end
```

### 7.3 Rule Engine Pipeline

```
Raw text (.conf or .srl)
  → Lexer (tokenizes)
    → Parser (builds AST — Abstract Syntax Tree)
      → Semantic Analyzer (validates variables, operators, transforms)
        → Bytecode Compiler (AST → Vec<Opcode> linear bytecode)
          → Stack-based VM (executes bytecode per-request, O(n) in rule count)
```

### 7.4 Paranoia Level Gating

Rules tagged with `paranoia-level/X` are only loaded if `paranoia_level >= X`.

| PL | Description |
|----|-------------|
| 1 | Baseline — minimal false positives |
| 2 | Standard — good balance (default) |
| 3 | Aggressive — more false positives expected |
| 4 | Paranoid — maximum coverage, many FP |

### 7.5 Rule Exclusions

Suppress false positives on specific rules + targets:
```yaml
rule_exclusions:
  - rule_id: 932236                      # RCE: Unix Command Injection
    exclude_targets: ["ARGS_NAMES"]      # Don't match on parameter NAMES
```

Equivalent to ModSecurity `ctl:ruleRemoveTargetById=932236;ARGS_NAMES`.

---

## 8. WASM Plugin Ecosystem

### Architecture

Plugins are `.wasm` modules running in **wasmtime** — fully sandboxed, no host filesystem/network access unless explicitly granted.

### SDKs

| SDK | Language | Compiler | Status |
|-----|----------|----------|--------|
| `plugins/sdk-rust/` | Rust | `cargo build --target wasm32-wasip1` | Stable |
| `plugins/sdk-go/` | Go | TinyGo → WASM | Stable |
| `plugins/sdk-assemblyscript/` | AssemblyScript | AS compiler | Stable |

### Host ABI (functions the WAF exposes to plugins)

```rust
host_log(level: i32, msg: *const u8, len: i32)           // Log from plugin
host_get_req_header(name: *const u8) -> *const u8        // Read any request header
host_set_decision(id: i32, status: i32, msg: *const u8)  // Block/Allow decision
host_http_callout(url: *const u8, body: *const u8)       // Outbound HTTP (e.g., auth)
host_add_score(score: i32)                                // Add to anomaly score
host_get_tx_var(name: *const u8) -> *const u8            // Read transaction variable
host_set_tx_var(name: *const u8, value: *const u8)        // Set transaction variable
```

### Plugin Manifest (sentinel-plugin.toml)

```toml
[plugin]
name = "jwt-validator"
version = "1.0.0"
wasm = "jwt-validator.wasm"

[plugin.hooks]
request_headers = true
request_body = false

[plugin.permissions]
host_log = true
host_get_req_header = true
host_set_decision = true
host_http_callout = true   # Can call external auth service
host_add_score = true
host_kv_write = false      # Cannot write to KV store
```

### Plugin Lifecycle

1. **Install:** `sentinel plugin install registry.example.com/ns/name:tag` — pulls OCI image layers
2. **Configure:** Add plugin manifest path to site's `waf.plugins` list
3. **Load:** Plugin runtime pre-compiles all `.wasm` files, creates wasmtime instances
4. **Execute:** Per-request, plugins are called in order after rule engine in Phase 1
5. **Hot-swap:** `Arc<ArcSwap<PluginRuntime>>` — atomic pointer swap, zero downtime

### Example Plugins

| Plugin | Purpose |
|--------|---------|
| `hello-world/` | Minimal "hello" plugin (Rust/WASM) |
| `hello-world-go/` | Same, in Go (TinyGo→WASM) |
| `hello-world-as/` | Same, in AssemblyScript |
| `custom-header/` | Injects custom response headers |
| `jwt-validator/` | Validates JWT tokens on incoming requests |

---

## 9. ML / AI Pipeline

### Three-Tier Architecture

| Tier | Latency | What runs | When |
|------|---------|-----------|------|
| **Inline** | ~2ms | 24-dim feature extraction + Isolation Forest + ONNX classifier | Every request, Phase 2 |
| **Near-line** | ~50-200ms | Transformer deep analysis (BERT for payloads) | ~1% of requests (async, sampled after high anomaly) |
| **Offline** | Minutes-hours | Model training, drift detection, LLM rule copilot | Control plane, scheduled |

### 24 Feature Dimensions (what the ML model sees)

1. Payload length (bytes)
2. Shannon entropy of payload
3. Ratio of special characters (`'`, `"`, `;`, `--`, `<`, `>`, `(`, `)`)
4. Number of URL-encoded sequences (`%XX`)
5. Presence of NULL bytes
6. Repeated parameter names count
7-26. Byte-level 4-gram frequencies (at positions 0-127)

### Models

| Model | Algorithm | Purpose |
|-------|-----------|---------|
| `payload-classifier` v2.1.0 | ONNX neural net | Classifies into SQLi, XSS, CMDi, LFI, SSRF, NoSQLi, Benign |
| `anomaly-detector` v1.8.0 | Isolation Forest | Zero-day attack detection (unsupervised) |
| `bot-classifier` v1.5.2 | ONNX | Bot vs human classification |

### LLM Copilot

Configured via env: `SENTINEL_LLM_ENDPOINT`, `SENTINEL_LLM_API_KEY`, `SENTINEL_LLM_MODEL`

Capabilities:
- **Explain alerts:** "Why was this blocked?" → plain English explanation
- **Suggest rules:** "Block requests from ASN 12345" → generates SRL DSL
- **Virtual patches:** "CVE-2024-1234" → generates compensating rule

---

## 10. eBPF Layer 4 Protection

### When it runs

**Before any userspace code.** The XDP program attaches to the NIC driver hook. Packets matched against the BPF blocklist are dropped in the kernel — they never reach the TCP stack.

### Performance

- Single XDP core: ~25M packets/sec
- Drop latency: ~50ns (vs ~100µs for userspace drop)
- BPF map: O(1) hash lookup

### Components

```rust
// crates/sentinel-ebpf/src/lib.rs → XDP program
fn xdp_main(ctx: &XdpContext) -> u32 {
    let ip = ctx.src_ip();
    if blocklist.contains(ip) {
        return XDP_DROP;  // Packet dies here, never reaches Rust
    }
    XDP_PASS  // Forward to kernel TCP stack → Rust data plane
}
```

### Auto-Blocklisting

When the correlation engine detects a persistent attacker (≥3 blocks in 60s window), the IP can be pushed to the eBPF blocklist. This means subsequent requests from that IP are dropped at L4 — zero CPU spent on HTTP parsing or rule evaluation.

---

## 11. Dashboard UI

### Technology Stack

| Tech | Purpose |
|------|---------|
| Next.js 14 (App Router) | Framework |
| TypeScript | Type safety |
| Tailwind CSS | Styling |
| Recharts | Traffic/block charts |
| React Query | Server state (auto-refetch, caching) |
| SSE (EventSource) | Live log streaming |

### Pages

| Route | Content |
|-------|---------|
| `/login` | JWT login form (email + password) |
| `/dashboard` → Overview | RPS, p99 latency, blocks, eBPF drops, connected clients, traffic chart |
| `/dashboard/sites` | CRUD for protected sites — name, domains, upstreams, TLS, WAF mode |
| `/dashboard/rules` | Rule list, create, test (dry-run DSL against payload) |
| `/dashboard/logs` | SSE live log viewer — filter by site, status, phase, kind (access/waf/error/audit) |
| `/dashboard/alerts` | Alert list with severity badges, ack/resolve buttons |
| `/dashboard/traffic` | Traffic history charts, request/block trends |
| `/dashboard/ml` | ML model stats — precision, recall, FP/TP rates, model versions |
| `/dashboard/plugins` | Installed WASM plugins list |
| `/dashboard/settings` | User management, API keys, RBAC, audit log viewer |
| `/dashboard/copilot` | LLM chat — explain alerts, suggest rules |

### Key Dashboard Behaviors

- **WAF Status Badge:** Probes `GET /api/v1/waf/status` → shows "WAF active · N sites" or "WAF NOT running"
- **Live Logs:** SSE connection to `GET /api/v1/logs/stream?token=JWT` — real-time JSON events
- **Simulator:** When data plane isn't running, the control plane runs an internal simulator (`logs/simulator.go`) that generates fake traffic so the dashboard always shows data
- **Auto-refresh:** React Query refetches every 10s; SSE streams live updates

---

## 12. Deployment

### 12.1 Local Development

```bash
# One command — everything
./sentinel.sh start

# Or step by step:
./sentinel.sh infra up                    # Docker: Postgres, Redis, ClickHouse, MinIO
./scripts/dev/run-controlplane.sh         # Go control plane (native)
./scripts/dev/run-dataplane.sh            # Rust data plane (native)
./scripts/dev/run-dashboard.sh            # Next.js dashboard (native)
```

### 12.2 Docker Compose (dev)

```bash
docker compose -f deploy/docker/compose.dev.yml up -d   # Infra only
docker compose -f deploy/docker/compose.full.yml up -d  # Full stack (not recommended for dev)
```

### 12.3 One-Command Server Deploy

```bash
sentinel deploy 10.0.1.50
```

This does:
1. Builds Go control plane (`go build`)
2. Builds Rust data plane (`cargo build --release`)
3. Builds Next.js dashboard (`npm run build`)
4. Generates Ansible inventory
5. Runs `deploy/ansible/deploy.yml` which:
   - Installs systemd units
   - Configures firewall rules
   - Sets up auto-restart on boot
   - Starts all services

### 12.4 Kubernetes

```bash
# Helm chart at deploy/helm/sentinel/
helm install sentinel deploy/helm/sentinel/ \
  --set dataPlane.replicas=3 \
  --set controlPlane.replicas=3
```

### 12.5 systemd Units

```
deploy/systemd/
├── sentinel-controlplane.service   # controllerd daemon
├── sentinel-proxy.service          # sentinel-bin proxy
└── sentinel-dashboard.service      # Next.js dashboard
```

### 12.6 Terraform

```
deploy/terraform/   # AWS/GCP infra-as-code (VPC, subnets, security groups, instances)
```

---

## 13. Operations & Troubleshooting

### 13.1 Health Checks

**Control plane:**
```bash
curl http://localhost:9501/health
# → {"status":"ok"}
```

**Data plane (proxy):**
```bash
curl http://localhost:9080/healthz
# → {"status":"ok","uptime_secs":3600,"sites":2,"listeners":[...],"version":"0.1.0"}
```

**Dashboard check:**
```bash
curl http://localhost:9501/api/v1/waf/status
# → {"waf_running":true,"sites":2,...}
```

### 13.2 Common Issues

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Dashboard shows "WAF NOT running" | Proxy not started | `sentinel start` or check systemd |
| 502 Bad Gateway | Upstream not reachable | Check upstream host:port, container status |
| No logs on dashboard | Data plane not sending logs | Check `sentinel status`, proxy binary |
| "DB unavailable" in API | Postgres down | `docker start sentinel-postgres` |
| Site added in dashboard but not protected | Config sync delay | Wait 5s (poll interval), check `/api/v1/internal/config` |
| Rules not blocking | Mode is "learning" | Change to "blocking" in site settings |
| Can't browse `:9080` | /etc/hosts missing | Add `127.0.0.1 dvwa.local` to /etc/hosts |
| `sentinel start` fails | sentinel-bin not built | `cargo build --bin sentinel-bin` |

### 13.3 Log Locations

| Component | Log Path |
|-----------|----------|
| Control plane | `/tmp/sentinel-controlplane.log` |
| Dashboard | `/tmp/sentinel-dashboard.log` |
| WAF proxy (background) | `/tmp/sentinel-waf.log` |
| WAF proxy (Rust CLI) | `~/.config/sentinel/sentinel.log` |
| NDJSON access logs | `/tmp/sentinel-logs/` (set via `SENTINEL_LOG_DIR`) |

### 13.4 Viewing Logs

```bash
# Pretty-printed (sentinel CLI)
sentinel logs -n 50
sentinel logs -f          # live tail
sentinel logs --raw       # raw JSON lines

# Raw file tail
tail -f /tmp/sentinel-logs/access-*.log

# Through sentinelctl (from remote)
sentinelctl stats          # live metrics
```

### 13.5 Testing the WAF

```bash
# Direct test (sentinel CLI)
sentinel test

# Remote operator test (sentinelctl — 26 OWASP vectors)
sentinelctl test --target http://localhost:9080 --host dvwa.local
sentinelctl test --site dvwa     # shortcut

# Manual curl
curl -H 'Host: dvwa.local' 'http://localhost:9080/?id=1%27%20UNION%20SELECT%201'
# → 403 Forbidden (SQLi blocked)

curl -H 'Host: dvwa.local' http://localhost:9080/
# → 200 OK (clean request passes)
```

---

## 14. Security Architecture

### Authentication

- **JWT:** Access tokens (15 min) + refresh tokens (7 days)
- **OIDC:** Login via Google, GitHub, Okta, etc.
- **API Keys:** Machine-to-machine — `sk-live-...` prefixed bearer tokens
- **Token storage:** `~/.config/sentinel/token` (0600 permissions)

### RBAC (3 Roles)

| Role | Permissions |
|------|-------------|
| `admin` | Full access — manage users, sites, rules, API keys, view audit |
| `editor` (operator) | Manage sites and rules — cannot manage users or API keys |
| `viewer` | Read-only — dashboard, logs, alerts, audit |

Enforcement: Every protected endpoint calls `enf.Allow(role, resource, action)` before executing.

### Audit Log

- **Append-only:** RLS policies forbid UPDATE/DELETE on `audit_logs`
- **HMAC-signed:** Each entry = `HMAC(prev_hash || event || actor || timestamp)`
- **Tamper-evident:** Modifying any entry breaks the chain — immediately detectable
- **Every action logged:** login, site.create, site.update, site.delete, rule.create, rule.enable, rule.disable, rule.delete, alert.ack, alert.resolve, site.status.active, site.status.paused

### Multi-Tenancy Defense-in-Depth

- **Application layer:** Every query filters by `tenant_id` (Go code)
- **Database layer:** Row-Level Security enforces `tenant_id` even if app code forgets
- **Dev tenant ID:** `00000000-0000-0000-0000-000000000001`

### TLS / Crypto

- **rustls:** Pure Rust TLS (no OpenSSL dependency)
- **Post-quantum:** Optional Kyber KEM + Dilithium hybrid mode
- **Minimum version:** TLS 1.2 or 1.3 (configurable)

---

## 15. Scaling & HA

### Data Plane (stateless — horizontal scale)

| Scaling Method | Details |
|----------------|---------|
| Add more nodes | Just run more `sentinel-bin` instances behind L4 LB |
| State | None — rate limits in Redis, config from gRPC |
| Hot-reload | SIGHUP or control-plane poll → zero-downtime config updates |
| Failover | L4 LB health checks remove dead proxies automatically |

### Control Plane (Raft cluster)

| Config | Details |
|--------|---------|
| Nodes | 3 or 5 (odd for quorum) |
| Leader election | ~150ms |
| Shared state | PostgreSQL (all nodes share same DB) |
| Config push | Leader writes to DB, all nodes serve reads |

### Raft Configuration

```bash
# Node 1 (bootstrap)
SENTINEL_NODE_ID=1 SENTINEL_RAFT_ADDR=0.0.0.0:9601 ./controllerd

# Node 2
SENTINEL_NODE_ID=2 SENTINEL_RAFT_ADDR=0.0.0.0:9602 \
  SENTINEL_RAFT_PEERS="1=node1:9601" ./controllerd

# Node 3
SENTINEL_NODE_ID=3 SENTINEL_RAFT_ADDR=0.0.0.0:9603 \
  SENTINEL_RAFT_PEERS="1=node1:9601,2=node2:9602" ./controllerd
```

### Degraded Mode Fallbacks

| Backend | When Unavailable | Fallback |
|---------|-----------------|----------|
| PostgreSQL | Down | Mock data served, writes fail gracefully |
| Redis | Down | In-memory rate limiter (per-node, reset on restart) |
| ClickHouse | Down | In-memory ring buffer (last 1000 entries) |
| S3 | Down | Local cache of ML models, last-loaded WASM plugins |

---

## 16. Quick Reference Cards

### Port Map

| Port | Service | Protocol |
|------|---------|----------|
| 2222 | Dashboard | HTTP |
| 9080 | WAF proxy (shared, routes by Host) | HTTP |
| 9095 | WAF proxy (DVWA, transparent) | HTTP |
| 3000 | WAF proxy (Juice Shop, transparent) | HTTP |
| 9500 | Control plane gRPC | gRPC |
| 9501 | Control plane REST API | HTTP |
| 5432 | PostgreSQL | TCP |
| 6379 | Redis | TCP |
| 8123 | ClickHouse HTTP | HTTP |
| 9000 | ClickHouse native | TCP |
| 9001 | MinIO console | HTTP |
| 9002 | MinIO S3 API | HTTP |
| 16686 | Jaeger UI | HTTP |

### Crate Map (Rust Workspace)

| Crate | Purpose |
|-------|---------|
| `sentinel-core` | Config, context, engine, phases — foundational types |
| `sentinel-proxy` | HTTP/1.1, HTTP/2, HTTP/3, TLS, LB, WAF phase pipeline |
| `sentinel-rules` | SRL DSL parser, CRS compat importer, bytecode compiler, stack VM |
| `sentinel-modules` | IP reputation, rate limiting, bot detection, GeoIP, anti-DDoS |
| `sentinel-ml` | Feature extraction, Isolation Forest, ONNX inference, LLM copilot |
| `sentinel-plugins` | WASM runtime (wasmtime), plugin ABI, manifest parser, SDK |
| `sentinel-storage` | Cache, KV, time-series, blob storage abstractions |
| `sentinel-telemetry` | OTel traces, metrics (Prometheus), structured logging |
| `sentinel-cluster` | Raft consensus, gossip, node discovery, config sync |
| `sentinel-ebpf` | XDP/TC eBPF programs for L4 DDoS, kernel blocklist |
| `sentinel-cli` | `sentinel` CLI — node-local admin |
| `sentinel-bin` | Main binary — ties all crates together |

### Go Package Map

| Package | Purpose |
|---------|---------|
| `cmd/controllerd` | Main daemon entry point |
| `cmd/sentinelctl` | Operator CLI |
| `cmd/seed` | DB seed tool |
| `internal/api` | Gin router + CORS middleware |
| `internal/auth` | JWT service, OIDC, middleware |
| `internal/rbac` | Role-based access control enforcer |
| `internal/db` | PostgreSQL store, migrations, seed data |
| `internal/cluster` | Raft cluster management |
| `internal/grpc` | gRPC server for data plane config push |
| `internal/logs` | SSE hub, simulator |
| `pkg/types` | Shared types |
| `pkg/client` | Control plane HTTP client |

### Key Directories

| Directory | What's inside |
|-----------|--------------|
| `configs/dev/` | Dev YAML config + sites registry |
| `rules/owasp-crs/rules/` | OWASP CRS 4.7 vendored rules |
| `rules/owasp-crs/` | CRS data files (LFI paths, SQL errors, etc.) |
| `ml-models/` | Pre-trained ONNX models |
| `plugins/examples/` | Reference WASM plugins |
| `deploy/docker/` | Docker Compose files |
| `deploy/ansible/` | Ansible deployment playbook |
| `deploy/systemd/` | systemd unit files |
| `deploy/helm/sentinel/` | Kubernetes Helm chart |
| `deploy/terraform/` | IaC for cloud |
| `docs/` | Architecture, user guide, API, RFCs |
| `tests/` | Integration, e2e, fuzz, load, security tests |
| `benchmarks/` | wrk, k6, vegeta load test scripts |
| `scripts/` | Dev, release, benchmark, migration shell scripts |

### Key Data Flow: Adding a Site End-to-End

```
1. Dashboard: User fills "Add Site" form, clicks submit
2. Browser: POST /api/v1/sites {name, domains, upstream, waf_policy}
3. controllerd: JWT validation → RBAC check → Raft propose → DB INSERT → audit log
4. controllerd: configVersion++ (atomic counter)
5. Rust proxy: polls GET /api/v1/internal/config every 5s
6. Rust proxy: version changed → deserialize sites → ArcSwap (atomic pointer swap)
7. Rust proxy: site now live — requests to that domain matched and inspected
```

### Key Data Flow: Request Blocked by WAF

```
1. Client sends: GET /?id=1' UNION SELECT password FROM users--
2. eBPF/XDP: IP not in blocklist → pass
3. Phase 0: Connection rate OK, IP not in block/suspect lists → pass
4. Phase 1: Rate limit OK, bot score OK, GeoIP OK → pass
5. Phase 1 Rule Engine: REQUEST-942-APPLICATION-ATTACK-SQLI.conf rule matches
   → anomaly_score += 5 (Error severity)
6. Phase 2 ML: Payload classifier: 94% confidence SQLi → anomaly_score += 3
7. Phase 2 Anomaly Gate: 5+3 = 8 >= threshold 5 → BLOCK
8. Phase 6: Log NDJSON event, emit OTel trace, update correlation engine
9. Response: 403 Forbidden {"error":"Forbidden","message":"anomaly score 8 >= threshold 5"}
10. Next request from same IP: Correlation engine adds +3 score → tighter scrutiny
```

---

*This is the complete internal reference for Sentinel WAF. When anyone asks how something works, you can answer from this document.*