# AGENTS.md — Sentinel WAF

## Critical Context First

**Read `SAVE1.md` before every session.** It is the project brain/memory. Update it at the end of each session with what was done and what's next. This file documents the _what_ and _why_; SAVE1.md tracks _current state_ and pending work.

**Current status: early scaffold (Phase 0).** Most crate `src/` directories are stubs (`lib.rs` with a single comment). Do not assume any code exists before reading it. The git repo has not been initialized yet.

---

## Repo Layout

```
sentinel-waf/
├── crates/                    # Rust workspace (data plane, 12 crates)
├── control-plane/             # Go module (control plane)
├── dashboard/                 # Next.js + TypeScript (no package.json yet)
├── plugins/                   # WASM plugin SDKs + examples
├── rules/                     # OWASP CRS, custom rules, virtual patches
├── ml-models/                 # Pre-trained ONNX models + training
├── configs/                   # YAML configs (dev/staging/prod/examples)
├── deploy/                    # Docker, Helm, K8s, Terraform, Ansible, systemd
├── tests/                     # integration / e2e / fuzz / load / security
├── benchmarks/                # k6 / vegeta scripts
├── scripts/dev/               # Dev workflow scripts (see below)
├── docs/                      # Architecture docs, dev-setup guide, RFCs
├── SAVE1.md                   # AI session memory — read this first
└── ROADMAP.md                 # 7-phase roadmap with perf targets
```

### Rust crates (`crates/`)

| Crate | Role |
|---|---|
| `sentinel-bin` | Main binary entry point |
| `sentinel-core` | Engine, config, request transaction context, phase lifecycle |
| `sentinel-proxy` | HTTP/1.1, HTTP/2, HTTP/3, TLS, load balancer |
| `sentinel-rules` | Rule DSL, parser, AST→bytecode compiler, CRS compat |
| `sentinel-modules` | IP rep, GeoIP, rate limit, bot detect, JA3/JA4, anti-DDoS |
| `sentinel-ml` | Feature extraction, ONNX inference, online learning |
| `sentinel-plugins` | wasmtime WASM runtime + host ABI |
| `sentinel-storage` | Cache/KV/timeseries/blob abstractions (memory, RocksDB, Redis) |
| `sentinel-telemetry` | OpenTelemetry logs/metrics/traces, audit |
| `sentinel-cluster` | Raft (openraft), gossip, discovery, config sync |
| `sentinel-ebpf` | XDP/TC eBPF programs via Aya (L4 DDoS, JA4 capture) |
| `sentinel-cli` | `sentinel` CLI for data-plane node |

### Control plane (`control-plane/`)

Go module. Internal packages (`internal/`) are private; `pkg/` is importable.

```
control-plane/
├── cmd/controllerd/    # Main daemon
├── cmd/sentinelctl/    # Operator CLI
├── cmd/operator/       # Kubernetes operator
├── api/proto/          # Protobuf definitions (config.proto)
├── internal/
│   ├── api/            # REST API handlers
│   ├── auth/           # JWT, OIDC, SAML
│   ├── rbac/           # Role definitions
│   ├── audit/          # Append-only signed audit log
│   ├── db/             # PostgreSQL pool + RLS multi-tenancy
│   ├── grpc/           # gRPC server (ConfigService impl)
│   ├── cluster/        # Raft cluster management
│   ├── rest/           # HTTP router (gin)
│   └── config/         # Config validation
└── pkg/
    ├── proto/          # Generated gRPC code
    └── client/         # Data-plane client library
```

---

## Commands

### Rust (data plane)

```bash
# From repo root
cargo build --workspace                   # debug build
cargo build --workspace --release         # release (LTO, strip)
cargo test --workspace                    # all tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Single crate
cargo build -p sentinel-core
cargo test -p sentinel-proxy

# Hot reload during dev (requires: cargo install cargo-watch)
cargo watch -x 'run --bin sentinel-bin'
```

### Go (control plane)

```bash
# From control-plane/
go build ./...
go test ./...
go vet ./...

# Hot reload during dev (requires: go install github.com/cosmtrek/air@latest)
air -c .air.toml

# Run daemon directly
go run ./cmd/controllerd
```

### Dashboard

```bash
# From dashboard/
npm ci
npm run dev        # HMR dev server
npm run build
npm run lint
```

### Dev environment (primary workflow)

```bash
# 1. Start infra (Postgres, Redis, ClickHouse, MinIO, OTel, Jaeger) in Docker
./scripts/dev/up.sh

# 2. Run each component natively in separate terminals
./scripts/dev/run-dataplane.sh         # cargo run --bin sentinel-bin
./scripts/dev/run-controlplane.sh      # go run ./cmd/controllerd
./scripts/dev/run-dashboard.sh         # npm run dev

# Tear down (keep data)
./scripts/dev/down.sh
# Tear down + wipe volumes
./scripts/dev/down.sh -v

# Full Docker mode (CI/demos only — slower rebuilds)
docker compose -f deploy/docker/compose.full.yml up --build

# Nuclear reset
docker system prune -af && cargo clean
rm -rf control-plane/bin dashboard/.next dashboard/node_modules
```

---

## Dev Environment Architecture

**Golden rule: infra in Docker, code native on host.**

| What | Where | Why |
|---|---|---|
| Postgres 16, Redis 7, ClickHouse 24, MinIO, OTel Collector, Jaeger | Docker (`compose.dev.yml`) | Zero-install, prod-parity, easy reset |
| Rust data plane | Native | Fast incremental builds, rust-analyzer/debugger, eBPF needs host kernel |
| Go control plane | Native | Fast builds, dlv debugger, `air` hot reload |
| Next.js dashboard | Native | HMR doesn't work well in containers |
| Python ML training | `uv` venv in `ml-models/training/` | Offline only, never on request path |

**Do not run Rust or Go inside Docker during dev** — 5-10× slower builds, debugger breaks.

### Default dev env vars (set by the run scripts)

```
SENTINEL_DB_URL          postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable
SENTINEL_REDIS_URL       redis://localhost:6379
SENTINEL_CLICKHOUSE_URL  http://sentinel:sentinel_dev@localhost:8123/sentinel_logs
SENTINEL_S3_ENDPOINT     http://localhost:9002
OTEL_EXPORTER_OTLP_ENDPOINT  http://localhost:4317
RUST_LOG                 info,sentinel=debug
RUST_BACKTRACE           1
SENTINEL_LOG_LEVEL       debug
```

Override by exporting before running scripts. The scripts respect existing env vars.

---

## Architecture

### Two-plane design

- **Data plane (Rust):** every request flows through here. Zero-GC, <1ms p99 target.
- **Control plane (Go):** never on the request path. Config, RBAC, audit, cluster mgmt.
- Communication: gRPC over mTLS. Config push is a server-streaming RPC (`Subscribe`).

### Request lifecycle (6+1 phases, Rust data plane)

```
Phase 0: Connection      — TLS, JA4 fingerprint, IP reputation, eBPF/XDP L4
Phase 1: Req Headers     — GeoIP, rate limit, bot detection
Phase 2: Req Body        — CRS rules, payload classifier ML
Phase 3: Upstream        — LB, retries, circuit breaker
Phase 4: Resp Headers    — CSP injection, header rewrite
Phase 5: Resp Body       — DLP scan, content rewrite
Phase 6: Logging         — OTel emit, anomaly score commit
```

Each phase is a hook list. Both rules and WASM plugins register against phases.

### Cluster model

- Control planes: **Raft** (3 or 5 nodes, using `openraft` Rust crate on data side, `hashicorp/raft` on Go side).
- Data planes: stateless workers. They `Subscribe` to the control plane gRPC stream for config, and `ReportStatus` (bidi-streaming) for metrics.
- No CARP/VRRP — clients hit a public L4 LB that fronts the data-plane fleet.

### Multi-tenancy (control plane DB)

PostgreSQL Row-Level Security (RLS). Every tenant-scoped query goes through `BeginTenant(ctx, tenantID, userID)` which sets `SET LOCAL app.current_tenant = ?`. Never bypass this by using a raw connection. See `control-plane/internal/db/db.go`.

---

## Key Technology Choices (locked — do not re-debate)

| Concern | Choice |
|---|---|
| Async runtime | `tokio` (full features) |
| HTTP | `hyper` v1 + `hyper-util` (lowest level, full control) |
| TLS | `rustls` (no OpenSSL) |
| HTTP/3 | `quinn` |
| Rule parser | `pest` or `nom` (TBD, Phase 1 RFC) |
| WASM runtime | `wasmtime` |
| ML inference | `ort` (ONNX Runtime) |
| Deep ML (transformers) | `candle` (Hugging Face pure-Rust) |
| eBPF | `aya` (pure Rust, no libbpf C dependency) |
| Raft | `openraft` (Rust data plane), `hashicorp/raft` (Go control plane) |
| Pattern matching | `aho-corasick` + `regex`; optionally `hyperscan` for DPI |
| Go HTTP framework | `gin` |
| Go gRPC | `grpc-go` |
| Dashboard | Next.js 14 App Router + TypeScript |
| Observability | OpenTelemetry native (traces + metrics + logs) |
| Control-plane DB | PostgreSQL 16 (primary) + Redis 7 + ClickHouse (logs) + S3/MinIO (blobs) |
| Migrations | SQL files in `control-plane/internal/db/migrations/`, applied by `compose.dev.yml` init |

---

## Configuration Schema

Config is YAML; hot-reloaded on `SIGHUP` or via control-plane gRPC push. Reference config: `configs/examples/sentinel.yaml`.

Top-level sections: `cluster`, `listeners`, `sites`, `logging`, `storage`, `ebpf`.

Per-site WAF config (`sites[].waf`) controls: `mode` (off/learning/blocking), `paranoia_level` (1–4, CRS-style), `anomaly_threshold`, `rules`, `ml`, `rate_limit`, `bot_detection`, `dlp`, `api_discovery`, `graphql`, `plugins`.

---

## gRPC / Proto

Proto file: `control-plane/api/proto/config.proto`
Go package: `github.com/your-org/sentinel-waf/control-plane/pkg/proto/sentinelv1`

Three RPCs on `ConfigService`:
- `Subscribe` — server-streaming; data plane calls this to receive config push.
- `ReportStatus` — client-streaming; data plane sends metrics.
- `GetBundle` — unary; used at data-plane boot to pull initial config.

`ConfigBundle` carries compiled rule bytecode, site configs, WASM manifests, and ONNX model refs — all as raw bytes to avoid proto versioning issues on binary blobs.

---

## CI (GitHub Actions)

Four jobs in `.github/workflows/ci.yml`:

| Job | What it does |
|---|---|
| `rust` | `fmt --check`, `clippy -D warnings`, `cargo test`, `cargo build --release` |
| `go` | `go vet`, `go test`, `go build` (cwd: `control-plane/`) |
| `dashboard` | `npm ci`, `npm run lint`, `npm run build` (cwd: `dashboard/`, all `|| true`) |
| `security` | `dependency-review-action` (PRs only) + `gitleaks` secret scan |

The dashboard CI steps use `|| true` because `package.json` doesn't exist yet (Phase 0). Remove those once the dashboard is initialized.

---

## Rust Workspace Notes

- Workspace root `Cargo.toml` pins all shared dependency versions under `[workspace.dependencies]`. Individual crates use `{ workspace = true }` — never specify versions directly in crate `Cargo.toml` files.
- `[profile.release]`: LTO fat, codegen-units=1, strip=true, panic=abort. Do not soften these for benchmarks; use `[profile.bench]` instead (LTO fat, debug=true).
- `[profile.dev]`: opt-level=1 intentionally (faster runtime perf during dev, not just compile speed).
- Minimum Rust version: **1.75**.

---

## Gotchas & Non-obvious Patterns

1. **Most crates are stubs.** `crates/*/src/lib.rs` contains only a single comment. Check before assuming any API exists.

2. **Dashboard has no `package.json` yet.** `npm ci` will fail. The Next.js project needs to be initialized (Phase 0 pending item).

3. **`git init` hasn't been run.** The repo is not a git repo. Check `SAVE1.md` "What Has NOT Been Done Yet" before making assumptions.

4. **eBPF requires a real Linux host kernel.** The `sentinel-ebpf` crate (Aya/XDP) cannot be developed or tested inside a container or macOS. This is one reason the data plane runs natively.

5. **`hyperscan` is optional.** It's listed in workspace dependencies but behind an optional feature. Don't make it required — it has a C dependency that complicates cross-compilation.

6. **RLS bypass prevention.** Never acquire a raw DB connection in the control-plane. Always go through `Pool.BeginTenant()`. The `Open()` function in `db.go` is not implemented yet (returns an error); build the `pgx.go` implementation there.

7. **Config hot-reload signal.** Data plane reloads config on `SIGHUP` or gRPC push. Changes pushed by the control plane should not require a restart.

8. **Dual Raft stacks.** Rust side uses `openraft`; Go side uses `hashicorp/raft`. They serve different cluster memberships (data-plane Raft vs. control-plane Raft). Don't conflate them.

9. **`cargo build --release` is slow.** LTO fat + codegen-units=1 is intentional for release but takes minutes. Use `cargo build` (debug) during development.

10. **Module path placeholder.** `go.mod` uses `github.com/your-org/sentinel-waf/control-plane` — update this to the real org/repo when the GitHub repo is created.

---

## What to Work on Next (from SAVE1.md Phase 0)

Priority order:
1. `git init && git add -A && git commit` (confirm with user first)
2. `crates/sentinel-proxy/src/` — async reverse proxy (hyper + rustls)
3. `crates/sentinel-core/src/config/mod.rs` — YAML config loader (serde_yaml, SIGHUP hot-reload)
4. `crates/sentinel-core/src/context.rs` — request transaction context struct
5. `crates/sentinel-bin/src/main.rs` — real tokio runtime startup
6. `dashboard/package.json` — `npx create-next-app@latest` init
7. `docs/rfcs/0001-rule-dsl.md` — rule language design RFC (Phase 1 prerequisite)

See ROADMAP.md for the full 7-phase plan and perf targets.
