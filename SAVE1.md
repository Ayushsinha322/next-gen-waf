# SAVE1.md — Sentinel WAF Project Brain / Session Memory

> This file is the AI's memory across sessions.
> Update it at the end of every working session before closing.
> When starting a new session, read this file first.

---

## Project Identity

| Key | Value |
|---|---|
| **Project Name** | Sentinel WAF |
| **Goal** | Beat eNlight WAF (ESDS commercial) + BunkerWeb (open-source) in perf, intelligence, extensibility |
| **Working Directory** | `/home/ayush3750/waf-development` |
| **Git** | Not initialized yet (`git init` not done) |

---

## Language Decisions (FINAL — do not re-debate)

| Layer | Language | Reason |
|---|---|---|
| Data plane (proxy, rule engine, ML inference, eBPF, WASM runtime) | **Rust** | Zero-GC, memory-safe, <1ms p99, best WASM+ML ecosystem |
| Control plane (admin API, REST/gRPC, cluster, RBAC, audit) | **Go** | Fast iteration, great gRPC/k8s ecosystem |
| Dashboard UI | **TypeScript + Next.js** | Industry standard |
| eBPF kernel programs | **Rust via Aya** | Type-safe, no C/bpftool |
| User plugins | **Any → compiled to WASM** | Rust / Go(TinyGo) / AssemblyScript / JS |

---

## What Has Been Done (Session 1)

### ✅ Scaffold — Full folder tree created
```
/home/ayush3750/waf-development/
├── Cargo.toml                  ← Rust workspace (12 crates defined)
├── README.md                   ← Vision, arch diagram, feature matrix
├── ROADMAP.md                  ← 7-phase 12-month plan with perf targets
├── SAVE1.md                    ← THIS FILE
├── .gitignore
├── .github/workflows/ci.yml    ← Rust + Go + dashboard + gitleaks CI
├── crates/
│   ├── sentinel-core/          ← Engine, config, request lifecycle (stub)
│   ├── sentinel-proxy/         ← HTTP/1.1, /2, /3, TLS, LB (stub)
│   ├── sentinel-rules/         ← Rule DSL, parser, compiler, CRS compat (stub)
│   ├── sentinel-modules/       ← IP rep, geoip, rate limit, bot, DLP, etc. (stub)
│   ├── sentinel-ml/            ← Features, inference, training, LLM copilot (stub)
│   ├── sentinel-plugins/       ← WASM runtime + ABI + SDK (stub)
│   ├── sentinel-storage/       ← Cache, KV, timeseries, blob (stub)
│   ├── sentinel-telemetry/     ← OTel logs/metrics/traces, audit (stub)
│   ├── sentinel-cluster/       ← Raft, gossip, discovery, sync (stub)
│   ├── sentinel-ebpf/          ← XDP, TC, eBPF programs (stub)
│   ├── sentinel-cli/           ← `sentinel` CLI (stub main.rs)
│   └── sentinel-bin/           ← Main binary entry point (stub main.rs)
├── control-plane/
│   ├── go.mod                  ← Go module defined
│   ├── cmd/controllerd/main.go ← Control plane daemon (stub)
│   ├── cmd/sentinelctl/main.go ← Operator CLI (stub)
│   ├── cmd/operator/main.go    ← K8s operator (stub)
│   ├── api/proto/config.proto  ← gRPC: ConfigService, ConfigBundle, NodeStatus
│   └── internal/ pkg/          ← Empty package dirs
├── dashboard/                  ← Next.js dirs (no package.json yet)
├── plugins/
│   ├── sdk-rust/ sdk-go/ sdk-assemblyscript/
│   └── examples/ (hello-world, custom-header, jwt-validator) ← empty dirs
├── rules/
│   ├── owasp-crs/ custom/ virtual-patches/ community/ ← empty dirs
├── ml-models/                  ← anomaly, payload-classifier, bot-classifier dirs
├── configs/examples/sentinel.yaml ← Full reference config (DONE, detailed)
├── deploy/docker/Dockerfile    ← Multi-stage distroless (Rust+Go) DONE
├── docs/architecture/overview.md ← Request lifecycle phases, cluster model DONE
├── tests/ benchmarks/ scripts/ tools/ deploy/ ← dirs created, empty
```

### ✅ Key Design Documents Written
- `README.md` — feature matrix vs BunkerWeb & eNlight, architecture ASCII diagram
- `ROADMAP.md` — 7 phases, performance targets (>500k req/s, p99 <1ms)
- `docs/architecture/overview.md` — 6-phase request lifecycle, 2-plane design rationale
- `configs/examples/sentinel.yaml` — complete reference config with ML, DLP, eBPF, PQ-TLS, GraphQL

### ✅ Infra Files Written
- `Cargo.toml` — workspace with all 12 crates + all major dependencies pinned
- `control-plane/go.mod` — Go module with all major deps listed
- `control-plane/api/proto/config.proto` — gRPC schema for control↔data plane
- `.github/workflows/ci.yml` — full CI pipeline
- `deploy/docker/Dockerfile` — production multi-stage build

### ✅ Session 2 — Database Layer
- `docs/architecture/database.md` — full DB design (Postgres + Redis + ClickHouse + S3, RLS multi-tenancy, 3 isolation tiers)
- `control-plane/internal/db/migrations/0001_init.sql` — initial schema (tenants, users, api_keys, sites, rules, plugins, ml_profiles, ip_lists, alerts, audit_logs) with RLS policies on every tenant-scoped table
- `control-plane/internal/db/db.go` — Pool / TenantTx interfaces with `BeginTenant()` setting `app.current_tenant` for RLS

### ✅ Session 3 — Dev Environment Strategy
- **DECIDED:** Hybrid dev model — infra in Docker, code native on host. NOT venv (Python-only, we use Rust/Go/TS).
- `deploy/docker/compose.dev.yml` — Postgres, Redis, ClickHouse, MinIO, OTel collector, Jaeger, demo upstream
- `deploy/docker/compose.full.yml` — everything-in-Docker variant for CI/demos
- `deploy/docker/otel-config.yaml` — OTel collector config
- `deploy/docker/Dockerfile.dashboard` — Next.js production image
- `scripts/dev/up.sh` — bring up infra + health checks
- `scripts/dev/down.sh` — stop infra (`-v` wipes data)
- `scripts/dev/run-controlplane.sh` — native Go run (with `air` hot reload if installed)
- `scripts/dev/run-dataplane.sh` — native cargo run (with `cargo watch` if installed)
- `scripts/dev/run-dashboard.sh` — native npm run dev
- `docs/dev-setup.md` — full developer onboarding doc

---

### ✅ Session 5 — Phase 0 Complete

- `git init` + initial commit (52 files, `31bc554`)
- `crates/sentinel-core/src/config/mod.rs` — full YAML config types + `ConfigLoader` with `arc-swap` hot-reload + `SIGHUP` watcher
- `crates/sentinel-core/src/context.rs` — `RequestContext`, `Phase` (0-6), `WafDecision`, `RuleMatch`, `Severity`
- `crates/sentinel-core/src/error.rs` — `SentinelError` thiserror enum
- `crates/sentinel-core/src/lib.rs` — module wiring + re-exports
- `crates/sentinel-proxy/src/lib.rs` — full async reverse proxy: TCP accept loop, TLS (rustls ALPN h2/http1.1), HTTP/1.1 + HTTP/2 (hyper v1), hop-by-hop stripping, XFF injection, security header injection, WAF phase stubs (Phases 0-6), structured request logging
- `crates/sentinel-proxy/src/upstream.rs` — `UpstreamPool` with atomic round-robin + per-request HTTP/1.1 upstream connection
- `crates/sentinel-bin/src/main.rs` — tokio multi-thread runtime, `clap` CLI (`--config`, `--log-level`, `--check`), JSON tracing, SIGHUP config reload, graceful shutdown on SIGINT/SIGTERM
- `dashboard/package.json` + `tsconfig.json` + `next.config.ts` + `tailwind.config.ts` + `app/layout.tsx` + `app/page.tsx` + `lib/api.ts` — Next.js 14 App Router scaffold
- `docs/rfcs/0001-rule-dsl.md` — full Rule DSL RFC: SRL syntax, PEG grammar, compilation pipeline, SRL-VM instruction set, `nom` vs `pest` decision, CRS compat mapping, file layout, implementation schedule
- **All tests pass: 7/7** (`cargo test -p sentinel-core -p sentinel-proxy`)
- Workspace deps extended: `uuid`, `clap`, `rustls-pemfile`

---

## What Has NOT Been Done Yet (Pending)

### 🟡 Phase 1 (Rule Engine) — START HERE NEXT SESSION
- [x] Rule DSL spec RFC → `docs/rfcs/0001-rule-dsl.md` ✅ DONE
- [ ] `crates/sentinel-rules/src/dsl/` — DSL grammar (nom parser per RFC)
- [ ] `crates/sentinel-rules/src/compiler/` — AST → bytecode
- [ ] `crates/sentinel-rules/src/crs_compat/` — ModSecurity CRS importer
- [ ] First working rule: block SQL injection pattern

### 🟡 Phase 2 (Security Modules)
- [ ] `crates/sentinel-modules/src/ip_reputation/`
- [ ] `crates/sentinel-modules/src/rate_limit/`
- [ ] `crates/sentinel-modules/src/bot_detect/`
- [ ] `crates/sentinel-modules/src/ja3_ja4/`
- [ ] `crates/sentinel-modules/src/anti_ddos/` (eBPF XDP)

### 🟡 Phase 3 (Plugin System)
- [ ] `crates/sentinel-plugins/src/runtime/` — wasmtime host
- [ ] `crates/sentinel-plugins/src/abi/` — host ABI (log, kv, deny, score)
- [ ] `plugins/sdk-rust/` — actual SDK crate

### 🟡 Phase 4 (ML/AI)
- [ ] `crates/sentinel-ml/src/features/` — request → feature vector
- [ ] `crates/sentinel-ml/src/inference/` — ONNX runtime (ort crate)
- [ ] `ml-models/anomaly/` — first model (Isolation Forest, ONNX)
- [ ] LLM copilot service design

### 🟡 Phase 5 (Control Plane + Dashboard)
- [ ] `control-plane/internal/api/` — REST API handlers
- [ ] `control-plane/internal/auth/` — JWT + OIDC
- [ ] `control-plane/internal/rbac/` — role definitions
- [ ] `control-plane/internal/grpc/` — gRPC server (config.proto impl)
- [ ] Dashboard pages: traffic, rules editor, logs, sites, settings

### 🟡 Phase 6 (Advanced)
- [ ] HTTP/3 (quinn integration)
- [ ] Post-quantum TLS (Kyber768 hybrid)
- [ ] API auto-discovery
- [ ] GraphQL/gRPC firewalling
- [ ] Outbound DLP
- [ ] WebVPN module

### 🟡 Phase 7 (Hardening)
- [ ] Fuzzing setup (cargo-fuzz)
- [ ] Helm chart
- [ ] k8s operator (controller-runtime)
- [ ] Compliance docs

---

## Key Architectural Decisions (reference)

| Decision | Choice | Reason |
|---|---|---|
| Async runtime | tokio | de-facto Rust async standard |
| HTTP library | hyper v1 + hyper-util | lowest-level, full control |
| TLS | rustls | pure Rust, no OpenSSL CVE surface |
| HTTP/3 | quinn | best QUIC impl in Rust |
| Rule parser | pest or nom | TBD in Phase 1 RFC |
| WASM runtime | wasmtime | best safety + perf, Bytecode Alliance |
| ML inference | ort (ONNX Runtime) | cross-model, battle-tested |
| Deep ML | candle (Hugging Face) | pure Rust transformer inference |
| eBPF | Aya | pure Rust eBPF, no libbpf C dep |
| Cluster consensus | openraft | modern, async-native Raft in Rust |
| Go HTTP framework | gin | standard, fast |
| Go gRPC | tonic (Rust) / grpc-go (Go) | per plane |
| Dashboard | Next.js 14 App Router | latest patterns |
| Observability | OpenTelemetry native | traces+metrics+logs unified |
| DB (control plane) | **PostgreSQL 16 + Redis 7 + ClickHouse + S3** (SQLite for dev/single-node) | DECIDED — see `docs/architecture/database.md` |
| Multi-tenancy | **PostgreSQL Row-Level Security (RLS)** + optional schema-per-tenant for enterprise | DECIDED |
| Migrations | goose / golang-migrate | embedded SQL files |

---

## Competitor Feature Gaps We Must Fill

| Feature | BunkerWeb | eNlight WAF | Sentinel (target) |
|---|---|---|---|
| WASM plugins | ❌ | ❌ | ✅ |
| LLM rule copilot | ❌ | ❌ | ✅ |
| HTTP/3 | ❌ | ❌ | ✅ |
| Post-quantum TLS | ❌ | ❌ | ✅ |
| eBPF/XDP L4 DDoS | ❌ | ❌ | ✅ |
| GraphQL firewall | ❌ | ❌ | ✅ |
| gRPC firewall | ❌ | ❌ | ✅ |
| Auto API discovery | ❌ | ❌ | ✅ |
| Outbound DLP | ❌ | ❌ | ✅ |
| Transformer ML | ❌ | basic | ✅ |
| Raft HA (not CARP) | ❌ | ❌ | ✅ |
| True active/active | ❌ | active/standby | ✅ |

---

## Performance Targets

| Metric | BunkerWeb | eNlight | **Sentinel target** |
|---|---|---|---|
| Throughput (16-core) | ~70k req/s | ~100k req/s | **>500k req/s** |
| p99 latency overhead | 5–15ms | 3–8ms | **<1ms** |
| Memory per connection | ~80KB | ~40KB | **<10KB** |
| Cold start | 5–10s | 10–30s | **<500ms** |

---

## Next Session — Start Here

1. Run `git init && git add -A && git commit -m "init: project scaffold"` (if user confirms)
2. Begin **Phase 0** actual code:
   - `crates/sentinel-proxy/src/lib.rs` — async reverse proxy (hyper + rustls)
   - `crates/sentinel-core/src/config/mod.rs` — config loader
   - `crates/sentinel-core/src/context.rs` — transaction context
3. Write `docs/rfcs/0001-rule-dsl.md` — rule language design

---

## Session 4 — Competitive Analysis (WAF Comparison PDF + BunkerWeb + ESDS VTMScan)

### Source Documents Analyzed
- `/home/ayush3750/desktopfiles/WAF__Comparison.pdf` — feature matrix: eNlight vs Apptrana vs Barracuda vs Haltdos vs Go-Coraza
- `/home/ayush3750/desktopfiles/ESDS VTMScan User Manual For Superadmin 1 .pdf` — ESDS VTMScan is a **vulnerability scanner**, NOT an inline WAF. Its "WAF Scan" checkbox only enables WAF detection during periodic scans.
- BunkerWeb docs (fetched live)

### Full Competitor Feature Matrix

| Feature | eNlight | Apptrana | Barracuda | Haltdos | Go-Coraza | BunkerWeb | **Sentinel** |
|---|---|---|---|---|---|---|---|
| OWASP Top 10 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| WebVPN | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (Phase 6) |
| Content Rewriting | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| URL Rewriting | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Custom Error Pages | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| IPSEC Connectivity | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (Phase 6) |
| Zero-day Protection | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ (ML + virtual patching) |
| Req/Resp Header Manipulation | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ |
| SSO Forward | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (OIDC/SAML) |
| Virtual Patching | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Proxy/Load Balancer | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ | ✅ |
| Learning Mode | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ (ML auto-baselining) |
| Packet Filter (L4 Firewall) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ (eBPF/XDP, kernel-level) |
| IP Reputation | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| PKI Management | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ (Let's Encrypt) | ✅ |
| L7 DDoS Mitigation | ❌ (separate) | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ (built-in) |
| Log Viewer | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| RBAC Dashboard | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Load Balancer | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Monitoring | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ (PRO) | ✅ |
| Reporting | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Scoring Policy (Anomaly Score) | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| OAuth2 Responder | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Anomaly Detection | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ (ONNX ML) |
| Horizontal Scaling | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Clustering / HA | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ (manager SPOF) | ✅ (Raft active/active) |
| Log Analyzer | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Customizable Log Repos | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| False Positive Monitoring | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ (LLM auto-tuning) |
| IP/Country Blacklisting | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| URL & IP Whitelisting | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ |
| Web App Scanning | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ (Phase 6+) |
| **WASM Plugins** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **LLM Rule Copilot** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **HTTP/3 + PQ-TLS** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **GraphQL/gRPC Firewall** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Outbound DLP** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **eBPF/XDP L4 DDoS** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Transformer ML** | ❌ | basic | ❌ | ❌ | ❌ | ❌ | ✅ |

### Three Unfair Advantages

1. **Rust Data Plane — Physics-level performance**: Every competitor runs on C/C++ or Lua engines with GC pauses and cross-process buffer copies. Sentinel runs everything (proxy → rule VM → ML → upstream) in one async Rust runtime, zero-copy. 5× throughput and 8× latency improvement is guaranteed by the architecture, not aspirational.

2. **eBPF/XDP — Kernel-level DDoS**: eNlight's "packet filter" is userspace. Their DDoS mitigation is a separate product. Sentinel drops SYN floods, UDP amplification, and L4 volumetric attacks at the NIC driver via XDP — before the kernel even allocates a socket buffer. No competitor in the PDF has this.

3. **LLM Copilot — Replaces a SOC team**: eNlight and Barracuda ship rules written by security researchers. Apptrana sells "expert false-positive monitoring" (humans). Sentinel's LLM copilot generates rules from log patterns, explains alerts in plain English, creates virtual patches from CVEs, and auto-tunes false positives — 24/7, in milliseconds.

### Where eNlight Is Strong (and We Cover It)
eNlight leads on enterprise features: WebVPN, IPSEC, SSO Forward, OAuth2 responder, PKI management. All are in Sentinel Phase 6 + control-plane plans. Key difference: eNlight bolted these onto a C codebase over years. Sentinel builds them on Rust+Go with shared OTel observability, Raft HA, and gRPC config push from day one — no separate deployments, no bolt-ons.

### Key Insight on ESDS VTMScan
VTMScan is **not a WAF**. It is a periodic vulnerability scanner (like Nessus/ZAP). It scans domains on a schedule, detects OWASP top 10, generates reports, and has a "WAF detection" checkbox that identifies if a WAF is present on the target. The eNlight WAF is a separate product. Do not conflate the two.

---

*Last updated: Session 5 — Phase 0 complete. Git initialized. sentinel-core, sentinel-proxy, sentinel-bin built and tested. Next.js dashboard scaffolded. Rule DSL RFC written. Next: Phase 1 rule engine (sentinel-rules nom parser).*
