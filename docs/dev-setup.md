# Sentinel WAF — Development Environment

## TL;DR

```bash
# 1. Start infra (databases, etc.) in Docker
./scripts/dev/up.sh

# 2. Run code natively in 3 separate terminals
./scripts/dev/run-controlplane.sh    # Go
./scripts/dev/run-dataplane.sh       # Rust
./scripts/dev/run-dashboard.sh       # Next.js
```

## What goes where

| Component | Where it runs | Why |
|---|---|---|
| **Postgres / Redis / ClickHouse / MinIO / Jaeger** | Docker (compose.dev.yml) | Zero-install, identical to prod, easy reset |
| **Rust data plane** | Native on host | Fast rebuild (cargo incremental), debugger works, eBPF needs host kernel |
| **Go control plane** | Native on host | Fast rebuild, dlv debugger, hot reload via `air` |
| **Next.js dashboard** | Native on host | HMR (hot module replacement) doesn't work well in containers |
| **Python ML training** | `uv` venv in `ml-models/training/` | Offline only — never on request path |

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| Docker + Compose v2 | latest | https://docs.docker.com/get-docker/ |
| Rust | 1.75+ | `curl https://sh.rustup.rs -sSf \| sh` |
| Go | 1.22+ | https://go.dev/dl/ |
| Node | 20+ | https://nodejs.org/ |
| protoc | 25+ | `apt install protobuf-compiler` (for gRPC codegen) |

Optional but recommended:
- `cargo install cargo-watch` — Rust hot reload
- `go install github.com/cosmtrek/air@latest` — Go hot reload
- `uv` (Python pkg mgr) — only if you'll touch ML training

## Three deployment modes

### Mode 1 — Dev (hybrid: infra in Docker, code native)
**Use for daily coding.** Fastest feedback loop.
```bash
./scripts/dev/up.sh
./scripts/dev/run-controlplane.sh
./scripts/dev/run-dataplane.sh
./scripts/dev/run-dashboard.sh
```

### Mode 2 — Full Docker (everything containerized)
**Use for integration tests, demos, or one-command trial.**
```bash
docker compose -f deploy/docker/compose.full.yml up --build
```

### Mode 3 — Production (Kubernetes + Helm)
**Use for real deployment.** Distroless images, managed databases.
```bash
helm install sentinel deploy/helm/sentinel -f my-values.yaml
```

## Why NOT venv?

`venv` is a Python-specific tool. Our runtime stack is Rust + Go + TypeScript. Each has its own dep manager:
- Rust → `cargo` + `target/`
- Go → `go.mod` + module cache
- Node → `node_modules/`

Python only appears later for offline ML model training. That gets `uv` in `ml-models/training/`, isolated from the runtime.

## Why NOT run Rust/Go in Docker during dev?

- Rebuilds are 5–10× slower (volume mount + Linux FS overhead)
- IDE debugger (rust-analyzer, dlv) integration breaks
- Hot-reload (`cargo watch`, `air`) is laggy in containers
- Linux users get zero benefit; Mac/Windows users get the worst path

**Databases in containers, code on host = best of both.**

## Environment variables (dev defaults)

```
SENTINEL_DB_URL          postgres://sentinel:sentinel_dev@localhost:5432/sentinel?sslmode=disable
SENTINEL_REDIS_URL       redis://localhost:6379
SENTINEL_CLICKHOUSE_URL  http://sentinel:sentinel_dev@localhost:8123/sentinel_logs
SENTINEL_S3_ENDPOINT     http://localhost:9002
OTEL_EXPORTER_OTLP_ENDPOINT  http://localhost:4317
RUST_LOG                 info,sentinel=debug
SENTINEL_LOG_LEVEL       debug
```

Override by exporting them before running the scripts.

## Reset everything

```bash
./scripts/dev/down.sh -v       # stop + wipe data volumes
docker system prune -af        # nuclear option
cargo clean
rm -rf control-plane/bin dashboard/.next dashboard/node_modules
```
