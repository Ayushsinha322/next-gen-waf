# Sentinel WAF — Deployment / VM Specification Sheet

> Hand-off doc for infra provisioning. All values derived from the actual
> deploy manifests (`deploy/docker`, `deploy/systemd`, `deploy/ansible`).

---

## 1 · Component Overview — What Runs Where

| # | Component | Language / Image | Stateful? | Role |
|---|-----------|------------------|-----------|------|
| 1 | **Data Plane** (`sentinel-bin`) | Rust (distroless/cc) | No (stateless) | Inspects & proxies all HTTP traffic |
| 2 | **Control Plane** (`controllerd`) | Go (distroless/static) | Yes (Raft state on disk) | Config, RBAC, audit, Raft cluster |
| 3 | **Dashboard** | Next.js / Node | No | Admin UI |
| 4 | **PostgreSQL 16** | postgres:16-alpine | Yes | System of record |
| 5 | **Redis 7** | redis:7-alpine | Semi (AOF) | Rate-limit counters, cache |
| 6 | **ClickHouse 24** | clickhouse:24-alpine | Yes | Request logs / analytics |
| 7 | **MinIO (or S3)** | minio/minio | Yes | ML models, backups, object store |
| 8 | **OTel Collector + Jaeger** | otel-collector / jaeger | No | Tracing & metrics (optional) |

---

## 2 · Recommended VM Layout (Production — HA)

> Control plane runs **3 Raft nodes** to tolerate 1 failure. Data plane scales
> horizontally behind the load balancer.

| VM | Hostname | Role | vCPU | RAM | Disk | OS |
|----|----------|------|:----:|:---:|------|----|
| VM-1 | `waf-cp-1` | Control plane (Raft node 1) + Postgres primary | 4 | 8 GB | 100 GB SSD | Ubuntu 22.04 LTS |
| VM-2 | `waf-cp-2` | Control plane (Raft node 2) + Postgres replica | 4 | 8 GB | 100 GB SSD | Ubuntu 22.04 LTS |
| VM-3 | `waf-cp-3` | Control plane (Raft node 3) | 2 | 4 GB | 50 GB SSD | Ubuntu 22.04 LTS |
| VM-4 | `waf-dp-1` | Data plane proxy | 4 | 8 GB | 40 GB SSD | Ubuntu 22.04 LTS |
| VM-5 | `waf-dp-2` | Data plane proxy | 4 | 8 GB | 40 GB SSD | Ubuntu 22.04 LTS |
| VM-6 | `waf-data` | ClickHouse + Redis + MinIO | 4 | 16 GB | 250 GB SSD | Ubuntu 22.04 LTS |
| VM-7 | `waf-ui` | Dashboard (Next.js) | 2 | 4 GB | 30 GB SSD | Ubuntu 22.04 LTS |

**Total (prod HA): 7 VMs · 24 vCPU · 56 GB RAM · ~610 GB SSD**

### Minimal / PoC Layout (single box — all-in-one Docker)

| VM | Role | vCPU | RAM | Disk | OS |
|----|------|:----:|:---:|------|----|
| VM-1 | Everything via `compose.full.yml` | 8 | 16 GB | 200 GB SSD | Ubuntu 22.04 LTS |

---

## 3 · Per-Component Resource Detail

### Data Plane (Rust) — CPU-bound, latency-critical
- **vCPU:** 4 min (8 for >10k rps). Scales with traffic.
- **RAM:** 8 GB (rule engine + ML models loaded in memory).
- **Disk:** 40 GB (binary, config, local log buffer).
- **Special:** needs `CAP_NET_BIND_SERVICE` (bind 80/443) and
  `CAP_NET_ADMIN` + `CAP_SYS_RESOURCE` (eBPF/XDP L4 filtering).
- **Stateless** — add/remove nodes freely; LB health-checks handle failover.

### Control Plane (Go) — Raft cluster
- **vCPU:** 2–4. **RAM:** 4–8 GB.
- **Disk:** SSD required — Raft persists `raft_state.json` (fsync on every
  write). 50–100 GB.
- **Count:** **3 nodes** (tolerate 1 failure) or **5 nodes** (tolerate 2).
  Never run 2 — any failure stalls writes.
- Low-latency network between Raft nodes (heartbeat every 100 ms).

### PostgreSQL 16 — system of record
- **vCPU:** 4. **RAM:** 8 GB. **Disk:** 100 GB SSD (grows with sites/rules).
- Run primary + streaming replica for HA.

### ClickHouse 24 — log analytics
- **vCPU:** 4. **RAM:** 16 GB (loves RAM). **Disk:** 250 GB+ (log volume driven).
- `ulimit nofile = 262144` required.

### Redis 7
- **vCPU:** 1–2. **RAM:** 2 GB (`maxmemory 512mb`, AOF persistence).

### MinIO / S3
- Use managed S3 (AWS S3 / GCS) in cloud, or MinIO VM with 100 GB+.

---

## 4 · Network / Port Map (Firewall Rules)

| Port | Proto | Component | Exposure | Purpose |
|------|-------|-----------|----------|---------|
| 80 | TCP | Data plane | **Public** | HTTP ingress |
| 443 | TCP | Data plane | **Public** | HTTPS ingress |
| 443 | UDP | Data plane | **Public** | HTTP/3 (QUIC) |
| 9500 | TCP | Control plane | Internal | gRPC config push → data plane |
| 9501 | TCP | Control plane | Internal | REST admin API |
| 9502 | TCP | Control plane | **Raft inter-node only** | Raft RPC node 1 |
| 9602 | TCP | Control plane | **Raft inter-node only** | Raft RPC node 2 |
| 9702 | TCP | Control plane | **Raft inter-node only** | Raft RPC node 3 |
| 3000 | TCP | Dashboard | Internal/VPN | Admin UI |
| 5432 | TCP | PostgreSQL | Internal | DB |
| 6379 | TCP | Redis | Internal | Cache |
| 8123 | TCP | ClickHouse | Internal | HTTP query |
| 9000 | TCP | ClickHouse | Internal | Native protocol |
| 9002 | TCP | MinIO | Internal | S3 API |
| 4317 | TCP | OTel | Internal | OTLP gRPC |

> **Public-facing:** only ports 80 / 443 (TCP+UDP) on the data plane.
> Everything else stays on the private/internal subnet.

---

## 5 · Software Prerequisites (per VM)

| Need | Version | Notes |
|------|---------|-------|
| OS | Ubuntu 22.04 LTS (or RHEL 9 / Debian 12) | 64-bit, kernel ≥ 5.15 for eBPF |
| Docker Engine | ≥ 24.x | if using container deploy |
| Docker Compose | v2 | for `compose.full.yml` |
| systemd | — | for bare-metal deploy (unit files in `deploy/systemd/`) |
| Kernel | ≥ 5.15 | eBPF/XDP support on data plane VMs |

**Build toolchain (only if compiling from source — not needed for prod images):**
Rust 1.82, Go 1.22, Node 18+, protobuf-compiler, clang, cmake.

---

## 6 · Required Environment / Secrets (provision before deploy)

| Variable | Component | Example | Notes |
|----------|-----------|---------|-------|
| `SENTINEL_DB_URL` | Control plane | `postgres://user:pass@host:5432/sentinel` | use TLS in prod |
| `SENTINEL_REDIS_URL` | Control plane | `redis://host:6379` | |
| `SENTINEL_CLICKHOUSE_URL` | Control plane | `http://user:pass@host:8123/sentinel_logs` | |
| `SENTINEL_S3_ENDPOINT` | Control plane | `https://s3.region.amazonaws.com` | |
| `SENTINEL_JWT_SECRET` | Control plane | random 64-char string | **must change from default** |
| `SENTINEL_REST_ADDR` | Control plane | `0.0.0.0:9501` | |
| `SENTINEL_GRPC_ADDR` | Control plane | `0.0.0.0:9500` | |
| `SENTINEL_CONFIG` | Data plane | `/etc/sentinel/sentinel.yaml` | |
| TLS certs | Data plane | per-site certs | for HTTPS termination |

---

## 7 · External Dependencies Checklist

- [ ] **Load balancer / Anycast IP** in front of the data-plane fleet (L4, with
      health checks). No VRRP/CARP needed.
- [ ] **PostgreSQL 16** reachable from all control-plane nodes.
- [ ] **Redis 7** reachable from control + data plane.
- [ ] **ClickHouse 24** for log ingestion.
- [ ] **S3-compatible bucket** (AWS S3 / GCS / MinIO) for models + backups.
- [ ] **DNS** pointing customer domains → LB public IP.
- [ ] **TLS certificates** for each protected site.
- [ ] Private subnet / security group isolating internal ports.

---

## 8 · TL;DR for the Tech Lead

```
Production HA = 7 VMs:
  • 3 × control-plane  (Raft cluster — survives 1 node loss)
  • 2 × data-plane     (stateless, behind load balancer)
  • 1 × data services  (Postgres + Redis + ClickHouse + MinIO)
  • 1 × dashboard

OS:        Ubuntu 22.04 LTS (kernel ≥ 5.15 for eBPF on data plane)
Total:     24 vCPU · 56 GB RAM · ~610 GB SSD
Public:    only ports 80 / 443 (TCP + UDP) on the data plane
Critical:  control-plane disk MUST be SSD (Raft fsync per write)
PoC:       single 8 vCPU / 16 GB / 200 GB box via compose.full.yml
```
