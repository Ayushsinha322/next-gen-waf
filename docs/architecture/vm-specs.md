# Sentinel WAF — VM Specification Request

> Infra provisioning request. Two phases: **MVP / PoC** (now) and **Production** (HA).

---

## PHASE 1 — MVP / PoC

**Goal:** working end-to-end demo, single-region, no high-availability.
**Approach:** all components on a small number of boxes (Docker Compose / single Raft node).

### Option A — Single Box (fastest, cheapest)

| VM | Role | vCPU | RAM | Disk | OS |
|----|------|:----:|:---:|------|----|
| poc-all-in-one | Everything (data + control + dashboard + Postgres + Redis + ClickHouse + MinIO) via Docker Compose | 8 | 16 GB | 200 GB SSD | Ubuntu 22.04 LTS |

**Total: 1 VM · 8 vCPU · 16 GB RAM · 200 GB SSD**

### Option B — 3 Boxes (more realistic PoC, separates concerns)

| VM | Role | vCPU | RAM | Disk | OS |
|----|------|:----:|:---:|------|----|
| poc-waf | Data plane + Control plane (single Raft node) | 4 | 8 GB | 60 GB SSD | Ubuntu 22.04 LTS |
| poc-data | PostgreSQL + Redis + ClickHouse + MinIO | 4 | 8 GB | 150 GB SSD | Ubuntu 22.04 LTS |
| poc-ui | Dashboard | 2 | 4 GB | 30 GB SSD | Ubuntu 22.04 LTS |

**Total: 3 VMs · 10 vCPU · 20 GB RAM · 240 GB SSD**

> PoC note: a **single** Raft node is fine here — no HA, just functional. No load balancer required.

---

## PHASE 2 — PRODUCTION (High Availability)

**Goal:** survive 1 node failure, scale data plane with traffic, no single point of failure.
**Approach:** 3-node Raft control plane + horizontally scaled data plane behind a load balancer.

| # | VM | Role | vCPU | RAM | Disk | OS |
|---|----|------|:----:|:---:|------|----|
| 1 | waf-cp-1 | Control plane (Raft node 1) | 4 | 8 GB | 100 GB **SSD** | Ubuntu 22.04 LTS |
| 2 | waf-cp-2 | Control plane (Raft node 2) | 4 | 8 GB | 100 GB **SSD** | Ubuntu 22.04 LTS |
| 3 | waf-cp-3 | Control plane (Raft node 3) | 2 | 4 GB | 50 GB **SSD** | Ubuntu 22.04 LTS |
| 4 | waf-dp-1 | Data plane proxy | 4 | 8 GB | 40 GB SSD | Ubuntu 22.04 LTS |
| 5 | waf-dp-2 | Data plane proxy | 4 | 8 GB | 40 GB SSD | Ubuntu 22.04 LTS |
| 6 | waf-data | PostgreSQL + Redis + ClickHouse + MinIO* | 8 | 16 GB | 250 GB SSD | Ubuntu 22.04 LTS |
| 7 | waf-ui | Dashboard | 2 | 4 GB | 30 GB SSD | Ubuntu 22.04 LTS |

**Total: 7 VMs · 28 vCPU · 56 GB RAM · ~610 GB SSD**

\* In production we recommend replacing the `waf-data` box with **managed
services** (AWS RDS / ClickHouse Cloud / ElastiCache / S3) instead of
self-hosting. If managed, drop VM #6.

### Plus 1 external dependency (not a VM we manage)
- **Load balancer / Anycast public IP** in front of `waf-dp-1` / `waf-dp-2`
  (cloud LB or hardware LB). Handles failover via health checks.

---

## Hard Requirements (apply to both phases)

| Requirement | Detail |
|-------------|--------|
| **OS** | Ubuntu 22.04 LTS (or RHEL 9 / Debian 12), 64-bit |
| **Kernel** | ≥ 5.15 on **data plane** VMs (needed for eBPF / XDP) |
| **Disk type** | Control-plane VMs **MUST be SSD** (Raft fsyncs to disk on every write) |
| **Public ports** | Only **80 / 443 TCP + 443 UDP** exposed (data plane). All else private subnet. |
| **Raft node count** | Production = **3 nodes** (never 2 — 2 cannot tolerate any failure) |
| **Network** | Low latency between Raft nodes (heartbeat every 100 ms) |

---

## Summary

```
┌──────────────────────────────────────────────────────────────┐
│  MVP / PoC                                                    │
│  • Option A: 1 VM  ·  8 vCPU · 16 GB · 200 GB SSD            │
│  • Option B: 3 VMs · 10 vCPU · 20 GB · 240 GB SSD  (preferred)│
│  • No load balancer, single Raft node, no HA                 │
├──────────────────────────────────────────────────────────────┤
│  PRODUCTION (HA)                                              │
│  • 7 VMs · 28 vCPU · 56 GB RAM · ~610 GB SSD                 │
│  • 3-node Raft cluster (survives 1 node failure)             │
│  • Data plane scales horizontally behind a load balancer     │
│  • + 1 cloud load balancer (external)                        │
│  • Recommended: use managed Postgres/Redis/ClickHouse/S3     │
│    → if managed, drops to 6 self-managed VMs                 │
├──────────────────────────────────────────────────────────────┤
│  OS everywhere: Ubuntu 22.04 LTS · kernel ≥ 5.15            │
│  Control-plane disks MUST be SSD                            │
│  Public exposure: only ports 80 / 443                       │
└──────────────────────────────────────────────────────────────┘
```
