# Sentinel WAF — High-Level Architecture

## 1. Two-plane design

**Data plane (Rust):** every request flows through here. Optimized for tail latency.
**Control plane (Go):** never on the request path. Manages config, RBAC, audit, dashboards.

This separation lets us use the right language for each job and lets us scale them independently.

## 2. Request lifecycle (Rust data plane)

```
       ┌─────────────────────────────────────────────────────────────┐
       │  Phase 0: Connection (TLS, JA4 fp, IP rep, eBPF L4)         │
       └────┬────────────────────────────────────────────────────────┘
            │
       ┌────▼────────────────────────────────────────────────────────┐
       │  Phase 1: Request Headers (geoip, rate limit, bot detect)   │
       └────┬────────────────────────────────────────────────────────┘
            │
       ┌────▼────────────────────────────────────────────────────────┐
       │  Phase 2: Request Body (CRS rules, payload classifier ML)   │
       └────┬────────────────────────────────────────────────────────┘
            │
       ┌────▼────────────────────────────────────────────────────────┐
       │  Phase 3: Upstream forward (LB, retries, circuit breaker)   │
       └────┬────────────────────────────────────────────────────────┘
            │
       ┌────▼────────────────────────────────────────────────────────┐
       │  Phase 4: Response Headers (CSP injection, header rewrite)  │
       └────┬────────────────────────────────────────────────────────┘
            │
       ┌────▼────────────────────────────────────────────────────────┐
       │  Phase 5: Response Body (DLP scan, content rewrite)         │
       └────┬────────────────────────────────────────────────────────┘
            │
       ┌────▼────────────────────────────────────────────────────────┐
       │  Phase 6: Logging (OTel emit, anomaly score commit)         │
       └─────────────────────────────────────────────────────────────┘
```

Every phase is a hook list; rules and WASM plugins register against phases.

## 3. Why Rust + Go (not pure Go, not pure Rust)

- **Pure Rust:** great perf, but slower iteration on REST/admin code, smaller hiring pool.
- **Pure Go:** GC pauses kill p99, regex slower, weaker WASM/ML ecosystem.
- **Hybrid:** data-plane perf where it matters, fast development for everything else.

Communication: gRPC over mTLS, with config push as a server-streaming RPC.

## 4. Cluster model (HA)

Control planes run **Raft** (3 or 5 nodes). Data planes are stateless workers; they
subscribe to config and report metrics. No CARP/VRRP needed — clients hit a public
LB or anycast IP that fronts the data-plane fleet. Failover is automatic via L4 LB
health checks.

## 5. Plugin model

WASM modules conforming to the Sentinel ABI. Sandboxed via wasmtime, hot-swappable,
with explicit capability grants (can_block, can_call_http, can_kv_write, etc.).

## 6. AI/ML positioning

- **Inline (every request):** lightweight payload classifier (~2ms) + isolation forest.
- **Near-line (async sampling):** transformer-based deep analysis on suspicious requests.
- **Offline (control plane):** training, drift detection, LLM rule-copilot.

The control plane owns model lifecycle; data planes only run inference.
