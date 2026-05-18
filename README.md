# Sentinel WAF

A next-generation, high-performance Web Application Firewall written in **Rust** (data plane) and **Go** (control plane), designed to surpass commercial WAFs (eNlight WAF) and open-source WAFs (BunkerWeb, ModSecurity) in performance, extensibility, and intelligence.

## Why Sentinel?

| Differentiator | Description |
|---|---|
| **Rust data plane** | Zero-GC, memory-safe, p99 latency under 1ms |
| **WASM plugin system** | Write extensions in Rust, Go, AssemblyScript, JS |
| **AI/ML built-in** | Transformer-based payload classification, anomaly detection, LLM rule-copilot |
| **eBPF L4 protection** | Kernel-level DDoS mitigation via XDP |
| **HTTP/3 + Post-Quantum TLS** | Future-proof crypto (Kyber/Dilithium hybrid) |
| **API-aware** | OpenAPI auto-discovery, GraphQL/gRPC schema firewalling |
| **Egress DLP** | Outbound PII/secret leak prevention |
| **Raft clustering** | True active/active HA, no CARP/VRRP limits |
| **OTel native** | Traces, metrics, logs out of the box |

## Architecture

```
                    ┌────────────────────────────────────┐
                    │         Internet / Clients         │
                    └────────────────┬───────────────────┘
                                     │
                    ┌────────────────▼───────────────────┐
                    │   eBPF/XDP L4 filter (kernel)      │
                    └────────────────┬───────────────────┘
                                     │
   ┌─────────────────────────────────▼────────────────────────────────┐
   │                  SENTINEL DATA PLANE (Rust)                      │
   │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
   │ │ TLS/QUIC │→│ HTTP P.  │→│ Rule Eng │→│ ML Infer │→│ Upstream │ │
   │ └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
   │       ↕             ↕            ↕            ↕            ↕     │
   │   WASM plugins · IP rep · GeoIP · Rate limit · Bot · DLP · ...   │
   └────────────────────────┬─────────────────────────────────────────┘
                            │ gRPC
   ┌────────────────────────▼─────────────────────────────────────────┐
   │              CONTROL PLANE (Go) — Raft cluster                   │
   │   Admin API · RBAC · Audit · Config · Multi-tenant orchestrator  │
   └────────────────────────┬─────────────────────────────────────────┘
                            │
              ┌─────────────▼─────────────┐
              │  Dashboard (Next.js + TS) │
              └───────────────────────────┘
```

## Repository Layout

```
sentinel/
├── crates/                    # Rust workspace (data plane)
│   ├── sentinel-core/         # Engine, config, request lifecycle
│   ├── sentinel-proxy/        # HTTP/1.1, HTTP/2, HTTP/3, TLS, LB
│   ├── sentinel-rules/        # Rule DSL, parser, compiler, CRS compat
│   ├── sentinel-modules/      # Security modules (IP rep, rate limit, bot, etc.)
│   ├── sentinel-ml/           # ML feature extraction & inference
│   ├── sentinel-plugins/      # WASM runtime + plugin ABI + SDKs
│   ├── sentinel-storage/      # Cache, KV, time-series, blob abstractions
│   ├── sentinel-telemetry/    # OTel logs/metrics/traces, audit
│   ├── sentinel-cluster/      # Raft, gossip, discovery, config sync
│   ├── sentinel-ebpf/         # XDP/TC programs (L4 DDoS, fingerprint)
│   ├── sentinel-cli/          # `sentinel` CLI (data-plane node)
│   └── sentinel-bin/          # Main binary entry point
│
├── control-plane/             # Go control plane
│   ├── cmd/
│   │   ├── controllerd/       # Main control plane daemon
│   │   ├── sentinelctl/       # Operator CLI
│   │   └── operator/          # Kubernetes operator
│   ├── internal/              # Private packages
│   │   ├── api/ auth/ rbac/ audit/ config/ cluster/ db/ grpc/ rest/
│   ├── pkg/                   # Public packages (importable)
│   └── api/proto/             # protobuf definitions
│
├── dashboard/                 # Next.js + TypeScript admin UI
│
├── plugins/
│   ├── sdk-rust/              # Plugin SDK (Rust)
│   ├── sdk-go/                # Plugin SDK (Go via TinyGo→WASM)
│   ├── sdk-assemblyscript/    # Plugin SDK (AS)
│   └── examples/              # Reference plugins
│
├── rules/
│   ├── owasp-crs/             # OWASP Core Rule Set (vendored)
│   ├── custom/                # Sentinel-native rules
│   ├── virtual-patches/       # Auto-generated from scanner reports
│   └── community/             # Community-contributed
│
├── ml-models/                 # Pre-trained ONNX models + training data
│
├── configs/                   # YAML configs (dev/staging/prod/examples)
├── deploy/                    # Docker, K8s, Helm, Terraform, Ansible, systemd
├── tests/                     # integration / e2e / fuzz / load / security
├── benchmarks/                # wrk, k6, vegeta scripts
├── docs/                      # Architecture, user guide, API, RFCs
├── scripts/                   # Dev, release, benchmark, migration scripts
└── tools/                     # Rule converter, log analyzer, debug CLI
```

## Quick Start

```bash
# Build data plane
cargo build --release --workspace

# Build control plane
cd control-plane && go build ./...

# Run in dev mode
./scripts/dev/up.sh
```

See [docs/architecture/](docs/architecture/) for design details and [ROADMAP.md](ROADMAP.md) for the development plan.

## License

Copyright © 2026 ESDS Networks Pvt. Ltd. All rights reserved.
This software is proprietary and confidential. See [LICENSE](LICENSE) for details.
