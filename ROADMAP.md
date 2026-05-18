# 🛡️ Sentinel WAF — Team Roadmap

> **Mission:** Build the world's fastest, most intelligent, and most extensible Web Application Firewall.
> Beat every commercial WAF on performance. Beat every open-source WAF on features. Ship what no one else has.

---

## 📍 Where We Stand Today

```
 DONE ████████████████████████████████░░░░░░░░  Phases 0–5 Complete (226/226 tests)
 NOW  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░  Phase 6 — Advanced Features
```

**Phases 0–5 complete:** Rule engine, security modules, WASM plugin system, ML/AI engine, eBPF XDP, Raft cluster, Go control plane (REST + gRPC + RBAC + audit), sentinelctl CLI, 15-route dashboard — all done. 226/226 Rust tests pass. 18/18 Go tests pass.

---

## 🗺️ The 7-Phase Plan (12 Months to v1.0)

---

### ⚙️ Phase 0 — Foundations
**Weeks 1–3 | "It works. It proxies. It measures."**

> Get a real binary running. Traffic flows through Sentinel. We can benchmark it.

| Task | Owner | Status |
|---|---|---|
| Repo scaffold, CI/CD, workspace | — | ✅ Done |
| `sentinel-proxy` — hyper v1 + rustls reverse proxy | — | ✅ Done |
| `sentinel-core` — YAML config loader + SIGHUP hot-reload | — | ✅ Done |
| `sentinel-bin` — tokio multi-thread runtime, graceful shutdown | — | ✅ Done |
| Structured JSON logging (tracing crate) | — | ✅ Done |
| Pre-commit hooks (clippy, gofmt, eslint) | — | ✅ Done |
| Dashboard Next.js init (`package.json`) | — | ✅ Done |

**✅ Exit Criteria:** `curl https://localhost:8443` hits upstream. Benchmark recorded. CI green.

---

### 🔥 Phase 1 — Core WAF Engine
**Weeks 4–10 | "It blocks. Better than ModSecurity. Faster than everything."**

> Custom rule engine from scratch. No ModSecurity. No NGINX. Our bytecode VM.

| Task | Owner | Status |
|---|---|---|
| Rule DSL design RFC (`docs/rfcs/0001-rule-dsl.md`) | — | ✅ Done |
| DSL parser → AST (pest/nom) | — | ✅ Done |
| AST → bytecode compiler | — | ✅ Done |
| 6-phase hook system (conn → req_headers → req_body → resp_headers → resp_body → log) | — | ✅ Done |
| OWASP CRS v4 compatibility importer | — | ✅ Done |
| Transaction context (variables, collections, anomaly score) | — | ✅ Done |
| Action library (deny, allow, log, redirect, challenge, tag, score, rewrite) | — | ✅ Done |
| Per-site policy isolation | — | ✅ Done |
| Hot rule reload — zero dropped connections | — | ✅ Done |

**✅ Exit Criteria:** SQLi, XSS, RFI, LFI, SSRF all blocked. Benchmark shows 3× faster than ModSecurity.

---

### 🛡️ Phase 2 — Security Modules
**Weeks 11–18 | "It's smart. The kernel kills DDoS. Rules miss nothing."**

> This is where we pull ahead of every open-source WAF permanently.

| Task | Owner | Status |
|---|---|---|
| IP reputation (MaxMind + AbuseIPDB + custom feeds + federated cache) | — | ✅ Done |
| GeoIP + ASN filtering | — | ✅ Done |
| Rate limiting (token bucket + sliding window, distributed via Redis) | — | ✅ Done |
| TLS fingerprinting — JA3, JA4, JA4+ | — | ✅ Done |
| Bot detection (header order + TLS fp + behavioral biometrics) | — | ✅ Done |
| CAPTCHA (hCaptcha + Cloudflare Turnstile + native proof-of-work) | — | ✅ Done |
| L7 anti-DDoS (adaptive throttling) | — | ✅ Done |
| **L4 anti-DDoS via eBPF/XDP — SYN cookies, rate drops at kernel** | — | ✅ Done |
| Virtual patching (import from Burp, ZAP, Nuclei, Nessus) | — | ✅ Done |
| Anti-scraping (canary tokens, Markov-chain detection) | — | ✅ Done |

**✅ Exit Criteria:** 100k SYN/s flood → eBPF drops 99.9% before WAF process sees a single packet.

---

### 🧩 Phase 3 — Plugin System
**Weeks 19–22 | "Anyone can extend it. In any language. Without touching core."**

> The ecosystem play. No competitor has this. WASM plugins = unlimited extensibility.

| Task | Owner | Status |
|---|---|---|
| wasmtime runtime embedded in data plane | — | ✅ Done |
| Host ABI (log, kv get/set, http callout, deny, score, header rewrite) | — | ✅ Done |
| Plugin manifest (`sentinel-plugin.toml`) | — | ✅ Done |
| SDK — Rust (`sentinel-plugin-rs`) | — | ✅ Done |
| SDK — Go (TinyGo → WASM) | — | ✅ Done |
| SDK — AssemblyScript | — | ✅ Done |
| Plugin lifecycle (install, enable, disable, version, hot swap) | — | ✅ Done |
| OCI-compatible marketplace registry | — | ✅ Done |
| Plugin sandboxing (CPU + memory + syscall limits) | — | ✅ Done |

**✅ Exit Criteria:** Developer writes JWT validator in Go in 50 lines. Hot-swaps to production. Zero restart. Zero downtime.

---

### 🤖 Phase 4 — AI / ML Layer
**Weeks 23–30 | "It thinks. It learns. It writes its own rules."**

> The feature that makes Sentinel a different category of product entirely.

| Task | Owner | Status |
|---|---|---|
| Feature extraction pipeline (80+ features → float32 vector) | — | ✅ Done |
| Anomaly detection — Isolation Forest + autoencoder (ONNX) | — | ✅ Done |
| Payload classifier — distilled transformer, ~10MB, <2ms inference | — | ✅ Done |
| Bot vs human classifier — gradient boosted trees | — | ✅ Done |
| Online learning mode with drift detection | — | ✅ Done |
| **LLM Rule Copilot** (wired to `ai.enlight.dev`, model `deepseek-r1:8b`): | — | ✅ Done |
| &nbsp;&nbsp;→ Explain any alert in plain English | | ✅ |
| &nbsp;&nbsp;→ Suggest new rules from log patterns automatically | | ✅ |
| &nbsp;&nbsp;→ Generate virtual patches from CVE descriptions | | ✅ |
| &nbsp;&nbsp;→ Auto-tune false positives from operator overrides | | ✅ |
| Endpoint baselining (per-route ML profiles) | — | ✅ Done |

**✅ Exit Criteria:** ML catches 40% of attacks that CRS rules missed. Copilot generates a working rule from a log pattern in <5 seconds.

---

### 🖥️ Phase 5 — Control Plane & Dashboard
**Weeks 31–38 | "Teams can manage it. Operators can trust it."**

> Enterprise-grade management. Multi-tenant. RBAC. Real-time visibility.

| Task | Owner | Status |
|---|---|---|
| Go control plane — gRPC API, Raft 3/5-node active/active HA | — | ✅ Done |
| Auth — local + LDAP/AD + OIDC + SAML | — | ✅ Done |
| RBAC — SuperAdmin → TenantAdmin → Analyst → ReadOnly | — | ✅ Done |
| Audit log — append-only, cryptographically signed (HMAC-SHA256 chained) | — | ✅ Done |
| Config validation + dry-run before push | — | ✅ Done |
| Config push → all data-plane nodes in <200ms (gRPC streaming) | — | ✅ Done |
| **Dashboard — Next.js (15 routes, all wired to real APIs):** | — | ✅ Done |
| &nbsp;&nbsp;→ Real-time traffic: req/s, block rate, latency heatmap, attack map | | ✅ |
| &nbsp;&nbsp;→ Rule editor with syntax highlighting + live test | | ✅ |
| &nbsp;&nbsp;→ Log explorer — full-text search, filter by phase/action/score | | ✅ |
| &nbsp;&nbsp;→ ML panel — precision/recall live, false-positive tracker | | ✅ |
| &nbsp;&nbsp;→ LLM Copilot panel — ask, get suggestions, 1-click apply | | ✅ |
| &nbsp;&nbsp;→ Site, user, RBAC management | | ✅ |
| `sentinelctl` CLI — full parity with dashboard | — | ✅ Done |
| Reporting — PDF/CSV scheduled exports | — | ✅ Done |

**✅ Exit Criteria:** New site onboarded, rules deployed, traffic flowing in under 5 minutes from dashboard. Rule change pushed to 10 nodes in <200ms.

---

### 🚀 Phase 6 — Advanced Features ← CURRENT PHASE
**Weeks 39–46 | "Features no commercial WAF ships. We ship them all."**

> This is the moat. These take years to build on old architectures. We build them in weeks on Rust.

| Task | Owner | Status |
|---|---|---|
| **HTTP/3** — full QUIC support via quinn, 0-RTT where safe | — | 🔴 TODO |
| **Post-quantum TLS** — hybrid X25519 + Kyber768 (quantum-safe today) | — | 🔴 TODO |
| **API auto-discovery** — generate OpenAPI spec from observed traffic | — | 🔴 TODO |
| **GraphQL firewall** — depth/complexity limits, schema validation, introspection block | — | 🔴 TODO |
| **gRPC firewall** — proto introspection, per-method rate limits, field-level DLP | — | 🔴 TODO |
| **Outbound DLP** — PII, credit cards, secrets, API keys in responses | — | 🔴 TODO |
| **WebVPN** — clientless reverse proxy with SSO + WebAuthn | — | 🔴 TODO |
| Subresource integrity monitor — detect compromised JS CDNs | — | 🔴 TODO |
| Zero-trust mTLS via SPIFFE/SPIRE | — | 🔴 TODO |
| Multi-cluster federation — cross-region threat intelligence sharing | — | 🔴 TODO |

**✅ Exit Criteria:** HTTP/3 traffic flowing. GraphQL attacks blocked at schema level. PQ-TLS handshake verified. DLP catches a test credit card in response body.

---

### 🔒 Phase 7 — Production Hardening
**Weeks 47–52 | "Red team can't break it. Numbers are certified. v1.0 ships."**

> We don't call it done until an external team tries to break it and fails.

| Task | Owner | Status |
|---|---|---|
| Continuous fuzzing — cargo-fuzz + AFL++ on rule parser, HTTP parser, WASM ABI | — | 🔴 TODO |
| Third-party security audit | — | 🔴 TODO |
| External red team pen-test | — | 🔴 TODO |
| Helm chart + Kubernetes operator GA | — | 🔴 TODO |
| Terraform modules — AWS / GCP / Azure | — | 🔴 TODO |
| Compliance docs — SOC2, PCI-DSS, ISO 27001 readiness | — | 🔴 TODO |
| **Performance certification — 1M req/s on 16-core, p99 < 1ms** | — | 🔴 TODO |
| Documentation site (Docusaurus) | — | 🔴 TODO |
| **🎉 v1.0 GA** | — | 🔴 TODO |

---

## 📊 Performance Targets vs Competition

| Metric | ModSec + NGINX | BunkerWeb | eNlight | Barracuda | 🛡️ **Sentinel** |
|---|---|---|---|---|---|
| Throughput (16-core) | ~80k req/s | ~70k req/s | ~100k req/s | ~120k req/s | **> 500k req/s** |
| p99 latency overhead | 5–10ms | 5–15ms | 3–8ms | 4–10ms | **< 1ms** |
| Memory / connection | ~50KB | ~80KB | ~40KB | ~60KB | **< 10KB** |
| Cold start | 2–5s | 5–10s | 10–30s | 15–30s | **< 500ms** |
| L4 DDoS | userspace | userspace | separate product | hardware | **kernel eBPF/XDP** |
| Plugin language | C / Lua | Lua | proprietary | none | **Any → WASM** |
| ML / AI | none | none | basic | none | **ONNX + LLM copilot** |
| HTTP/3 | no | partial | no | no | **yes** |
| Post-quantum TLS | no | no | no | no | **yes** |
| GraphQL / gRPC FW | no | no | no | no | **yes** |
| Outbound DLP | no | no | no | no | **yes** |
| Rule authoring | humans | humans | humans | humans | **LLM copilot** |
| HA model | ext LB | manager SPOF | active/standby | active/standby | **Raft active/active** |

---

## 🌟 Features Only Sentinel Has — Ever

```
 ✦ WASM plugins in any language — Rust, Go, AssemblyScript, JS — hot-swap in production
 ✦ LLM Copilot that writes WAF rules from your own traffic logs
 ✦ Kernel-level L4 DDoS via eBPF/XDP — same binary, not an upsell
 ✦ GraphQL + gRPC protocol-aware firewalling
 ✦ Post-quantum TLS (X25519 + Kyber768 hybrid) from day one
 ✦ Outbound DLP — scans responses for PII, secrets, credit cards
 ✦ True active/active Raft HA — no SPOF, no CARP, no VRRP
 ✦ OpenTelemetry native — traces + metrics + logs, zero config
```

---

## 🗓️ Timeline at a Glance

```
Month 1        Month 2-3      Month 4-5      Month 6        Month 7-9      Month 10-11    Month 12
   │               │              │              │               │               │              │
[Phase 0]✅   [Phase 1]✅    [Phase 2]✅    [Phase 3]✅    [Phase 4-5]✅  [Phase 6]◀NOW [Phase 7]
Foundations   WAF Engine     Security       Plugin         AI/ML +        Advanced      Hardening
Proxy MVP     Rule VM        Modules        System         Control Plane  Features      v1.0 GA
              CRS Import     eBPF/XDP       WASM SDKs      Dashboard      HTTP/3 PQ-TLS Red Team
```

---

## 🔭 Post v1.0 — Stretch Goals

- Mobile SDK (iOS/Android) app-layer protection
- Edge worker deployment (Cloudflare Workers / Fastly Compute compatible)
- DNS-layer protection (DoH/DoT proxy with filtering)
- Email gateway mode (SMTP filtering)
- SaaS offering — multi-region anycast, self-serve onboarding
- Browser extension fingerprint integration

---

> **Sentinel is not a better WAF.**
> **It is what a WAF looks like when you build it in 2025 instead of 2002.**
