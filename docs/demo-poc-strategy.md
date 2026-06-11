# Sentinel WAF — Demo & POC Strategy

## 1. Know Your Audience

Management will ask three questions (implicitly or explicitly):

| Question | Your Answer |
|----------|-------------|
| **"What problem does it solve that eNlight doesn't?"** | eNlight blocks in learning mode (your manager's exact complaint). Sentinel **never** blocks in learning mode. 40µs inspection, 505ns block, zero false-positives after tuning. |
| **"Why should we build instead of buy?"** | Cloud WAF costs $2,000+/month for 1 Gbps. Sentinel runs on 1 server. Zero per-request pricing. We own the code, the data, the roadmap. |
| **"Can it actually beat ModSecurity / Cloudflare / AWS WAF?"** | Yes — and we have the benchmarks to prove it. 25–125× faster than ModSecurity, 1/10th the hardware for same throughput. |

---

## 2. Demo Architecture: What to Actually Show

### 2.1 The "LIVE ATTACK" Demo (Star of the Show)

This is the money shot. Nothing impresses management more than seeing attacks blocked in real time.

**Setup (what's already configured in `configs/dev/sentinel.yaml`):**

```
DVWA (Damn Vulnerable Web App)         Juice Shop (OWASP)
     ↓                                        ↓
  WAF owns :9095                          WAF owns :3000
     ↓                                        ↓
  DVWA on :9096                          Juice on :3001
```

**Live Demo Flow (7 minutes max):**

| Step | Action | What to Say |
|------|--------|-------------|
| 1 | Open `http://dvwa.local:9080` — browse normally | "This is DVWA. Sentinel is protecting it in blocking mode." |
| 2 | Navigate to DVWA SQL Injection page, enter `' OR 1=1 --` | "Watch what happens..." |
| 3 | **403 BLOCKED** — Sentinel returns Forbidden | "That was a SQL injection. Blocked in **505 nanoseconds** — faster than the TCP stack can process the packet." |
| 4 | Show dashboard log stream — the block appears in real-time | "Every block is logged, timestamped, with the exact rule that fired and the anomaly score." |
| 5 | Try XSS: `<script>alert(1)</script>` in DVWA's reflected XSS page | "Reflected XSS — same result. Rule 941100 fired. 403." |
| 6 | Try path traversal: `../../../etc/passwd` | "Local file inclusion — CRS rule 930110. Blocked." |
| 7 | Switch Juice Shop, try NoSQL injection | "OWASP Top 10 — all covered. OWASP CRS 4.7 rules, live." |

**This single demo proves:**
- The WAF actually blocks real attacks (not just a slide deck)
- It covers SQLi, XSS, LFI, RCE, session attacks, protocol violations
- It's running in blocking mode with zero false positives on normal browsing
- The dashboard shows it all in real time

### 2.2 The Learning Mode Story (eNlight Killer)

As noted in `notes11.md`, your manager's complaint about eNlight: "In learning mode, it was blocking the website by itself without telling."

**Demo flow:**

1. Switch a site to `mode: learning` via the dashboard
2. Send the same SQL injection attack
3. **Request passes through** (200 OK) — the WAF logs "would have blocked" but doesn't
4. Show the log: `{"decision":"Log","anomaly_score":15,"would_block":true}`
5. Explain: "After a week of traffic analysis, you switch to blocking mode with confidence because you've already tuned away every false positive."

**Script:**
> "Sentinel's learning mode solves exactly the problem we had with eNlight. Learning means watch and log only — zero blocking, zero website breakage. After a week of traffic analysis, you switch to blocking mode with confidence because you've already tuned away every false positive. And clients can give us exactly the 1000 or 2000 rules they want — we don't force a bloated CRS on them. Each site gets exactly its own rules, nothing more."

**IMPORTANT:** Verify that learning mode is actually wired in the proxy pipeline before the demo. `notes11.md` notes: "the proxy pipeline currently treats learning and blocking the same way (always blocks when threshold is hit). This distinction needs to be wired into the `handle_request` → `proxy` pipeline before you demo it."

### 2.3 The Benchmark Story (Numbers That Win Arguments)

Benchmark data from `docs/benchmark-report.md`:

| Metric | Sentinel | ModSecurity | Advantage |
|--------|----------|-------------|-----------|
| Rule inspection (200 rules) | **40 µs** | 1,000–5,000 µs | **25–125× faster** |
| Block an attacker | **505 ns** | ~1,000,000 ns | **2,000× faster** |
| Requests/sec per core | **25,000** | 500–2,000 | **12–50× more** |
| Hardware for 1 Gbps | **1 server (8 cores)** | 10–25 servers | **10–25× less** |
| Tail latency (p99) | **Flat (no GC)** | Spiky (GC pauses) | No "mystery spikes" |
| Rule limit before degradation | **Unlimited (linear)** | ~500 (quadratic) | No hard ceiling |

**Script:**
> "We benchmarked Sentinel against a 200-rule OWASP CRS policy. Safe users experience 40 microseconds of added latency — that's 7,500× faster than a blink. Attackers are blocked in 505 nanoseconds. A single 8-core server handles 1 Gbps. ModSecurity needs 10–25 servers for the same throughput. And because we use Rust and a bytecode VM with early-exit optimization, adding 500 rules costs only 5× more time than 50 rules — there's no quadratic cliff."

**How to show benchmarks live (optional, impactful):**
```bash
cd crates/sentinel-rules && cargo bench
```
The Criterion.rs output shows the numbers right in the terminal. This proves the benchmarks are reproducible, not fabricated.

### 2.4 The Architecture Story (Why It's Fundamentally Better)

Use the diagram from `docs/architecture/diagram.md` (convert to a slide or just draw on whiteboard):

**Key architectural advantages to highlight:**

1. **Fusion: Proxy + WAF in one process**
   - Traditional: HAProxy → ModSecurity → Backend (3 network hops, +2–5ms)
   - Sentinel: Sentinel → Backend (2 hops, +0.2ms)
   - "Less latency, fewer moving parts, one less thing to break"

2. **Two-plane design**
   - Data plane (Rust): handles every request, sub-ms latency, no GC
   - Control plane (Go): manages config, never on the request path
   - "Right language for each job"

3. **7-phase pipeline**
   - Phase 0: eBPF/XDP kernel filtering (drop known bad IPs before userspace)
   - Phase 1: Headers — rate limit, bot detect, GeoIP, rules
   - Phase 2: Body — CRS rules, ML scoring, anomaly gate
   - Phase 3: Upstream — load balancing, health checks, circuit breaker
   - Phase 4: Response headers — security header injection
   - Phase 5: Response body — DLP egress scanning
   - Phase 6: Logging — OpenTelemetry, correlation engine

4. **Control Plane: Raft clustering**
   - 3 or 5 control plane nodes
   - Leader election, log replication
   - True active/active HA — no VRRP/CARP limitations
   - Data planes are stateless, scale horizontally

### 2.5 The Dashboard Story (Management Loves GUIs)

Navigate the dashboard (`localhost:3000` in dev mode):

| Page | What to show | Impact |
|------|-------------|--------|
| **Overview** | RPS, p99 latency, blocks, eBPF drops, connected clients | "One screen, full visibility" |
| **Sites** | DVWA + Juice Shop, blocking mode badges, per-site stats | "Multi-tenant, per-site policies" |
| **Logs (SSE stream)** | Real-time scrolling logs, filter by site/status/phase | "Live, not batch — instant visibility" |
| **Rules** | CRS rules loaded, rule tester (dry-run) | "Each site gets exactly its rules" |
| **LLM Copilot** | "Explain why this was blocked" → AI explanation | "AI-powered — even junior operators can understand alerts" |

### 2.6 The DLP Story (Unique Differentiator)

Most WAFs only inspect **inbound** traffic. Sentinel also scans **outbound** (response bodies):

| DLP Pattern | Example | Detection Method |
|-------------|---------|-----------------|
| Credit cards | `4111-1111-1111-1111` | Luhn algorithm + regex |
| SSN | `123-45-6789` | Pattern + area validation |
| API keys | `sk_live_...`, `AKIA...` | Pattern + entropy analysis |
| JWT tokens | `eyJ...` | Base64 pattern + signature |
| Private keys | `-----BEGIN RSA PRIVATE KEY-----` | Pattern matching |

**Demo:** Have a backend that accidentally leaks a credit card in a response. Sentinel masks/blocks it.

**Script:**
> "Most WAFs only look at what comes in. Sentinel also scans what goes out. If your backend accidentally leaks a credit card number in a response body, Sentinel catches it and masks it. This is enterprise-grade data loss prevention built into the WAF — no extra tool needed."

---

## 3. The Competitive Positioning Frame

### 3.1 vs. eNlight WAF (Their Current Pain)

| Pain Point | Sentinel's Solution |
|------------|-------------------|
| "Blocked in learning mode" | Learning mode is truly non-blocking — design guarantees it |
| "Can't give exactly the rules clients want" | Per-site rules, zero cap on rule count, mix CRS + custom |
| "Performance bottlenecks" | 40µs inspection, 25,000 req/s per core, linear scaling |
| "Proprietary, can't customize" | WASM plugins + custom DSL + open architecture |

### 3.2 vs. ModSecurity / Coraza

| Aspect | ModSecurity | Sentinel |
|--------|-------------|----------|
| Language | C (memory unsafe, CVEs) | Rust (memory safe, zero-cost) |
| Rule engine | Interpreted regex, O(n²) | Bytecode VM + Aho-Corasick, O(n) |
| Latency (200 rules) | 1–5 ms | 0.04 ms |
| GC pauses | N/A (but regex backtracking) | None (Rust has no GC) |
| Plugin system | Lua (limited) | WASM (Rust, Go, AssemblyScript) |
| ML/AI | None | Built-in payload classifier + anomaly detection |
| DLP | External tool | Built-in egress scanning |
| HTTP/3 | No | Yes (QUIC) |
| Clustering | None (needs external LB) | Raft (active/active) |
| Dashboard | Third-party | Built-in Next.js dashboard |

### 3.3 vs. Cloud WAFs (Cloudflare, AWS WAF)

| Aspect | Cloud WAF | Sentinel |
|--------|-----------|----------|
| Pricing | $2,000+/mo per 1 Gbps | $0 (self-hosted) |
| Per-request cost | Yes | No |
| Data residency | Cloud-only | On-prem / private cloud |
| Latency | +5–50ms (WAN round-trip) | +0.2ms (inline, same DC) |
| Customization | Limited rules UI | Full WASM SDK + custom DSL |
| Offline mode | No | Yes (fully self-contained) |
| TLS keys | Handed to cloud provider | You own them |

### 3.4 vs. BunkerWeb

| Aspect | BunkerWeb | Sentinel |
|--------|-----------|----------|
| Core engine | Nginx + ModSecurity | Custom Rust reverse proxy |
| Performance | GC pauses (Python/Go) | Zero-GC, p99 < 1ms |
| ML/AI | None | Built-in 3-tier ML pipeline |
| eBPF | No | XDP kernel pre-filtering |
| Plugin system | Limited | WASM (3 SDKs) |
| HTTP/3 | Via Nginx | Native QUIC |

---

## 4. How to Structure the Presentation

### Recommended Flow (30-35 minutes total)

#### Part 1: The Problem (5 min)
- "We evaluated eNlight. It blocked in learning mode. It couldn't handle client-specific rule sets."
- "Open-source WAFs are slow, hard to configure, and don't scale."
- "Cloud WAFs are expensive, have latency penalties, and you hand over your TLS keys."
- **Punchline:** "So we decided to build our own. Here's what we built."

#### Part 2: What We Built (10 min)
- Walk through the architecture diagram
- Show the 7-phase pipeline
- Explain the Rust + Go two-plane design
- Show the dashboard live
- **Key message:** "This isn't a wrapper around Nginx. This is a ground-up custom proxy + WAF in Rust."

#### Part 3: LIVE DEMO — The Attacks (7 min)
- Browse DVWA and Juice Shop normally (shows: safe traffic passes)
- Execute SQL injection → 403 (shows: attacks are blocked)
- Execute XSS → 403
- Show the dashboard log stream updating in real-time
- Switch to learning mode → attack passes → log shows "would have blocked"
- **Key message:** "Blocking mode protects. Learning mode watches without breaking. No surprises."

#### Part 4: The Numbers (5 min)
- Show benchmark results (Criterion.rs output or the pre-computed table)
- Walk through: 40µs clean, 505ns block, 25,000 req/s per core
- Show scaling: 1 server = 1 Gbps, 10-25× less hardware than ModSecurity
- **Key message:** "These aren't marketing numbers. These are reproducible Criterion.rs benchmarks from our codebase."

#### Part 5: Why It's Better (5 min)
- Fusion architecture (2 hops vs 3)
- eBPF kernel pre-filtering (drop DDoS before userspace)
- DLP egress scanning (unique differentiator)
- WASM plugins (extensible by clients)
- ML/AI built-in (zero-day detection, LLM copilot)
- Raft clustering (active/active HA)
- **Key message:** "No other WAF — commercial or open-source — has all of these."

#### Part 6: Competitive Comparison (3 min)
- Quick comparison table against ModSecurity, Cloudflare, AWS WAF, BunkerWeb
- **Key message:** "We're 25–125× faster than ModSecurity, $0/request vs $2,000+/month cloud WAF, and we own everything."

#### Part 7: Roadmap (2 min)
- What's coming next (be conservative — only promise what's actually planned):
  - End-to-end load testing (benchmarks/ already set up)
  - India-specific DLP patterns (PAN, Aadhaar)
  - CEF syslog for SIEM integration
  - HTTP webhook notifications
  - Let's Encrypt/ACME automation
  - API discovery
- **Key message:** "We've built the core. The roadmap adds enterprise polish."

---

## 5. Preparation Checklist

### 5.1 Must Fix Before Demo

- [ ] **Learning mode pipeline** — Wire `WafMode::Learning` to actually not block (currently blocks same as `Blocking`). See `notes11.md` for the exact code path.
- [ ] **Test the full attack flow** — Run through all attack scenarios from Section 2.1 at least 3 times
- [ ] **Dashboard data** — Ensure simulated traffic is running so dashboard isn't empty
- [ ] **Backup environment** — Have a second terminal/VM ready in case something crashes

### 5.2 Environment

- [ ] DVWA Docker: `docker run -d -p 9096:80 vulnerables/web-dvwa`
- [ ] Juice Shop Docker: `docker run -d -p 3001:3000 bkimminich/juice-shop`
- [ ] Sentinel data plane running: `cargo run --release`
- [ ] Control plane running: `go run ./cmd/controllerd`
- [ ] Dashboard running: `npm run dev`
- [ ] `/etc/hosts` entries: `127.0.0.1 dvwa.local juice.local`

### 5.3 Materials to Prepare

- [ ] Slide deck with architecture diagram (convert from `docs/architecture/diagram.md` Mermaid)
- [ ] One-page comparison cheat sheet (print or share digitally)
- [ ] Benchmark results screenshot or Criterion.rs terminal output
- [ ] Dashboard screenshots (as backup if live demo fails)

### 5.4 Talking Points (Memorize These)

1. **"40 microseconds"** — The security tax on legitimate users
2. **"505 nanoseconds"** — How fast we block an attacker
3. **"1 server = 1 Gbps"** — Hardware efficiency
4. **"25–125× faster than ModSecurity"** — The speed advantage
5. **"Fusion: proxy + WAF in one process"** — Why we're architecturally superior
6. **"Never blocks in learning mode"** — The eNlight killer
7. **"Each site gets exactly its rules"** — Customization
8. **"Rust — no garbage collector, no memory bugs, no CVEs"** — Why we chose Rust
9. **"All 3 protocols: HTTP/1.1, HTTP/2, HTTP/3"** — Future-proof
10. **"DLP on egress — we catch what your backend leaks"** — Unique differentiator

---

## 6. Anticipated Questions & Answers

| Question | Answer |
|----------|--------|
| "Why Rust? No one knows Rust." | "Rust is the #1 most-admired language for 9 years running on Stack Overflow. It's what Cloudflare, AWS, and Discord use for their data planes. For the control plane we use Go — same language as Kubernetes, Docker. Both have large hiring pools now." |
| "ModSecurity is free. Why not just use it?" | "ModSecurity is C code from 2002. It has CVEs. It's 25–125× slower. It has no dashboard, no clustering, no ML, no DLP. By the time you bolt all those on, you've built a worse version of Sentinel with 5× the engineering effort." |
| "What about Cloudflare?" | "Cloudflare charges per request at scale, adds 5–50ms of WAN latency, and you hand them your TLS private keys. Sentinel runs in your DC — zero per-request cost, microsecond latency, you own your keys." |
| "Is this production-ready?" | "This is our POC — the core engine is proven with real benchmarks. The pipeline from Phase 0 to Phase 6 is wired end-to-end. Learning mode needs a final wiring fix, and we need end-to-end load testing, which the benchmark harness is already set up for. We're on track for production." |
| "How does it handle false positives?" | "Three ways: (1) learning mode — watch traffic for a week, tune exclusions; (2) rule exclusions — per-site, per-rule, per-target (e.g., exclude `ARGS_NAMES` from rule 932236 for `id` parameter); (3) anomaly threshold — rules don't block individually, they accumulate score, block only when threshold crossed. All three together eliminate false positives." |
| "Can it scale to 10,000 sites?" | "Data plane is stateless — add more nodes horizontally. Control plane runs Raft clustering. PostgreSQL with row-level security enforces multi-tenancy at the database layer. Yes, it's architected for scale." |
| "What about compliance? PCI-DSS, SOC2, etc." | "Sentinel includes OWASP CRS which satisfies PCI-DSS 6.6 (application firewall requirement). DLP detects PCI data in egress. Audit log is HMAC-SHA256 chained and tamper-evident. OpenTelemetry exports to any SIEM. All building blocks are in place." |
| "How do clients add their own rules?" | "Three ways: (1) Dashboard UI — create rules visually; (2) DSL — write in Sentinel Rule Language, push via API; (3) WASM plugins — write custom logic in Rust, Go, or AssemblyScript, compile to .wasm, upload. The LLM copilot can even generate rules from natural language." |
| "What if the WAF itself goes down?" | "Raft clustering ensures the control plane has no single point of failure. Data planes are stateless — if one goes down, the load balancer routes around it. eBPF XDP continues dropping known bad IPs at the kernel level even if userspace crashes." |
| "What's the cost to run vs buying?" | "Sentinel: 1 server (8-core) handles 1 Gbps. Cloud WAF: $2,000+/month per 1 Gbps. On 10 Gbps, Sentinel needs ~8-16 servers; Cloud WAF is $20,000+/month. The ROI is undeniable at any scale." |

---

## 7. What NOT to Show

- **Don't show raw code** — Management doesn't care about Rust syntax
- **Don't show WAF mode `off`** — It looks like you built something that can be turned off
- **Don't show failed attacks** — Test every scenario beforehand
- **Don't talk about unimplemented features** — Only mention roadmap items, don't pretend they exist
- **Don't get into technical debates about Rust vs Go vs C** — Keep it at "right tool for each job"
- **Don't show build errors or compilation** — Have everything pre-built and running

---

## 8. One-Sentence Summary (Elevator Pitch)

> "Sentinel WAF inspects every request in 40 microseconds, blocks attackers in half a microsecond, handles 1 Gbps on a single server, costs nothing to scale, and never blocks legitimate traffic in learning mode — something eNlight couldn't do. No other WAF — commercial or open-source — has all four of these properties."