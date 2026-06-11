# Sentinel WAF — Architecture Deep-Dive

```mermaid
%%{init: {"theme": "dark", "themeVariables": {"primaryColor": "#1a1a2e", "secondaryColor": "#16213e", "tertiaryColor": "#0f3460", "mainBkg": "#1a1a2e", "nodeBorder": "#e94560", "clusterBkg": "#0f3460", "lineColor": "#e94560", "fontFamily": "monospace"}}}%%
flowchart TB
    subgraph Clients["🌐 Internet / Clients"]
        C1["Users / Browsers"]
        C2["APIs / Mobile Apps"]
        C3["Botnets / Attackers"]
    end

    subgraph L4["Layer 4 — Kernel Space (eBPF/XDP)"]
        XDP["eBPF XDP Program\nKernel-level packet filter\nDrops L4 DDoS before userspace"]
        BL["Kernel Blocklist\nExact IPs + CIDR ranges\nManaged via BPF maps"]
    end

    subgraph DataPlane["Data Plane — Rust (per-request, p99 < 1ms)"]
        direction TB
        subgraph Listeners["Listeners"]
            H1["HTTP/1.1 (hyper)"]
            H2["HTTP/2 (h2)"]
            H3["HTTP/3 (QUIC, s2n-quic)"]
            TLS["TLS Termination (rustls)\nPost-Quantum Kyber/Dilithium"]
        end

        subgraph Phase0["Phase 0: Connection"]
            P0_ANTIDDoS["Anti-DDoS\nConnection rate tracking\nAuto-block at threshold"]
            P0_IPREP["IP Reputation\nCIDR allow/deny lists\nExternal feed ingestion"]
        end

        subgraph Phase1["Phase 1: Request Headers"]
            P1_RL["Rate Limiting\nToken-bucket algorithm\nPer-IP, per-site, global"]
            P1_BOT["Bot Detection\nUser-agent classification\nJA4 TLS fingerprint"]
            P1_GEO["GeoIP\nMaxMind GeoLite2\nCountry allow/deny"]
            P1_RULES["Rule Engine (SRL)\nDSL parser → AST → bytecode → VM\nCRS compat layer (SecRule)"]
            P1_WASM["WASM Plugins\nSandboxed via wasmtime\nHot-swappable"]
        end

        subgraph Phase2["Phase 2: Request Body"]
            P2_BODY["Body Size Limit\nConfigurable per-site"]
            P2_RULES["Rule Engine (Body)\nCRS rules, body vars\nParanoia-level gating"]
            P2_ML["ML Inference\nONNX payload classifier\nIsolation Forest anomaly"]
            P2_ANOMALY["Anomaly Gate\nMulti-rule scoring\nBlock at threshold"]
        end

        subgraph Phase3["Phase 3: Upstream"]
            P3_LB["Load Balancer\nRoundRobin, LeastConn\nIpHash, Adaptive"]
            P3_HC["Health Checks\nActive probes\nPassive failure tracking"]
            P3_CB["Circuit Breaker\nConsecutive failure threshold\nHalf-open recovery"]
            P3_WS["WebSocket Relay\nBidirectional upgrade"]
        end

        subgraph Phase4["Phase 4: Response Headers"]
            P4_SEC["Security Headers\nHSTS, X-Frame-Options\nCSP, X-Content-Type-Options"]
            P4_REWRITE["Header Rewrite\nStrip hop-by-hop\nAdd/remove headers"]
        end

        subgraph Phase5["Phase 5: Response Body"]
            P5_DLP["DLP Scanner\nCredit cards (Luhn)\nSSN, API keys, JWTs\nPattern + entropy detection"]
        end

        subgraph Phase6["Phase 6: Logging"]
            P6_LOG["Structured Logging\nNDJSON access/WAF events\nOTel traces + metrics"]
            P6_CORR["Correlation Engine\nPer-IP attack history\nAnomaly score accumulation"]
        end
    end

    subgraph ControlPlane["Control Plane — Go (Raft Cluster)"]
        direction TB
        CP_GIN["REST API (Gin)\n/api/v1/* endpoints\nCORS, JWT middleware"]
        CP_GRPC["gRPC Server\nConfigService push\nmTLS authenticated"]
        CP_RAFT["Raft Consensus\nLeader election\nLog replication\n3 or 5 nodes"]
        CP_DB["PostgreSQL 16\nRLS multi-tenancy\nUsers, sites, rules, alerts"]
        CP_AUTH["Auth + RBAC\nJWT / OIDC\nRole-based access control"]
        CP_AUDIT["HMAC-signed Audit\nAppend-only log\nTamper-evident"]
        CP_CONFIG["Config Service\nPushes site configs\nto data plane over gRPC"]
        CP_LOGS["SSE Log Stream\nLive log streaming\nto dashboard"]
    end

    subgraph Storage["Storage Backends"]
        S_PG[(PostgreSQL 16\nOLTP - config, users, rules)]
        S_RD[(Redis 7\nRate-limit state, cache, pub/sub)]
        S_CH[(ClickHouse\nTime-series metrics, access logs)]
        S_S3[(S3/MinIO\nML models, WASM plugins, reports)]
    end

    subgraph Dashboard["Dashboard — Next.js 14 + TypeScript"]
        D_UI["Admin Web UI\nOverview, Sites, Rules\nLogs, Alerts, ML, Plugins"]
        D_SSE["SSE Client\nLive log streaming\nReal-time stats"]
        D_API["API Client\nTyped fetch wrapper\nAuto-refresh on 401"]
        D_COPILOT["LLM Copilot\nAlert explanations\nRule generation suggestions"]
    end

    subgraph ML["ML Pipeline"]
        ML_INLINE["Inline ML (~2ms)\n24-dim feature extraction\nPayload attack classifier"]
        ML_NEAR["Near-line\nTransformer deep analysis\nSuspicious request sampling"]
        ML_OFFLINE["Offline (Control Plane)\nModel training, drift detection\nLLM rule copilot"]
    end

    subgraph Plugins["Plugin Ecosystem"]
        PL_SDK["WASM SDKs\nRust, Go (TinyGo)\nAssemblyScript"]
        PL_ABI["Host ABI\nhost_log, host_get_req_header\nhost_set_decision, host_http_callout"]
        PL_MANIFEST["Plugin Manifests\nsentinel-plugin.toml\nCapability grants"]
    end

    subgraph Rules["Rule Sources"]
        R_CRS["OWASP CRS 4.7\nVendored ModSecurity rules\nSecRule compatibility"]
        R_SRL["Sentinel Rule Language\nCustom DSL\nDSL parser → AST → VM bytecode"]
        R_VP["Virtual Patches\nAuto-generated from\nscanner reports"]
        R_COMM["Community Rules\nUser-contributed\nShared rule sets"]
    end

    %% Data flow connections
    Clients -->|"HTTP/HTTPS/H3"| XDP
    XDP -->|"Pass through"| BL
    BL -->|"Clean traffic"| Listeners
    XDP -->|"Drop"| Junk["Dropped Packets"]
    BL -->|"Block"| Junk

    Listeners --> Phase0
    Phase0 --> Phase1
    Phase1 --> Phase2
    Phase2 --> Phase3
    Phase3 --> Phase4
    Phase4 --> Phase5
    Phase5 --> Phase6
    Phase6 -->|"Forward response to client"| Clients

    %% Module connections
    P0_ANTIDDoS --> P0_IPREP
    P1_RL --> P1_BOT --> P1_GEO --> P1_RULES --> P1_WASM
    P2_BODY --> P2_RULES --> P2_ML --> P2_ANOMALY
    P3_LB --> P3_HC --> P3_CB --> P3_WS
    P4_SEC --> P4_REWRITE
    P5_DLP
    P6_LOG --> P6_CORR

    %% Cross-plane connections
    Phase1 -.->|"gRPC config push"| CP_GRPC
    Phase6 -.->|"Metrics push (OTel)"| CP_LOGS
    CP_GIN -->|"Read/write"| CP_DB
    CP_GIN -.->|"Push config"| CP_CONFIG
    CP_CONFIG -.->|"gRPC stream"| Phase1
    CP_RAFT -.->|"Raft RPC (TCP/JSON)"| CP_GIN

    %% Control plane to storage
    CP_DB --> S_PG
    S_RD -.->|"Rate limit counters"| P1_RL
    S_CH <-.->|"Metrics read/write"| Phase6
    S_S3 -.->|"Model/WASM blobs"| P2_ML
    S_S3 -.->|"Plugin WASM files"| P1_WASM

    %% ML pipeline connections
    P2_ML --> ML_INLINE
    ML_INLINE -.-> ML_NEAR
    ML_NEAR -.-> ML_OFFLINE
    ML_OFFLINE -.->|"Model updates"| S_S3

    %% Dashboard connections
    D_UI -->|"HTTP/REST"| CP_GIN
    D_SSE -->|"SSE stream"| CP_LOGS
    D_COPILOT -->|"LLM requests"| CP_GIN

    %% Plugin & Rule connections
    PL_ABI -.->|"Compiled to .wasm"| PL_SDK
    PL_SDK -.->|"Loaded into"| P1_WASM
    R_CRS -.->|"Imported by"| Phase1
    R_SRL -.->|"Loaded by"| P1_RULES
    R_VP -.->|"Managed by"| CP_GIN
    R_COMM -.->|"Community source"| CP_GIN

    %% Styling
    classDef dataplane fill:#16213e,stroke:#e94560,stroke-width:2px,color:#fff
    classDef controlplane fill:#1a1a2e,stroke:#533483,stroke-width:2px,color:#fff
    classDef storage fill:#0f3460,stroke:#3b82f6,stroke-width:2px,color:#fff
    classDef clients fill:#2d2d44,stroke:#6c6c8a,stroke-width:1px,color:#aaa
    classDef kernel fill:#333311,stroke:#999922,stroke-width:2px,color:#ddcc44
    classDef rules fill:#1e3a5f,stroke:#4a90d9,stroke-width:1px,color:#aaccff
    classDef plugins fill:#2d1b2d,stroke:#993399,stroke-width:1px,color:#ff99ff
    classDef ml fill:#1a3a2a,stroke:#33cc66,stroke-width:1px,color:#99ff99
    classDef dashboard fill:#222244,stroke:#6666cc,stroke-width:2px,color:#ccccee
    classDef phase highlight fill:#0f3460,stroke:#e94560,stroke-width:3px,stroke-dasharray: 5 5,color:#fff

    class Listeners,Phase0,Phase1,Phase2,Phase3,Phase4,Phase5,Phase6 dataplane
    class ControlPlane,CP_GIN,CP_GRPC,CP_RAFT,CP_DB,CP_AUTH,CP_AUDIT,CP_CONFIG,CP_LOGS controlplane
    class S_PG,S_RD,S_CH,S_S3 storage
    class C1,C2,C3 clients
    class XDP,BL kernel
    class R_CRS,R_SRL,R_VP,R_COMM rules
    class PL_SDK,PL_ABI,PL_MANIFEST plugins
    class ML_INLINE,ML_NEAR,ML_OFFLINE ml
    class D_UI,D_SSE,D_API,D_COPILOT dashboard
```

---

## Section-by-Section Explanation

### 1. 🌐 Clients (Top of Diagram)

Every incoming request comes from one of three kinds of clients:

| Type | Examples | Why it matters |
|------|----------|----------------|
| **Users/Browsers** | Someone visiting your website | Legitimate traffic that should pass through |
| **APIs/Mobile Apps** | Programmatic clients, app backends | May send structured data (JSON, GraphQL), need different rules |
| **Botnets/Attackers** | Scanners, exploit tools, DDoS botnets | Traffic you want to drop as early as possible |

All of these arrive on the same IP/port — the WAF's job is to distinguish them.

---

### 2. 🟨 Layer 4 — Kernel Space (eBPF/XDP)

Before any userspace code runs, the Linux kernel can filter packets using **eBPF (extended Berkeley Packet Filter)** programs attached at the **XDP (eXpress Data Path)** hook. This is the earliest possible interception point — right when the NIC driver receives the packet, before the kernel even allocates an `sk_buff`.

**What happens here:**

```rust
// sentinel-ebpf crate — XDP program (runs in kernel)
fn xdp_main(ctx: &XdpContext) -> Result<u32, u64> {
    let ip = get_src_ip(ctx)?;
    if blocklist.contains(&ip) {          // BPF map lookup (O(1))
        return Ok(XdpAction::Drop);       // Packet never reaches userspace
    }
    Ok(XdpAction::Pass)                   // Forward to network stack
}
```

**Two components:**
- **eBPF XDP Program** — Runs in kernel, O(1) blocklist lookup, drops known bad IPs before any CPU time is wasted on parsing HTTP.
- **Kernel Blocklist** — A **BPF hash map** (hash table in kernel memory) shared between the XDP program and userspace. The data plane adds IPs here when it detects sustained attacks. This is also how the CLI tool `sentinel block add 1.2.3.4` works — it writes directly to this BPF map.

**Performance impact:** Dropping at XDP is ~10x faster than dropping in userspace. A single XDP core can handle ~25M packets/sec.

**Limitation:** XDP sees IP packets, not HTTP. It can only filter on IP + port + protocol. Application-layer attacks (SQL injection, XSS) can't be detected here — that's what the Rust data plane does.

> **🟢 Green path (clean traffic):** → Passes through XDP → checked against blocklist → forwarded to kernel TCP stack → reaches Rust data plane listeners.
>
> **🔴 Red path (blocked):** → XDP drops the packet → kernel never sees it → done in ~50ns.

---

### 3. 🔴 Data Plane — Rust (The Core Engine)

This is where every byte of every request is inspected. Written in Rust for **memory safety without garbage collection** — critical for maintaining consistent p99 < 1ms latency under any load.

#### 3a. Listeners

The data plane binds to configured ports and accepts connections via three protocols simultaneously:

| Protocol | Rust Crate | TLS | Use Case |
|----------|-----------|-----|----------|
| **HTTP/1.1** | `hyper` | rustls | Legacy clients, proxied traffic |
| **HTTP/2** | `h2` (via hyper) | rustls | Modern browsers, gRPC (coming) |
| **HTTP/3 (QUIC)** | `s2n-quic` | rustls + Kyber/Dilithium | Future-proof, avoids head-of-line blocking |

**TLS Termination** uses `rustls` — a pure-Rust TLS library (no OpenSSL dependency). The production config enables **post-quantum key agreement** (Kyber KEM + Dilithium signatures hybrid with X25519/ECDSA), making recorded traffic immune to future quantum decryption.

Each listener runs in its own tokio task. When a TLS connection arrives, rustls performs the handshake, extracts the **SNI (Server Name Indication)** to determine the target site config, and passes the decrypted byte stream to the HTTP parser.

#### 3b. 7-Phase Request Lifecycle

Every request travels through **7 sequential phases**. Any phase can **block** the request (returning 403, 429, or a redirect) or **pass** it through. Think of this like an assembly line — each station inspects the request and either passes it forward or rejects it.

---

##### Phase 0: Connection (Pre-HTTP)

Runs immediately after TCP/TLS handshake, before reading a single HTTP byte.

**Anti-DDoS:**
- Tracks **connection rate per source IP** using a sliding window (token bucket).
- If an IP opens >N connections/second → the phase returns `Decision::Block` (typically 429 Too Many Requests or connection drop).
- Bucket refills over time — after the attack subsides, the IP gradually regains access.

```rust
// Token-bucket rate limiting (conceptual)
fn check_connection_rate(ip: &IpAddr) -> Decision {
    let mut bucket = rate_limiter.get_or_init(ip, || TokenBucket::new(100, 10));
    // 100 tokens capacity, 10 tokens/sec refill
    if !bucket.consume(1) {
        return Decision::Block(StatusCode::TOO_MANY_REQUESTS);
    }
    Decision::Pass
}
```

**IP Reputation:**
- Checks the source IP against:
  1. **Allow list** (CIDR) — bypasses all later checks (e.g., internal monitoring tools).
  2. **Deny list** (CIDR) — immediately blocked (e.g., known bad ASNs).
  3. **External feeds** — the blocklist is periodically updated from threat intelligence feeds (e.g., AlienVault OTX, abuse.ch) via a background task.
- Also checks IP **reputation score** from the correlation engine (persistent across requests). An IP that scored 80+ on previous attacks gets tighter rate limits even on Phase 0.

---

##### Phase 1: Request Headers

Runs after the full HTTP request line and headers are parsed. This is the **heaviest phase** — most rules and checks fire here.

**Rate Limiting (token bucket):**
- Applied at three levels simultaneously:
| Scope | Bucket Key | Capacity | Refill |
|-------|-----------|----------|--------|
| **Per-IP** | `{site_id}:{client_ip}` | 1000 req | 100 req/sec |
| **Per-site** | `{site_id}` | 10000 req | 500 req/sec |
| **Global** | `__global__` | 50000 req | 2000 req/sec |

- Uses **Redis** as the distributed counter store (or in-memory HashMap as fallback).
- The `X-RateLimit-Remaining` and `Retry-After` headers are set on the response.
- Burst traffic within token bucket capacity passes; sustained overuse gets 429.

**Bot Detection (two layers):**
1. **User-Agent classification** — Regex-based detection of known bot UAs (Googlebot, Bingbot, etc.) vs. headless browsers (Puppeteer, Playwright) vs. curl/wget/Go HTTP client.
2. **JA4 TLS fingerprint** — Extracts the TLS handshake parameters (cipher suites, extensions, curves) and hashes them into a fingerprint string. This identifies the actual TLS library regardless of what the User-Agent header claims. A request claiming to be Chrome but showing a Go TLS fingerprint → flagged as bot.

```rust
// JA4 fingerprint extraction (conceptual)
fn ja4_fingerprint(tls: &TlsClientHello) -> String {
    let ciphers = hash_cipher_suites(&tls.cipher_suites);
    let extensions = hash_extensions(&tls.extensions);
    let curves = hash_supported_groups(&tls.supported_groups);
    format!("t{tls.version:d}{ciphers}{extensions}{curves}")
}
// Example: "t13d1516h2_8daaf6152771_b011b1e0e2f9" = real Chrome
// Anything else may be suspicious
```

**GeoIP filtering:**
- Uses the **MaxMind GeoLite2** database (downloaded and periodically refreshed) to map the source IP to a country code.
- Configurable per-site: `allow_countries: [US, GB, DE]` (only these countries allowed) or `deny_countries: [RU, CN, KP]`.
- Useful for geo-fencing — e.g., a US-only e-commerce site can block all non-US traffic at the WAF layer.

**Rule Engine (SRL — Sentinel Rule Language):**
This is the heart of the WAF. It supports two rule formats:

1. **CRS compatibility (ModSecurity SecRule syntax):**
   ```
   SecRule REQUEST_HEADERS:User-Agent "@pmFromFile ua-blocklist.data" \
       "id:1000001,phase:1,deny,status:403,msg:'Blocked UA'"
   ```
   The CRS compatibility layer (`crates/sentinel-rules/src/crs_compat/`) parses `SecRule` directives, transforms them into the internal AST, compiles to bytecode, and runs them through the same VM. This means **existing ModSecurity/CRS rule sets work without modification**.

2. **Native SRL DSL:**
   ```
   rule BlockSQLInjection
       when REQUEST_ARGS matches r"(\bselect\b.*\bfrom\b|union\s+select|--\s)"
       phase 1
       action deny(403)
       msg "SQL injection attempt detected"
   end
   ```

The rule pipeline:
```
Raw text (SecRule or DSL)
  → Lexer (tokenizes into tokens)
    → Parser (builds AST — Abstract Syntax Tree)
      → Semantic Analyzer (validates variables, operators, transforms)
        → Bytecode Compiler (AST → Vec<Opcode> linear bytecode)
          → Stack-based VM (executes bytecode per-request, O(n) in rule count)
```

Variables available to rules include all HTTP headers, URI components, body fields, and internal WAF state:
| Variable | Description |
|----------|-------------|
| `REQUEST_HEADERS:User-Agent` | The User-Agent header |
| `REQUEST_METHOD` | GET, POST, etc. |
| `REQUEST_URI` | Full URI path + query string |
| `ARGS:username` | POST/GET parameter |
| `FILES` | Uploaded file names |
| `TX:anomaly_score` | Internal anomaly score |
| `IP:src` | Source IP address |

**WASM Plugins:**
Plugins are `.wasm` modules compiled from Rust, Go (via TinyGo), or AssemblyScript. They run in **wasmtime** — a sandboxed WebAssembly runtime with no access to the host system unless explicitly granted.

```rust
// A WASM plugin's evaluate() function (called per-request)
#[no_mangle]
pub extern "C" fn evaluate() -> i32 {
    let uri = host_get_req_header(":path");  // Imported from host
    if uri.contains("wp-admin") {
        host_set_decision(0, 403, "Blocked wp-admin"); // decision_id, status, msg
        return 0; // blocked
    }
    1 // pass
}
```

**Capability grants** (declared in `sentinel-plugin.toml`):
```toml
[capabilities]
can_block = true       # Plugin can block requests
can_read_headers = true
can_call_http = true   # Plugin can make outbound HTTP calls (to auth services, etc.)
can_kv_write = false   # Plugin cannot write to KV store
```

Plugins are **hot-swappable** — the plugin runtime watches the filesystem for new `.wasm` files and atomically swaps the `Arc<ArcSwap<PluginSet>>` pointer. Zero-downtime plugin updates.

---

##### Phase 2: Request Body

Runs after the full body is buffered (up to the configured size limit, default 1MB — larger bodies are streamed but not inspected).

**Body Size Limit:**
- Configurable per-site: `max_body_size: 10MB`.
- Requests exceeding the limit get `413 Payload Too Large` — prevents memory exhaustion attacks.

**Rule Engine (Body mode):**
- Same SRL VM as Phase 1, but now `REQUEST_BODY` and individual `ARGS:name` variables are populated.
- CRS rules that operate on POST parameters fire here.
- Supports `t:urlDecode`, `t:htmlEntityDecode`, `t:removeNulls`, `t:compressWhitespace` **transformations** — the same as ModSecurity.

**ML Inference (inline):**
This is where the machine learning models run:

1. **Feature extraction** — 24 numerical features are extracted from the request:
   - Payload length, entropy, character distribution
   - Ratio of special characters (`'`, `"`, `;`, `--`, `<`, `>`)
   - Number of URL-encoded sequences
   - Presence of NULL bytes
   - Repeated parameter names
   - Byte-level n-gram frequencies (4-grams at positions 0-127)
   - ... and more

2. **Isolation Forest** — An unsupervised anomaly detection algorithm. It builds random decision trees and measures how "isolated" a request payload is. Requests that isolate quickly (short path in the tree) are anomalies — likely attacks. This catches **zero-day attacks** that no rule has ever seen.

3. **Payload Attack Classifier** — A small ONNX neural network (~2ms inference) trained on 500K+ real attack payloads. Classifies into: SQLi, XSS, Command Injection, Path Traversal, SSRF, LDAP Injection, NoSQL Injection, and Benign.

```rust
// ML inference pipeline (conceptual)
fn ml_classify(ctx: &RequestContext) -> MlResult {
    let features = extract_24_dim_features(ctx.body());
    let anomaly = isolation_forest.score(&features); // 0.0 = normal, 1.0 = anomalous
    let attack_type = onnx_classifier.predict(&features); // "sqli", "xss", etc.
    MlResult { anomaly_score: anomaly, predicted_class: attack_type, confidence: 0.94 }
}
```

**Anomaly Gate:**
- Combines scores from ALL checks so far — rule matches (weighted by severity), ML anomaly score, bot score, IP reputation.
- Each rule match adds to a running anomaly score:
  | Severity | Points |
  |----------|--------|
  | Critical | +10 |
  | Error | +5 |
  | Warning | +2 |
  | Notice | +1 |

- If total >= configured threshold (default 10) → block with 403.
- The anomaly score is also stored in the **correlation engine** for the source IP, so even if this request barely misses the threshold, subsequent requests from the same IP accumulate.

---

##### Phase 3: Upstream Forwarding

If all previous phases passed the request, it's now forwarded to the **backend server** (your actual application).

**Load Balancer:**
- **RoundRobin** — simple, distributes evenly (default).
- **LeastConn** — sends to the upstream with fewest active connections (good for variable-length requests).
- **IpHash** — same client IP always goes to same upstream (useful for session affinity without cookies).
- **Adaptive** — monitors response times and dynamically weights upstreams. Slower upstreams receive fewer requests.

**Health Checks:**
- **Active** — the proxy periodically sends `GET /health` (configurable) to each upstream. If N consecutive checks fail, the upstream is marked **unhealthy** and removed from rotation.
- **Passive** — the proxy monitors real request failures (5xx, timeouts, connection refused). If M consecutive failures occur, the upstream is also marked unhealthy. This catches failures faster than periodic active checks.

**Circuit Breaker:**
- Tracks **consecutive failures** per upstream (timeouts, 5xx, connection errors).
- After threshold (configurable, default 5) → circuit **opens** → all requests to that upstream fail instantly (returning 503 to client).
- After a **cool-down period** (default 30s) → circuit enters **half-open** → allows 1 probe request. If it succeeds, circuit **closes** (normal operation). If it fails, back to open.
- Prevents cascade failures — your backend crashing doesn't take down the proxy.

**WebSocket Relay:**
- Detects `Upgrade: websocket` header.
- Upgrades the connection and **bidirectionally relays** frames between client and backend.
- WAF rules still apply to the initial HTTP upgrade request (Phase 1-2), but once upgraded, no further inspection happens on individual WebSocket frames (they're opaque binary at this layer).

---

##### Phase 4: Response Headers

Runs after the backend sends response headers back through the proxy.

**Security Headers (injected automatically):**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'; script-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

These mitigate entire classes of client-side attacks (clickjacking, MIME sniffing, XSS via inline scripts).

**Header Rewriting:**
- Strips **hop-by-hop headers** (`Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Authorization`) — these are meant for the proxy, not the client.
- Optionally rewrites `Location` headers in redirects (for reverse proxy setups where internal hostnames must be replaced with public ones).
- Strips `Server` header or sets it to a generic value (security by obscurity — don't advertise your backend stack).

---

##### Phase 5: Response Body

Runs after the full response body is received from the backend (before sending to client). This is the **DLP (Data Loss Prevention)** scan.

**What it scans for:**
1. **Credit card numbers** — Luhn algorithm check + regex for major card prefixes (Visa, MasterCard, Amex, etc.). Catches both explicit and obfuscated numbers (`4111-1111-1111-1111` or `4111111111111111`).
2. **Social Security Numbers** — `\d{3}-\d{2}-\d{4}` pattern with area number validation.
3. **API keys / Secrets** — Pattern matching for common formats:
   - `sk_live_...` / `pk_live_...` (Stripe)
   - `ghp_...` (GitHub PAT)
   - `AKIA...` (AWS Access Key)
   - `-----BEGIN RSA PRIVATE KEY-----` (Private keys)
   - High-entropy strings (Shannon entropy > 4.5 on alphanumeric tokens)
4. **JWT tokens** — `eyJ...` base64url-encoded patterns with signature verification.

**When it triggers:**
- If a DLP match is found, the response body is **replaced** with a sanitized version (numbers masked, keys redacted) or the entire response is replaced with a 403.
- Configurable per-site: `dlp: { mode: "log" | "block" | "mask" }`.

---

##### Phase 6: Logging

After the response is sent to the client, the WAF records everything that happened.

**Structured Logging (NDJSON — Newline-Delimited JSON):**
Each event type is a JSON object on its own line:

```json
// Access event (every request)
{"type":"access","ts":"2026-05-25T12:34:56Z","src_ip":"203.0.113.5","method":"GET","uri":"/login","status":200,"latency_ms":2.3,"site_id":"acme-corp"}

// WAF block event
{"type":"waf","ts":"2026-05-25T12:34:57Z","src_ip":"198.51.100.20","rule_id":1000001,"msg":"SQL injection attempt","severity":"critical","anomaly_score":15,"phase":2}
```

**OpenTelemetry:**
- **Traces** — Each request generates a trace spanning all 7 phases. Phase-level spans show which phase consumed the most time.
- **Metrics** — Exposed in Prometheus text format:
  ```
  sentinel_requests_total{site="acme-corp",status="200"} 154320
  sentinel_blocks_total{site="acme-corp",phase="1"} 1245
  sentinel_latency_ms{site="acme-corp",quantile="0.99"} 0.87
  sentinel_rule_hits_total{rule_id="1000001"} 342
  sentinel_ebpf_drops_total 89234
  ```
- **Logs** — The same NDJSON events are also emitted via OTLP for ingestion into observability platforms.

**Correlation Engine:**
- Maintains a **per-IP state** in Redis (TTL: 24h):
  ```json
  { "hits": 154, "blocks": 12, "anomaly_score": 67, "rules_hit": [1000001, 1000002], "first_seen": "2026-05-24T08:00:00Z" }
  ```
- This state feeds back into Phase 0 and Phase 1 for the same IP on subsequent requests.
- If an IP accumulates enough anomaly score over time, it gets **auto-blocklisted** (added to the eBPF kernel blocklist for faster dropping).

---

### 4. 🟣 Control Plane — Go (Raft Cluster)

The control plane never touches the request path. It's the **management layer** — handles configuration, user authentication, dashboards, and coordination.

**Why Go instead of Rust?** Go's goroutines, fast compilation, and extensive web ecosystem make it ideal for REST APIs, database operations, and CLI tools. The request path is in Rust where every nanosecond counts; the admin path is in Go where developer velocity matters more.

**REST API (Gin):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /api/v1/auth/login` | POST | JWT login |
| `GET /api/v1/dashboard/stats` | GET | Live dashboard numbers |
| `GET/POST /api/v1/sites` | GET/POST | List / create sites |
| `PUT/DELETE /api/v1/sites/:id` | PUT/DELETE | Update / delete site |
| `PUT /api/v1/sites/:id/status` | PUT | Pause / resume site |
| `GET/POST /api/v1/rules` | GET/POST | List / create rules |
| `POST /api/v1/rules/test` | POST | Dry-run rule against payload |
| `GET /api/v1/traffic/history` | GET | Time-series chart data |
| `DELETE /api/v1/rules/:id` | DELETE | Delete rule |
| `GET /api/v1/logs/stream` | GET | **SSE endpoint** — live streaming logs |
| `POST /api/v1/admin/users` | POST | Create admin user |
| `GET /api/v1/internal/config` | GET | **Data plane polls this** for site config |

**gRPC Server (port 9500):**
- Used by data planes to subscribe to config changes (server-streaming RPC).
- Used for internal cluster communication.
- Authenticated with mTLS certs.

**Raft Consensus:**
- The control plane runs as a cluster of **3 or 5 nodes** (odd number for quorum).
- **Raft** is a consensus algorithm that ensures all nodes agree on the same state (sites, rules, users) even if some nodes fail.
- If the leader fails, the remaining nodes elect a new leader within ~150ms.
- Data planes connect to any control plane node — writes go through the leader, reads work on any node.
- This means no single point of failure.

**PostgreSQL 16:**
- Stores all persistent data: tenants, users, sites, rules, alerts, audit logs.
- **Row-Level Security (RLS):** Every table has a `tenant_id` column + RLS policy. Even if a bug in the application code forgets to filter by tenant, the database enforces it. This is defense-in-depth for multi-tenancy.

**Auth + RBAC:**
- JWT-based authentication (access + refresh tokens).
- OIDC support (login via Google, GitHub, Okta, etc.).
- Three default roles:
  | Role | Permissions |
  |------|-------------|
  | `admin` | Full access — manage everything |
  | `operator` | Manage sites, rules — cannot manage users |
  | `viewer` | Read-only dashboard access |

**HMAC-signed Audit Log:**
- Every sensitive operation (login, rule change, site create/delete, user management) is logged with a **HMAC-SHA256 signature** chained to the previous entry.
- `audit_entry[i] = { event, timestamp, actor, hash_of(prev_entry), HMAC(concat(prev_hash, event, actor, ts)) }`
- This makes the audit log **tamper-evident** — modifying any entry breaks the HMAC chain, and the breakage is immediately detectable.

**Config Service:**
- When sites or rules are created/updated via the REST API, the config service:
  1. Writes the new state to PostgreSQL.
  2. Raft-replicates it across the cluster.
  3. Pushes the update to all connected data planes via gRPC server-streaming.
- Data planes hot-swap the config via `Arc<ArcSwap<SiteConfig>>` — atomically, no downtime.

**SSE Log Stream:**
- The control plane subscribes to Redis pub/sub for WAF events (or receives them directly from data planes via gRPC).
- Dashboard clients connect to `GET /api/v1/logs/stream` and receive **Server-Sent Events** (SSE) — real-time log streaming without WebSockets or polling.
- Dev mode includes a **simulator** that generates fake traffic so the dashboard always has data to display.

---

### 5. 💾 Storage Backends

| Database | Technology | What it stores | Access pattern |
|----------|-----------|----------------|----------------|
| **PostgreSQL 16** | SQL (relational) | Users, tenants, sites, rules, plugins, alerts, audit logs | OLTP — frequent small reads/writes |
| **Redis 7** | In-memory KV | Rate-limit counters, per-IP correlation state, distributed locks, pub/sub for log streaming | Microsecond reads/writes, TTL-based expiry |
| **ClickHouse** | OLAP (columnar) | Access logs, security events, traffic metrics (1s/1m/1h rollups) | Analytical queries, time-range aggregations |
| **S3/MinIO** | Object storage | ML model blobs (ONNX), WASM plugin binaries, scanner reports, config backups | Infrequent large reads/writes |

All backends have **degraded-mode fallbacks**:
- Redis down → rate limiting falls back to in-memory HashMap (per-node, reset on restart).
- ClickHouse down → metrics stored in memory ring buffer (last 1000 entries).
- S3 down → ML models are loaded from a local cache; WASM plugins use the last loaded set.

---

### 6. 📊 Dashboard — Next.js 14 + TypeScript

The admin web interface for managing the WAF. Built with:

| Technology | Purpose |
|-----------|---------|
| **Next.js 14 (App Router)** | Framework — server-side rendering, API routes |
| **TypeScript** | Type safety |
| **Tailwind CSS** | Styling — utility-first CSS |
| **Recharts** | Charts — traffic/block graphs |
| **React Query** | Server state management — auto-refetch, caching |
| **SSE (EventSource)** | Live log streaming from control plane |

**Pages:**
| Route | Content |
|-------|---------|
| `/login` | JWT login form |
| `/dashboard` | Overview — RPS, p99 latency, blocks, eBPF drops, connected clients |
| `/sites` | CRUD for protected sites — name, upstreams, TLS, rules |
| `/rules` | Rule list, create, tester (dry-run against sample payload) |
| `/logs` | SSE live log viewer — filter by site, status, phase |
| `/alerts` | Alert list with ack/resolve |
| `/ml` | ML model stats — precision, recall, FP/TP rates |
| `/plugins` | Installed WASM plugins |
| `/settings` | User management, API keys, RBAC, audit log viewer |

**LLM Copilot:**
A chat UI (floating action button) that:
1. **Explains alerts** — "Why was this request blocked?" → sends alert context to an LLM → returns plain-English explanation.
2. **Suggests rules** — "Write a rule to block requests from ASN 12345" → generates SRL DSL → user can one-click add.

---

### 7. 🤖 ML Pipeline

Three tiers with increasing cost and capability:

| Tier | Latency | Scope | Model | When it runs |
|------|---------|-------|-------|-------------|
| **Tier 1: Inline** | ~2ms | Every request | 24-dim features + Isolation Forest + light ONNX classifier | Phase 2 of every request |
| **Tier 2: Near-line** | ~50-200ms | ~1% of requests (suspicious only) | Transformer-based deep analysis (e.g., BERT for payloads) | Async, sampled after Phase 2 if anomaly score > 3 |
| **Tier 3: Offline** | Minutes-hours | Training pipeline | Model training, drift detection, LLM copilot | Control plane, scheduled |

**Inline ONNX models** are loaded from S3 at startup and cached in memory. Inference uses the `ort` crate (ONNX Runtime for Rust).

---

### 8. 🔌 Plugin Ecosystem

WASM-based extension system:

| SDK | Language | Compiler | Status |
|-----|----------|----------|--------|
| `sdk-rust` | Rust | `wasm32-wasip1` target | ✅ Stable |
| `sdk-go` | Go | TinyGo → WASM | ✅ Stable |
| `sdk-assemblyscript` | AssemblyScript | AS compiler | ✅ Stable |

**Host ABI** — functions the WASM runtime exposes to plugins:
```rust
// Host functions imported by plugins
host_log(level: i32, msg: *const u8, len: i32);          // Log from plugin
host_get_req_header(name: *const u8) -> *const u8;       // Read request header
host_set_decision(id: i32, status: i32, msg: *const u8); // Block/allow request
host_http_callout(url: *const u8, body: *const u8) -> *const u8; // Outbound HTTP
```

Plugin examples include JWT validators, custom auth headers, IP allowlists, and request transformers.

---

### 9. 📜 Rule Sources

Sentinel loads rules from four sources:

| Source | Format | Authority | Update method |
|--------|--------|-----------|---------------|
| **OWASP CRS 4.7** | ModSecurity `SecRule` syntax | CRS project | Vendored, periodic sync |
| **SRL (native DSL)** | `sentinel-rule-language` | WAF administrator | Written via dashboard or API |
| **Virtual Patches** | SRL DSL | Auto-generated from scanner reports | Created by `rule-converter` tool |
| **Community** | SRL DSL | Community submissions | Downloaded via dashboard |

The **CRS compat layer** (`crates/sentinel-rules/src/crs_compat/`) parses ModSecurity syntax and compiles it to the same bytecode VM. This means Sentinel can run **any existing ModSecurity rule set** — including the OWASP Core Rule Set, which contains ~200 rules covering SQLi, XSS, LFI, RCE, and other attack categories.

---

## Request Flow Example (End-to-End)

Let's trace a single request through the entire system:

```
Client sends: POST /login HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/124
Content-Type: application/x-www-form-urlencoded
Body: username=admin'--&password=letmein
```

| Step | Component | What happens | Decision |
|------|-----------|-------------|----------|
| 1 | **eBPF/XDP** | Source IP `203.0.113.5` checked against BPF blocklist → not found | PASS |
| 2 | **TLS** | Handshake completes, SNI `app.example.com` matched to site config | PASS |
| 3 | **Phase 0** | Connection rate: 2 connections in last second (< threshold 100) | PASS |
| 4 | **Phase 1** | JA4 fingerprint matches real Chrome; UA known browser; GeoIP US allowed; rate limit: 20 req/min (< 1000) | PASS |
| 5 | **Phase 2** | Body parsed. Rule `1000001` (SQLi detection) matches `username=admin'--` → anomaly +10. ML classifier: 94% confidence SQLi, anomaly score 0.87. Total anomaly: 10.87 > threshold 10 | **BLOCK (403)** |
| 6 | **Correlation** | IP `203.0.113.5` anomaly score updated to 67 in Redis | — |
| 7 | **Logging** | WAF event logged: `{"rule_id":1000001,"msg":"SQLi","anomaly":10.87,"action":"block"}` | — |
| 8 | **Response** | Client receives `403 Forbidden` with `Content-Type: text/plain` body "Request blocked by security policy" | — |

Total latency added by the WAF: **~0.4ms** (p50) — the request never reached the backend.

---

## Scaling

| Component | Scales by | State |
|-----------|-----------|-------|
| **Data plane (Rust)** | Add more nodes horizontally (stateless) | None — config from gRPC, rate limit in Redis |
| **Control plane (Go)** | Raft cluster (3 or 5 nodes) | PostgreSQL (shared) + Raft replicated state |
| **eBPF/XDP** | Per-node (kernel does the work) | BPF maps (kernel memory) |
| **Dashboard** | Stateless Next.js — scale via CDN/LB | JWT carries session |

Data planes are completely stateless — you can run 1 or 1000 of them behind a load balancer. Control planes form a Raft cluster for HA.

---

*Generated from the Sentinel WAF codebase at `/home/ayush3750/waf-development/`*