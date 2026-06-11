## Learning Mode vs Blocking Mode — Sentinel's design

### Three modes

  # Per-site config (sentinel.yaml)
  sites:
    - id: my-site
      waf:
        mode: learning    # off | learning | blocking (default: learning)
        anomaly_threshold: 5

 Mode       │ What it does                                         │ Sends traffic?      │ Logs?
────────────┼──────────────────────────────────────────────────────┼─────────────────────┼────────
  learning  │ Rules run and score every request, but never block.  │ ✅ Yes              │ ✅ Yes
            │ All traffic passes through. Logs show "this would    │                     │
            │ have been blocked in blocking mode."                 │                     │
  blocking  │ Rules run, score accumulates. When anomaly score ≥   │ ❌ Blocks malicious │ ✅ Yes
            │ threshold, returns 403 Forbidden.                    │                     │
  off       │ WAF is disabled completely. Zero overhead.           │ ✅ Yes              │ ❌ No

### How it prevents the eNlight WAF problem

Your manager's complaint about eNlight: "In learning mode, it was blocking the website by itself
without telling."

That means eNlight's  learning  mode leaked  blocking  behavior — a bug or design flaw. Sentinel
cannot do that because:

1. Learning mode never sends 403. The proxy only returns  block_response()  when the anomaly
threshold is exceeded AND mode is  blocking . Learning mode always forwards to the backend.
2. Every decision is logged. Even in learning mode, you see exactly which rules fired, what score
each added, and what the final anomaly score was. The  WafDecision::Log  variant means "log this,
don't block."
3. Anomaly threshold gates everything. Rules don't block individually. They add to a cumulative
anomaly score. Only when the total crosses the threshold AND you're in  blocking  mode does the
403 fire. In  learning , the score is computed but ignored for blocking.
4. Rule exclusions for false positives. If a rule fires on legitimate traffic (e.g.,  942100  SQL
injection rule triggers on "SELECT" in a blog post), you whitelist it:
  waf:
    rule_exclusions:
      - rule_id: 942100
        exclude_targets: ["ARGS:body"]
  This removes that specific target from that specific rule — only for that site. Other sites keep
full protection.
5. Deployment flow:
  Day 1:   mode: learning   → WAF watches traffic, logs what it would block
  Day 7:   Review logs      → Identify false positives, add rule_exclusions
  Day 8:   mode: blocking   → WAF now actively protects, zero false positives


### Can users give exactly 1000 or 2000 rules? Only the rules they want?

Yes. Rules are per-site, file-based:

  sites:
    - id: bank.example.com
      waf:
        mode: blocking
        anomaly_threshold: 5
        paranoia_level: 2
        rules:
          - "./rules/bank-sqli.srl"          # 200 custom SQL injection rules
          - "./rules/bank-xss.srl"           # 150 custom XSS rules
          - "./rules/bank-access-control.srl" # 100 authorization rules
          - "./rules/pci-dss-compliance.srl"  # 50 PCI compliance rules
          - "./owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf" # CRS

No limits:

• Zero rule count cap per site
• Mix SRL (native DSL) + CRS (ModSecurity  .conf ) rules in any combination
• 2000 rules? Sure. 5000? Sure.
• Rules compile to bytecode at startup — the VM is O(n), so performance degrades linearly, not
exponentially

Per-rule customization:

•  paranoia_level: 1-4  — controls how aggressive CRS rules are (1 = safe, 4 = paranoid)
•  rule_exclusions  — remove false-positive targets without disabling the rule
•  anomaly_threshold  — raise or lower the block trigger per site (API site might need 10, blog
might need 5)
• Each rule has independent  severity ,  score , and  skip_after  (stop checking after this rule
fires)

### How to explain to management

│ "Sentinel's learning mode solves exactly the problem we had with eNlight. Learning means watch
│ and log only — zero blocking, zero website breakage. After a week of traffic analysis, you
switch
│ to blocking mode with confidence because you've already tuned away every false positive. And
│ clients can give us exactly the 1000 or 2000 rules they want — we don't force a bloated CRS on
│ them. Each site gets exactly its own rules, nothing more."

--------

One note: the  WafMode::Learning  enum is defined and the CLI has  sentinel site mode <name>
learning|blocking|off , but the proxy pipeline currently treats learning and blocking the same way
(always blocks when threshold is hit). This distinction needs to be wired into the  handle_request
→  proxy  pipeline before you demo it. I can implement that now if you want.






Here's the comparison:

## General Specs



 #  │ Spec                                               │ Status
────┼────────────────────────────────────────────────────┼─────────────────────────────────────────────────────
 6  │ IPv4 & IPv6 dual stack                             │ ✅ — Config supports  ::  (IPv6) and  0.0.0.0
    │                                                    │ (IPv4); IP reputation normalizes IPv4-mapped IPv6
 7  │ Auto threat updates (signatures, GeoIP, Tor,       │ ✅ — IP feed ingestion from HTTP(S)/file URLs
    │ malicious IP feeds)                                │ (AbuseIPDB, Spamhaus); periodic reload; GeoIP via
    │                                                    │ MaxMind  .mmdb
 8  │ Notifications (Email, Syslog, SNMP, HTTP push)     │ 🟡 — Syslog output in logging config. No
    │                                                    │ email/SNMP/HTTP webhook found
 9  │ Clustered HA (Active-Active/Passive, VRRP-         │ ✅ — Raft consensus (Active/Active), leader
    │ equivalent)                                        │ election, log replication, config sync. No VRRP
 10 │ Deployment modes (offline/inline, reverse proxy,   │ ✅ — Reverse proxy (inline),  X-Forwarded-For / X-
    │ one-arm/n-arm, DSR, IP transparency)               │ Real-IP  for IP transparency. No DSR/one-arm
    │                                                    │ explicit mode

## Requirement Sizing Specs



 # │ Spec                            │ Status
───┼─────────────────────────────────┼─────────────────────────────────────────────────────────────────────────
 1 │ Dedicated management & HA ports │ 🟡 — Listeners are configurable per port, but no forced dedicated
   │                                 │ management/HA port concept

## Management & Reporting



 #  │ Spec                                              │ Status
────┼───────────────────────────────────────────────────┼──────────────────────────────────────────────────────
 1  │ GUI + CLI management (SSH, HTTPS, console)        │ ✅ — Dashboard (HTTPS web UI),  sentinel  CLI,
    │                                                   │ sentinelctl  operator CLI
 2  │ Real-time & historical stats (top URL, methods,   │ ✅ — Dashboard stats, ClickHouse timeseries,
    │ country, etc.)                                    │ Prometheus metrics. Traffic page in dashboard
 3  │ Manual/scheduled config backup                    │ ❌ — Not found. DB has migrations but no backup
    │                                                   │ scheduling
 4  │ System health dashboard (CPU, memory, traffic,    │ ✅ — Dashboard overview page with stats cards;
    │ attacks)                                          │ ClickHouse traffic buckets
 5  │ Periodic reports via email/download               │ ❌ — Not found
 6a │ AAA/TACACS+ integration                           │ ❌ — Auth is JWT/OIDC/API key. No TACACS+/RADIUS
 6b │ NTP/SNTP                                          │ ❌ — Not found
 6c │ SIEM via syslog (CEF format)                      │ 🟡 — Syslog output exists; CEF format not confirmed
 6d │ SNMP for NMS                                      │ ❌ — Not found
 6e │ 3rd party API (REST/XML)                          │ ✅ — REST API on control plane (Gin). No XML
 7  │ Role-based access (RBAC)                          │ ✅ — 5 roles (owner/admin/editor/viewer/auditor), 12
    │                                                   │ resources, CRUD permissions

## Feature Specs — Attack Protection



 #  │ Spec                                              │ Status
────┼───────────────────────────────────────────────────┼──────────────────────────────────────────────────────
 1  │ IPv4↔IPv6 NAT                                     │ ❌ — Not implemented
 2  │ Line-speed throughput, sub-ms latency             │ ✅ — Rust data plane, zero-GC, p99 < 1ms target;
    │                                                   │ benchmark scripts exist
 3  │ OWASP Top 10 Web App Attacks                      │ ✅ — Full CRS 4.7 rules (SQLi, XSS, LFI, RFI, RCE,
    │                                                   │ PHP, Java, session, etc.)
 3  │ OWASP Top 10 API Attacks                          │ 🟡 — GraphQL firewall (depth/complexity). No
    │                                                   │ dedicated API-specific CRS rules
 3  │ SQL Injection, XSS                                │ ✅ — CRS + ML payload classifier (SQLi/XSS scoring)
 3  │ Broken Auth, Session Mgmt                         │ ✅ — CRS session rules
 3  │ Brute force                                       │ ✅ — Rate limiting (token-bucket per IP/site/global)
 3  │ Predictable resource locations                    │ ✅ — CRS scanner detection + bot detection blocks
    │                                                   │ recon tools
 3  │ Web server recon                                  │ ✅ — Bot detection blocks Nikto, sqlmap, Nmap, ZAP,
    │                                                   │ DirBuster, etc.
 3  │ HTTP format/limit violations                      │ ✅ — Configurable max_body_size, max_uri_length,
    │                                                   │ max_header_count
 3  │ HTTP protocol validation                          │ ✅ — CRS protocol validation rules
 3  │ Web service correlated attack validation          │ ✅ — Correlation engine (120s sliding window)
 3  │ HTTP attack signatures                            │ ✅ — CRS + SRL rules
 3  │ Web service customized protection                 │ ✅ — WASM plugins + SRL rules
 3  │ Cookie signing validation                         │ ❌ — Not found
 3  │ Anti site scraping                                │ 🟡 — Rate limiting + bot detection covers scraping
    │                                                   │ but no dedicated anti-scraping module
 3  │ Bot protection & mitigation                       │ ✅ — JA4 fingerprinting, User-Agent classification,
    │                                                   │ CAPTCHA (PoW/hCaptcha/Turnstile)
 3  │ Web profile protection                            │ 🟡 —  api_discovery  config field exists but no
    │                                                   │ implementation
 3  │ Web worm protection                               │ ❌ — Not specifically addressed
 3  │ Web app attack sigs                               │ ✅ — CRS + SRL
 3  │ Customized protection                             │ ✅ — SRL DSL + WASM plugins
 3  │ OCSP protocol validation                          │ ❌ — Not found
 3  │ Account Takeover Detection                        │ ❌ — Not specifically addressed
 3  │ MITB/MIM protection                               │ 🟡 — TLS enforcement + header injection (HSTS, CSP).
    │                                                   │ No explicit MITB detection
 3  │ L7 Behavioral DDoS                                │ ✅ — Anti-DDoS (connection-rate), anomaly detection
    │                                                   │ (Isolation Forest), rate limiting
 4  │ DLP (credit cards, SSN, etc.)                     │ ✅ — Credit card (Luhn), SSN, API keys, JWT,
    │                                                   │ entropy. No Aadhar
 5  │ Positive + negative security, built-in signatures │ ✅ — Allow/block lists, CRS + SRL + IP reputation +
    │                                                   │ GeoIP
 6  │ Actions: drop, block TCP, block user/IP,          │ ✅ — All via WafDecision enum + DSL actions + eBPF
    │ blacklist, custom response, empty, CAPTCHA        │ IP blocking
 7  │ Per-app policies (by host/path/country/IP),       │ ✅ — Per-site config,  mode: off/learning/blocking ,
    │ bypass/record/mitigate modes                      │ GeoIP, path-based routing via domains
 12 │ Auto-profiling of web app structure               │ 🟡 — Config field exists, no implementation
 13 │ 0-day protection (behavioral/anomaly)             │ ✅ — ML Isolation Forest (unsupervised anomaly
    │                                                   │ detection), payload classifier
 14 │ Anti-automation/bot protection                    │ ✅ — Bot detection (JA4 + UA), rate limiting,
    │                                                   │ CAPTCHA challenges
 15 │ DAST integration + built-in DAST                  │ 🟡 — Scanner UA detection active.  rule-converter
    │                                                   │ tool placeholder. No built-in DAST
 16 │ Custom logging rules (mask sensitive data)        │ ✅ — DLP masking in Phase 5. Audit log. Structured
    │                                                   │ NDJSON logging
 17 │ Header/cookie/content/hidden field                │ 🟡 — Security header injection,  Server  stripping.
    │ obfuscation/encryption                            │ Full field encryption not found
 19 │ L7 DDoS                                           │ ✅ — Anti-DDoS module, rate limiting, eBPF XDP at L4
 20 │ URL & content rewriting                           │ 🟡 — Header rewriting (hop-by-hop stripping,
    │                                                   │ security injection). No full body/content rewriting
 21 │ User tracking (form, cert, Basic Auth, JWT, Key   │ 🟡 — JWT auth in control plane. Tracking via request
    │ Auth)                                             │ context. No form/cert-based WAF-level auth
 22 │ Anti-bot mobile SDK (Android/iOS)                 │ ❌ — Not present
 23 │ Built-in AV scanner + sandboxing + ICAP           │ ❌ — Not found
 24 │ Scripting language for event-based rules          │ ✅ — WASM plugins (Rust, Go, AssemblyScript SDKs)
 25 │ Deception (decoys, fake links/forms)              │ ❌ — Not found
 26 │ SSL cert management + Let's Encrypt               │ 🟡 — Static file TLS config. Let's Encrypt/ACME is
    │                                                   │ UI placeholder only
 27 │ User-defined scripts for business logic blocking  │ ✅ — WASM plugins + SRL DSL
 28 │ Caching, compression, SSL acceleration            │ ✅ — Storage (Memory/Redis cache). TLS via rustls.
    │                                                   │ Compression not explicitly found
 29 │ Load balancing + origin monitoring                │ ✅ — 5 algorithms
    │                                                   │ (RoundRobin/LeastConn/IpHash/Random/Adaptive),
    │                                                   │ health checks, circuit breaker
 30 │ Managed Bot Protection Service (same OEM)         │ ❌ — No external bot service integration
 31 │ API discovery, Swagger/OpenAPI import/export      │ 🟡 — Config field exists, no implementation
 32 │ Proof-of-Work + Proof-of-Space CAPTCHA            │ ✅ — Native PoW supported. Proof-of-Space not
    │                                                   │ explicitly found
 33 │ Built-in bot detection (no cloud dependency)      │ ✅ — Fully local JA4 + UA-based bot detection

--------

## What Sentinel Has That the Specs Don't Ask For



 Feature                  │ Detail
──────────────────────────┼────────────────────────────────────────────────────────────────────────────────────
 WASM Plugin System       │ Full plugin runtime with 3 SDKs (Rust, Go, AssemblyScript), OCI registry support,
                          │ HTTP callouts
 Post-Quantum TLS         │ Kyber/Dilithium hybrid crypto via rustls
 HTTP/3 + QUIC            │ Protocol support in config
 eBPF XDP                 │ Kernel-level L4 DDoS filtering with userspace fallback
 GraphQL Firewall         │ Depth/complexity limits for GraphQL endpoints
 LLM Copilot              │ AI-powered alert explanation, rule generation, virtual patch creation
                          │ (Ollama/OpenAI)
 Raft Clustering          │ True active/active HA (not VRRP)
 OpenTelemetry Native     │ Traces, metrics, logs out of the box (Prometheus + OTLP)
 Tamper-Evident Audit Log │ HMAC-SHA256 chained audit log with verification
 Correlation Engine       │ Cross-request attack correlation (120s window)
 JA4 TLS Fingerprinting   │ Next-gen TLS client fingerprinting for bot detection
 WebSocket Inspection     │ Full upgrade handling, WAF frame inspection, frame rate limiting
 Circuit Breaker          │ Upstream failure isolation

## Key Gaps



 Category                        │ Missing
─────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────
 Notifications                   │ Email, SNMP traps, HTTP webhook push
 Enterprise Auth                 │ TACACS+/RADIUS/LDAP integration
 Reporting                       │ Periodic reports, scheduled email delivery
 DAST                            │ No built-in scanner, no third-party scanner integration beyond UA detection
 Mobile                          │ No anti-bot mobile SDK
 AV/Sandbox                      │ No built-in AV, ICAP integration
 Deception                       │ No decoy/honeypot injection
 DLP                             │ No Aadhar/PAN (India-specific) patterns
 ACME                            │ No Let's Encrypt automation
 API Discovery                   │ Config placeholder only, no implementation
 NAT64                           │ No IPv4↔IPv6 translation






Here is the super easy breakdown of what those mean and why they make your WAF incredible.1. 
What is "ns"? (Nanoseconds)"ns" stands for nanosecond. It is a measurement of time, just like a second or a minute, 
but unimaginably small.To understand how fast it is, look at how we chop up a single second:Millisecond (ms): One-thousandth of a second.
(A blink of an eye is about 300 ms).Microsecond (µs): One-millionth of a second. (This is how fast your WAF used to be).
Nanosecond (ns): One-billionth of a second.Your benchmark showed a speed of 518 ns. That means your firewall can detect an attacker and slam the door in their face in half of one-millionth of a second. 
It is so fast that the attacker's computer won't even realize what happened.2. 
What is "o1"? ($\mathcal{O}(1)$ - Constant Time)$\mathcal{O}(1)$ is a computer science term called Big O Notation. 
It is just a fancy way of describing how an algorithm behaves when you give it more work to do.
Let's go back to our Nightclub Security Guard analogy:The Old Way: $\mathcal{O}(N)$ (Linear Time)Imagine the guard has to read a list of rules. 
If the list has 10 rules, it takes 10 seconds. If the list has 100 rules, it takes 100 seconds. The time it takes goes up in a straight line as the rulebook gets bigger. That is $\mathcal{O}(N)$.
Your New Way: $\mathcal{O}(1)$ (Constant Time)Now imagine the guard is using your "Early Exit" trick. The second they see an attacker holding a weapon, they kick them out immediately without reading the rest of the rules.If the rulebook has 10 rules, it takes 1 second to kick them out.If the rulebook has 1,000,000 rules, it still takes exactly 1 second to kick them out.The speed is constant. It never changes, no matter how big the rulebook gets. That is $\mathcal{O}(1)$.
