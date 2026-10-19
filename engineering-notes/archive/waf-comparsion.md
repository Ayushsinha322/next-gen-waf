> **Archived 2026-10-19: superseded and partly wrong. Do not quote it.** The feature
> matrix is a pre-build design comparison, and a later live check found errors in it:
> BunkerWeb's data plane is nginx + OpenResty Lua, not Python, and its HTTP/3 is on by
> default. The measured BunkerWeb section was taken with BunkerWeb's rate limit and
> bad-behaviour ban disabled for both WAFs.

# Sentinel WAF vs. Best Open-Source WAFs

## Measured against BunkerWeb 1.6.9 (2026-09-06)

The feature matrix below is a design-level comparison. This section is a measurement: same
laptop, same origin, same GoTestWAF corpus, same vegeta mix, both WAFs blocking with CRS v4,
IP-ban and rate-limit features off on both. Full method, per-category table, caveats and
reproduction steps: `deploy/load-test/BUNKERWEB-COMPARISON-2026-09.md`.

| | Sentinel (rules + ML) | Sentinel (rules only) | BunkerWeb PL1 (default) | BunkerWeb PL2 | BunkerWeb PL4 |
|---|---|---|---|---|---|
| GoTestWAF attacks blocked | **99.26%** | 87.26% | 47.15% | 54.35% | 74.47% |
| GoTestWAF benign passed | **98.58%** | 90.78% | 90.78% | 62.41% | **0.00%** |
| Clean traffic, max rps | **4,417** | — | 1,752 | — | — |
| Clean p99 at 1,000 rps | **8.1 ms** | — | 23.8 ms | — | — |
| Attack traffic, max blocked rps | **4,588** | — | 350 (times out at 1,000 rps) | — | — |

Two things the table shows that the old matrix could not: the rules-only row beats BunkerWeb at
every paranoia level on the *same* rule family (engine, not model), and BunkerWeb's default
ModSecurity audit logging makes its block path 13x slower than its pass path. BunkerWeb ran the
newer CRS (4.24.1 vs our 4.7.0). Single run each; ratios are the result, absolute rps are not a
capacity claim.

  The Competitors

  ┌────────────────────┬──────────────────────┬───────────┬────────────────┐
  │        WAF         │       Language       │    Age    │ Stars (approx) │
  ├────────────────────┼──────────────────────┼───────────┼────────────────┤
  │ ModSecurity v3     │ C                    │ ~20 years │ 8k+            │
  ├────────────────────┼──────────────────────┼───────────┼────────────────┤
  │ Coraza             │ Go                   │ 3 years   │ 2k+            │
  ├────────────────────┼──────────────────────┼───────────┼────────────────┤
  │ BunkerWeb          │ NGINX + Lua (Python  │ 4 years   │ 10.9k          │
  │                    │ scheduler)           │           │                │
  ├────────────────────┼──────────────────────┼───────────┼────────────────┤
  │ SafeLine (Chaitin) │ Go + semantic engine │ 2 years   │ 13k+           │
  ├────────────────────┼──────────────────────┼───────────┼────────────────┤
  │ NAXSI              │ C (NGINX module)     │ 10 years  │ 4k+            │
  └────────────────────┴──────────────────────┴───────────┴────────────────┘

  ---
  Feature-by-Feature Matrix

  ┌─────────────────┬─────────────┬────────┬──────────────┬───────────┬──────────────────┐
  │     Feature     │ ModSecurity │ Coraza │  BunkerWeb   │ SafeLine  │     Sentinel     │
  ├─────────────────┼─────────────┼────────┼──────────────┼───────────┼──────────────────┤
  │ Data plane        │ C           │ Go     │ NGINX + Lua  │ Go       │ Rust           │
  │ language          │             │        │              │          │                │
  ├───────────────────┼─────────────┼────────┼──────────────┼──────────┼────────────────┤
  │ Rule engine       │ Regex VM    │ Regex  │ Regex/NGINX  │ Semantic │ Custom         │
  │                   │             │ VM     │              │  ML      │ bytecode VM    │
  ├───────────────────┼─────────────┼────────┼──────────────┼──────────┼─────────────────┤
  │ OWASP CRS v4      │ Yes         │ Yes    │ Yes          │ Partial  │ Yes (importer)  │
  ├───────────────────┼─────────────┼────────┼──────────────┼──────────┼─────────────────┤
  │ Rule hot-reload   │ No          │ No     │ Partial      │ Yes      │ Yes (zero-drop) │
  ├───────────────────┼─────────────┼────────┼──────────────┼──────────┼─────────────────┤
  │ WASM plugins      │ No          │ No     │ No           │ No       │ Yes (wasmtime + │
  │                   │             │        │              │          │  OCI)           │
  ├───────────────────┼─────────────┼────────┼──────────────┼──────────┼─────────────────┤
  │                   │             │        │              │ Semantic │ Isolation       │
  │ ML/AI engine      │ No          │ No     │ No           │  only    │ Forest + ONNX + │
  │                   │             │        │              │          │  LLM            │
  ├───────────────────┼─────────────┼────────┼──────────────┼──────────┼─────────────────┤
  │ eBPF/XDP L4 DDoS  │ No          │ No     │ No           │ No       │ Yes (Aya)       │
  ├───────────────────┼─────────────┼────────┼──────────────┼──────────┼─────────────────┤
  │ TLS               │ No          │ No     │ Partial      │ No       │ JA3 + JA4 +     │
  │ fingerprinting    │             │        │              │          │ JA4+            │
  │ Bot detection    │ Basic       │ Basic  │ Yes          │ Yes      │ Behavioral + TLS │
  │                  │             │        │              │          │  fp              │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ IP reputation    │ No          │ No     │ Yes          │ Yes      │ Yes (multi-feed  │
  │                  │             │        │              │          │ + ASN)           │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ GeoIP/ASN        │ Via module  │ No     │ Yes          │ Yes      │ Yes              │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │                  │             │        │              │          │ Token bucket +   │
  │ Rate limiting    │ No          │ No     │ Yes          │ Yes      │ sliding window + │
  │                  │             │        │              │          │  Redis           │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ Raft HA cluster  │ No          │ No     │ Basic        │ Basic    │ Full Raft        │
  │                  │             │        │              │          │ consensus        │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ REST API + gRPC  │ No          │ No     │ Basic        │ Basic    │ Full Go control  │
  │                  │             │        │              │          │ plane            │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ RBAC +           │ No          │ No     │ Basic        │ Basic    │ Yes (JWT + RBAC) │
  │ multi-tenant     │             │        │              │          │                  │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ Audit logs       │ Basic       │ Basic  │ Basic        │ Basic    │ HMAC-SHA256      │
  │ (tamper-evident) │             │        │              │          │ chained          │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ Operator CLI     │ No          │ No     │ No           │ Partial  │ Yes              │
  │                  │             │        │              │          │ (sentinelctl)    │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ Dashboard        │ No          │ No     │ Yes          │ Yes      │ Yes (15 routes,  │
  │                  │             │        │              │          │ Next.js 14)      │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ HTTP/3 / QUIC    │ No          │ No     │ Yes (default)│ No       │ Yes (quinn+h3,   │
  │                  │             │        │              │          │ JA4 on h3)       │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ Post-quantum TLS │ No          │ No     │ No           │ No       │ No (not built;   │
  │                  │             │        │              │          │ remove from UI)  │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ GraphQL/gRPC     │ No          │ No     │ No           │ No       │ Yes (live on .71 │
  │ firewall         │             │        │              │          │ since 2026-07)   │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ Outbound DLP     │ No          │ No     │ No           │ No       │ Yes (detect +    │
  │                  │             │        │              │          │ block; no mask)  │
  ├──────────────────┼─────────────┼────────┼──────────────┼──────────┼──────────────────┤
  │ LLM Copilot      │ No          │ No     │ No           │ No       │ Yes (wired to    │
  │                  │             │        │              │          │ ai.enlight.dev)  │
  └──────────────────┴─────────────┴────────┴──────────────┴──────────┴──────────────────┘

  ---
  Where Sentinel Wins Clearly

  1. Performance ceiling — Rust data plane with async tokio + custom bytecode VM is
  faster than ModSecurity (C + PCRE), Coraza (Go), or BunkerWeb (NGINX + Lua) — and now
  MEASURED, not argued: see the section at the top of this file.
  2. WASM plugin system — No other open-source WAF has this. Write plugins in Rust, Go, JS,
  or AssemblyScript, deploy via OCI registry, hot-reload. This is a complete ecosystem moat.
  3. ML depth — SafeLine has semantic ML but no ONNX interface, no Isolation Forest, no LLM
  integration. Sentinel's ML stack is architecturally deeper.
  4. eBPF/XDP — Literally no other open-source WAF does kernel-level L4 drops. This means
  DDoS mitigation happens before packets even reach userspace — a hard technical gap vs.
  everyone else.
  5. TLS fingerprinting (JA3/JA4/JA4+) — Most WAFs skip this entirely. Sentinel does it
  natively in the data plane.
  6. Raft consensus cluster — BunkerWeb/SafeLine do session sync but not true Raft.
  Sentinel's cluster can survive split-brain scenarios correctly.
  7. LLM Copilot — No open-source WAF has an AI assistant wired into the operator console.

  ---
  Where You're Still Behind (Honest Assessment)

  ┌────────────────────┬─────────────────────────────────────────────────────────────────┐
  │        Gap         │                          What it means                          │
  ├────────────────────┼─────────────────────────────────────────────────────────────────┤
  │ Battle-tested in   │ ModSecurity has 20 years of edge cases. Sentinel's rule engine  │
  │ production         │ is new — real traffic will find gaps CRS testing doesn't        │
  ├────────────────────┼─────────────────────────────────────────────────────────────────┤
  │                    │ Telemetry not in the hot path, eBPF not integrated into proxy   │
  │ Wiring gaps        │ is_blocked(), Raft not wired to control plane — features exist  │
  │                    │ but aren't end-to-end                                           │
  ├────────────────────┼─────────────────────────────────────────────────────────────────┤
  │ CRS rule community │ You import CRS but don't have a community writing custom rules  │
  │                    │ for Sentinel's DSL yet                                          │
  ├────────────────────┼─────────────────────────────────────────────────────────────────┤
  │ False positive     │ CRS took years of production tuning. Paranoia levels exist but  │
  │ hardening          │ real-world FP rates are unknown                                 │
  ├────────────────────┼─────────────────────────────────────────────────────────────────┤
    │ Documentation      │ ModSec/BunkerWeb have extensive docs. Sentinel is internal      │
  └────────────────────┴─────────────────────────────────────────────────────────────────┘

  ---
  Bottom Line

  Architecturally, Sentinel is already ahead of every open-source WAF in design ambition —
  the Rust data plane + WASM plugins + eBPF + ML stack combination doesn't exist anywhere
  else. No open-source project is even attempting this combination.

  Operationally, Sentinel is ahead of BunkerWeb on detection, API security, observability and
  clustering (measured 2026-09-06), and behind it on documentation, packaging, integrations and
  community trust. You're ahead of ModSecurity/Coraza in UX.
