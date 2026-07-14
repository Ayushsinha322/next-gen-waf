# Sentinel WAF — Load-Test Results (MEASURED)

> **Every number on this page was measured by `run-loadtest.sh` on the hardware
> and date below.** It is not projected, estimated, or extrapolated. Re-run the
> harness to reproduce it. Raw per-scenario reports are in `results/*.report.txt`
> and `results/*.json`.

## Environment (as measured)

| Item | Value |
|---|---|
| Date | 2026-07-14 |
| Host | AMD Ryzen 7 7730U · 16 logical cores · 14 GiB RAM |
| OS / kernel | Linux 7.0.9 (Parrot) |
| WAF build | `target/release/sentinel-bin` v0.1.0 (release) |
| Ruleset | OWASP CRS 4.7 — 13 attack-detection rule files, PL2, anomaly threshold 5, `mode: blocking` |
| ML | **disabled** (isolates rule-engine + proxy) |
| Rate-limit | **disabled** (single source IP would otherwise be throttled) |
| Origin | `nginx:alpine` in Docker, static default page, over loopback |
| Generator | `vegeta` open-loop, `-rate=0 -max-workers=64 -connections=200`, 20 s/scenario |
| Topology | vegeta → WAF `:18081` → nginx `:18080` (all on the same box) |

## Results

| Scenario | What it exercises | Throughput (req/s) | p50 | p95 | p99 | Result codes |
|---|---|---:|---:|---:|---:|---|
| **S0 baseline** | direct → origin, WAF bypassed | **16,917** | 3.01 ms | 6.43 ms | 8.22 ms | 100% `200` |
| **S1 WAF clean** | clean GET through WAF (PASS path) | **7,946** | 6.94 ms | 12.22 ms | 15.02 ms | 100% `200` |
| **S3 WAF attack** | all-malicious GET (BLOCK path) | **21,531** | 2.47 ms | 5.33 ms | 6.76 ms | 100% `403` |
| S2 WAF mixed | 90/10 clean/attack, single IP | 22,574 | 2.34 ms | 5.11 ms | 6.54 ms | see note ▼ |

### What the numbers mean (honestly)

- **Clean pass-through (S1): ~7,950 req/s at p99 15 ms**, single node, full CRS loaded,
  every request inspected and proxied to the origin. This is the real "security tax
  on legitimate traffic" under load — the measurement the project previously did **not**
  have (only rule-VM micro-benchmarks existed).
- **The origin round-trip dominates.** Baseline direct-to-origin (S0) is 16,917 req/s;
  routing the *same* origin through the WAF (S1) roughly halves it to 7,946. That gap is
  the second proxy hop + origin round-trip, not just rule evaluation. On a real backend
  and dedicated hardware the ratio will differ.
- **Blocking is cheaper than passing (S3 > S1).** Blocked requests early-exit and never
  touch the origin, so the block path sustains ~21,500 req/s vs ~7,950 for the proxied
  clean path. Blocking an attacker is fast; the cost of clean traffic is mostly the
  upstream round-trip.

### ▼ Note on S2 (mixed) — a real finding, not a clean throughput number

S2 sent 90% clean + 10% attack URLs **from a single source IP**. Only **30** of 451,478
requests returned `200`; the rest were `403`. Inspecting the log, the blocked *clean*
requests carry `anomaly_score:5` with **empty `rule_ids`** — i.e. no CRS rule matched them.
That residual score is **stateful IP threat-scoring**: once the source IP sends attacks,
the WAF flags it and applies a carry-over score to *every* subsequent request from that IP,
so its later clean requests are blocked too.

This is legitimate repeat-offender behaviour and a genuine defensive feature — but it means
**a single-IP mixed test cannot measure a 90/10 throughput mix** (it collapses to the block
path after the first attacks). A faithful mixed-traffic throughput test needs many distinct
source IPs (e.g. a distributed generator or spoofed `X-Forwarded-For` with trust configured).
Recorded here rather than hidden.

## Caveats (so nobody over-reads this)

1. **Single run on a shared developer laptop**, not an isolated benchmark lab. Treat as
   indicative, not certified.
2. Generator, WAF, and origin all share the same 16 cores → CPU contention **understates**
   what dedicated hardware would sustain.
3. Origin is a Docker nginx over loopback; real upstreams and networks behave differently.
4. **Data plane only.** The full `deploy/docker/compose.prod.yml` stack (Postgres, ClickHouse,
   control plane) was not exercised here. ML and rate-limiting were off. A full 7-phase,
   full-stack run is the documented next step.

## Reproduce

```bash
cd deploy/load-test
./run-loadtest.sh          # brings up nginx + WAF, runs all 4 scenarios, writes results/
```

See `README.md` for prerequisites and tunables.
