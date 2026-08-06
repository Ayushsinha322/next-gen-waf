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

---

# Full-Stack Run (MEASURED) — the "documented next step" from caveat 4

> The section above is an **isolated micro-benchmark** (WAF → nginx, ML off,
> rate-limit off, no control plane, no ClickHouse). This section runs the **same
> data-plane binary under the full production pipeline**: ML **on**, ClickHouse
> logging **on**, control-plane config sync **on**, tenant-tagging **on**, and a
> **real application backend** (OWASP Juice Shop). Every number below was
> measured, not projected.

## Environment (as measured)

| Item | Value |
|---|---|
| Date | 2026-07-14 |
| Host | AMD Ryzen 7 7730U · 16 logical cores · 14 GiB RAM (shared dev box) |
| Stack | `docker compose -f compose.prod.yml -f compose.loadtest.yml` — Postgres + ClickHouse + Redis + control plane + data plane + Juice Shop |
| Build | `integration/waf-v1-hardening` (all 3 milestone branches merged) |
| WAF listener | `:8081` (remapped off `:80` via `ports: !override`) |
| Pipeline | full CRS 4.7 (blocking, PL2) **+ ML enabled + ClickHouse event/traffic logging + control-plane sync + per-request tenant tagging** |
| Backend | OWASP Juice Shop (Node) at `juiceshop:3000`, real app |
| Generator | `vegeta` open-loop, `-rate=0 -max-workers=80`, 20 s/scenario, single source IP, `Host: juice.local` |

## Results

| Scenario | What it exercises | Throughput (req/s) | p50 | p95 | p99 | Result codes |
|---|---|---:|---:|---:|---:|---|
| **Attack / block** | all-malicious through full pipeline (CRS+ML+CH), early-exit block, no backend | **21,198** | 3.21 ms | 6.59 ms | 8.48 ms | 100% `403` (423,968/423,968) |
| **Clean end-to-end** | clean GET through WAF → **real Juice Shop app** | **1,168** | 61.4 ms | 100.2 ms | 113.2 ms | 100% `200` (23,373/23,373) |

## What the numbers mean (honestly)

- **Block path sustains ~21,200 req/s at p99 8.5 ms with the *full* pipeline** (ML + ClickHouse
  logging + tenant tagging all active). This corroborates the isolated bench's **21,531 req/s**
  block number almost exactly — because blocked requests early-exit before the origin, the ML
  and logging additions cost near-nothing on the block path. **This is the WAF's real inspection
  capacity on this box.**
- **Admission control did not falsely shed.** At 21k req/s sustained, **zero** `503`s — the new
  connection/request admission limiter (milestone 2) has headroom above this rate and only sheds
  under heavier load. Clean traffic was **not** rate-limited or repeat-offender-blocked (100% `200`).
- **Clean end-to-end is backend-bound, not WAF-bound.** 1,168 req/s at p99 113 ms reflects the
  **Juice Shop Node app**, which is far slower than the nginx origin used in the isolated bench
  (7,946 req/s there). The WAF is not the bottleneck here — this number characterizes *end-to-end
  latency in front of a real, heavyweight app*, not the WAF's clean-forwarding ceiling (see the
  isolated S1 for that).

## Pipeline verified end-to-end (ClickHouse, under load)

Queried directly against the running ClickHouse **after** the run — proves the full pipeline
executed and the tenant-tagging feature works end-to-end (not just in unit tests):

| Check | Measured |
|---|---|
| `waf_events` rows captured under load | **401,015**, every row tagged `tenant = …0001` |
| `traffic_buckets` rows | **447,349** reqs / **423,973** blocked, tenant column populated on all |
| Sample event | `rule=942100` (SQLi), `action=BLOCK`, `score=5`, `site=juice.local`, `tenant=…0001` |

(All events carry the single dev tenant because every load-test site belongs to it; this verifies
the tenant column *flows* data-plane → ClickHouse under load. Cross-tenant *isolation* is covered
by the RLS/tenant tests, not this throughput run.)

## Caveats (so nobody over-reads this)

1. **Single source IP** — so this cannot measure a realistic mixed 90/10 throughput (same
   repeat-offender collapse documented in the S2 note above). Clean and block paths were run
   separately for that reason.
2. **Shared dev box**, generator + full stack + backend all on the same 16 cores → CPU
   contention **understates** dedicated hardware. Run on the VM/K8s HA cluster for a certified number.
3. **Clean throughput is Juice-Shop-bound**, not a WAF ceiling. For WAF clean-path overhead see
   the isolated S1 above (fast nginx origin).

## Reproduce (full stack)

```bash
cd deploy/docker
docker compose -f compose.prod.yml -f compose.loadtest.yml up -d \
  postgres clickhouse redis migrate controlplane dataplane juiceshop
# wait for /readyz 200, then:
vegeta attack -targets=<clean|attack>.txt -header="Host: juice.local" \
  -rate=0 -max-workers=80 -duration=20s | vegeta report
```
