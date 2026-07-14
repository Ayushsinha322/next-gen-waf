# Sentinel WAF — Load-Test Harness

A real, reproducible end-to-end load test for the WAF **data plane**. It stands up a
fast static origin and the WAF in front of it, then drives traffic with
[`vegeta`](https://github.com/tsenart/vegeta) and records throughput, latency
percentiles, and error rates. Nothing here is simulated or hard-coded.

```
vegeta ──▶ WAF :18081 ──▶ nginx origin :18080
```

## Files

| File | Purpose |
|---|---|
| `run-loadtest.sh` | Orchestrates origin + WAF + all scenarios, writes `results/` |
| `waf-loadtest.yaml` | Minimal WAF config: 1 listener, 1 site, full CRS, ML/RL off |
| `traffic/clean.txt` | Benign GET targets (vegeta format) |
| `traffic/attack.txt` | Malicious GETs (SQLi, XSS, LFI, RCE) — must be blocked |
| `traffic/mixed.txt` | 90% clean / 10% attack |
| `results/` | Per-scenario `*.report.txt` + `*.json` + `summary.txt` (raw `*.bin`/logs gitignored) |
| `RESULTS.md` | The measured numbers from the last committed run + methodology |

## Prerequisites

- **vegeta**: `go install github.com/tsenart/vegeta/v12@latest`
- **docker** (for the nginx origin)
- A built WAF binary at `target/release/sentinel-bin` in the Sentinel repo, plus the
  `rules/owasp-crs/` tree. Build with `cargo build --release -p sentinel-bin`.

## Run

```bash
cd deploy/load-test
./run-loadtest.sh
```

The script auto-detects the Sentinel repo (looks for `rules/owasp-crs` +
`target/release/sentinel-bin`). Override anything via env:

```bash
WAF_REPO=/path/to/waf-development \
DURATION=30s MAX_WORKERS=128 CONNS=400 \
./run-loadtest.sh
```

| Env | Default | Meaning |
|---|---|---|
| `WAF_REPO` | auto-detect | Repo root holding `rules/` + `target/` |
| `WAF_BIN` | `$WAF_REPO/target/release/sentinel-bin` | WAF binary |
| `WAF_CONFIG` | `./waf-loadtest.yaml` | WAF config |
| `DURATION` | `20s` | Per-scenario duration |
| `MAX_WORKERS` | `64` | vegeta concurrent workers (open-loop) |
| `CONNS` | `200` | Max connections per host |
| `HOST_HDR` | `loadtest.local` | Host header (non-numeric — avoids CRS 920350) |

## Notes / gotchas

- **Host header matters.** The harness sends `Host: loadtest.local`. If you point vegeta
  at `127.0.0.1` *without* a hostname, CRS rule **920350** ("Host header is a numeric IP")
  fires on every request and — on its own — hits the anomaly threshold, so you'd measure
  the block path instead of clean pass-through. A real browser never sends a numeric-IP Host.
- **Single source IP.** Because the generator is one IP, the WAF's stateful repeat-offender
  scoring blocks that IP after it sends attacks — so the *mixed* scenario collapses to the
  block path. See the S2 note in `RESULTS.md`. For a true 90/10 mix, use many source IPs.
- **Not the full stack.** This exercises the data plane with ML and rate-limiting off, to
  isolate the rule engine + proxy. For a full 7-phase run, bring up
  `deploy/docker/compose.prod.yml` and point the harness at it (`HOST_HDR` + ports adjusted).

## Fallback without vegeta

`ab` (ApacheBench) is a crude fallback for the single-URL clean case:

```bash
ab -n 100000 -c 100 -H 'Host: loadtest.local' http://127.0.0.1:18081/
```

It cannot replay the multi-target attack/mixed lists, so prefer vegeta.
