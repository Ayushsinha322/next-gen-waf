# Smoke run — 2026-07-25 21:30, 10 s/scenario

**This is NOT the baseline. Do not quote these numbers.** The baseline lives one
directory up and is documented in `../../RESULTS.md`.

These four scenarios were re-run as a quick liveness check while setting up the
scaling/soak/flood drills (`soak-test.sh` and `PERFORMANCE-RESULTS.md` were
written ~1 h later the same evening). Because `run-loadtest.sh` writes fixed
filenames, the run silently overwrote the committed 2026-07-14 baseline
artifacts in `../`. They have been restored; this copy is kept so the data is
not thrown away.

## Why it is not comparable to the baseline

| | Baseline (`../`) | This run |
|---|---|---|
| Date | 2026-07-14 15:10 | 2026-07-25 21:30 |
| Duration | **20 s**/scenario (harness default, the documented protocol) | **10 s**/scenario |
| `-max-workers` / `-connections` | recorded in `../../RESULTS.md` | **not recorded** |

All four scenarios completed inside ~50 s total, i.e. this was a smoke check,
not a measurement run.

## What it measured

| Scenario | Throughput | p99 | Outcome |
|---|---:|---:|---|
| s0 baseline origin | 16,907 rps | 8.09 ms | 100% `200` |
| s1 WAF clean | 5,729 rps | 20.77 ms | 100% `200` |
| s2 WAF mixed | 21,999 rps | 6.71 ms | 219,982 × `403` |
| s3 WAF attack | 21,588 rps | 6.84 ms | 100% `403` |

## The one number worth a follow-up

The block path (s2/s3) and the origin baseline (s0) reproduce the 2026-07-14
figures closely. **The clean pass-through path does not: 5,729 rps @ p99
20.77 ms here versus 7,946 rps @ p99 15.02 ms on 2026-07-14** — roughly 28%
lower throughput and ~38% higher p99.

This is **not** a regression claim. A 10 s run with unrecorded generator
settings, executed on a box that was being set up for other drills, cannot
support one; contention on the shared host is at least as likely an explanation
as a code change. It is recorded here so the discrepancy is not lost: if it
matters, re-run `run-loadtest.sh` at the documented 20 s protocol on an idle box
and compare against `../summary.txt`.
