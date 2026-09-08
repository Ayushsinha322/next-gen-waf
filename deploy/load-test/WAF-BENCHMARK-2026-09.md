# Three-way WAF benchmark — Next-Gen ESDS WAF vs BunkerWeb 1.6.9 vs SafeLine 9.4.1

Measured 2026-09-08, **all five detection arms and all 22 load arms in one session on one box**,
sharing one origin container. This file is the consolidated result; the per-product method,
per-payload analysis and gotchas are in `BUNKERWEB-COMPARISON-2026-09.md` and
`SAFELINE-COMPARISON-2026-09.md`.

Published report: <https://claude.ai/code/artifact/a88753e1-b9cd-44fc-9e99-1238aa369200>

Why one session matters: the BunkerWeb arms were first measured 2026-09-06 with Sentinel reached
over loopback and BunkerWeb over the docker bridge, against a `return 200` origin. Re-running them
today over loopback against the shared all-methods origin **reproduced the detection numbers
exactly** (PL1 59.47% / TN 90.78%; PL4 App-TP 74.01% / TN 0.00%), which validates both sessions.
The load numbers moved — ours 4,417 → 7,595 rps clean — so only same-session load figures are
comparable, and everything below is same-session.

## Detection — GoTestWAF, 675 attack + 141 benign, 403 blocked / 200,404 passed

| Arm | Composite | App TP | API TP | TN | Benign wrongly blocked |
|---|---|---|---|---|---|
| **Next-Gen ESDS WAF** (CRS 4.7.0 PL2 + ML) | **99.64%** | **99.24%** | 100% (n=14) | 99.29% | 1 / 141 |
| SafeLine, shipped defaults | 58.28% | 47.38% | 42.86% (n=7) | **100.00%** | **0 / 141** |
| SafeLine, all modules `strict` | 75.30% | 60.47% | 71.43% (n=7) | 97.87% | 3 / 141 |
| BunkerWeb, PL1 (shipped) | 59.47% | 47.09% | 50.00% (n=12) | 90.78% | 13 / 141 |
| BunkerWeb, PL4 (maximum) | 68.51% | 74.01% | 100% (n=12) | **0.00%** | **141 / 141** |

API denominators differ (14 / 12 / 7 resolved) — read the App column as the like-for-like number.
GoTestWAF's composite is the mean of the API and App averages, which is how PL4 keeps a 68.51%
composite while passing no benign traffic at all.

### Percent blocked by attack class

| Class (payloads) | ESDS WAF | BW PL1 | BW PL4 | SL default | SL strict |
|---|---|---|---|---|---|
| sql-injection (48) | 97.9 | 39.6 | 66.7 | **100** | **100** |
| community-sqli (12) | **100** | **100** | **100** | 66.7 | 66.7 |
| nosql-injection (50) | **100** | 24.0 | 66.0 | 20.0 | 20.0 |
| ldap-injection (24) | **100** | 8.3 | 66.7 | 0 | 0 |
| mail-injection (24) | **100** | 12.5 | 62.5 | 0 | 0 |
| xml-injection (7) | **100** | 0 | **100** | 0 | 0 |
| sst-injection (24) | **100** | 29.2 | 62.5 | 33.3 | 33.3 |
| xss-scripting (224) | **100** | 39.7 | 62.9 | 64.3 | 86.6 |
| community-xss (104) | 98.1 | 94.2 | **100** | 78.8 | 92.3 |
| shell-injection (32) | **100** | 18.8 | 75.0 | 0 | 25.0 |
| rce (6) | **100** | 33.3 | 83.3 | 0 | 33.3 |
| rce-urlparam (9) | **100** | 33.3 | **100** | 33.3 | 33.3 |
| rce-urlpath (3) | **100** | 0 | 33.3 | 0 | 33.3 |
| community-rce (4) | **100** | 50.0 | **100** | 0 | **100** |
| path-traversal (20) | **100** | 30.0 | 70.0 | 10.0 | 10.0 |
| community-lfi (8) | 87.5 | **100** | **100** | 25.0 | 25.0 |
| community-lfi-multipart (2) | **100** | 0 | 0 | 0 | 0 |
| crlf (7) | **100** | 85.7 | **100** | 0 | 0 |
| ss-include (24) | **100** | 50.0 | 62.5 | 0 | 0 |
| community-xxe (2) | **100** | 0 | 50.0 | 0 | 0 |
| community-user-agent (9) | **88.9** | 66.7 | 66.7 | 11.1 | 11.1 |
| rest (7) | **100** | 57.1 | **100** | 42.9 | 71.4 |
| soap (5) | **100** | 40.0 | **100** | 40.0 | 80.0 |
| non-crud (2) | **100** | 0 | 0 | 50.0 | 50.0 |
| large payloads 8–128 KB | **15/15** | 12/15 | 12/15 | 0/5 | 0/0 |

The two rivals fail in **opposite** directions and neither is fixable by configuration:

* **SafeLine** scores 0% on ldap-injection, mail-injection, xml-injection, crlf and ss-include — 86
  payloads — at *both* postures. Absent modules, not loose tuning. In exchange it is the only arm
  that blocks all 48 OWASP SQLi payloads, including the one we miss, and the only arm with zero
  false positives.
* **BunkerWeb** has coverage everywhere, set either too loose to catch half (PL1) or too tight to
  pass anyone (PL4, TN 0%). There is no usable point between in this corpus.

SafeLine could not complete 10 of 675 requests at defaults and 15 at strict (all large-payload
cases); GoTestWAF drops those from the denominator, so they cost it nothing. Not reproducible —
replaying the exact placement 30× at concurrency 10 gave 403 every time from both products.

## Performance — vegeta, 15 s, keep-alive, 200 connections

Clean traffic, 3-target mix, open loop / 64 workers. All arms 100% 200.

| Target | Throughput | p50 | p99 | p99.9 |
|---|---|---|---|---|
| Origin direct, no WAF | 32,190 rps | 1.74 ms | 4.79 ms | 13.5 ms |
| **Next-Gen ESDS WAF** | **7,595 rps** | 7.45 ms | 16.3 ms | 50.6 ms |
| SafeLine, defaults | 6,006 rps | 10.7 ms | 14.6 ms | 26.1 ms |
| SafeLine, strict | 4,688 rps | 13.1 ms | 22.9 ms | 45.6 ms |
| BunkerWeb, PL1 | 2,000 rps | 27.5 ms | 94.4 ms | 126 ms |

Attack traffic, open loop. **Read the deny-body column first** — it, not the rule engine, dominates
max block throughput.

| Target | Deny body | Block throughput | p50 | p99 |
|---|---|---|---|---|
| **Next-Gen ESDS WAF** | 125 B | **7,870 rps** | 7.49 ms | 15.8 ms |
| SafeLine, defaults | 15,604 B | 4,573 rps | 12.0 ms | 29.7 ms |
| SafeLine, strict | 15,604 B | 4,054 rps | 13.1 ms | 37.4 ms |
| BunkerWeb PL1, error page on | 69,283 B | 376 rps | 135 ms | 722 ms |
| BunkerWeb PL1, error page off | 146 B | 1,541 rps | 38.0 ms | 103 ms |

SafeLine's 15,604 B **cannot be shrunk** — a custom block page is a commercial-edition feature.
BunkerWeb's can, by dropping 403 from `INTERCEPTED_ERROR_CODES`.

Fixed-rate attack — the engine comparison, where body size is irrelevant on loopback:

| Target | 1,000 rps p50 / p99 / dropped | 3,000 rps p50 / p99 / dropped |
|---|---|---|
| **Next-Gen ESDS WAF** | 0.65 / 1.63 ms / 0 | 0.93 / **8.16 ms** / 0 |
| SafeLine, defaults | 0.81 / 1.97 ms / 0 | 1.19 / 59.1 ms / 0 |
| SafeLine, strict | 0.78 / **1.33 ms** / 0 | 1.34 / 14.1 ms / 0 |
| BunkerWeb PL1, error page on | 10.8 s / 30 s / **2,404** | 13.4 s / 30 s / **13,073** |
| BunkerWeb PL1, error page off | 5.13 / 137 ms / 0 | 2.79 s / 30 s / **4,672** |

30 s is the client timeout, so a p99 of 30 s means no answer ever arrived.

**At 1,000 attack rps the three engines are indistinguishable and SafeLine strict is marginally the
fastest.** Separation only appears at 3,000. Fixing BunkerWeb's error page saves it at 1,000 and it
still loses 4,672 of 45,000 at 3,000 — the deny page was costing it 4x its block throughput and the
engine underneath is still the ceiling. **SafeLine is not slow and the comparison must not say it
is.**

## Where we lose

1. 🔴 **OPEN — our ML classifier blocks ordinary login forms.**
   `POST /login  username=alice&password=s3cret&remember=1` → 403, `ML-ANOMALY`, score 13 vs
   threshold 10, so it blocks with no rule match. Attributed by running two instances from an
   identical config differing only in `ml.enable` (403 vs 200). 2 of 8 ordinary form bodies
   affected, both login forms with a remember-me field. Deferred by decision 2026-09-08.
2. **Our TN figure is measured on a corpus that cannot see that.** GoTestWAF's 141 benign payloads
   are plain text bodies, not form-encoded credential posts. 99.29% is accurate about the corpus and
   optimistic about production. Corpus coverage problem, not a threshold problem.
3. **SafeLine is more precise than we are** — 0/141 false positives at shipped defaults vs our 1
   plus the login defect. That is the number a risk-averse customer asks about.
4. **SafeLine's SQLi engine catches a payload ours misses** — 48/48 vs our 47/48.
5. **BunkerWeb leads on community-lfi** — 8/8 vs our 7/8 (we lead its multipart variant 2/2 to 0/2).

## Limits

One 16-thread laptop, loopback, no TLS, nothing pinned. GoTestWAF is a corpus, not the internet, and
its benign half is narrow (see #2). API percentages use different denominators. Our arm was measured
at one configuration only — both rivals got a defaults arm and a maximum arm; a rules-only arm from
2026-09-06 put our engine alone at 90.91% composite but was not re-run today. No real-traffic
false-positive measurement exists yet; that is separate, still-open work.
