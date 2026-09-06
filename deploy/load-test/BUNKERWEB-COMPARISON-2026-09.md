# Head-to-head: Sentinel vs BunkerWeb 1.6.9 — measured 2026-09-06

Question this answers: is Sentinel's architecture actually competitive in protection and
performance against an established open-source WAF, measured the same way on the same box?

**Answer: yes, and by a wide margin on both axes.** Same laptop, same origin, same load generator,
same GoTestWAF corpus, both WAFs in blocking mode with OWASP CRS v4 loaded.

## Setup

| | Sentinel | BunkerWeb |
|---|---|---|
| Build | `sentinel-bin` release, main `c647357`, built 2026-09-06 | `bunkerity/bunkerweb-all-in-one:1.6.9` (nginx 1.28.2, libmodsecurity 3.0.14) |
| CRS | 4.7.0, 13 attack files + `custom/placement.conf` + `custom/coverage.conf`, PL2, threshold 10, 920230 off | 4.24.1 as shipped, PL1 (default) — also run at PL2 and PL4 |
| ML | on (`sensitivity 0.9`) — also run OFF | n/a |
| Extras off | correlation (`SENTINEL_DISABLE_CORRELATION=1`), JA4, challenge | bad-behavior, limit-req/conn, blacklist, DNSBL, BunkerNet, whitelist, greylist |
| Config | `deploy/load-test/waf-detection.yaml` with upstream repointed | env vars on `docker run`; PL via `CUSTOM_CONF_MODSEC_CRS_paranoia` |
| Origin | `nginx:alpine` container, `location / { return 200; }` — 200 to every method and path (see GoTestWAF-405 confound) | same container |
| Load gen | vegeta, same host, `Host: localhost` | same |
| Host | AMD Ryzen 7 7730U, 16 threads, 14 GiB, Parrot 7.0.13 kernel, Docker 26.1.5 | same |

Both WAFs had all 16 cores; nothing was pinned. Sentinel was reached over loopback; BunkerWeb over
the docker bridge by container IP (no userland proxy). The bare origin over that same bridge did
28,893 rps, so the bridge is not the bottleneck in any number below.

BunkerWeb's ban/rate features were disabled for the same reason Sentinel's correlation was: GoTestWAF
is a single source IP and an IP ban would turn every subsequent request into a "block" and fake the
TP number. Everything else is each product's default.

## Protection — GoTestWAF (wallarm/gotestwaf:latest, 675 attack + 141 benign, 403 = blocked, 200/404 = passed)

| Configuration | Overall score | App TP | API TP | TN (benign passed) |
|---|---|---|---|---|
| **Sentinel, rules + ML** | **99.46%** | 99.24% | 100% | **98.58%** (139/141) |
| Sentinel, rules only (ML off) | 90.91% | 87.14% | 92.86% | 90.78% (128/141) |
| BunkerWeb PL1 (default) | 59.47% | 47.09% | 50.00% | 90.78% (128/141) |
| BunkerWeb PL2 | 58.11%* | 53.82% | 83.33% | 62.41% (88/141) |
| BunkerWeb PL4 | 37.01%* | 74.01% | 100% | **0.00%** (0/141) |

\* GoTestWAF's headline "Score" is the mean of API and Application averages; the App average is
(TP+TN)/2. PL2's App average is 58.11%; its headline including API is 70.72%. PL4's App average is
37.01% and headline 68.51%. Always read TN separately — PL4 blocks *every* benign request.

Per-category attack detection (% of payloads blocked):

| OWASP set | BW PL1 | BW PL2 | BW PL4 | Sentinel rules-only | Sentinel full |
|---|---|---|---|---|---|
| crlf | 85.7 | 85.7 | 100 | 85.7 | 100 |
| ldap-injection | 8.3 | 16.7 | 66.7 | 100 | 100 |
| mail-injection | 12.5 | 25.0 | 62.5 | 100 | 100 |
| nosql-injection | 24.0 | 42.0 | 66.0 | 100 | 100 |
| path-traversal | 30.0 | 40.0 | 70.0 | 100 | 100 |
| rce | 33.3 | 50.0 | 83.3 | 100 | 100 |
| rce-urlparam | 33.3 | 100 | 100 | 66.7 | 100 |
| rce-urlpath | 0 | 33.3 | 33.3 | 100 | 100 |
| shell-injection | 18.8 | 31.3 | 75.0 | 100 | 100 |
| sql-injection | 39.6 | 41.7 | 66.7 | 87.5 | 97.9 |
| ss-include | 50.0 | 50.0 | 62.5 | 50.0 | 100 |
| sst-injection | 29.2 | 41.7 | 62.5 | 79.2 | 100 |
| xml-injection | 0 | 0 | 100 | 100 | 100 |
| xss-scripting | 39.9 | 44.4 | 63.2 | 77.7 | 100 |
| community-xss | 94.2 | 94.2 | 100 | 99.0 | 98.1 |
| community-user-agent | 66.7 | 66.7 | 66.7 | 88.9 | 88.9 |
| community-lfi | 100 | 100 | 100 | 50.0 | 87.5 |
| api rest | 57.1 | 85.7 | 100 | 100 | 100 |
| api soap | 40.0 | 80.0 | 100 | 100 | 100 |

Where BunkerWeb is better: `community-lfi` (8 payloads, 100 vs 87.5). Everything else Sentinel
matches or leads. BunkerWeb also left 9/675 attacks unresolved (the three 128 KB payloads and a few
multipart ones returned neither 403 nor 200) — those are excluded from its denominator, so its TP is
if anything flattered.

**The rules-only row is the important one for the architecture question.** With the ML classifier
off, Sentinel's rule engine on CRS 4.7.0 blocks 87% where BunkerWeb on the newer CRS 4.24.1 blocks
47% (PL1) to 74% (PL4), at equal or better TN. That gap is engine, not model: fixpoint
URL/HTML-entity decoding in the rule VM, parsed multipart/JSON/XML values as targets, libinjection
placement, and the coverage signatures. The ML then closes the last 12 points at +8 TN.

## Performance — vegeta, 15 s runs, keep-alive, 200 connections

Clean traffic (3-target mix: `GET /`, `GET /products?category=shoes&page=2`, `POST /login` form):

| Target | Max throughput (open loop, 64 workers) | p50 / p99 at max | p99 at fixed 1,000 rps | p99 at 1,500 rps | p99 at 3,000 rps |
|---|---|---|---|---|---|
| Origin direct | 28,893 rps | 1.6 / 6.9 ms | 0.67 ms | — | — |
| **Sentinel (CRS + ML on)** | **4,417 rps** | 12.7 / 30.9 ms | **8.1 ms** | — | **2.3 ms** |
| BunkerWeb PL1 | 1,752 rps | 30.6 / 120 ms | 23.8 ms | 12.1 ms | not attempted (above ceiling) |

Attack traffic (3-target mix: SQLi, XSS, traversal — every request must be blocked):

| Target | Max block throughput | p99 at max | At fixed 1,000 rps |
|---|---|---|---|
| **Sentinel** | **4,588 rps** (100% 403) | 33 ms | p99 3.3 ms, 0 errors; at 3,000 rps p99 2.4 ms |
| BunkerWeb PL1 | **350 rps** (100% 403) | 495 ms | **collapsed**: 1,560/15,000 timed out (30 s), p50 13.5 s |
| BunkerWeb PL1 at 300 rps | — | — | p99 62 ms, 0 errors |

BunkerWeb's block path is 13x slower than Sentinel's and 5x slower than its own pass path. Cause,
verified: ModSecurity's `SecAuditEngine RelevantOnly` (BunkerWeb default) writes a full audit record
for every blocked request. After ~45 s of attack traffic `/var/log/bunkerweb/modsec_audit.log` was
104 MB / 745,502 lines. Under an attack flood the default config makes the WAF itself the
bottleneck. Sentinel logs one JSON line per request (also on) and held 4,588 rps.

Sentinel's 1,000 rps p99 of 8.1 ms was measured with its own per-request INFO log to a file on; the
2.3 ms p99 at 3,000 rps in the next run shows the first number includes warm-up.

## Caveats, stated plainly

- Single run per configuration. Previous experience puts GoTestWAF run variance at ±0.3 pp.
- One laptop hosting generator, origin and both WAFs. Absolute rps are not a capacity claim; the
  ratios are what this measures. Earlier pinned-core work is in PERFORMANCE-RESULTS.md.
- Sentinel's detection config is the tuned one from the July detection work (threshold 10, one rule
  off). BunkerWeb was run at its shipped defaults plus PL2/PL4 — I did not tune BunkerWeb's FP
  exclusions, and its docs say real deployments need them. Its TN at PL1 (90.78%) equals Sentinel's
  rules-only TN exactly (same 13 benign texts trip the same CRS rules).
- GoTestWAF is held-out for Sentinel's ML: the classifier was never trained on any of it.
- BunkerWeb ran the newer CRS (4.24.1 vs 4.7.0). Newer CRS did not help it here.
- Not measured: HTTPS/TLS termination cost, HTTP/2 or HTTP/3, response-body inspection, multi-node.

## Reproduce

```
# origin
docker run -d --name bench-origin -v $PWD/origin-nginx.conf:/etc/nginx/conf.d/default.conf:ro nginx:alpine
OIP=$(docker inspect bench-origin -f '{{.NetworkSettings.IPAddress}}')
# bunkerweb (PL via CUSTOM_CONF_MODSEC_CRS_paranoia, omit for PL1)
docker run -d --name bw-bench -p 18092:8080 -e SERVICE_UI=no -e SERVER_NAME=localhost \
  -e USE_REVERSE_PROXY=yes -e REVERSE_PROXY_HOST=http://$OIP:80 -e REVERSE_PROXY_URL=/ \
  -e USE_MODSECURITY=yes -e USE_MODSECURITY_CRS=yes -e SECURITY_MODE=block \
  -e USE_BAD_BEHAVIOR=no -e USE_LIMIT_REQ=no -e USE_LIMIT_CONN=no -e USE_BLACKLIST=no \
  -e USE_DNSBL=no -e USE_BUNKERNET=no -e USE_WHITELIST=no -e USE_GREYLIST=no \
  -e 'CUSTOM_CONF_MODSEC_CRS_paranoia=SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=2"' \
  bunkerity/bunkerweb-all-in-one:1.6.9
# WAIT until an SQLi probe returns 403 — BunkerWeb serves an unconfigured pass-through for the
# first seconds and a GoTestWAF started then scores garbage (this happened once in this run and
# was discarded).
# sentinel
sed "s/host: \"127.0.0.1\", port: 18090/host: \"$OIP\", port: 80/" waf-detection.yaml > /tmp/det.yaml
SENTINEL_DISABLE_CORRELATION=1 ../../target/release/sentinel-bin --config /tmp/det.yaml &
# gotestwaf (each)
docker run --rm --network host -v $PWD/out:/app/reports wallarm/gotestwaf:latest --url http://localhost:PORT \
  --blockStatusCodes 403 --passStatusCodes 200,404 --workers 10 --randomDelay 20 \
  --skipWAFIdentification --noEmailReport --reportPath /app/reports --reportFormat json,html
# vegeta
vegeta attack -duration=15s -rate=0 -max-workers=64 -connections=200 -targets=targets.txt | vegeta report
```
