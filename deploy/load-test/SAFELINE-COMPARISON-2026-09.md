# Head-to-head: Sentinel vs SafeLine 9.4.1 — measured 2026-09-08

Question this answers: BunkerWeb is a rules-first WAF built on ModSecurity + CRS, so beating it
partly measures our CRS integration against theirs. SafeLine is the opposite design — a
semantic-analysis engine with no signature corpus — and it is the WAF most often named as the
strongest free option. Does Sentinel hold up against a detection engine built on a different
principle, measured the same way on the same box?

Short answer: yes on detection, by a wide margin that widens rather than narrows when SafeLine is
given its strongest configuration. Throughput is much closer than against BunkerWeb — SafeLine is a
serious performer and does not collapse under attack load. And the exercise found a false positive
in **our** ML classifier on ordinary login traffic that our own benchmark corpus cannot see.

## Harness — identical for both

| | Sentinel | SafeLine |
|---|---|---|
| Version | `92e0d46` (release build, local) | 9.4.1 community, 7 containers |
| Listener | `:18091`, plain HTTP | `:18092`, plain HTTP (tengine, host network) |
| Origin | `bench-origin` at `172.17.0.2:80` | same container, same address |
| Mode | blocking | Defense (`mode: 0`) |
| Detection config | CRS 4.7.0, 13 rule files + 2 custom, PL2, anomaly threshold 10, ML on | as shipped, and again with every semantic module at `strict` |
| Rate limiting | off (`SENTINEL_DISABLE_CORRELATION=1`) | none configured; only the builtin Search-Engine-Spider allowlist policy, anti-bot challenge off |
| Detection tool | GoTestWAF, 675 attack + 141 benign payloads | same invocation, same corpus |
| Load tool | vegeta, 15 s, keep-alive, 200 connections | same |

The origin is the all-methods-200 origin, not a static nginx, so every request reaches a 200 backend
and block-vs-pass is decided purely by the WAF. A static origin's 405s on benign non-GET requests
distort both TP and TN — see `gotestwaf_405_confound`.

Both WAFs are configured against a *shared* origin container rather than one each, so the backend
cannot be a variable.

**Rate-limit fairness.** A WAF that bans the scanning source part-way through a GoTestWAF run scores
garbage in both directions: the remaining attacks count as blocked, and the benign corpus counts as
blocked too. Sentinel's repeat-offender correlation is switched off for the run. SafeLine community
ships no rate-limit or CC policy, which was verified by reading its policy list rather than assumed,
and a benign probe was sent immediately after every single run — it returned 200 every time, so no
ban was ever in effect.

## Detection — GoTestWAF, 675 attack payloads + 141 benign

| Target | Composite | App-sec TP | API-sec TP | TN (benign passed) |
|---|---|---|---|---|
| **Sentinel** (CRS PL2 + ML) | **99.64%** | 99.24% (656/661) | 100% (14/14) | 99.29% (140/141) |
| SafeLine, shipped defaults | 58.28% | 47.38% | 42.86% (3/7) | **100.00%** (141/141) |
| SafeLine, all modules `strict` | 75.30% | 60.47% | 71.43% (5/7) | 97.87% (138/141) |

SafeLine ships two semantic modules disabled (`m_scanner`, `m_response`). `strict` is its maximum
posture and is what the third row measures — the analogue of the PL4 arm in the BunkerWeb
comparison. It buys SafeLine 17 points of true-positive and costs it 3 false positives.

SafeLine's defaults are the most conservative thing in this document: **zero** false positives on
141 benign payloads. That is its design goal and it hits it exactly.

### Per attack class — blocked / sent

| Attack class | Sentinel | SafeLine default | SafeLine strict |
|---|---|---|---|
| sql-injection (owasp) | 47/48 · 97.9% | **48/48 · 100%** | **48/48 · 100%** |
| community-sqli | 12/12 · 100% | 8/12 · 66.7% | 8/12 · 66.7% |
| xss-scripting | 224/224 · 100% | 144/224 · 64.3% | 194/224 · 86.6% |
| community-xss | 102/104 · 98.1% | 82/104 · 78.8% | 96/104 · 92.3% |
| nosql-injection | 50/50 · 100% | 10/50 · 20.0% | 10/50 · 20.0% |
| shell-injection | 32/32 · 100% | 0/32 · 0% | 8/32 · 25.0% |
| ldap-injection | 24/24 · 100% | 0/24 · 0% | 0/24 · 0% |
| mail-injection | 24/24 · 100% | 0/24 · 0% | 0/24 · 0% |
| ss-include | 24/24 · 100% | 0/24 · 0% | 0/24 · 0% |
| sst-injection | 24/24 · 100% | 8/24 · 33.3% | 8/24 · 33.3% |
| path-traversal | 20/20 · 100% | 2/20 · 10.0% | 2/20 · 10.0% |
| community-lfi | 7/8 · 87.5% | 2/8 · 25.0% | 2/8 · 25.0% |
| rce (owasp) | 6/6 · 100% | 0/6 · 0% | 2/6 · 33.3% |
| rce-urlparam | 9/9 · 100% | 3/9 · 33.3% | 3/9 · 33.3% |
| crlf | 7/7 · 100% | 0/7 · 0% | 0/7 · 0% |
| xml-injection | 7/7 · 100% | 0/7 · 0% | 0/7 · 0% |
| community-xxe | 2/2 · 100% | 0/2 · 0% | 0/2 · 0% |
| community-user-agent | 8/9 · 88.9% | 1/9 · 11.1% | 1/9 · 11.1% |
| rest (API) | 7/7 · 100% | 3/7 · 42.9% | 5/7 · 71.4% |
| soap (API) | 5/5 · 100% | 2/5 · 40.0% | 4/5 · 80.0% |
| large payloads 8–128 KB (15 cases) | 15/15 · 100% | not completed | not completed |
| **benign wrongly blocked** | 1/141 | **0/141** | 3/141 |

The shape of that table is the interesting part, and it is not "we are better everywhere".

SafeLine is at or above us exactly where its semantic engine is aimed: it is the only arm that
blocks all 48 OWASP SQL-injection payloads, including the one that gets past us. Where it has no
module, it scores zero — LDAP injection, mail injection, server-side includes, CRLF and XML
injection are 0/24, 0/24, 0/24, 0/7, 0/7 at *both* postures. Those are not tuning misses, they are
absent coverage, and no configuration change reaches them. That is the structural cost of a
semantic-only engine with no signature corpus: excellent precision inside its scope, nothing at all
outside it.

Our own worst classes are `community-lfi` (7/8) and `community-user-agent` (8/9), and both SafeLine
arms are far behind on them, so they are not a relative weakness here.

**The 10 and 15 uncompleted requests.** GoTestWAF could not complete 10 of 675 requests against
SafeLine at defaults and 15 at strict, all of them the 8–128 KB payload cases. Requests it cannot
complete are dropped from the denominator, so those cases were scored against neither WAF's
credit — the SafeLine percentages above are, if anything, slightly generous. This did **not**
reproduce in isolation: replaying the exact placement (128 KB urlencoded form body, the `HTMLForm`
placeholder) 30 times at concurrency 10 returned 403 thirty times from both WAFs. Treat it as
transient, not as a SafeLine size limit.

Oversized *URIs* do produce a real difference, though both answers are legitimate: Sentinel returns
414 from an 8 KB query string upward, SafeLine tolerates 16 KB and returns 414 at 32 KB. GoTestWAF
treats 414 as neither a block nor a pass.

## Performance — vegeta, 15 s runs, keep-alive, 200 connections

Clean traffic (`GET /`, `GET /products?category=shoes&page=2`, `POST /login` form). Every arm below
returned 100% 200 — see the false-positive section for why that took two attempts.

| Target | Max throughput (open loop, 64 workers) | p50 | p99 | p99.9 |
|---|---|---|---|---|
| Origin direct | 32,190 rps | 1.74 ms | 4.79 ms | 13.5 ms |
| **Sentinel** (CRS + ML on) | **7,595 rps** | 7.45 ms | 16.3 ms | 50.6 ms |
| SafeLine, defaults | 6,006 rps | 10.7 ms | 14.6 ms | 26.1 ms |
| SafeLine, strict | 4,688 rps | 13.1 ms | 22.9 ms | 45.6 ms |

Attack traffic (SQLi, XSS, traversal — every request must be blocked). All arms were 100% 403.

| Target | 403 body | Max block throughput | p50 | p99 |
|---|---|---|---|---|
| **Sentinel** | 125 B | **7,870 rps** | 7.49 ms | 15.8 ms |
| SafeLine, defaults | 15,604 B | 4,573 rps | 12.0 ms | 29.7 ms |
| SafeLine, strict | 15,604 B | 4,054 rps | 13.1 ms | 37.4 ms |

Read the `403 body` column before reading the throughput column: SafeLine's deny page is **125x**
larger than ours, and the BunkerWeb work showed that deny-response size, not the rule engine,
dominates max block throughput. Unlike BunkerWeb, SafeLine cannot be made to send a small deny body
for comparison — a custom block page is a commercial-edition feature in 9.4.1, so 15,604 B is what
community-edition users actually get and there is no config to shrink it.

Because of that, the honest engine comparison is at a fixed rate, where 15 KB per response is
irrelevant on loopback:

| Fixed attack rate | Sentinel p99 / p99.9 | SafeLine default p99 / p99.9 | SafeLine strict p99 / p99.9 |
|---|---|---|---|
| 1,000 rps (15,000 requests) | 1.63 / 8.82 ms | 1.97 / 8.81 ms | **1.33 / 5.97 ms** |
| 3,000 rps (45,000 requests) | **8.16 / 50.6 ms** | 59.1 / 188 ms | 14.1 / 73.7 ms |

Zero errors and zero timeouts in every one of those six arms. At 1,000 attack rps the three engines
are indistinguishable and SafeLine strict is marginally the fastest. At 3,000 rps we hold a real
lead. This is a completely different picture from BunkerWeb, whose block path collapsed at 1,000
attack rps with 1,560 requests timing out at 30 s — **SafeLine is a genuinely fast WAF and should
not be described as slow.** Our advantage over it is roughly 1.3x on clean throughput and about 1.7x
on max block throughput, and part of that 1.7x is its deny page rather than its engine.

## What this run found in our own WAF

A false positive in the ML classifier, on traffic that could not be more ordinary:

```
POST /login   username=alice&password=s3cret&remember=1     ->  403
```

SafeLine passes it. Attributed, not guessed: two probe instances from the identical config, one with
`ml.enable: true` and one with `false`, gave 403 and 200 respectively. The data plane's own record
names the cause and shows the ML verdict is sufficient on its own:

```
anomaly_score 13, rule_ids "ML-ANOMALY", decision Block,
block_reason "anomaly score 13 >= threshold 10"
```

The classifier alone contributes 13 against a threshold of 10, so no rule match is needed and no
rule tuning will fix it. Of eight ordinary form bodies tried, two are blocked — both login forms
carrying a remember-me field (`remember=1` and `remember=on`); a search form, a name/address form, a
product review and a payment form all pass. So the blast radius is narrow, but it lands on the
single most common authenticated POST on the web.

Two things worth keeping:

1. **Our 99.29% TN is measured on a corpus that cannot see this.** GoTestWAF's 141 benign payloads
   are plain text bodies, not form-encoded credential posts. A benchmark's true-negative score is
   only as good as the shapes in its benign corpus, and ours has a hole exactly where real login
   traffic lives. The fix is corpus coverage, not a threshold change.
2. **It was found by borrowing a competitor's traffic mix**, not by our own suite. The three-target
   clean mix exists because the BunkerWeb comparison needed a POST arm.

Not fixed in this commit — this document records the measurement. The FP is a data/ML-corpus issue
and belongs in the detection-engineering track alongside `ml_ngram_augmentation_benchmark`.

## Verdict

| Dimension | Sentinel | SafeLine 9.4.1 |
|---|---|---|
| Detection breadth | 99.64% composite; covers every class in the corpus | 58–75%; whole classes at 0% with no config that reaches them |
| Detection precision | 1 FP / 141, plus a real login-form FP the corpus misses | 0 FP / 141 at defaults; best-in-class precision |
| Deep SQLi | 47/48 | 48/48 — beats us |
| Clean throughput | 7,595 rps | 6,006 rps |
| Block path under flood | 7,870 rps; p99 8 ms at 3,000 rps | 4,573 rps; p99 59 ms at 3,000 rps, but no collapse |
| Deny page | 125 B | 15,604 B, not changeable in community |

Where SafeLine is genuinely ahead of us: zero false positives at its defaults, and complete OWASP
SQLi coverage. Both are worth taking seriously — its precision is the thing we just demonstrated we
do not match, and its SQLi engine catches a payload ours does not.

Where we are ahead: breadth, by a margin no amount of SafeLine configuration closes, and headroom
under attack load.

## Reproducing

```bash
# shared origin for both WAFs
docker run -d --name bench-origin -v $PWD/origin-all-methods.nginx.conf:/etc/nginx/conf.d/default.conf:ro nginx:alpine

# sentinel
sed 's/host: "127.0.0.1", port: 18090/host: "172.17.0.2", port: 80/' waf-detection.yaml > /tmp/det.yaml
SENTINEL_DISABLE_CORRELATION=1 ../../target/release/sentinel-bin --config /tmp/det.yaml &

# safeline: the console AES-encrypts the password client-side, so the login API needs
#   GET  /api/open/system/key    -> 16-char AES key
#   GET  /api/open/auth/csrf     -> csrf_token
#   POST /api/open/auth/login    {username, password: b64(iv_ascii + AES-128-CBC/PKCS7(pw)), csrf_token}
# where iv_ascii is hex(8 random bytes), i.e. 16 ASCII chars used directly as the CBC IV.
# Then POST /api/open/site {server_names:["*"], ports:["18092"], upstreams:["http://172.17.0.2:80"],
#                           load_balance:{balance_type:1}, mode:0, type:0, cert_id:0}
# and PUT /api/open/global/mode {semantics:{<every module>:"strict"}} for the strict arm.

# gotestwaf (each target)
docker run --rm --network host -v $PWD/out:/app/reports wallarm/gotestwaf:latest \
  --url http://localhost:PORT --blockStatusCodes 403 --passStatusCodes 200,404 \
  --workers 10 --randomDelay 20 --skipWAFIdentification --noEmailReport --reportPath /app/reports

# vegeta — pipe straight into the report; a 15 s open-loop capture against a 32k-rps
# origin writes GBs of .bin and will fill a tmpfs scratch dir.
vegeta attack -duration=15s -rate=0 -max-workers=64 -connections=200 -targets=clean.txt \
  | vegeta report -type=json

# after EVERY run, confirm the source was not banned — a 403 here invalidates the TN score
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:PORT/
```
