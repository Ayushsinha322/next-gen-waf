# Sentinel WAF — Detection Benchmark (MEASURED, fair harness)

> Every number here is measured by `benchmark-detection.sh` (GoTestWAF v0.5.8)
> against the **all-methods-200 origin**, so it reflects the WAF, not a mock
> backend. Reproduce with `./benchmark-detection.sh`.

## ⚠️ Why the earlier numbers were wrong (the 405 confound)

Earlier runs used a **static** origin (nginx serving files). Static files only
allow `GET`, so the origin returned **405** to every benign/attack POST/PUT/etc.
GoTestWAF cannot classify a 405, so it **drops those from the score**. Effect:

- bypassed **non-GET attacks** disappeared → **attack-detection (TP) INFLATED**
- allowed **non-GET benign** requests disappeared → **benign-allow (TN) DEFLATED**
- ~22% of all tests came back "unresolved"

The fair all-methods-200 origin returns 200 for every method+path, so block/pass
is decided purely by the WAF (403 = blocked). **0% unresolved.**

## True baseline (fair origin) — 2026-07-15

Config: `waf-detection.yaml` (CRS 4.7, PL2, anomaly_threshold **10**, rule 920230
disabled, ML off, correlation off). Binary includes the CRS transform-coverage
fixes (commit `7d17fe7`).

| Metric | Confounded (static origin) | **TRUE (fair origin)** |
|---|---:|---:|
| Overall | 85.65% | **62.58%** |
| Attack detection (TP) | 61.47% | **43.41%** (293/675) |
| Benign allowed (TN) | 81.13% | **92.91%** (131/141) |
| Unresolved | ~22% | **0%** |

**Reading:** false-positives are already good (**93% benign allowed**). The real
weakness is **attack detection (43%)**. Per-category (fair origin), the gaps:

| Category | Detection |
|---|---:|
| CRLF, LDAP, mail-injection | **0%** (no rules) |
| SSTI | 12.5% |
| shell-injection | 18.75% |
| path-traversal | 25% |
| SQL-injection (owasp evasion set) | 35.4% |
| XSS-scripting | 37.5% |
| NoSQL | 40% |

## Goal & how we get to genuine >90

Overall >90 requires driving **TP 43% → 90%+** while holding **TN ~93%**. Levers
(in build priority): (1) coverage rules for the 0%/weak categories +
all-placement inspection; (2) a **retrained ML precision layer** (the only thing
that raises TP without raising FP — regex alone cannot hit TP≥90 & TN≥90 at once
on this corpus); (3) per-deployment FP tuning on real traffic.

## Progress log (fair origin, measured)

| Build step | TP | TN | Overall |
|---|---:|---:|---:|
| True baseline (threshold 10 + 920230 off) | 43.41% | 92.91% | 62.58% |
| + all-placement libinjection (`placement.conf`) | 44.15% | 91.49% | 62.41% |
| + coverage signatures (`coverage.conf`: CRLF/SMTP-IMAP/LDAP/SSTI/NoSQL) | **49.33%** | 91.49% | **63.74%** |
| + ML char-n-gram classifier (embedded, trained on HttpParamsDataset + adversarial-benign) | **57.19%** | 88.65% | **75.63%** |
| + base64 decode-and-rescore in the ML path (defeats the Base64 encoder axis) | **62.22%** | 87.23% | **76.57%** |
| + mutation-augmented model (evasion transforms in training) | 68.08% | 87.23% | 78.11% |
| + obfuscation canonicalizers ($IFS/comment/whitespace) + per-category-balanced retrain (full-enc benign) + precise cmdi rules (9900207/8) + **ML scoring of parsed form/multipart field values** | **80.30%** | **85.82%** | **80.82%** |

**2026-07-18: crossed 80% (overall 80.82%, App-TP 80.30%, TN 85.82%, API 78.57%).** The decisive
lever was feeding the ML classifier the *parsed, decoded* form/multipart field values — encoded
attacks in body fields were previously diluted inside the raw body blob and never decoded, so they
bypassed. This lifted xss-scripting 68→90%, ss-include 75→100%, and raised sql/ldap/path-traversal/
shell across the board. TN cost was +4 FP (88.65→85.82) for +12pp App-TP. Category highlights (final):
xss-scripting 90.2%, ss-include 100%, xml/crlf/xxe/rce-urlparam/urlpath 100%, sqli 60%, shell 56%,
ldap 58%, nosql 58%, sst 67%, path-traversal 60%. Remaining bypass mass: mail-injection (46%),
evasive XSS tail (22/224), SQLi/shell obfuscation tail — the next targets beyond 80%.

Category gains from coverage: CRLF 0→85.7%, mail(SMTP/IMAP) 0→33.3%, NoSQL 40→50%,
LDAP 0→33.3%, SSTI 12.5→45.8%. TN held (coverage added 0 false-positives; the
2-request TN dip is from libinjection in `placement.conf` on 2 benign requests).

**Empirically proven ceiling of the rule-only approach on this corpus ≈ 50% TP.**
The dominant remaining bypass mass is (a) evasive XSS (37.9%, 139 bypassed) + SQLi
(39.6%, 29 bypassed) that libinjection/CRS regex miss, and (b) the Base64Flat
encoder axis across all categories. Neither is closable with more signatures —
they require the **retrained ML classifier + recursive normalization** (Phase 2).
Also found: several CRS rules silently fail to compile on PCRE→RE2 regex
incompatibilities (921200=the only LDAP rule, 932170/171 RCE, 933170 PHP) — a
regex-sanitizer would recover them (custom rules already cover LDAP).

## Rule for all future benchmarking

**Always** use `benchmark-detection.sh` / an all-methods-200 origin. Never quote
detection/FP numbers from a static origin — they are distorted in both directions.
