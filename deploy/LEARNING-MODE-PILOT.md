# Learning-mode pilot — the gate before blocking real traffic

**Status:** planned for the 2026-08-15 internal launch.
**Owner:** whoever turns blocking on. Do not skip to blocking without this.

## Why this exists

Every detection number in `deploy/load-test/DETECTION-RESULTS.md` — composite
99.60%, App-TP 99.09%, true-negative 99.29% — was measured against GoTestWAF's
synthetic corpus. That corpus is adversarial and useful, and it is **not your
traffic**. It contains no ESDS application, no real user behaviour, none of your
customers' URL shapes, and none of your internal tooling's requests.

The honest position on 2026-07-27: **real-traffic false-positive rate has never
been measured, not once.** A 99.29% true-negative rate on 141 synthetic benign
requests tells you the engine is well-calibrated. It does not tell you that
turning on blocking won't break a login flow on Monday morning.

That is the entire purpose of this pilot. It is cheap, it takes two weeks of
calendar time and almost no engineering time, and it converts the largest
remaining unknown in the launch into a number.

## The gate

**Do not enable blocking on a site until its detection rate on real traffic is
below 1%, and the detections that remain have been individually judged to be
genuine attacks.**

## Procedure

### 1. Launch in learning mode (2026-08-15)

`WafMode::Learning` is the enum default, but be explicit per site — an omitted
mode is easy to misread as intent.

```
PATCH /api/v1/sites/<id>
{ "waf_policy": { "mode": "learning", "paranoia_level": 2, "anomaly_threshold": 10 } }
```

In learning mode the data plane evaluates everything normally, downgrades any
Block/Challenge/Limit verdict to `Log`, sets `would_block`, and **keeps the block
reason** (`enforce_mode`, `crates/sentinel-proxy/src/lib.rs`). Traffic passes.
The verdict is recorded in ClickHouse with `action='DETECT'`.

Confirm the sites are where you think they are before trusting any measurement:

```sql
SELECT name, waf_policy->>'mode' FROM sites ORDER BY name;
```

### 1a. Know what learning mode does NOT stop

Learning mode downgrades the verdict of **content inspection** — rules, ML,
scoring. It does not disable the defences that run *before* the request is routed
to a site, because at that point there is no site policy to consult yet:
threat-intel IP/UA blocking, IP reputation, and anti-DDoS admission control all
still return 403.

Verified on the deploy VM with the site in learning mode: SQLi, XSS and SSTI were
recorded and passed through (`action=DETECT`, `mode=learning`), while a request
with a `sqlmap` user-agent was blocked outright (`action=BLOCK`, `mode=node`,
`rule=THREATINTEL`). The `mode=node` in that row is the tell — no site
enforcement mode was stamped, because routing had not happened yet.

This is defensible: those layers match on reputation, not on your application's
content, so they are not the false-positive source a pilot is measuring. But it
means **"learning mode" is not "nothing blocks"**, and a legitimate user whose
address or client appears in a threat feed will still be turned away during the
pilot. `fpr-report.sh` reports actual blocks on a separate line from detections
for exactly this reason — a non-zero "actually blocked" count while every site is
in learning mode is that pre-routing layer, not a rule.

If you need a genuinely inert pilot, set `mode: off` on the site instead — but
then you measure nothing, because `off` discards the verdict rather than recording
it.

### 2. Let it run

Two weeks is the target. One week is the minimum, and it must include a full
business cycle — a weekday morning peak, a weekend, and any batch/reporting job
that only runs monthly if one exists. False positives cluster in traffic you see
rarely, which is exactly the traffic a short window misses.

### 3. Measure

```bash
# On the deploy host
./deploy/load-test/fpr-report.sh 168     # last 7 days
```

The report prints the detection rate, a per-rule triage worklist, a worked
example per rule, and a per-site breakdown.

**Read the rate correctly.** It is an *upper bound* on the false-positive rate,
not the false-positive rate. Some detections will be real attacks — on any
internet-facing site a background rate of scanning and probing is normal and
healthy to block. The rate tells you how much triage there is to do; the per-rule
table tells you what.

### 4. Triage

The discriminator is in the report's `uniq_ips` and `uniq_paths` columns:

| Shape | Reading |
|---|---|
| Many distinct IPs, many distinct paths | **Almost certainly a false positive.** Real users doing real things. |
| Few distinct IPs, few distinct paths | **Almost certainly a real attack.** Concentrated, targeted. |
| Many IPs, one path | Look closely — either a botnet on one endpoint, or one endpoint whose legitimate payload trips a rule. The worked example decides it. |

The `explanation` column (added 2026-07-27) names the rule, the attack class and
the parameter that fired, so a detection can be judged without reconstructing the
request from logs.

### 5. Fix, with the narrowest tool

Preference order, narrowest first:

1. **Target exclusion** — `{"rule_id": N, "exclude_targets": ["ARGS:field"]}`.
   Kills the false positive on one parameter, leaves the rule protecting
   everything else.
2. **Whole-rule disable** — `{"rule_id": N, "disable": true}`. Only when a rule
   is wrong for this application everywhere.
3. **Threshold change** — last resort, and usually the wrong answer.
   `anomaly_threshold` already sits at the benchmarked value of 10. Lowering it
   trades detection away across every rule to fix one, and it invalidates the
   configuration the published numbers were measured on.

```
POST /api/v1/sites/<id>/exclusions
{ "rule_id": 920230, "exclude_targets": ["ARGS:redirect_to"] }
```

Omitting `exclude_targets` is not the same as an empty exclusion:
`handleAddSiteExclusion` treats a missing target list as "disable the whole rule"
(option 2), so always send the targets when you mean option 1. To remove an
exclusion again: `DELETE /api/v1/sites/<id>/exclusions/<rule_id>`.

Re-run the report after each change. The rate should fall while the detection
counts for *other* rules stay put; if other rules move, you changed something
broader than you meant to.

### 6. Flip to blocking, one site at a time

Under 1%, remaining detections judged genuine, and then:

```
PATCH /api/v1/sites/<id>
{ "waf_policy": { "mode": "blocking", ... } }
```

Watch `action='BLOCK'` volume for the first hour and keep the learning-mode
report running for a week afterwards. Have the mode revert ready — it is a single
PATCH, and rehearse it once before you need it.

## What this pilot does not cover

- **Response-side false positives.** DLP masking and response-body scanning are
  not measured by this report, which counts request verdicts only.
- **Latency under real traffic patterns.** The load tests measured synthetic
  traffic on a clean path (`PERFORMANCE-RESULTS.md`); real traffic has different
  body sizes and cache behaviour.
- **Anything about a site with no traffic.** An empty report is not a pass.

## Related

- `deploy/load-test/fpr-report.sh` — the measurement tool
- `deploy/load-test/DETECTION-RESULTS.md` — the synthetic-corpus numbers this
  pilot exists to supplement
- `deploy/DEPLOYMENT-CHECKLIST.md` — the wider pre-launch list
