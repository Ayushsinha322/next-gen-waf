#!/usr/bin/env bash
# Real-traffic false-positive report for a WAF running in LEARNING mode.
#
# Every detection number we publish (composite 99.60%, true-negative 99.29%) was
# measured against a synthetic adversarial corpus. This script measures the one
# thing that corpus cannot tell us: how often the WAF would block REAL traffic
# from REAL users. That number gates turning blocking on.
#
# HOW THE MEASUREMENT WORKS, because the schema makes it non-obvious:
#
#   * waf_events stores ONLY notable requests. In learning mode a would-have-been
#     blocked request is stored with action='DETECT'; an ordinary allowed request
#     is not stored at all (see record_event() in sentinel-proxy/src/lib.rs).
#   * traffic_buckets.blocked counts only ACTUAL Block/Challenge decisions, so in
#     learning mode it stays 0. The total request count comes from `reqs`.
#
#   detection rate = count(waf_events action='DETECT') / sum(traffic_buckets.reqs)
#
# READ THE RESULT CORRECTLY: that rate is an UPPER BOUND on the false-positive
# rate, not the false-positive rate. Some detections are genuine attacks, and on
# an internet-facing site a background rate of real attack traffic is normal. The
# rate tells you how much to triage; the per-rule table below tells you what.
#
# Usage:
#   ./fpr-report.sh [HOURS]                      # default 24
#   CH_CONTAINER=sentinel-clickhouse-1 ./fpr-report.sh 72
#
# Run it on the deploy host (it shells into the ClickHouse container).

set -euo pipefail

HOURS="${1:-24}"
CH_CONTAINER="${CH_CONTAINER:-sentinel-clickhouse-1}"
PG_CONTAINER="${PG_CONTAINER:-sentinel-postgres-1}"
DB="${CLICKHOUSE_DB:-sentinel_logs}"
PGUSER="${PGUSER:-sentinel}"
PGDB="${PGDB:-sentinel}"

if ! [[ "$HOURS" =~ ^[0-9]+$ ]] || [ "$HOURS" -lt 1 ]; then
  echo "error: HOURS must be a positive integer, got '$HOURS'" >&2
  exit 2
fi

ch() { docker exec "$CH_CONTAINER" clickhouse-client -q "$1"; }
pg() { docker exec "$PG_CONTAINER" psql -U "$PGUSER" -d "$PGDB" -tAc "$1"; }

WINDOW="ts >= now() - INTERVAL $HOURS HOUR"

echo "=============================================================="
echo " WAF false-positive report — last ${HOURS}h"
echo "=============================================================="
echo

# ---------------------------------------------------------------------------
# Precondition: are the sites actually in learning mode? Measuring a "would
# block" rate while the WAF is already blocking measures nothing — the blocked
# users never came back, so the traffic is self-censored.
# ---------------------------------------------------------------------------
echo "-- Site enforcement modes ------------------------------------"
modes=$(pg "SELECT name || ' -> ' || coalesce(waf_policy->>'mode','(unset: defaults to learning)') FROM sites ORDER BY name" || true)
if [ -z "$modes" ]; then
  echo "  (could not read sites from Postgres — check \$PG_CONTAINER)"
else
  echo "$modes" | sed 's/^/  /'
fi
blocking=$(pg "SELECT count(*) FROM sites WHERE waf_policy->>'mode' = 'blocking'" || echo "?")
if [ "$blocking" != "0" ] && [ "$blocking" != "?" ]; then
  echo
  echo "  ⚠  $blocking site(s) are in BLOCKING mode. Their traffic is already"
  echo "     filtered, so the rate below understates what tuning still needs to"
  echo "     fix. Put a site in learning mode for a clean measurement."
fi
echo

# ---------------------------------------------------------------------------
# The headline rate.
# ---------------------------------------------------------------------------
reqs=$(ch "SELECT sum(reqs) FROM $DB.traffic_buckets WHERE $WINDOW")
hard=$(ch "SELECT sum(blocked) FROM $DB.traffic_buckets WHERE $WINDOW")
detects=$(ch "SELECT count() FROM $DB.waf_events WHERE $WINDOW AND action = 'DETECT'")
blocks=$(ch "SELECT count() FROM $DB.waf_events WHERE $WINDOW AND action = 'BLOCK'")

reqs=${reqs:-0}; hard=${hard:-0}; detects=${detects:-0}; blocks=${blocks:-0}
[ "$reqs" = "\\N" ] && reqs=0
[ "$hard" = "\\N" ] && hard=0

echo "-- Volume ----------------------------------------------------"
printf "  requests seen        %s\n" "$reqs"

# A non-zero shed means the data plane enforced blocks it could NOT record, so
# waf_events undercounts and every ratio below is understated. Read from the live
# node rather than ClickHouse — the whole point is that these never reached it.
shed=$(curl -s --max-time 3 http://127.0.0.1:80/healthz 2>/dev/null \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("history_shed",0))' 2>/dev/null || echo 0)
if [ "${shed:-0}" -gt 0 ] 2>/dev/null; then
  printf "  ⚠️  events SHED       %s   (enforced but never recorded — history buffer full)\n" "$shed"
  echo   "      waf_events undercounts blocks, so the rate below is UNDERSTATED."
  echo   "      Usually means a flood: at 20k rps every blocked request wants a row."
fi
printf "  would-have-blocked   %s   (action=DETECT, learning mode)\n" "$detects"
printf "  actually blocked     %s   (action=BLOCK)\n" "$blocks"
echo

if [ "$reqs" -eq 0 ]; then
  echo "  No traffic in the window. Either nothing is flowing, or ClickHouse"
  echo "  ingestion is broken — check that the data plane can reach clickhouse:8123."
  exit 0
fi

# ── Is this denominator actually REAL traffic? ────────────────────────────────
#
# In the 2-VM topology keepalived's health check issues a REAL request to each
# node every `interval` seconds, so both nodes manufacture traffic whether or not
# a user is present: 2 nodes / 2s = ~3600 requests an hour, ~86k a day.
#
# Those probes score below threshold (one unvarying benign GET), so they never
# become detections — they land ONLY in the denominator. That biases the rate
# DOWNWARD, i.e. toward a false PASS, which is the dangerous direction for a gate.
# Measured 2026-07-30 on the .88/.89 pair: 364 of 373 requests in the window were
# the probe, and the report duly announced 0.18% "under the 1% gate" on four
# self-inflicted test attacks.
#
# So say so, loudly, rather than letting a padded denominator read as a pass.
# Absence of keepalived is an EXPECTED state, not an error: the standalone and
# 3-node-cluster topologies have no /etc/keepalived/keepalived.conf at all. Under
# `set -euo pipefail` the bare grep pipeline below used to exit non-zero there,
# which killed the whole report at this assignment — silently, right after the
# volume block, so it read as "the report ended" rather than "the report died".
# The gate tool failing closed on the very topology being piloted is worse than
# no probe estimate, so the lookup is guarded and its absence simply means "no
# self-generated probes to warn about".
probe_iv=""
if [ -r /etc/keepalived/keepalived.conf ]; then
  probe_iv=$(grep -oE '^[[:space:]]*interval[[:space:]]+[0-9]+' /etc/keepalived/keepalived.conf 2>/dev/null \
               | grep -oE '[0-9]+' | head -1 || true)
fi
probe_est=0
if [ -n "${probe_iv:-}" ] && [ "${probe_iv:-0}" -gt 0 ]; then
  # Two nodes in this topology, each probing itself.
  probe_est=$(( (3600 / probe_iv) * 2 * HOURS ))
fi

rate=$(ch "SELECT round(($detects / $reqs) * 100, 4)")
echo "-- Detection rate (UPPER BOUND on false-positive rate) -------"
printf "  %s%% of real traffic would have been blocked\n" "$rate"
echo

probe_dominated=no
if [ "$probe_est" -gt 0 ]; then
  printf "  ⚠️  Up to %s of those %s requests are keepalived health-check probes\n" "$probe_est" "$reqs"
  printf "      (2 nodes x every %ss). They never trigger detections, so they inflate\n" "$probe_iv"
  echo   "      ONLY the denominator — which pushes this rate DOWN, toward a false pass."
  if [ "$(( probe_est * 2 ))" -ge "$reqs" ]; then
    probe_dominated=yes
    echo   "      More than half your denominator is self-generated. This number is NOT"
    echo   "      yet a false-positive rate for real users."
  fi
  echo
fi

verdict=$(ch "SELECT if($detects / $reqs < 0.01, 'under', 'over')")
if [ "$verdict" = "over" ]; then
  echo "  ❌ Over the 1% gate. Do NOT enable blocking yet — work the table below."
elif [ "$probe_dominated" = "yes" ]; then
  echo "  ⏳ NOT A PASS — the gate cannot be judged on this data. The window is"
  echo "     dominated by synthetic health-check traffic, so the rate is an artefact"
  echo "     of the probe, not a measurement of your users. Keep learning mode on"
  echo "     until real traffic has run for a full business cycle (see"
  echo "     deploy/LEARNING-MODE-PILOT.md step 2), then re-run."
else
  echo "  ✅ Under the 1% gate. Triage the table below to confirm the remaining"
  echo "     detections are genuine attacks, then blocking mode is defensible."
fi
echo

# ---------------------------------------------------------------------------
# The triage table. This is the part that does the work.
#
# uniq_ips and uniq_paths are the discriminator: a real attack campaign is
# concentrated (few source IPs, few paths), whereas a false positive fires
# broadly across ordinary users and ordinary URLs. A rule at the top of this
# table with a high uniq_ips count is almost always a false positive.
# ---------------------------------------------------------------------------
echo "-- Top detections by rule (triage worklist) ------------------"
echo "   many distinct IPs + many distinct paths => likely FALSE POSITIVE"
echo "   few distinct IPs  + few distinct paths  => likely a REAL attack"
echo
ch "SELECT
      rule,
      if(target = '', '(multi-target rule)', target) AS target,
      attack,
      count()      AS hits,
      uniq(ip)     AS uniq_ips,
      uniq(path)   AS uniq_paths,
      round(count() / $reqs * 100, 4) AS pct_of_traffic
    FROM $DB.waf_events
    WHERE $WINDOW AND action = 'DETECT'
    GROUP BY rule, target, attack
    ORDER BY hits DESC
    LIMIT 20
    FORMAT PrettyCompactMonoBlock"
echo

# ---------------------------------------------------------------------------
# Worked examples. The explanation column (added 2026-07-27) means an operator
# can judge a detection without reconstructing the request by hand.
# ---------------------------------------------------------------------------
echo "-- One worked example per top rule --------------------------"
ch "SELECT rule, any(path) AS example_path, any(explanation) AS why
    FROM $DB.waf_events
    WHERE $WINDOW AND action = 'DETECT'
    GROUP BY rule
    ORDER BY count() DESC
    LIMIT 8
    FORMAT Vertical"
echo

echo "-- Per-site rate --------------------------------------------"
ch "SELECT
      e.site,
      e.detects,
      t.reqs,
      round(e.detects / t.reqs * 100, 4) AS pct
    FROM (
      SELECT site, count() AS detects FROM $DB.waf_events
      WHERE $WINDOW AND action = 'DETECT' GROUP BY site
    ) AS e
    LEFT JOIN (
      SELECT site_id, sum(reqs) AS reqs FROM $DB.traffic_buckets
      WHERE $WINDOW GROUP BY site_id
    ) AS t ON e.site = t.site_id
    ORDER BY pct DESC
    FORMAT PrettyCompactMonoBlock"
echo

cat <<'NEXT'
-- Next step --------------------------------------------------
For each row you judge a false positive, add a site exclusion rather than
lowering the threshold globally (the threshold is already at the benchmarked
value of 10; dropping it trades away detection everywhere to fix one rule):

  POST /api/v1/sites/<id>/exclusions
    { "rule_id": <rule>, "exclude_targets": ["<target>"] }   # scope to one target
    { "rule_id": <rule>, "disable": true }                   # whole rule, last resort

Prefer exclude_targets. Note that OMITTING exclude_targets is read as "disable the
whole rule", so send the target list explicitly when you mean to scope it.

Re-run this report after each change; the rate should fall without the detection
count for other rules moving.
NEXT
