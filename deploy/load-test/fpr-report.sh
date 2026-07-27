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
printf "  would-have-blocked   %s   (action=DETECT, learning mode)\n" "$detects"
printf "  actually blocked     %s   (action=BLOCK)\n" "$blocks"
echo

if [ "$reqs" -eq 0 ]; then
  echo "  No traffic in the window. Either nothing is flowing, or ClickHouse"
  echo "  ingestion is broken — check that the data plane can reach clickhouse:8123."
  exit 0
fi

rate=$(ch "SELECT round(($detects / $reqs) * 100, 4)")
echo "-- Detection rate (UPPER BOUND on false-positive rate) -------"
printf "  %s%% of real traffic would have been blocked\n" "$rate"
echo
verdict=$(ch "SELECT if($detects / $reqs < 0.01, 'under', 'over')")
if [ "$verdict" = "under" ]; then
  echo "  ✅ Under the 1% gate. Triage the table below to confirm the remaining"
  echo "     detections are genuine attacks, then blocking mode is defensible."
else
  echo "  ❌ Over the 1% gate. Do NOT enable blocking yet — work the table below."
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
