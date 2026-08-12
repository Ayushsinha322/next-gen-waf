#!/usr/bin/env bash
# =============================================================================
# Sentinel WAF — START the real-traffic false-positive pilot.
#
# The measurement half of this pilot is fpr-report.sh. This is the other half:
# putting the named sites into learning mode SAFELY, and proving they actually
# got there.
#
# It exists because "flip the site to learning mode" is four API calls and about
# six ways to get a silently wrong result. Every guard below is here because the
# corresponding mistake was made once already:
#
#   * A PATCH with a partial waf_policy can DROP sub-objects such as `ml`. This
#     script always reads the current policy and sends it back whole.
#   * Verification must traverse the OPERATOR's path. Querying the datastore
#     behind the API proves storage, not retrieval — that produced a false PASS
#     on the Support-ID fix. So this checks the API read-back, the live wire
#     behaviour, AND the DB row, and disagreement is a failure.
#   * A denominator you generate yourself is not a measurement. Health probes
#     and your own curl loops bias the rate DOWNWARD, toward a false pass. This
#     records the pre-pilot traffic level so you can see what the baseline was.
#   * Rule 920350 fires on any numeric-IP Host header, scoring 3 on every single
#     request. A site reached by bare IP will drown its own triage in noise.
#
# Usage:
#   SENTINEL_ADMIN_PASSWORD=... ./start-fpr-pilot.sh <site-id> [<site-id>...]
#
#   --dry-run     show what would change, change nothing
#   --yes         skip the confirmation prompt
#
# Env:
#   SENTINEL_API              default https://127.0.0.1:9443
#   SENTINEL_ADMIN_EMAIL      default admin@sentinel.local
#   SENTINEL_ADMIN_PASSWORD   required
#   CH_CONTAINER              default sentinel-clickhouse-1
#   PG_CONTAINER              default sentinel-postgres-1
#
# Run it on the deploy host. Exit 0 only if every site is verifiably in learning
# mode by all three checks.
# =============================================================================
set -uo pipefail

API="${SENTINEL_API:-https://127.0.0.1:9443}"
EMAIL="${SENTINEL_ADMIN_EMAIL:-admin@sentinel.local}"
CH_CONTAINER="${CH_CONTAINER:-sentinel-clickhouse-1}"
PG_CONTAINER="${PG_CONTAINER:-sentinel-postgres-1}"
PGUSER="${PGUSER:-sentinel}"
PGDB="${PGDB:-sentinel}"
CHDB="${CLICKHOUSE_DB:-sentinel_logs}"

DRY=0
ASSUME_YES=0
SITES=()

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) SITES+=("$1") ;;
  esac
  shift
done

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
warn()  { printf '\033[33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
die()   { red "FATAL: $*"; exit 1; }

[ ${#SITES[@]} -gt 0 ] || die "name at least one site id. Usage: $0 <site-id> [<site-id>...]"
[ -n "${SENTINEL_ADMIN_PASSWORD:-}" ] || die "SENTINEL_ADMIN_PASSWORD is not set"
command -v jq  >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

api() { # api METHOD PATH [BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sk -X "$method" "$API/api/v1$path" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body"
  else
    curl -sk -X "$method" "$API/api/v1$path" -H "Authorization: Bearer $TOKEN"
  fi
}
ch() { docker exec "$CH_CONTAINER" clickhouse-client -q "$1" 2>/dev/null; }
pg() { docker exec "$PG_CONTAINER" psql -U "$PGUSER" -d "$PGDB" -tAc "$1" 2>/dev/null; }

echo "=============================================================="
echo " FPR pilot — START"
echo " api=$API  sites=${SITES[*]}$([ $DRY -eq 1 ] && echo '  [DRY RUN]')"
echo "=============================================================="
echo

# ---------------------------------------------------------------------------
# 0. Preconditions. Fail here rather than half-way through a mutation.
# ---------------------------------------------------------------------------
bold "0 · preflight"

LOGIN=$(curl -sk -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg e "$EMAIL" --arg p "$SENTINEL_ADMIN_PASSWORD" '{email:$e,password:$p}')")
TOKEN=$(jq -r '.access_token // .token // empty' <<<"$LOGIN")
[ -n "$TOKEN" ] || die "login failed as $EMAIL — $(jq -rc '.' <<<"$LOGIN" | head -c 300)"
green "  ✓ authenticated as $EMAIL"

docker exec "$CH_CONTAINER" clickhouse-client -q 'SELECT 1' >/dev/null 2>&1 \
  || die "ClickHouse ($CH_CONTAINER) unreachable — the pilot would record nothing"
green "  ✓ ClickHouse reachable"

# The measurement reads traffic_buckets for the denominator and waf_events for
# the numerator. If either is not being written, the pilot is silently useless.
for tbl in waf_events traffic_buckets; do
  ch "SELECT count() FROM $CHDB.$tbl LIMIT 1" >/dev/null \
    || die "$CHDB.$tbl is not queryable — fix before starting a measurement window"
done
green "  ✓ waf_events + traffic_buckets queryable"

# ---------------------------------------------------------------------------
# 1. Baseline. What does the denominator look like BEFORE the pilot? If it is
#    dominated by health probes or your own testing, the rate will read low for
#    reasons that have nothing to do with the WAF.
# ---------------------------------------------------------------------------
echo
bold "1 · pre-pilot baseline (last 24h)"
BASE_REQS=$(ch "SELECT sum(reqs) FROM $CHDB.traffic_buckets WHERE ts >= now() - INTERVAL 24 HOUR" || echo 0)
BASE_EVENTS=$(ch "SELECT count() FROM $CHDB.waf_events WHERE ts >= now() - INTERVAL 24 HOUR" || echo 0)
BASE_IPS=$(ch "SELECT uniq(client_ip) FROM $CHDB.waf_events WHERE ts >= now() - INTERVAL 24 HOUR" || echo 0)
echo "  requests: ${BASE_REQS:-0}   events: ${BASE_EVENTS:-0}   distinct event IPs: ${BASE_IPS:-0}"
if [ "${BASE_REQS:-0}" -lt 1000 ] 2>/dev/null; then
  warn "  ! fewer than 1000 requests in 24h. If that does not change once the pilot"
  warn "    starts, you are measuring a denominator you generated yourself and the"
  warn "    result will not be judgeable. fpr-report.sh will say so."
fi

# ---------------------------------------------------------------------------
# 2. Inspect each site and build the new policy. Read-modify-write, whole object.
# ---------------------------------------------------------------------------
echo
bold "2 · sites"
declare -A NEW_POLICY
declare -A SITE_JSON

for id in "${SITES[@]}"; do
  # GET /sites/:id wraps the object as {"site":{…}} while GET /sites returns a
  # bare array. Unwrap both shapes rather than assuming one — an unwrap that is
  # wrong reads as "site not found", which is indistinguishable from a bad id.
  SITE=$(api GET "/sites/$id" | jq -c '.site // .')
  NAME=$(jq -r '.name // .id // empty' <<<"$SITE")
  [ -n "$NAME" ] || die "site '$id' not found via the API — check the id with: $0 --help"
  SITE_JSON[$id]="$SITE"

  MODE=$(jq -r '.waf_policy.mode // "unset"' <<<"$SITE")
  THRESH=$(jq -r '.waf_policy.anomaly_threshold // "unset"' <<<"$SITE")
  PL=$(jq -r '.waf_policy.paranoia_level // "unset"' <<<"$SITE")
  DOMAINS=$(jq -r '.domains // [] | join(", ")' <<<"$SITE")

  echo "  ─ $NAME ($id)"
  echo "      domains:   $DOMAINS"
  echo "      mode:      $MODE  →  learning"
  echo "      threshold: $THRESH        paranoia: $PL"

  # The benchmarked posture is the PAIR: threshold 10 AND rule 920230 excluded.
  # A site created before that default landed is running a posture nobody has
  # measured, so its pilot result would not be comparable to the published one.
  if [ "$THRESH" != "10" ]; then
    warn "      ! threshold is $THRESH, not the benchmarked 10. Every published detection"
    warn "        number was measured at 10 with rule 920230 excluded. Migrate this row"
    warn "        first, or the pilot measures a configuration nobody benchmarked."
  fi

  # 920350 scores 3 on every request whose Host is a bare IP. On the historical
  # log that was 70% of all events — pure artefact of testing by address.
  if jq -e '.domains // [] | map(test("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")) | any' >/dev/null <<<"$SITE"; then
    warn "      ! a domain here is a bare IP. Rule 920350 will fire on every request"
    warn "        reaching it by address and will dominate your triage. Point clients"
    warn "        at a hostname before the window opens."
  fi

  if [ "$MODE" = "learning" ]; then
    green "      already in learning mode — will re-verify, not re-write"
  fi

  # Whole policy, mode replaced. Never construct a fresh object: a partial
  # waf_policy risks dropping sub-objects such as `ml`.
  NEW_POLICY[$id]=$(jq -c '.waf_policy | .mode = "learning"' <<<"$SITE")
done

if [ $DRY -eq 1 ]; then
  echo
  warn "dry run — nothing was changed."
  exit 0
fi

if [ $ASSUME_YES -eq 0 ]; then
  echo
  read -r -p "Flip the sites above to learning mode? [yes/NO] " ans
  [ "$ans" = "yes" ] || { echo "aborted."; exit 1; }
fi

# ---------------------------------------------------------------------------
# 3. Apply.
# ---------------------------------------------------------------------------
echo
bold "3 · applying"
for id in "${SITES[@]}"; do
  RESP=$(api PATCH "/sites/$id" "$(jq -nc --argjson p "${NEW_POLICY[$id]}" '{waf_policy:$p}')")
  if jq -e '.error // .message' >/dev/null 2>&1 <<<"$RESP" && ! jq -e '.id // .name' >/dev/null 2>&1 <<<"$RESP"; then
    die "PATCH $id failed: $(jq -rc '.' <<<"$RESP" | head -c 300)"
  fi
  green "  ✓ PATCH $id accepted"
done

# The data plane polls /internal/config every 5s. Give it a margin.
echo "  waiting 15s for the data plane to pick up the new config…"
sleep 15

# ---------------------------------------------------------------------------
# 4. Verify three ways. Disagreement between them is the failure mode that
#    produced a false PASS before — storage is not retrieval, and neither is
#    enforcement.
# ---------------------------------------------------------------------------
echo
bold "4 · verification"
FAILED=0

for id in "${SITES[@]}"; do
  NAME=$(jq -r '.name // .id' <<<"${SITE_JSON[$id]}")
  echo "  ─ $NAME"

  # (a) the operator's own path
  A=$(api GET "/sites/$id" | jq -r '(.site // .) | .waf_policy.mode // "unset"')
  if [ "$A" = "learning" ]; then green "      ✓ API read-back: learning"
  else red "      ✗ API read-back: $A"; FAILED=1; fi

  # (b) the stored row — catches an API that echoes without persisting
  B=$(pg "SELECT waf_policy->>'mode' FROM sites WHERE name = '$NAME' OR id::text = '$id' LIMIT 1")
  if [ "$B" = "learning" ]; then green "      ✓ DB row:        learning"
  else red "      ✗ DB row:        ${B:-<not found>}"; FAILED=1; fi

  # (c) the wire — the only check that proves the DATA PLANE agrees. An attack
  #     must now pass through with 200 rather than 403. This is the check that
  #     would have caught every silently-inert defect in this codebase.
  HOST=$(jq -r '.domains[0] // empty' <<<"${SITE_JSON[$id]}")
  if [ -n "$HOST" ]; then
    CODE=$(curl -sk -o /dev/null -w '%{http_code}' -G --resolve "$HOST:443:127.0.0.1" \
             --data-urlencode "q=1' OR '1'='1" "https://$HOST/" 2>/dev/null || echo 000)
    if [ "$CODE" = "200" ]; then
      green "      ✓ live wire:     SQLi returned 200 (detected, not blocked)"
    elif [ "$CODE" = "403" ]; then
      red   "      ✗ live wire:     SQLi still 403 — the data plane has NOT applied learning mode"
      FAILED=1
    else
      warn "      ? live wire:     got $CODE — could not reach the site by its own hostname."
      warn "        Re-run this check from somewhere that resolves $HOST. Do NOT treat"
      warn "        an unreachable check as a pass."
    fi
  else
    warn "      ? live wire:     site has no domain to test with"
  fi
done

# ---------------------------------------------------------------------------
# 5. Mark the window and hand over.
# ---------------------------------------------------------------------------
echo
if [ $FAILED -ne 0 ]; then
  red "=============================================================="
  red " PILOT NOT STARTED — at least one check disagreed."
  red " Do not begin a measurement window until all three agree."
  red "=============================================================="
  exit 1
fi

STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
STAMP_DIR="${SENTINEL_STATE_DIR:-/var/lib/sentinel}"
if mkdir -p "$STAMP_DIR" 2>/dev/null; then
  printf 'started_at=%s\nsites=%s\nbaseline_reqs_24h=%s\nbaseline_events_24h=%s\n' \
    "$STARTED_AT" "${SITES[*]}" "${BASE_REQS:-0}" "${BASE_EVENTS:-0}" \
    > "$STAMP_DIR/fpr-pilot.start" 2>/dev/null && \
    green "  window marker written to $STAMP_DIR/fpr-pilot.start"
fi

green "=============================================================="
green " PILOT STARTED — $STARTED_AT"
green "=============================================================="
cat <<EOF

  Sites in learning mode: ${SITES[*]}

  Learning mode is NOT "nothing blocks". Threat-intel, IP reputation and
  anti-DDoS run BEFORE routing, so they still return 403 with mode=node. A
  non-zero "actually blocked" count in the report is that layer, not a rule.

  Next:
    1. Leave it alone for a full business cycle. Two weeks target, one week
       minimum, and it must include a weekday peak, a weekend, and any monthly
       batch job. False positives cluster in traffic you see rarely.
    2. Measure:      ./fpr-report.sh 168
    3. Triage using uniq_ips / uniq_paths — broad means false positive,
       concentrated means real attack.
    4. Fix with the narrowest tool: target exclusion, then whole-rule disable,
       then (almost never) threshold.
    5. Under 1% with the remainder judged genuine → flip ONE site to blocking
       and watch it for 48h.

  Do not read an early report as a result. Check what is in the denominator
  first: a rate whose denominator you generated yourself is not a measurement.

EOF
