#!/usr/bin/env bash
# =============================================================================
# Next-Gen ESDSWAF — onboard the public practice site (Ghost) behind the WAF.
#
# Creates ONE site: a public hostname, upstream ghost:2368, in LEARNING mode.
# It is deploy/SITE-ONBOARDING-CHECKLIST.md §1–§3 executed rather than read, with
# the answers for Ghost filled in (§7 of the README records them).
#
# Every guard below is here because the corresponding mistake has already been
# made on this product:
#
#   * A site is accepted by the API and then silently dropped by the data plane,
#     leaving the dashboard showing a site that protects nothing. So this
#     dry-runs POST /sites/validate first and refuses to create on any problem.
#   * waf_policy is an ALLOWLIST (buildRustWaf, handlers.go:1574). A key it does
#     not name is stored, echoed back to the dashboard, and never reaches the
#     data plane — block_page shipped that way. So this sends only allowlisted
#     keys, and prints them for the record.
#   * GET /sites/:id returns {"site":{…}} while GET /sites returns a bare array.
#     Assuming the list shape made every site read as "not found" (c61ea54).
#   * Verification must traverse the operator's path AND the wire. Storage is not
#     retrieval, and retrieval is not enforcement.
#   * A new site never launches in blocking mode. Its false-positive rate is
#     unknown until it has seen real traffic — that is the entire point of the
#     exercise, and blocking first would be assuming the answer.
#
# Usage:
#   SENTINEL_ADMIN_PASSWORD=... ./onboard-ghost-site.sh <public-hostname> [--dry-run] [--yes]
#
# Env:
#   SENTINEL_API              default https://127.0.0.1:9443
#   SENTINEL_ADMIN_EMAIL      default admin@sentinel.local
#   SENTINEL_ADMIN_PASSWORD   required
#   GHOST_UPSTREAM            default ghost:2368
#   PG_CONTAINER              default sentinel-postgres-1
#
# Run it on the WAF host. Exit 0 only if the site is verifiably serving.
# =============================================================================
set -uo pipefail

API="${SENTINEL_API:-https://127.0.0.1:9443}"
EMAIL="${SENTINEL_ADMIN_EMAIL:-admin@sentinel.local}"
UPSTREAM="${GHOST_UPSTREAM:-ghost:2368}"
PG_CONTAINER="${PG_CONTAINER:-sentinel-postgres-1}"
PGUSER="${PGUSER:-sentinel}"
PGDB="${PGDB:-sentinel}"

DRY=0
ASSUME_YES=0
DOMAIN=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) DOMAIN="$1" ;;
  esac
  shift
done

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
warn()  { printf '\033[33m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
die()   { red "FATAL: $*"; exit 1; }

[ -n "$DOMAIN" ] || die "name the public hostname. Usage: $0 <public-hostname>"
[ -n "${SENTINEL_ADMIN_PASSWORD:-}" ] || die "SENTINEL_ADMIN_PASSWORD is not set"
command -v jq   >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

# A bare IP as the site domain makes rule 920350 fire on every single request,
# scoring 3 each time. The site would drown its own triage in noise before any
# real false positive showed up — the exact thing that made the Juice Shop
# rehearsal's only "detection" meaningless.
case "$DOMAIN" in
  *[0-9].[0-9]*) [[ "$DOMAIN" =~ ^[0-9.]+$ ]] && die \
    "$DOMAIN is a bare IP. Rule 920350 fires on every numeric Host, so every
     request scores 3 and the measurement is noise. Use a DNS name." ;;
esac

UP_HOST="${UPSTREAM%%:*}"
UP_PORT="${UPSTREAM##*:}"

api() { # api METHOD PATH [BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sk -X "$method" "$API/api/v1$path" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "$body"
  else
    curl -sk -X "$method" "$API/api/v1$path" -H "Authorization: Bearer $TOKEN"
  fi
}
pg() { docker exec "$PG_CONTAINER" psql -U "$PGUSER" -d "$PGDB" -tAc "$1" 2>/dev/null; }

echo "=============================================================="
echo " Onboard public practice site"
echo " domain=$DOMAIN  upstream=$UPSTREAM$([ $DRY -eq 1 ] && echo '  [DRY RUN]')"
echo "=============================================================="
echo

# ---------------------------------------------------------------------------
bold "0 · preflight"

LOGIN=$(curl -sk -X POST "$API/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg e "$EMAIL" --arg p "$SENTINEL_ADMIN_PASSWORD" '{email:$e,password:$p}')")
TOKEN=$(jq -r '.access_token // .token // empty' <<<"$LOGIN")
[ -n "$TOKEN" ] || die "login failed as $EMAIL — $(jq -rc '.' <<<"$LOGIN" | head -c 300)"
green "  ✓ authenticated as $EMAIL"

# The origin must be up first. A site whose upstream is not running returns 502,
# and 502 on a brand-new site reads as "the WAF is broken" rather than "the app
# is not started" — the juiceshop profile note in compose.prod.yml exists for
# exactly this confusion.
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$UP_HOST"; then
  green "  ✓ origin container matching '$UP_HOST' is running"
else
  die "no running container matches '$UP_HOST'. Start it first, using the SAME
     -f chain the stack is running (docker inspect sentinel-waf1-1 --format
     '{{index .Config.Labels \"com.docker.compose.project.config_files\"}}'):
       cd /opt/sentinel-src/deploy/docker && docker compose \\
         -f compose.prod.yml -f compose.cluster.yml -f compose.ha.yml \\
         -f compose.ghost.yml --profile ghost up -d ghost-db ghost
     Without it every request to $DOMAIN returns 502."
fi

# Does the name resolve, and to where? Not fatal — DNS may legitimately not be
# pointed yet — but a site created for a name that resolves somewhere ELSE is a
# misconfiguration that will not surface until a real visitor arrives.
RESOLVED=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -1)
if [ -n "$RESOLVED" ]; then
  green "  ✓ $DOMAIN resolves to $RESOLVED"
else
  warn "  ! $DOMAIN does not resolve yet. The site will work by Host header, but"
  warn "    ACME (HTTP-01) cannot issue a certificate until it resolves publicly"
  warn "    and port 80 is reachable from the internet."
fi

# An existing site holding this domain wins or clashes; either way, know now.
EXISTING=$(api GET /sites | jq -r --arg d "$DOMAIN" \
  'if type=="array" then . else (.sites // []) end | .[] | select(.domains[]? == $d) | .id' 2>/dev/null)
[ -z "$EXISTING" ] || die "site $EXISTING already claims domain $DOMAIN"
green "  ✓ $DOMAIN is not claimed by an existing site"
echo

# ---------------------------------------------------------------------------
bold "1 · the configuration"

# Answers to SITE-ONBOARDING-CHECKLIST.md §1, for Ghost specifically:
#   1.2  origin is plaintext HTTP inside the compose network → tls:false
#   1.4  Ghost has no unauthenticated /healthz; `/` returns 200 → health path /
#   1.5  Ghost's own upload ceiling is well under 20 MiB for images → 20 MiB.
#        Not "generous": max_body_size is also the per-in-flight-request memory
#        bound, and a public site is a free memory-amplification target.
#   1.6  no report/export endpoints → default 30 s read timeout is right
#   1.7  no SAML → default 8192 max_uri is right
#   1.8  Ghost admin does not require WebSockets → gate stays closed (2.5)
#   1.12 no PII in responses on a practice blog → DLP off, and it would buffer
#        response bodies up to 512 KB for nothing
UPSTREAM_JSON=$(jq -nc --arg h "$UP_HOST" --argjson p "$UP_PORT" '{
  load_balancer: "round_robin",
  servers: [ { host: $h, port: $p, weight: 1, tls: false } ],
  health_check: { path: "/", interval: "10s", timeout: "3s" },
  timeout_secs: 30,
  connect_timeout_secs: 5,
  proxy: { websocket: false, keepalive: true }
}')

# Every key here is in buildRustWaf's allowlist (handlers.go:1574). anomaly
# threshold 10, not 5: two correlated signals rather than one weak +5 heuristic,
# which is the posture the 99.60%/TN 99.29% detection benchmark measured.
WAF_JSON=$(jq -nc '{
  mode: "learning",
  paranoia_level: 2,
  anomaly_threshold: 10,
  max_body_size: 20971520,
  max_uri_length: 8192,
  max_header_count: 100,
  allowed_methods: ["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"],
  security_headers: { enabled: true },
  dlp: { enabled: false }
}')

echo "  upstream:   $(jq -c . <<<"$UPSTREAM_JSON")"
echo "  waf_policy: $(jq -c . <<<"$WAF_JSON")"
echo "  mode:       learning   (never blocking on a site with no measured FPR)"
echo

# ---------------------------------------------------------------------------
bold "2 · dry-run validation (changes nothing)"

VALID=$(api POST /sites/validate "$(jq -nc \
  --arg n "ghost-practice" --arg d "$DOMAIN" \
  --argjson u "$UPSTREAM_JSON" --argjson w "$WAF_JSON" \
  '{name:$n, domains:[$d], upstream:$u, waf_policy:$w}')")
if [ "$(jq -r '.valid // false' <<<"$VALID")" != "true" ]; then
  red "  ✗ the data plane cannot use this configuration:"
  jq -r '.problems[]? | "      - \(.)"' <<<"$VALID"
  die "refusing to create a site that would be stored but not enforced"
fi
green "  ✓ configuration is usable by the data plane"
echo

if [ $DRY -eq 1 ]; then
  warn "DRY RUN — nothing was created."
  exit 0
fi

if [ $ASSUME_YES -eq 0 ]; then
  echo "This creates a site serving $DOMAIN from $UPSTREAM in learning mode."
  printf 'Type yes to continue: '
  read -r ans
  [ "$ans" = "yes" ] || die "aborted"
  echo
fi

# ---------------------------------------------------------------------------
bold "3 · create"

CREATED=$(api POST /sites "$(jq -nc \
  --arg n "ghost-practice" --arg d "$DOMAIN" \
  --argjson u "$UPSTREAM_JSON" --argjson w "$WAF_JSON" \
  '{name:$n, domains:[$d], upstream:$u, waf_policy:$w}')")
SID=$(jq -r '.site.id // .id // empty' <<<"$CREATED")
[ -n "$SID" ] || die "create failed — $(jq -rc '.' <<<"$CREATED" | head -c 400)"
green "  ✓ created site $SID"
echo

# ---------------------------------------------------------------------------
# Three independent checks, and they must agree. Any one alone has produced a
# false PASS on this product before.
# ---------------------------------------------------------------------------
bold "4 · verify — API read-back, DB row, and the live wire"

FAIL=0

# 4a. The operator's path. Note the wrapped shape.
RB=$(api GET "/sites/$SID")
RB_MODE=$(jq -r '.site.waf_policy.mode // .waf_policy.mode // empty' <<<"$RB")
RB_DOM=$(jq -r '[.site.domains[]? , .domains[]?] | join(",")' <<<"$RB")
if [ "$RB_MODE" = "learning" ] && [[ ",$RB_DOM," == *",$DOMAIN,"* ]]; then
  green "  ✓ API read-back: mode=learning, domains=$RB_DOM"
else
  red   "  ✗ API read-back disagrees: mode=$RB_MODE domains=$RB_DOM"; FAIL=1
fi

# 4b. The stored row. Proves persistence, which retrieval alone does not.
DB_MODE=$(pg "SELECT waf_policy->>'mode' FROM sites WHERE id='$SID'")
if [ "$DB_MODE" = "learning" ]; then
  green "  ✓ DB row: waf_policy.mode=learning"
elif [ -z "$DB_MODE" ]; then
  warn  "  ! could not read the DB row (container '$PG_CONTAINER'?) — not proof of failure"
else
  red   "  ✗ DB row says mode=$DB_MODE"; FAIL=1
fi

# 4c. The wire. The only check that proves the data plane is actually serving
#     this site — the config reaches nodes by a 5s poll, so allow for it.
bold "     waiting for the data-plane config poll (5s)…"
sleep 8

CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "Host: $DOMAIN" https://127.0.0.1/ 2>/dev/null)
if [ "$CODE" = "200" ]; then
  green "  ✓ live wire: GET / with Host: $DOMAIN → 200 (reaching Ghost)"
elif [ "$CODE" = "502" ]; then
  red   "  ✗ live wire: 502 — the site is served but the origin is not answering."
  red   "    Check: docker logs \$(docker ps -qf name=ghost) --tail 50"; FAIL=1
else
  red   "  ✗ live wire: $CODE — expected 200"; FAIL=1
fi

# An attack must be SEEN and not blocked. Learning mode is not "nothing
# inspects": it detects and forwards. 200 here plus a DETECT event is correct;
# 403 would mean the site is not in learning mode after all.
ACODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
  -H "Host: $DOMAIN" -G --data-urlencode "q=1' OR '1'='1" https://127.0.0.1/ 2>/dev/null)
if [ "$ACODE" = "200" ]; then
  green "  ✓ live wire: SQLi probe → 200 (learning mode forwards, and logs a DETECT)"
elif [ "$ACODE" = "403" ]; then
  red   "  ✗ live wire: SQLi probe → 403. The site is BLOCKING, not learning."; FAIL=1
else
  warn  "  ! SQLi probe → $ACODE"
fi
echo

# ---------------------------------------------------------------------------
bold "verdict"
if [ $FAIL -ne 0 ]; then
  red "  checks disagree — the site is NOT verifiably serving. Fix before pointing DNS."
  echo "  Roll back with:  curl -sk -X DELETE $API/api/v1/sites/$SID -H \"Authorization: Bearer \$TOKEN\""
  exit 1
fi
green "  site $SID is serving $DOMAIN from $UPSTREAM in learning mode."
cat <<EOF

  Next, in order:
    1. ./pre-exposure-audit.sh --expect-domain $DOMAIN
       Nothing goes public until this exits 0.
    2. Have the network team forward ONLY tcp/80 and tcp/443 to this host.
    3. Point $DOMAIN at the public address.
    4. Issue the certificate — staging first, so a mistake is not rate-limited:
       curl -sk -X POST $API/api/v1/certs/acme -H "Authorization: Bearer \$TOKEN" \\
         -H 'Content-Type: application/json' \\
         -d '{"domains":["$DOMAIN"],"email":"you@esds.co.in","provider":"letsencrypt_staging","challenge":"http_01"}'
       Then re-issue with provider letsencrypt once staging succeeds.
    5. Leave it in learning mode and let real traffic accumulate. Measure with
       deploy/load-test/fpr-report.sh 168 — and remember the go-live gate needs a
       denominator of real visitors, not your own probes.
EOF
exit 0
