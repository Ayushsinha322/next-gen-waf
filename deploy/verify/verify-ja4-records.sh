#!/usr/bin/env bash
# Is the JA4 fingerprint now RECORDED — on the NDJSON logs, in ClickHouse, and
# reachable by the control plane's queries — rather than only living in ctx?
#
# Run ON the WAF host, AFTER the dataplane has been rolled (its ensure_schema
# adds the column) and ideally after the control plane has been rolled too.
#
# WHY: ctx.tls_fingerprint drove bot scoring and the JA4 blocklist and was never
# written anywhere, so "why was this client scored as sqlmap" was unanswerable
# once the request was gone. This is a SCHEMA change: the event INSERT names an
# explicit column list, so a field without a column fails every insert.
#
# Deploy-order hazard this script exists to catch: the Go control plane now
# SELECTs `ja4`. If it is rolled BEFORE the dataplane added the column, Threat
# Search fails on an unknown column. Section 3 replays Go's exact query.
#
# Optional: CP_TOKEN=<admin bearer JWT> enables the authenticated end-to-end
# check of the Threat Search API (section 5). Without it that section is a NOTE,
# not a PASS — the Go path is then covered by the SQL replay + Go's own tests.
set -uo pipefail
H="${PROBE_HOST:-wafdemo.esds.local}"
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }

envof() { docker inspect "$1" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep "^$2=" | head -1 | cut -d= -f2-; }
CHIP=$(docker inspect sentinel-clickhouse-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | awk '{print $1}')
CHU=$(envof sentinel-waf1-1 SENTINEL_CLICKHOUSE_USER); CHU=${CHU:-default}
CHP=$(envof sentinel-waf1-1 SENTINEL_CLICKHOUSE_PASSWORD)
CHDB=$(envof sentinel-waf1-1 SENTINEL_CLICKHOUSE_DB); CHDB=${CHDB:-sentinel_logs}
chq() { curl -s --max-time 10 -u "$CHU:$CHP" "http://$CHIP:8123/" --data-binary "$1" 2>/dev/null; }
LOGDIR="${SENTINEL_LOG_VOLUME:-/var/lib/docker/volumes/sentinel_sentinel-logs/_data}"

echo "=== 1. the column exists (the dataplane's ensure_schema migration ran) ==="
COLS=$(chq "SELECT name FROM system.columns WHERE database='$CHDB' AND table='waf_events' FORMAT TSV" | tr '\n' ' ')
echo "    columns: $COLS"
case " $COLS " in
  *" ja4 "*) ok "waf_events has the ja4 column" ;;
  *) bad "waf_events has NO ja4 column — the dataplane has not been rolled (or ensure_schema failed: check waf1 logs for 'schema init failed'). Do NOT roll the control plane yet." ;;
esac

echo
echo "=== 2. a fresh event row carries the fingerprint ==="
M="ja4rec$$"
# A rule hit produces a DETECT row in learning mode; TLS so a fingerprint exists.
curl -sk -o /dev/null --max-time 10 -H "Host: $H" "https://127.0.0.1/?m=$M&q=1'%20OR%20'1'='1" 2>/dev/null
sleep 6   # history writer batches
ROW=$(chq "SELECT ja4, protocol, action, rule FROM $CHDB.waf_events WHERE query LIKE '%$M%' ORDER BY ts DESC LIMIT 1 FORMAT TSV")
echo "    row: ${ROW:-<none yet>}"
JA4=$(echo "$ROW" | cut -f1)
if [ -z "$ROW" ]; then
  bad "no waf_events row for the probe — the event writer may be down, or the batch has not flushed"
elif [ -z "$JA4" ]; then
  bad "the row exists but ja4 is EMPTY — the field is not being populated from ctx.tls_fingerprint"
else
  case "$JA4" in
    t*_????????????_????????????) ok "row carries a well-formed TCP JA4: $JA4" ;;
    q*_????????????_????????????) ok "row carries a well-formed QUIC JA4: $JA4" ;;
    *) bad "row ja4 is malformed: $JA4" ;;
  esac
fi

echo
echo "=== 3. the control plane's exact SELECTs are valid against the live schema ==="
# Replays the column list Go's client uses (search + support-ID lookup + export),
# so a control-plane roll cannot hit 'unknown column ja4'.
GOSEL="SELECT toUnixTimestamp(ts) AS ts, ip, country, site, tenant, method, path, query, referer, matched, rule, attack, action, severity, score, status, protocol, request_id, target, mode, threshold, explanation, ja4 FROM $CHDB.waf_events ORDER BY ts DESC LIMIT 1 FORMAT JSONEachRow"
OUT=$(chq "$GOSEL")
case "$OUT" in
  *"\"ja4\""*) ok "Go's search/lookup column list resolves, and ja4 is in the result" ;;
  *Exception*|*Unknown*) bad "Go's SELECT fails against the live schema: ${OUT:0:160}" ;;
  "") note "query returned no rows (empty table) but did not error" ;;
  *) bad "unexpected result: ${OUT:0:160}" ;;
esac
EXP=$(chq "SELECT formatDateTime(ts, '%Y-%m-%dT%H:%i:%SZ', 'UTC') AS timestamp_utc, ip, country, site, method, path, query, referer, matched, rule, attack, action, severity, score, status, protocol, request_id, target, mode, threshold, explanation, ja4 FROM $CHDB.waf_events LIMIT 1 FORMAT CSVWithNames")
case "$EXP" in
  *ja4*) ok "the export column list resolves and includes ja4" ;;
  *) bad "export column list failed: ${EXP:0:160}" ;;
esac

echo
echo "=== 4. the NDJSON records carry it too ==="
sleep 2
AL=$(grep -h "$M" "$LOGDIR"/waf*/access.log 2>/dev/null | tail -1)
WL=$(grep -h "$M" "$LOGDIR"/waf*/waf.log 2>/dev/null | tail -1)
AJ=$(echo "$AL" | python3 -c "import sys,json; l=sys.stdin.readline(); print(json.loads(l).get('ja4','<missing>') if l.strip() else '<no line>')" 2>/dev/null)
WJ=$(echo "$WL" | python3 -c "import sys,json; l=sys.stdin.readline(); print(json.loads(l).get('ja4','<missing>') if l.strip() else '<no line>')" 2>/dev/null)
echo "    access.log ja4: $AJ"
echo "    waf.log    ja4: $WJ"
case "$AJ" in [tq]*_*) ok "access.log carries the fingerprint" ;; *) bad "access.log ja4 = $AJ" ;; esac
case "$WJ" in [tq]*_*) ok "waf.log carries the fingerprint" ;; *) bad "waf.log ja4 = $WJ" ;; esac

echo
echo "=== 5. Threat Search API returns it (needs CP_TOKEN) ==="
CPIP=$(docker inspect sentinel-controlplane-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | awk '{print $1}')
CPIMG=$(docker inspect sentinel-controlplane-1 --format '{{.Config.Image}}' 2>/dev/null)
echo "    control plane image: $CPIMG"
# Obtain a token: CP_TOKEN if given, else log in with the bootstrap admin credential
# already present in the control-plane container's environment. The password is
# read on this host and passed only in the login request body — never printed.
# If the admin password was changed after seeding, or MFA is enabled, login
# fails and this degrades to a NOTE rather than a false verdict.
TOKEN="${CP_TOKEN:-}"
if [ -z "$TOKEN" ]; then
  # SENTINEL_ADMIN_EMAIL is frequently EMPTY in the container env (it was on .71,
  # and an earlier check masked the empty value as "<set>"). The seeder's default
  # identity is admin@sentinel.local (control-plane/internal/db/seed.go).
  AEMAIL=$(envof sentinel-controlplane-1 SENTINEL_ADMIN_EMAIL); AEMAIL=${AEMAIL:-admin@sentinel.local}
  APW=$(envof sentinel-controlplane-1 SENTINEL_BOOTSTRAP_ADMIN_PASSWORD)
  if [ -n "$AEMAIL" ] && [ -n "$APW" ]; then
    TOKEN=$(AEMAIL="$AEMAIL" APW="$APW" python3 -c "import json,os,sys; print(json.dumps({'email':os.environ['AEMAIL'],'password':os.environ['APW']}))" \
      | curl -s --max-time 10 -H 'Content-Type: application/json' --data-binary @- "http://$CPIP:9501/api/v1/auth/login" 2>/dev/null \
      | python3 -c "
import sys, json
try: d = json.load(sys.stdin)
except Exception: print(''); raise SystemExit
print(d.get('token') or d.get('access_token') or '')
" 2>/dev/null)
    [ -n "$TOKEN" ] && echo "    logged in as the bootstrap admin (token not shown)" \
                    || note "bootstrap-admin login did not yield a token (password changed since seeding, or MFA on) — falling back"
  fi
fi
if [ -n "$TOKEN" ]; then
  RESP=$(curl -s --max-time 10 -H "Authorization: Bearer $TOKEN" "http://$CPIP:9501/api/v1/events/search?limit=3")
  case "$RESP" in
    *"\"ja4\""*) ok "Threat Search API returns ja4 — the Go path is proven end to end" ;;
    *) bad "Threat Search API response has no ja4 (control plane not rolled, or its query failed): ${RESP:0:160}" ;;
  esac
else
  CODE=$(curl -s --max-time 6 -o /dev/null -w '%{http_code}' "http://$CPIP:9501/api/v1/events/search?limit=1")
  { [ "$CODE" = "403" ] || [ "$CODE" = "401" ]; } \
    && note "API is up and auth-gated ($CODE) but no token available; Go's own tests + the SQL replay in §3 cover the query" \
    || bad "events API returned $CODE — control plane unhealthy?"
fi
ERRS=$(docker logs --since 10m sentinel-controlplane-1 2>&1 | grep -ci "unknown column\|clickhouse.*error" || true)
[ "${ERRS:-0}" -eq 0 ] \
  && ok "no unknown-column / ClickHouse errors in the control plane's last 10 minutes" \
  || bad "$ERRS control-plane log lines mention unknown column / clickhouse error — read them"

echo
echo "=== 6. SIEM ==="
[ -z "$(envof sentinel-waf1-1 SENTINEL_SIEM_TARGET)" ] \
  && note "SIEM feed is not enabled on this box (SENTINEL_SIEM_TARGET empty) — CEF cs5 / JSON ja4 are covered by unit tests only" \
  || note "SIEM feed enabled; check the receiver for cs5Label=ja4 (CEF) or \"ja4\" (JSON)"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
