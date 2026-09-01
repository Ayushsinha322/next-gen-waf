#!/usr/bin/env bash
# Verify the two claims: GeoIP now SAYS when it is not enforcing, and a 502 now
# leaves a log record.
#
# Both were silent before. The GeoIP control was displayed and inert on every
# deployment (no .mmdb has ever shipped), and a 502 produced no access-log line,
# no waf.log entry and no ClickHouse row while /metrics still counted it.
set -uo pipefail
H="wafdemo.esds.local"
LOGDIR=/var/lib/docker/volumes/sentinel_sentinel-logs/_data
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }

echo "=== 1. GeoIP: /healthz now reports configured vs enforced ==="
HZ=$(curl -sk https://127.0.0.1:9443/healthz 2>/dev/null || curl -s http://127.0.0.1:8080/healthz 2>/dev/null)
if [ -z "$HZ" ]; then bad "could not read /healthz"; else
  echo "$HZ" | python3 -c "
import sys, json
d = json.load(sys.stdin)
g = d.get('geoip')
if g is None:
    print('  MISSING'); sys.exit(3)
print('    configured=%s active=%s inert=%d' % (g['configured'], g['active'], len(g['inert'])))
for i in g['inert']:
    print('      inert: site=%s db_present=%s db_path=%s' % (i['site'], i['db_present'], i['db_path']))
sys.exit(0)
" && ok "/healthz publishes a geoip block (was absent entirely)" \
   || bad "/healthz has no geoip block — the gap is still unreportable"
fi

echo
echo "=== 2. GeoIP: is the ERROR emitted when a site wants country filtering? ==="
N=$(docker logs sentinel-waf1-1 2>&1 | grep -c 'COUNTRY FILTERING IS NOT ENFORCED')
if [ "$N" -gt 0 ]; then
  ok "startup ERROR names the consequence ($N occurrence(s))"
  docker logs sentinel-waf1-1 2>&1 | grep -o 'COUNTRY FILTERING IS NOT ENFORCED[^"]*' | head -1 | cut -c1-150 | sed 's/^/    /'
else
  note "no site on this box has country rules configured, so the ERROR path is not exercised — expected here"
fi

echo
echo "=== 3. 502: an unmatched Host must now leave a log record ==="
MARK="fivetwo$$"
BEFORE=$(grep -hc '"status":502' $LOGDIR/waf*/access.log 2>/dev/null | paste -sd+ - | bc 2>/dev/null || echo 0)
# Host: 127.0.0.1 is not one of the site's domains -> no site matches -> 502.
CODE=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: 127.0.0.1" "https://127.0.0.1/$MARK")
echo "    request with an unmatched Host returned: $CODE"
[ "$CODE" = "502" ] && ok "still answers 502 (correct routing behaviour)" || bad "expected 502, got $CODE"
sleep 4
if grep -qh "$MARK" $LOGDIR/waf*/access.log 2>/dev/null; then
  ok "the 502 IS logged in access.log — it was completely invisible before"
  ACC=$(grep -h "$MARK" $LOGDIR/waf*/access.log 2>/dev/null | tail -1)
  echo "$ACC" | python3 -c "
import sys, json
d = json.loads(sys.stdin.readline())
print('    access: status=%s action=%s site=%s' % (d.get('status'), d.get('action'), d.get('site')))
" 
  # The first live run of this check caught two things the unit tests could not:
  # action said PASS on a 502, and there was no waf.log line at all, so the
  # failure REASON existed only in container logs.
  ACT=$(echo "$ACC" | python3 -c "import sys,json;print(json.loads(sys.stdin.readline()).get('action'))")
  [ "$ACT" = "ERROR" ] \
    && ok "action=ERROR, not PASS — a 502 no longer claims the request was served" \
    || bad "action=$ACT on a 502 — filtering by action cannot find gateway failures"

  RID=$(echo "$ACC" | python3 -c "import sys,json;print(json.loads(sys.stdin.readline())['request_id'])")
  if grep -qh "$RID" $LOGDIR/waf*/waf.log 2>/dev/null; then
    ok "a matching waf.log line exists (joined by request_id)"
    grep -h "$RID" $LOGDIR/waf*/waf.log 2>/dev/null | tail -1 | python3 -c "
import sys, json
d = json.loads(sys.stdin.readline())
print('    waf.log: rule=%s attack=%s' % (d.get('rule'), d.get('attack')))
print('    reason : %s' % (d.get('msg') or '<none>')[:110])
"
    REASON=$(grep -h "$RID" $LOGDIR/waf*/waf.log 2>/dev/null | tail -1 \
             | python3 -c "import sys,json;print(json.loads(sys.stdin.readline()).get('msg') or '')")
    [ -n "$REASON" ] \
      && ok "the CAUSE is on a structured record, not only in container logs" \
      || bad "waf.log line has no reason — an operator still has to read container logs"
  else
    bad "no waf.log line for the 502 — the reason lives only in container logs"
  fi
else
  bad "the 502 left NO access-log line — still invisible"
fi
AFTER=$(grep -hc '"status":502' $LOGDIR/waf*/access.log 2>/dev/null | paste -sd+ - | bc 2>/dev/null || echo 0)
echo "    access-log lines with status 502: $BEFORE -> $AFTER"

echo
echo "=== 4. nothing regressed ==="
echo "    benign=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" https://127.0.0.1/)  sqlmap=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" -A 'sqlmap/1.7' https://127.0.0.1/)"
B=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" https://127.0.0.1/)
S=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" -A 'sqlmap/1.7' https://127.0.0.1/)
[ "$B" = "200" ] && ok "benign 200" || bad "benign $B"
[ "$S" = "403" ] && ok "sqlmap 403" || bad "sqlmap $S"
curl -sk -o /dev/null -H "Host: $H" "https://127.0.0.1/rest/x?q=1%27%20UNION%20SELECT%20pw--"
sleep 3
grep -qh '"rule":"942100"' $LOGDIR/waf*/waf.log 2>/dev/null && ok "SQLi still detected" || bad "SQLi not detected"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
