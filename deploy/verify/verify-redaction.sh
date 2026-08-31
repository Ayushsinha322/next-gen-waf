#!/usr/bin/env bash
# Final end-to-end proof of the redaction work, run ON .71 against live traffic.
#
# Deliberately checks BOTH directions. Under-redaction leaks a credential;
# over-redaction destroys the payload an operator needs to judge an alert. A
# pass requires both.
set -uo pipefail
H="wafdemo.esds.local"; B="https://127.0.0.1"
LOGDIR=/var/lib/docker/volumes/sentinel_sentinel-logs/_data
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SQLI="ZZ1' UNION SELECT password FROM users--"
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }

echo "=== generating traffic ==="
# 1 credential in query        2 OAuth       3 percent-encoded smuggle
curl -sk -o /dev/null -H "Host: $H" "$B/rest/products/search?q=apple&token=CAN_qt&page=2"
curl -sk -o /dev/null -H "Host: $H" "$B/callback?code=CAN_code&state=CAN_state"
curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?api_key=CAN_ak&%74oken=CAN_pe&q=shoes"
# 4 SEMICOLON separator (was a leak)
curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?a=1;token=CAN_semi;b=2"
# 5 Referer with plain query   6 Referer with SPA FRAGMENT (was a leak)
curl -sk -o /dev/null -H "Host: $H" -H "Referer: https://$H/reset?token=CAN_ref&lang=en" "$B/main.js"
curl -sk -o /dev/null -H "Host: $H" -H "Referer: https://$H/#/reset?token=CAN_frag&lang=en" "$B/polyfills.js"
# 7 author must STAY VISIBLE (WordPress enumeration is an attack to see)
curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?author=CAN_author_visible"
# 8/9 cookie distinction
curl -sk -o /dev/null -H "Host: $H" -H "Cookie: theme=$SQLI"   "$B/rest/products/search?q=apple"
curl -sk -o /dev/null -H "Host: $H" -H "Cookie: session=$SQLI" "$B/rest/products/search?q=apple"
# 10 attack battery — detection must be unchanged
for u in "rest/products/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--" \
         "rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E" \
         "rest/x?file=../../../../etc/passwd" "rest/x?cmd=%3Bcat%20/etc/passwd"; do
  curl -sk -o /dev/null -H "Host: $H" "$B/$u"
done
BEN=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" "$B/rest/products/search?q=apple")
SQLMAP=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" -A "sqlmap/1.7" "$B/")
sleep 5

echo
echo "=== A. credentials must NOT be written (any sink) ==="
for c in CAN_qt CAN_code CAN_state CAN_ak CAN_pe CAN_semi CAN_ref CAN_frag; do
  if grep -qh "$c" $LOGDIR/waf*/access.log $LOGDIR/waf*/waf.log 2>/dev/null; then
    bad "$c LEAKED"
  else ok "$c redacted"; fi
done
if [ "$(docker exec sentinel-clickhouse-1 clickhouse-client -q \
      "SELECT count() FROM sentinel_logs.waf_events WHERE query LIKE '%CAN_%' OR referer LIKE '%CAN_%'" 2>/dev/null)" = "0" ]; then
  ok "ClickHouse 90-day store clean"
else bad "ClickHouse holds a canary"; fi

echo
echo "=== B. evidence must SURVIVE (over-redaction is a failure too) ==="
grep -qh "CAN_author_visible" $LOGDIR/waf*/access.log 2>/dev/null \
  && ok "?author= kept visible (WordPress enumeration stays auditable)" \
  || bad "?author= was redacted — an attack payload was hidden"
grep -qh "ZZ1" $LOGDIR/waf*/waf.log 2>/dev/null \
  && ok "SQLi in an ORDINARY cookie kept its payload" \
  || bad "an ordinary cookie's payload was destroyed"

echo
echo "=== C. security behaviour unchanged ==="
[ "$BEN" = "200" ] && ok "benign 200" || bad "benign returned $BEN"
[ "$SQLMAP" = "403" ] && ok "sqlmap UA still 403" || bad "sqlmap UA returned $SQLMAP"

echo
echo "=== D. what was actually recorded ==="
for f in $LOGDIR/waf*/access.log; do
  awk -v t="$T0" -F'"ts":"' 'NF>1{split($2,a,"\""); if(a[1]>=t) print}' "$f"
done 2>/dev/null | python3 -c "
import sys,json
rows=[]
for l in sys.stdin:
    try: rows.append(json.loads(l))
    except: pass
rows.sort(key=lambda d: d.get('ts',''))
for d in rows:
    q=d.get('query') or ''; r=d.get('referer') or '-'
    if q or r!='-': print('  %-26s q=%-44s ref=%s' % (d.get('path'), q[:44], r[:58]))
"
echo "  --- matches ---"
for f in $LOGDIR/waf*/waf.log; do
  awk -v t="$T0" -F'"ts":"' 'NF>1{split($2,a,"\""); if(a[1]>=t) print}' "$f"
done 2>/dev/null | python3 -c "
import sys,json
rows=[]
for l in sys.stdin:
    try: d=json.loads(l)
    except: continue
    if d.get('rule')!='920350': rows.append(d)
rows.sort(key=lambda d: d.get('ts',''))
for d in rows: print('  rule=%-12s %-7s matched=%r' % (d.get('rule'), d.get('action'), str(d.get('matched'))[:58]))
"
echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
