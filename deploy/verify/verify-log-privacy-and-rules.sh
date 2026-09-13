#!/usr/bin/env bash
# Verify this morning's four fixes on .71, with real traffic.
#
# Compiling is not detecting and delivering is not enforcing, so each fix is
# checked by its observable effect, not by the presence of its code.
set -uo pipefail
H="wafdemo.esds.local"; B="https://127.0.0.1"
LOGDIR=/var/lib/docker/volumes/sentinel_sentinel-logs/_data
pass=0; fail=0
ok()  { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }

echo "=== 1. the six CRS rules now load ==="
SKIPPED=$(docker logs sentinel-waf1-1 2>&1 | grep -c 'skipping rule (compile error)')
[ "$SKIPPED" = "0" ] && ok "no rule dropped at compile time (was 6)" \
                     || bad "$SKIPPED rule(s) still dropped"
# and they are actually reachable: Shellshock in a header must be DETECTED
curl -sk -o /dev/null -H "Host: $H" -H 'User-Agent: () { :; }; /bin/bash -c id' "$B/cgi-bin/x"
curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?tpl=%7B%7B7*7%7D%7D"
curl -sk -o /dev/null -H "Host: $H" "$B/rest/y?u=O%3A4%3A%22User%22%3A1%3A%7Bs%3A5%3A%22a%22%3Bb%3A1%3B%7D"
sleep 4
for r in 932170 941380 933170; do
  if grep -qh "\"rule\":\"$r\"" $LOGDIR/waf*/waf.log 2>/dev/null; then
    ok "rule $r fired on its attack (was absent entirely)"
  else bad "rule $r loaded but did not fire"; fi
done

echo
echo "=== 2. ACME no longer errors hourly for un-issuable names ==="
ERRS=$(docker logs --since 5m sentinel-waf1-1 2>&1 | grep -c 'ACME renewal failed')
[ "$ERRS" = "0" ] && ok "no ACME renewal errors since restart" || bad "$ERRS ACME errors"
# Captured, not piped: `grep -q` exits on its first match, `docker logs` dies on
# SIGPIPE with 141, and pipefail then makes the pipeline non-zero — so a warning
# that IS present would read as absent and this check would report the wrong
# branch. See deploy/ci/check-pipefail-grep.sh.
acmelog=$(docker logs sentinel-waf1-1 2>&1 || true)
if grep -q 'none of its domains can be' <<<"$acmelog"; then
  ok "logged ONE warning naming the misconfiguration instead"
else
  printf "  \033[33mNOTE\033[0m  the skip warning appears on the first hourly tick, not at boot\n"
fi

echo
echo "=== 3. framework session cookies are redacted ==="
curl -sk -o /dev/null -H "Host: $H" \
  -H "Cookie: PHPSESSID=CAN_php_sess_value; connect.sid=CAN_express_sid; theme=dark" \
  "$B/rest/products/search?q=apple"
curl -sk -o /dev/null -H "Host: $H" "$B/socket.io/?EIO=4&transport=polling&sid=CAN_socketio_sid"
curl -sk -o /dev/null -H "Host: $H" "$B/sso/acs?SAMLResponse=CAN_saml_blob&RelayState=CAN_relay"
curl -sk -o /dev/null -H "Host: $H" "$B/blog?author=CAN_author_visible&page=2"
sleep 4
for c in CAN_php_sess_value CAN_express_sid CAN_socketio_sid CAN_saml_blob CAN_relay; do
  grep -qh "$c" $LOGDIR/waf*/access.log $LOGDIR/waf*/waf.log 2>/dev/null \
    && bad "$c LEAKED" || ok "$c redacted"
done
grep -qh "CAN_author_visible" $LOGDIR/waf*/access.log 2>/dev/null \
  && ok "?author= still visible (enumeration stays auditable)" \
  || bad "?author= was over-redacted"

echo
echo "=== 4. security behaviour unchanged ==="
BEN=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" "$B/rest/products/search?q=apple")
SQL=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" -A 'sqlmap/1.7' "$B/")
[ "$BEN" = "200" ] && ok "benign 200" || bad "benign $BEN"
[ "$SQL" = "403" ] && ok "sqlmap UA 403" || bad "sqlmap UA $SQL"
for f in 942100 941100 930100 930120; do
  curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?q=1%27%20UNION%20SELECT%20pw--" >/dev/null
done
sleep 3
grep -qh '"rule":"942100"' $LOGDIR/waf*/waf.log 2>/dev/null && ok "SQLi still detected" || bad "SQLi not detected"

echo
echo "=== 5. what the log shows SINCE THIS BUILD STARTED SERVING ==="
# Scoped to the current nodes on purpose. Grepping the whole file showed
# pre-roll lines with sid= in the clear and read as a failure of the fix.
ROLLED=$(docker inspect -f '{{.State.StartedAt}}' sentinel-waf2-1 | cut -c1-19)Z
export ROLLED
for f in $LOGDIR/waf*/access.log; do cat "$f" 2>/dev/null; done | python3 -c "
import sys, json, os
cut = os.environ['ROLLED']
rows = []
for l in sys.stdin:
    l = l.strip()
    if not l.startswith('{'): continue
    try: d = json.loads(l)
    except: continue
    if d.get('ts','') < cut: continue
    q = d.get('query') or ''
    if q: rows.append(d)
rows.sort(key=lambda d: d.get('ts',''))
print('  (since %s)' % cut)
for d in rows[-8:]:
    print('  %-26s q=%s' % ((d.get('path') or '')[:26], (d.get('query') or '')[:66]))
"
echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
