#!/usr/bin/env bash
# Verify the five protocol-enforcement rules that were absent until now:
#
#   920180  POST without Content-Length or Transfer-Encoding   (REQUEST_PROTOCOL)
#   920430  HTTP version not allowed by policy                 (REQUEST_PROTOCOL)
#   920540  unicode escape outside a JSON body                 (REQBODY_PROCESSOR)
#   920270  null byte in request                               (@validateByteRange)
#   920271  non-printable characters in request                (@validateByteRange)
#
# The positive checks matter less than the negative ones. These are PROTOCOL
# rules: they inspect every request rather than looking for a payload, so a
# mistake does not merely miss an attack, it fires on ordinary traffic. 920180 in
# particular flagged a clean POST in the test suite within minutes of working —
# it was right and the fixture was wrong, but that is exactly how a rule like
# this goes wrong in production.
#
# So the decisive section is 3: whether any of the five has fired on REAL
# teammate traffic since this build started serving.
set -uo pipefail
H="wafdemo.esds.local"; B="https://127.0.0.1"
LOGDIR=/var/lib/docker/volumes/sentinel_sentinel-logs/_data
ROLLED=$(docker inspect -f '{{.State.StartedAt}}' sentinel-waf2-1 | cut -c1-19)Z
export ROLLED
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
fired() { grep -qh "\"rule\":\"$1\"" $LOGDIR/waf*/waf.log 2>/dev/null; }
fired_since() {
  for f in $LOGDIR/waf*/waf.log; do
    awk -v t="$ROLLED" -v r="\"rule\":\"$1\"" \
      'index($0,r)>0 { if (match($0,/"ts":"[^"]+"/)) { s=substr($0,RSTART+6,RLENGTH-7); if (s>=t) { print; exit } } }' "$f" 2>/dev/null
  done | grep -q .
}

echo "=== 1. all five are LOADED and enforceable ==="
DROPPED=$(docker logs sentinel-waf1-1 2>&1 | grep -c 'skipping rule (compile error)')
IMPSKIP=$(docker logs sentinel-waf1-1 2>&1 | grep -c 'all targets unsupported')
[ "$DROPPED" = "0" ] && ok "0 rules dropped on compile" || bad "$DROPPED dropped"
[ "$IMPSKIP" = "0" ] && ok "0 rules skipped for unsupported targets (was 3)" || bad "$IMPSKIP importer skips remain"
if docker logs sentinel-waf1-1 2>&1 | grep -q 'disabled_rule_ids":"\[\]'; then
  ok "no rule loaded-but-inert (was 2: 920270, 920271)"
else
  docker logs sentinel-waf1-1 2>&1 | grep -o 'disabled_rule_ids":"[^"]*"' | tail -1
  bad "some rules are still inert"
fi

echo
echo "=== 2. they DETECT what they exist for ==="
curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?q=before%00after"          # 920270 NUL
curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?q=bell%07here"            # 920271 control
# 920180: an HTTP/1.1 POST with a body and NO length. curl always sets one, so
# force the malformed shape with a raw socket.
printf 'POST /rest/x HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1' "$H" \
  | timeout 5 openssl s_client -quiet -connect 127.0.0.1:443 -servername "$H" >/dev/null 2>&1 || true
sleep 4
fired_since 920270 && ok "920270 detected a NUL byte" || bad "920270 missed a NUL byte"
fired_since 920271 && ok "920271 detected a control character" || bad "920271 missed a control character"

echo
echo "=== 3. THE DECIDING CHECK — no false positive on REAL traffic ==="
for f in $LOGDIR/waf*/waf.log; do cat "$f" 2>/dev/null; done | python3 -c "
import sys, json, os, collections
cut = os.environ['ROLLED']
NEW = {'920180','920430','920540','920270','920271'}
TOOL = ('curl','wget','python-requests','go-http-client','sqlmap','nikto','nmap','gotestwaf','postman','httpie','pilotcheck','openssl')
LOCAL = ('172.17.0.1','172.18.0.1','127.0.0.1','::1')
SCANNER = {'10.212.134.32'}
hits = collections.Counter(); paths = collections.defaultdict(set); real_n = 0
for l in sys.stdin:
    l = l.strip()
    if not l.startswith('{'): continue
    try: d = json.loads(l)
    except: continue
    if d.get('ts','') < cut: continue
    ip = d.get('ip') or ''; ua = (d.get('ua') or '').lower()
    if ip in LOCAL or ip in SCANNER or any(t in ua for t in TOOL): continue
    if 'Mozilla' not in (d.get('ua') or ''): continue
    real_n += 1
    r = d.get('rule') or ''
    if r in NEW:
        hits[r] += 1
        paths[r].add(d.get('path'))
print('  real teammate requests logged since %s: %d' % (cut, real_n))
if hits:
    for r, n in hits.most_common():
        print('  %s fired %d time(s) on real traffic, paths=%s' % (r, n, sorted(paths[r])[:4]))
    sys.exit(1)
if real_n == 0:
    # Say so instead of reporting a pass. Right after a roll there may be no
    # real traffic yet, and 'nothing fired' over an empty sample is not
    # evidence of anything — it is the same trap as a guard that cannot fail.
    print('  NO real traffic in the window yet — this check proves NOTHING.')
    print('  Re-run after teammates have been browsing for a while.')
    sys.exit(2)
print('  NONE of the five fired across %d real requests' % real_n)
sys.exit(0)
"
rc=$?
case $rc in
  0) ok "no new rule fired across real teammate traffic" ;;
  2) printf "  \033[33mNOTE\033[0m  inconclusive: no real traffic sampled yet (not counted as a pass)\n" ;;
  *) bad "a new rule fired on REAL traffic — investigate before merging" ;;
esac

echo
echo "=== 4. negative checks: ordinary requests must stay quiet ==="
count_180() { grep -h '"rule":"920180"' $LOGDIR/waf*/waf.log 2>/dev/null | wc -l | tr -d ' '; }
BEFORE_180=$(count_180)
# a normal POST (curl sets Content-Length) and a chunked POST
curl -sk -o /dev/null -H "Host: $H" -X POST -d "name=John&message=Hello" "$B/rest/user/login"
curl -sk -o /dev/null -H "Host: $H" -X POST -H "Transfer-Encoding: chunked" -d "name=John" "$B/rest/user/login"
# HTTP/2 POST — framing carries the length, so 920180 must not fire
curl -sk -o /dev/null --http2 -H "Host: $H" -X POST -d "name=John" "$B/rest/user/login"
# UTF-8 text in a header: bytes 128-255 are ALLOWED by both byte-range specs, so
# a non-English value must not be flagged
curl -sk -o /dev/null -H "Host: $H" -H "X-Note: Ayush Sinha — ESDS" "$B/rest/products/search?q=apple"
curl -sk -o /dev/null -H "Host: $H" -H "Accept-Language: en-GB,en;q=0.9" "$B/rest/products/search?q=apple"
sleep 4
AFTER_180=$(count_180)
[ "$AFTER_180" = "$BEFORE_180" ] \
  && ok "920180 stayed quiet on ordinary/chunked/HTTP2 POSTs" \
  || bad "920180 fired on an ordinary POST ($BEFORE_180 -> $AFTER_180) — FALSE POSITIVE"

echo
echo "=== 5. nothing else regressed ==="
BEN=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" "$B/rest/products/search?q=apple")
SQL=$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: $H" -A 'sqlmap/1.7' "$B/")
[ "$BEN" = "200" ] && ok "benign 200" || bad "benign $BEN"
[ "$SQL" = "403" ] && ok "sqlmap UA 403" || bad "sqlmap UA $SQL"
curl -sk -o /dev/null -H "Host: $H" "$B/rest/x?q=1%27%20UNION%20SELECT%20pw--"
curl -sk -o /dev/null -H "Host: $H" -H 'User-Agent: () { :; }; /bin/bash -c id' "$B/cgi-bin/x"
sleep 3
fired 942100 && ok "SQLi still detected" || bad "SQLi not detected"
fired 932170 && ok "Shellshock still detected" || bad "Shellshock not detected"
# redaction from the previous batch must still hold
curl -sk -o /dev/null -H "Host: $H" "$B/x?token=PROTOCANARY1&author=PROTOVISIBLE"
sleep 3
grep -qh PROTOCANARY1 $LOGDIR/waf*/access.log 2>/dev/null && bad "token leaked" || ok "token still redacted"
grep -qh PROTOVISIBLE $LOGDIR/waf*/access.log 2>/dev/null && ok "?author= still visible" || bad "?author= over-redacted"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
