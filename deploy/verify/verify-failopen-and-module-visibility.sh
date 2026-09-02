#!/usr/bin/env bash
# Can a client still opt itself out of Phase-1 protection, and can each module
# now say whether it ran?
#
# Run ON the WAF host. Sends probes; safe to re-run.
#
# THE TWO DEFECTS THIS PROVES FIXED, both verified live before the fix:
#
#   1. A URI longer than max_uri_length was downgraded to WafDecision::Log by
#      learning mode, and every Phase-1 check was gated on `== Allow`. So one
#      long URI switched off smuggling, bot, GeoIP, rate-limit, JWT, gRPC, the
#      rule engine and the plugins — chosen by the client. Measured before:
#      a UTF-8 header alone -> 400, the same request with a 9000-byte URI -> 200.
#
#   2. A non-ASCII header value was reported as "HTTP request smuggling: invalid
#      UTF-8" and HARD-BLOCKED with 400 on a site configured only to observe,
#      with the internal reason returned verbatim in the body. That is a false
#      positive on ordinary traffic (an accented Referer, cookie or filename)
#      during a soak an operator was told was non-disruptive.
#
# NOTE ON MODE: .71 runs Juice Shop in LEARNING mode for the false-positive
# pilot. Rule hits are recorded with action=DETECT and served 200. These checks
# look for RECORDS and COUNTERS, never for a 403 — asserting a block here would
# fail on a healthy box.
set -uo pipefail
H="${PROBE_HOST:-wafdemo.esds.local}"
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }

# /healthz is served on the management port, per node.
HZ="https://127.0.0.1:9443/healthz"
hz() { curl -sk --max-time 8 "$HZ" 2>/dev/null; }
# Read a dotted path out of /healthz without python (kept awk/grep-only so this
# is safe to lift into the alpine CI image, which has no python3).
hzval() { hz | tr ',' '\n' | grep -m1 "\"$1\"" | grep -oE '[0-9]+$'; }

echo "=== 0. is /healthz reachable, and does it carry the new keys? ==="
BODY=$(hz)
if [ -z "$BODY" ]; then
  bad "/healthz not reachable at $HZ — cannot judge module visibility"
else
  for key in threat_intel modules smuggling graphql ja4 good_bot_allowed_unverified; do
    case "$BODY" in
      *"\"$key\""*) ok "/healthz carries \"$key\"" ;;
      *) bad "/healthz is missing \"$key\" — the running image predates this change" ;;
    esac
  done
fi

echo
echo "=== 1. THE DECIDING CHECK — a long URI must NOT exempt a request ==="
echo "    (smuggling.evaluated must advance for a request whose URI exceeds the limit)"
BEFORE=$(hzval evaluated)
LONG=$(head -c 9000 /dev/zero | tr '\0' 'a')
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: $H" \
  "https://127.0.0.1/?pad=$LONG")
sleep 2
AFTER=$(hzval evaluated)
echo "    over-long-URI request -> HTTP $CODE ; smuggling.evaluated ${BEFORE:-?} -> ${AFTER:-?}"
if [ -z "$BEFORE" ] || [ -z "$AFTER" ]; then
  bad "could not read smuggling.evaluated from /healthz"
elif [ "$AFTER" -gt "$BEFORE" ]; then
  ok "desync detection RAN on an over-long-URI request — the bypass is closed"
else
  bad "smuggling.evaluated did not advance: the request skipped Phase 1 entirely, \
which is a client-selectable protection bypass. Do not leave this deployed."
fi

echo
echo "=== 2. a UTF-8 header value is not smuggling, and must not be rejected ==="
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: $H" \
  -H "$(printf 'X-Note: caf\xc3\xa9')" "https://127.0.0.1/")
BODY2=$(curl -sk --max-time 10 -H "Host: $H" -H "$(printf 'X-Note: caf\xc3\xa9')" \
  "https://127.0.0.1/" 2>/dev/null | head -c 200)
echo "    UTF-8 header -> HTTP $CODE"
[ "$CODE" != "400" ] \
  && ok "a non-ASCII header value is no longer treated as a desync attempt" \
  || bad "still 400 — the false positive is live, and it rejects ordinary traffic \
(accented Referer / cookie / filename) on a site configured only to observe"
case "$BODY2" in
  *"request smuggling"*|*"invalid UTF-8"*)
    bad "the response body still leaks the internal block reason: $BODY2" ;;
  *) ok "no internal block reason leaked to the client" ;;
esac

echo
echo "=== 3. the real desync primitive must STILL be blocked ==="
# CL+TE ambiguity is what the module exists for. Sent over a raw socket because
# curl refuses to emit both headers.
RAW=$(printf 'GET / HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n' "$H" \
      | timeout 8 openssl s_client -quiet -connect 127.0.0.1:443 -servername "$H" 2>/dev/null | head -1)
echo "    CL+TE request -> ${RAW:-<no response>}"
case "$RAW" in
  *400*) ok "CL/TE ambiguity is still rejected" ;;
  "")    note "no response captured — openssl may be unavailable; check manually" ;;
  *)     bad "CL+TE was NOT rejected: $RAW" ;;
esac

echo
echo "=== 4. is global IOC enforcement on, and does it say so? ==="
POLLER=$(hz | tr ',' '\n' | grep -m1 '"poller"' | sed 's/.*: *//;s/"//g')
ACTIVE=$(hz | tr ',' '\n' | grep -m1 '"active"' | sed 's/.*: *//;s/[^a-z]//g')
ENTRIES=$(hz | tr ',' '\n' | grep -m1 '"entries"' | grep -oE '[0-9]+$')
echo "    threat_intel: poller=${POLLER:-?} active=${ACTIVE:-?} entries=${ENTRIES:-?}"
if [ -n "$POLLER" ]; then
  ok "threat-intel state is reportable (was absent from /healthz entirely)"
  [ "$ACTIVE" = "true" ] \
    && ok "IOCs are being enforced ($ENTRIES indicators)" \
    || note "IOC enforcement is OFF — read threat_intel.inert_reason; that is the \
point of the field, not necessarily a fault on this box"
else
  bad "no threat_intel.poller in /healthz"
fi

echo
echo "=== 5. module reachability, the question their silence hid ==="
for k in evaluated inspected attempts; do
  v=$(hzval "$k"); printf "    %-12s %s\n" "$k" "${v:-?}"
done
JA4A=$(hz | tr ',' '\n' | grep -m1 '"attempts"' | grep -oE '[0-9]+$')
JA4S=$(hz | tr ',' '\n' | grep -m1 '"success"' | grep -oE '[0-9]+$')
echo "    ja4: attempts=${JA4A:-?} success=${JA4S:-?}"
if [ -n "$JA4A" ] && [ -n "$JA4S" ] && [ "$JA4A" -gt 0 ]; then
  if [ "$JA4S" -lt "$JA4A" ]; then
    note "$((JA4A - JA4S)) of $JA4A TLS handshakes yielded no JA4 — that shortfall \
silently disables every JA4-dependent control for those connections"
  else
    ok "every TLS handshake yielded a JA4 fingerprint"
  fi
else
  note "no JA4 attempts recorded yet (plaintext traffic only, or an old image)"
fi
BOTJA4=$(hz | tr ',' '\n' | grep -m1 '"ja4_fingerprints"' | grep -oE '[0-9]+$')
[ -n "$BOTJA4" ] \
  && note "bot JA4 table holds ${BOTJA4} fingerprints — a static built-in demo set; \
runtime additions are discarded on config reload" \
  || bad "modules.bot.ja4_fingerprints missing"

echo
echo "=== 6. existing protection is unchanged ==="
M="foa$$"
for q in "1'+OR+'1'='1" "%3Cscript%3Ealert(1)%3C/script%3E" "../../../../etc/passwd"; do
  curl -sk -o /dev/null --max-time 8 -H "Host: $H" "https://127.0.0.1/?m=$M&q=$q"
done
sleep 4
LOGDIR="${SENTINEL_LOG_VOLUME:-/var/lib/docker/volumes/sentinel_sentinel-logs/_data}"
HITS=$(grep -h "$M" "$LOGDIR"/waf*/waf.log 2>/dev/null | grep -cE '"rule":"(94[12]|930)[0-9]{3}"' || true)
echo "    SQLi/XSS/traversal rule records: $HITS"
[ "$HITS" -ge 2 ] \
  && ok "core attack detection unchanged" \
  || bad "core attack detection regressed — only $HITS records"
SQLMAP=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $H" -A 'sqlmap/1.7' https://127.0.0.1/)
echo "    sqlmap UA -> $SQLMAP"
[ "$SQLMAP" = "403" ] \
  && ok "threat-intel/UA blocking still enforces over HTTPS" \
  || bad "sqlmap UA returned $SQLMAP, expected 403"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
