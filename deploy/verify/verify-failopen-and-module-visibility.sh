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

# ⚠️ COUNTERS ARE PER-NODE, AND TRAFFIC LOAD-BALANCES ACROSS THREE.
#
# The first version of this script read /healthz from waf1 (the only node
# publishing :9443) and probed through the LB on :443. The probe landed on waf2
# or waf3, incremented THEIR counter, and the check reported "the request skipped
# Phase 1 entirely" — a false alarm about a client-selectable bypass, which is
# about the worst thing a verifier can cry wolf about. Same trap as the earlier
# GeoIP verification on this box.
#
# So: read every node directly on its container address and SUM. Each waf
# container serves /healthz on 8080 internally and the host can reach the docker
# network.
#
# python3 is used for parsing because the values are nested JSON and a
# comma-split grep silently mis-read `}`-terminated numbers and booleans as
# missing. That is safe here: the deploy-shell CI job only lints deploy/**/*.sh
# (bash -n plus a static check), it does not EXECUTE them, and this script runs
# on the WAF host where python3 is present. Do not lift this into a script CI
# actually runs.
#
# (And note a line comment must never START with the word that names that static
# checker: it is read as an inline directive, and an unparseable one is an ERROR
# that fails the lint job. Caught by running the linter in the CI image, which is
# the whole reason for doing that before pushing.)
node_ips() {
  for n in waf1 waf2 waf3; do
    docker inspect "sentinel-$n-1" \
      --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
      | awk '{print $1}'
  done
}

# hzsum <dotted.path>  -> sum of that numeric field across all nodes
hzsum() {
  local path="$1" total=0 v
  for ip in $(node_ips); do
    v=$(curl -s --max-time 6 "http://$ip:8080/healthz" 2>/dev/null \
        | PATHSPEC="$path" python3 -c "
import sys, json, os
try: d = json.load(sys.stdin)
except Exception: print(0); raise SystemExit
for k in os.environ['PATHSPEC'].split('.'):
    d = (d or {}).get(k) if isinstance(d, dict) else None
print(d if isinstance(d, (int, float)) else 0)
" 2>/dev/null)
    total=$(( total + ${v:-0} ))
  done
  echo "$total"
}

# hzfield <dotted.path> -> the field from waf1, rendered as JSON (any type)
hzfield() {
  local path="$1"
  curl -sk --max-time 8 "https://127.0.0.1:9443/healthz" 2>/dev/null \
    | PATHSPEC="$path" python3 -c "
import sys, json, os
try: d = json.load(sys.stdin)
except Exception: print(''); raise SystemExit
for k in os.environ['PATHSPEC'].split('.'):
    d = (d or {}).get(k) if isinstance(d, dict) else None
print('' if d is None else (d if isinstance(d, str) else json.dumps(d)))
" 2>/dev/null
}

hz() { curl -sk --max-time 8 "https://127.0.0.1:9443/healthz" 2>/dev/null; }

echo "=== 0. is /healthz reachable, and does it carry the new keys? ==="
BODY=$(hz)
if [ -z "$BODY" ]; then
  bad "/healthz not reachable on waf1:9443 — cannot judge module visibility"
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
BEFORE=$(hzsum modules.smuggling.evaluated)
LONG=$(head -c 9000 /dev/zero | tr '\0' 'a')
CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: $H" \
  "https://127.0.0.1/?pad=$LONG")
sleep 2
AFTER=$(hzsum modules.smuggling.evaluated)
echo "    over-long-URI request -> HTTP $CODE ; smuggling.evaluated (all nodes) $BEFORE -> $AFTER"
if [ "$AFTER" -gt "$BEFORE" ]; then
  ok "desync detection RAN on an over-long-URI request — the bypass is closed"
else
  bad "smuggling.evaluated did not advance across ANY node: the request skipped Phase 1, \
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
# CL+TE ambiguity is what this module actually exists for, and the check that
# matters most: the header-byte arm was just deliberately loosened, so the
# framing arm has to be shown still working.
#
# Asserted on the COUNTER, not on the response text. A CL+TE request is malformed
# at the protocol level and the connection is closed without a body a raw socket
# can reliably read back — the first version of this check reported
# "<no response>" and could not tell "blocked" from "openssl missing". The
# counter is unambiguous, and splitting framing from header rejections is exactly
# why those are two counters.
FRAME_BEFORE=$(hzsum modules.smuggling.rejected_framing)
{ printf 'GET / HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n' "$H"; sleep 2; } \
  | timeout 10 openssl s_client -quiet -connect 127.0.0.1:443 -servername "$H" >/dev/null 2>&1
sleep 2
FRAME_AFTER=$(hzsum modules.smuggling.rejected_framing)
echo "    CL+TE probe: rejected_framing (all nodes) $FRAME_BEFORE -> $FRAME_AFTER"
if [ "${FRAME_AFTER:-0}" -gt "${FRAME_BEFORE:-0}" ]; then
  ok "CL/TE ambiguity is still rejected by the framing checks"
else
  bad "the CL+TE probe did not increment rejected_framing — real desync detection may \
have been lost when the header-byte arm was loosened. This is the regression that \
matters; do not leave it unresolved."
fi
HDR=$(hzsum modules.smuggling.rejected_header)
note "rejected_header total is $HDR — before the fix this arm fired on any non-ASCII \
header byte, so a non-trivial number here on real traffic would mean the false positive \
is back"

echo
echo "=== 4. is global IOC enforcement on, and does it say so? ==="
POLLER=$(hzfield threat_intel.poller)
ACTIVE=$(hzfield threat_intel.active)
ENTRIES=$(hzfield threat_intel.entries)
REASON=$(hzfield threat_intel.inert_reason)
echo "    threat_intel: poller=${POLLER:-?} active=${ACTIVE:-?} entries=${ENTRIES:-?}"
if [ -n "$POLLER" ]; then
  ok "threat-intel state is reportable (was absent from /healthz entirely)"
  if [ "$ACTIVE" = "true" ]; then
    ok "IOCs are being enforced ($ENTRIES indicators)"
  else
    note "IOC enforcement is OFF: ${REASON:-no reason given} — the field exists so this \
is answerable, which it was not before"
  fi
else
  bad "no threat_intel.poller in /healthz"
fi

echo
echo "=== 5. module reachability, the question their silence hid ==="
SM=$(hzsum modules.smuggling.evaluated)
GQ=$(hzsum modules.graphql.inspected)
GR=$(hzsum modules.grpc.inspected)
JA=$(hzsum modules.ja4.attempts)
JS=$(hzsum modules.ja4.success)
GB=$(hzsum modules.bot.good_bot_allowed_unverified)
BJ=$(hzfield modules.bot.ja4_fingerprints)
AP=$(hzfield modules.bot.attacker_ua_patterns)
printf "    fleet totals: smuggling.evaluated=%s graphql.inspected=%s grpc.inspected=%s\n" "$SM" "$GQ" "$GR"
printf "    ja4: %s/%s handshakes fingerprinted   good-bot allowed (unverified)=%s\n" "$JS" "$JA" "$GB"
printf "    bot tables: ja4_fingerprints=%s attacker_ua_patterns=%s\n" "${BJ:-?}" "${AP:-?}"

[ "${SM:-0}" -gt 0 ] \
  && ok "desync detection is demonstrably running across the fleet" \
  || bad "smuggling.evaluated is 0 fleet-wide — the control never runs"

if [ -n "$BJ" ] && [ "$BJ" -gt 0 ]; then
  note "the JA4 blocklist holds $BJ fingerprints — a static built-in demo table, and \
runtime additions are discarded on config reload. Readable now; still a product gap."
else
  bad "modules.bot.ja4_fingerprints missing or zero"
fi

if [ "${JA:-0}" -gt 0 ]; then
  if [ "${JS:-0}" -lt "${JA:-0}" ]; then
    note "$(( JA - JS )) of $JA TLS handshakes produced NO JA4 fingerprint. Every \
JA4-dependent control (bot scoring's malicious-JA4 signal, JA4 blocklists) is inert for \
those connections. This ratio was uncomputable before these counters existed."
  else
    ok "every TLS handshake yielded a JA4 fingerprint"
  fi
else
  note "no JA4 attempts recorded (plaintext traffic only)"
fi

[ "${GQ:-0}" -eq 0 ] \
  && note "graphql.inspected is 0 — expected on this box (no GraphQL site configured); \
on a site that HAS graphql enabled, a persistent 0 means the endpoint gate does not match" \
  || ok "the GraphQL firewall has inspected $GQ bodies"

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
