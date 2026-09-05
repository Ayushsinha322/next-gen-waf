#!/usr/bin/env bash
# Do HTTP/3 clients now get a JA4 fingerprint, and is the fingerprint real?
#
# Run ON the WAF host. Needs the `ymuski/curl-http3` image (present on .71);
# the system curl has no HTTP3 support.
#
# WHY THIS EXISTS: http3.rs passed a literal `None` fingerprint into the pipeline
# for its entire existence, so bot scoring's malicious-JA4 signal and the JA4
# blocklist were blind to h3 — and Alt-Svc ADVERTISES h3, so a blocklisted client
# could evade by preferring it. The fix decorates quinn's crypto::Session and
# reads the same ClientHello bytes rustls reads.
#
# :443/udp is published on waf1 ONLY (QUIC does not traverse the tcp-mode LB),
# so every h3 connection lands on waf1 and the counters there are the whole
# story — unlike the TCP checks, which must be summed across three nodes.
#
# NOTE ON MODE: .71 runs Juice Shop in LEARNING mode. These checks look at
# counters and log fields, never at a 403.
set -uo pipefail
H="${PROBE_HOST:-wafdemo.esds.local}"
N="${H3_PROBES:-8}"
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }

hz() { curl -sk --max-time 8 "https://127.0.0.1:9443/healthz" 2>/dev/null; }
# waf1 only — see header. python3 is fine here: deploy-shell lints, it does not
# execute (and a comment must never begin with the linter's own name).
h3field() {
  hz | PATHSPEC="modules.ja4.h3.$1" python3 -c "
import sys, json, os
try: d = json.load(sys.stdin)
except Exception: print(''); raise SystemExit
for k in os.environ['PATHSPEC'].split('.'):
    d = (d or {}).get(k) if isinstance(d, dict) else None
print('' if d is None else d)
" 2>/dev/null
}

echo "=== 0. prerequisites ==="
docker image inspect ymuski/curl-http3:latest >/dev/null 2>&1 \
  && ok "curl-http3 image present" \
  || { bad "ymuski/curl-http3 image missing — cannot generate h3 traffic"; echo "=== RESULT: $pass passed, $fail failed ==="; exit 1; }
A0=$(h3field attempts); S0=$(h3field success); X0=$(h3field absent)
if [ -z "$A0" ]; then
  bad "/healthz has no modules.ja4.h3 — the running image predates the h3 fix"
  echo "=== RESULT: $pass passed, $fail failed ==="; exit 1
fi
ok "/healthz carries modules.ja4.h3 (attempts=$A0 success=$S0 absent=$X0)"

echo
echo "=== 1. THE DECIDING CHECK — $N real HTTP/3 handshakes must each yield a fingerprint ==="
VER_OK=0
for i in $(seq 1 "$N"); do
  V=$(docker run --rm --network host ymuski/curl-http3 \
        curl -sk --http3-only --max-time 10 -o /dev/null -w '%{http_version}' \
        -H "Host: $H" "https://127.0.0.1/?h3probe=$i" 2>/dev/null | tail -1)
  [ "$V" = "3" ] && VER_OK=$((VER_OK+1))
done
sleep 3
A1=$(h3field attempts); S1=$(h3field success); X1=$(h3field absent)
DA=$(( A1 - A0 )); DS=$(( S1 - S0 )); DX=$(( X1 - X0 ))
echo "    h3 negotiated on $VER_OK/$N probes"
echo "    ja4.h3 deltas: attempts=+$DA success=+$DS absent=+$DX"
[ "$VER_OK" -eq "$N" ] \
  && ok "every probe negotiated HTTP/3 (not a TCP fallback masquerading as the test)" \
  || bad "only $VER_OK/$N probes negotiated h3 — the remainder prove nothing about h3 JA4"
if [ "$DA" -ge "$VER_OK" ] && [ "$DS" -eq "$DA" ] && [ "$DX" -eq 0 ]; then
  ok "every h3 handshake produced a fingerprint ($DS/$DA) — h3 is no longer JA4-blind"
elif [ "$DA" -eq 0 ]; then
  bad "no h3 attempts counted at all — the decorator is not being reached"
elif [ "$DX" -gt 0 ]; then
  bad "$DX h3 connections completed with NO fingerprint. If absent == attempts, the \
decorator is not installed (quic_server_config lost its wrapper) — check for the ERROR log."
else
  bad "h3 fingerprint coverage is $DS/$DA — a refusal path is firing on real clients"
fi

echo
echo "=== 2. the h3 probes reached the pipeline AS h3 ==="
# The access record carries `protocol` (h1/h2/h3) but NOT the fingerprint itself:
# ctx.tls_fingerprint drives bot scoring and the blocklist and is never written
# to the request log. So the counter in section 1 is the proof the fingerprint
# existed, and this section proves the same requests were seen by the pipeline
# as HTTP/3 rather than as a TCP fallback.
#
# (That absence is a real audit gap — "why was this client scored as sqlmap"
# cannot be answered from the log after the fact. Recorded, not fixed here.)
LOGDIR="${SENTINEL_LOG_VOLUME:-/var/lib/docker/volumes/sentinel_sentinel-logs/_data}"
sleep 2
PROTO=$(grep -h "h3probe=" "$LOGDIR"/waf1/access.log 2>/dev/null | tail -"$N" | python3 -c "
import sys, json, collections
c = collections.Counter()
for l in sys.stdin:
    try: c[json.loads(l).get('protocol')] += 1
    except Exception: pass
print(dict(c))
")
echo "    protocol on the last $N h3probe records: $PROTO"
case "$PROTO" in
  *"'h3': $N"*) ok "all $N probes were processed by the pipeline as HTTP/3" ;;
  *"'h3'"*)     bad "some probes were not seen as h3: $PROTO" ;;
  *)            bad "no h3 records found for the probes — they did not reach the pipeline as h3" ;;
esac
note "the JA4 value itself is not on the access record (only in ctx) — audit gap, see header"

echo
echo "=== 3. TCP fingerprinting is unaffected ==="
T0=$(hz | python3 -c "import sys,json; j=json.load(sys.stdin)['modules']['ja4']; print(j['attempts'], j['success'])")
curl -sk -o /dev/null --max-time 8 -H "Host: $H" https://127.0.0.1/ 2>/dev/null
sleep 2
T1=$(hz | python3 -c "import sys,json; j=json.load(sys.stdin)['modules']['ja4']; print(j['attempts'], j['success'])")
echo "    tcp attempts/success: $T0 -> $T1"
[ "$T1" != "$T0" ] && ok "TCP path still fingerprinting" || note "TCP counters did not move (probe may have landed on waf2/waf3 — expected under the LB)"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
