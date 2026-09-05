#!/usr/bin/env bash
# Does a crawler User-Agent still buy a free pass, and is a spoofed claim caught?
#
# Run ON the WAF host. Sends probes.
#
# BEFORE: any User-Agent matching one of fourteen crawler patterns scored 0 and
# was allowed — one header opted a client out of bot scoring. Measured on .71
# before the fix: four spoofed Googlebot requests, each score 0, action PASS.
# NOW a claim earns the allowlist only when the client IP's PTR sits in the
# operator's published domain AND forward-resolves back to that IP.
#
# WHAT THIS ENVIRONMENT CAN AND CANNOT SHOW
# The host's docker address (172.18.0.1) HAS a PTR — Docker's embedded DNS
# answers `Waf-21` — which is not in googlebot.com. So a Googlebot claim from
# here is the SPOOFED case: PTR present, contradicts the claim. That is the
# security-relevant path and this battery proves it live.
# The "unknown" path (no PTR at all, or a lookup still in flight) cannot be
# manufactured here, because every address on this network answers PTR. It is
# covered by unit tests, including the SEO-safety property that a real crawler's
# first request from a new address is never challenged.
#
# ⚠️ Verdicts are cached per client IP (rejected for 1h), so on a re-run inside
# that window no NEW lookup happens. Checks below tolerate a cache hit rather
# than demanding an increment — a verifier that only passes on a cold cache is a
# verifier that fails every second run.
#
# NOTE ON MODE: .71 runs learning mode with bot_detection challenge=off, so a
# penalised claim contributes to the anomaly score rather than serving a
# challenge; `action` stays PASS. The counters are the signal, not the action.
set -uo pipefail
H="${PROBE_HOST:-wafdemo.esds.local}"
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }
hz() { curl -sk --max-time 8 "https://127.0.0.1:9443/healthz" 2>/dev/null; }
node_ips() { for n in waf1 waf2 waf3; do docker inspect "sentinel-$n-1" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | awk '{print $1}'; done; }
hzsum() { local t=0 v; for ip in $(node_ips); do v=$(curl -s --max-time 6 "http://$ip:8080/healthz" 2>/dev/null | PATHSPEC="$1" python3 -c "
import sys, json, os
try: d = json.load(sys.stdin)
except Exception: print(0); raise SystemExit
for k in os.environ['PATHSPEC'].split('.'): d = (d or {}).get(k) if isinstance(d, dict) else None
print(d if isinstance(d, (int, float)) else 0)" 2>/dev/null); t=$((t + ${v:-0})); done; echo "$t"; }
LOGDIR="${SENTINEL_LOG_VOLUME:-/var/lib/docker/volumes/sentinel_sentinel-logs/_data}"
action_for() { grep -h "$1" "$LOGDIR"/waf*/access.log 2>/dev/null | tail -1 | python3 -c "import sys,json; l=sys.stdin.readline(); print(json.loads(l).get('action','<none>') if l.strip() else '<no record>')" 2>/dev/null; }

echo "=== 0. prerequisites ==="
case "$(hz)" in
  *'"good_bot"'*) ok "/healthz carries modules.bot.good_bot" ;;
  *) bad "/healthz has no modules.bot.good_bot — the running image predates this change"; echo "=== RESULT: $pass passed, $fail failed ==="; exit 1 ;;
esac
# ⚠️ THE VACUOUS-PASS GUARD. The bot block is wrapped in
# `if let Some(ref bot_cfg) = site.waf.bot_detection`, so with the key absent
# NOTHING below runs, every counter stays 0, and "the grant counter did not
# advance" reads as a triumphant PASS on an empty result. On .71 bot_detection
# WAS null — bot scoring had never run on the only site — and a first attempt at
# a baseline read 0 and proved nothing. Refuse to judge rather than pass vacuously.
CPIP=$(docker inspect sentinel-controlplane-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | awk '{print $1}')
SEC=$(docker inspect sentinel-waf1-1 --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep '^SENTINEL_INTERNAL_SECRET=' | cut -d= -f2-)
BD=$(curl -s --max-time 10 -H "x-sentinel-internal: $SEC" "http://$CPIP:9501/api/v1/internal/config" 2>/dev/null \
  | python3 -c "
import sys, json
try: d = json.load(sys.stdin)
except Exception: print(''); raise SystemExit
print(','.join(s.get('id','?') for s in d.get('sites', []) if (s.get('waf') or {}).get('bot_detection')))
" 2>/dev/null)
if [ -n "$BD" ]; then
  ok "bot_detection is configured on: $BD"
else
  bad "NO site has bot_detection configured — the bot block never runs, so every check \
below would pass on an empty result. Enable it before trusting this battery."
  echo "=== RESULT: $pass passed, $fail failed ==="; exit 1
fi

echo
echo "=== 1. THE DECIDING CHECK — a spoofed crawler claim earns NOTHING and is caught ==="
G0=$(hzsum modules.bot.good_bot_allowlisted)
R0=$(hzsum modules.bot.good_bot.rejected); L0=$(hzsum modules.bot.good_bot.lookups)
M="gb$$"
for i in 1 2 3 4; do
  curl -sk -o /dev/null --max-time 10 -H "Host: $H" -H 'Accept: text/html' \
    -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
    "https://127.0.0.1/?m=${M}_$i" 2>/dev/null
  sleep 1
done
sleep 5
G1=$(hzsum modules.bot.good_bot_allowlisted)
R1=$(hzsum modules.bot.good_bot.rejected); L1=$(hzsum modules.bot.good_bot.lookups)
echo "    good_bot_allowlisted: $G0 -> $G1   rejected: $R0 -> $R1   lookups: $L0 -> $L1"
[ "$G1" -eq "$G0" ] \
  && ok "NO allowlist granted to an unverifiable claim (before the fix this was +4 free passes)" \
  || bad "the allowlist was granted $((G1-G0)) times WITHOUT verification — the bypass is back"
# Cache-tolerant: a fresh verdict OR one already held for this address both prove
# the verifier is consulted; only a total absence of either is a failure.
if [ "$R1" -gt "$R0" ]; then
  ok "the spoofed claim was CAUGHT by reverse DNS ($((R1-R0)) rejected: PTR contradicts the crawler's domain)"
elif [ "$R1" -gt 0 ]; then
  ok "a rejection verdict is held for this address ($R1 total) — cached from an earlier probe, within TTL"
else
  bad "no rejection recorded at all: the verifier is not being consulted, or the PTR unexpectedly matched"
fi
[ "$L1" -gt 0 ] \
  && ok "reverse-DNS verification has run ($L1 lookups)" \
  || bad "zero lookups — the verifier was never invoked"

echo
echo "=== 2. bot scoring itself is intact, and nothing is being hard-blocked ==="
A1=$(action_for "${M}_4")
echo "    spoofed Googlebot request: action=$A1"
case "$A1" in
  PASS|DETECT) ok "served without a hard block ($A1) — learning mode, challenge=off, as configured" ;;
  BLOCK) bad "a spoofed claim was BLOCKED outright; the penalty is meant to reach a challenge tier, not a block" ;;
  *) note "unexpected action=$A1" ;;
esac
note "with challenge=off the penalty raises the anomaly score rather than challenging, so \
`action` cannot distinguish penalised from clean here — §1's counters are the signal"

echo
echo "=== 3. bounded and cached ==="
hz | python3 -c "
import sys, json
g = json.load(sys.stdin)['modules']['bot']
b = g['good_bot']
print('    verified=%s rejected=%s unverifiable=%s cache=%s inflight_cap=%s  allowlisted=%s'
      % (b['verified'], b['rejected'], b['unverifiable'], b['cache_entries'], b['max_inflight'], g['good_bot_allowlisted']))
print('    ja4_fingerprints=%s attacker_ua_patterns=%s good_bot_ua_patterns=%s'
      % (g['ja4_fingerprints'], g['attacker_ua_patterns'], g['good_bot_ua_patterns']))
"
note "the 'unknown' path (no PTR / lookup in flight) cannot be produced here — every \
address on this network answers PTR — so the SEO-safety property that a first-sight \
crawler is never challenged rests on the unit tests"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
