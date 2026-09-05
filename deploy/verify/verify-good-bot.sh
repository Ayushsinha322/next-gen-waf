#!/usr/bin/env bash
# Is the good-bot allowlist now GATED on reverse-DNS verification, and does a
# genuine crawler's first sight still pass without a challenge?
#
# Run ON the WAF host. Sends probes.
#
# BEFORE: any request whose User-Agent matched a crawler pattern scored 0 and was
# allowed — `curl -A Googlebot` opted out of bot scoring with one header. NOW a
# claim earns the allowlist only when the client IP's PTR sits in the operator's
# published domain AND forward-resolves back. Unverified claims are scored like
# any other client (no bypass, no penalty); contradicted claims are penalised.
#
# The host's docker address (172.18.0.1) has no PTR, so a Googlebot UA from here
# is the UNVERIFIED case — the one every spoofer and every first-sight crawler
# lands in. What this proves: no free pass (the tripwire counter stays 0), the
# lookup happened (counters), and the SEO-safety property (an unverified crawler
# UA passes; a generic bot UA is challenged). The PTR-contradiction path cannot
# be manufactured from this host and rests on the unit tests.
#
# NOTE ON MODE: .71 runs learning mode. A challenge verdict shows as
# action=DETECT (downgraded), a pass as action=PASS.
set -uo pipefail
H="${PROBE_HOST:-wafdemo.esds.local}"
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }
hz() { curl -sk --max-time 8 "https://127.0.0.1:9443/healthz" 2>/dev/null; }
# waf1 only publishes 9443; the probes below go through the LB and may land on
# any node, so counters are SUMMED across the fleet like the other batteries.
node_ips() { for n in waf1 waf2 waf3; do docker inspect "sentinel-$n-1" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | awk '{print $1}'; done; }
hzsum() { local t=0 v; for ip in $(node_ips); do v=$(curl -s --max-time 6 "http://$ip:8080/healthz" 2>/dev/null | PATHSPEC="$1" python3 -c "
import sys,json,os
try: d=json.load(sys.stdin)
except Exception: print(0); raise SystemExit
for k in os.environ['PATHSPEC'].split('.'): d=(d or {}).get(k) if isinstance(d,dict) else None
print(d if isinstance(d,(int,float)) else 0)" 2>/dev/null); t=$((t+${v:-0})); done; echo "$t"; }
LOGDIR="${SENTINEL_LOG_VOLUME:-/var/lib/docker/volumes/sentinel_sentinel-logs/_data}"
action_for() { grep -h "$1" "$LOGDIR"/waf*/access.log 2>/dev/null | tail -1 | python3 -c "import sys,json; l=sys.stdin.readline(); print(json.loads(l).get('action','<none>') if l.strip() else '<no record>')" 2>/dev/null; }

echo "=== 0. prerequisites ==="
case "$(hz)" in
  *'"good_bot"'*) ok "/healthz carries modules.bot.good_bot" ;;
  *) bad "/healthz has no modules.bot.good_bot — the running image predates this change"; echo "=== RESULT: $pass passed, $fail failed ==="; exit 1 ;;
esac

# ⚠️ THE VACUOUS-PASS GUARD. The whole bot block is wrapped in
# `if let Some(ref bot_cfg) = site.waf.bot_detection`, so with the key absent
# from the site policy NOTHING below runs and every counter stays 0 — which a
# naive "the tripwire did not advance" check would report as a PASS. That was
# not hypothetical: on .71 `bot_detection` was null in the live config, bot
# scoring had never run on the only site, and a first attempt at a "before"
# baseline read 0 and proved nothing. Refuse to judge rather than pass vacuously.
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
echo "=== 1. THE DECIDING CHECK — a Googlebot UA from an unverifiable address gets NO free pass ==="
TRIP0=$(hzsum modules.bot.good_bot_allowed_unverified)
LOOK0=$(hzsum modules.bot.good_bot.lookups); UNV0=$(hzsum modules.bot.good_bot.unverifiable)
M="gb$$"
for i in 1 2 3; do
  curl -sk -o /dev/null --max-time 10 -H "Host: $H" -H 'Accept: text/html' \
    -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' \
    "https://127.0.0.1/?m=${M}_$i" 2>/dev/null
  sleep 1
done
sleep 4
TRIP1=$(hzsum modules.bot.good_bot_allowed_unverified)
LOOK1=$(hzsum modules.bot.good_bot.lookups); UNV1=$(hzsum modules.bot.good_bot.unverifiable)
echo "    good_bot_allowed_unverified (tripwire): $TRIP0 -> $TRIP1"
echo "    good_bot.lookups: $LOOK0 -> $LOOK1   good_bot.unverifiable: $UNV0 -> $UNV1"
[ "$TRIP1" -eq "$TRIP0" ] \
  && ok "no allowlist was granted to an unverified claim (tripwire unchanged)" \
  || bad "the tripwire advanced by $((TRIP1-TRIP0)): an UNVERIFIED good-bot claim was allowlisted — the bypass is back"
[ "$LOOK1" -gt "$LOOK0" ] \
  && ok "a reverse-DNS lookup was actually attempted for the claim" \
  || bad "no lookup happened — the verifier is not being consulted"
[ "$UNV1" -gt "$UNV0" ] \
  && ok "the claim was recorded as unverifiable (no PTR for this address), not trusted" \
  || note "unverifiable did not advance — if lookups did, the PTR may have resolved; check the cache verdict"

echo
echo "=== 2. SEO safety — an unverified crawler UA passes; a generic bot UA is challenged ==="
# Both lack Accept-Language, like real crawlers. Only the second carries a
# generic bot word WITHOUT a crawler claim.
A1=$(action_for "${M}_3")
MB="gbctl$$"
curl -sk -o /dev/null --max-time 10 -H "Host: $H" -H 'Accept: text/html' -A 'MyCrawlerBot/1.0 (+https://example.test)' "https://127.0.0.1/?m=$MB" 2>/dev/null
sleep 4
A2=$(action_for "$MB")
echo "    Googlebot UA (unverified, first sight): action=$A1"
echo "    generic 'MyCrawlerBot' UA:               action=$A2"
[ "$A1" = "PASS" ] \
  && ok "an unverified crawler claim is allowed on merit — not challenged, not allowlisted" \
  || bad "an unverified Googlebot UA got action=$A1; first-sight crawlers would be challenged once per IP (SEO regression)"
case "$A2" in
  DETECT|BLOCK|CHALLENGE) ok "a generic bot UA is still challenged/scored ($A2) — bot scoring itself is intact" ;;
  *) note "generic bot UA got $A2 — bot-word scoring did not reach a challenge tier on this request" ;;
esac

echo
echo "=== 3. bounded, cached ==="
S=$(hz | python3 -c "import sys,json; g=json.load(sys.stdin)['modules']['bot']['good_bot']; print('inflight_cap=%s cache=%s verified=%s rejected=%s' % (g['max_inflight'], g['cache_entries'], g['verified'], g['rejected']))")
echo "    $S"
note "the PTR-contradiction (spoof) path cannot be manufactured from this host; it is covered by unit tests"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
