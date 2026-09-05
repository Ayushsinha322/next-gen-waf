#!/usr/bin/env bash
# Is a newly created site inspectable before it is matchable?
#
# Run ON the WAF host. Creates a temporary site and DELETES it again.
#
# THE DEFECT (measured 2026-08-14): the site list and the rule engines are
# published by two different tasks, so a new site was routable before its rules
# were compiled. A SQLi passed with `rule_matches=0, decision=Allow` 1.5 s before
# "rule engine loaded" appeared. A site created directly in BLOCKING mode failed
# open through that window — the one direction a WAF may never fail.
#
# THE TEST reproduces exactly that: create a blocking-mode site, hammer it with a
# SQLi across its creation, and read the sequence of status codes.
#   200 before its engine loads = the bug: forwarded to the origin uninspected.
#   503 then 403                = the fix: refused while warming, then blocked.
# The origin is real (juiceshop:3000), so a pass-through is an unmistakable 200
# rather than an ambiguous error.
#
# ⚠️ WHAT THIS DOES AND DOES NOT ATTRIBUTE. The 503 warming gate that §2
# exercises was introduced in d1d508c, NOT by the commit that adds this script.
# §2 is therefore a REGRESSION check on protection that already exists — it
# proves the gate is intact on the deployed build, not that this commit created
# it. Reporting §2 as evidence for this commit's own change would be a lie.
#
# This commit's own change is twofold, and only the second half is checkable
# here:
#   - the mid-build race (a second sync landing while the engines compile, which
#     let the finishing build clear the warming flag for an already-superseded
#     config). It cannot be triggered deterministically from outside, and is
#     covered by `a_config_change_during_the_build_must_not_clear_warming`,
#     verified to fail when the fix is reverted.
#   - the `inspection` block §0 and §1 read, which makes a site with no engine
#     enumerable instead of visible in one log line.
set -uo pipefail
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }
PSQL="docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -At -c"
DOMAIN="probe-newsite.local"
NAME="probe-newsite"
SQLI="/?id=1%27%20OR%20%271%27%3D%271"

# Only ever restarts the control plane if this script actually CREATED the probe
# site. Without the guard the trap fired on the §0 early exit too, restarting the
# control plane for a run that had changed nothing.
CREATED=0
cleanup() {
  [ "$CREATED" = "1" ] || return 0
  $PSQL "delete from sites where name='$NAME'" >/dev/null 2>&1
  docker compose -p sentinel -f /opt/sentinel-src/deploy/docker/compose.prod.yml \
    -f /opt/sentinel-src/deploy/docker/compose.cluster.yml \
    -f /opt/sentinel-src/deploy/docker/compose.ha.yml \
    up -d --no-deps --force-recreate controlplane >/dev/null 2>&1
}
trap cleanup EXIT

hz() { curl -sk --max-time 8 "https://127.0.0.1:9443/healthz" 2>/dev/null; }

echo "=== 0. the running image has the inspection block ==="
case "$(hz)" in
  *'"inspection"'*) ok "/healthz carries inspection{engines_warming,sites_without_engine}" ;;
  *) bad "no inspection block — the running image predates this change"; echo "=== RESULT: $pass passed, $fail failed ==="; exit 1 ;;
esac

echo
echo "=== 1. healthy baseline ==="
hz | python3 -c "
import sys, json
i = json.load(sys.stdin)['inspection']
print('    engines_warming=%s  sites_without_engine=%s' % (i['engines_warming'], i['sites_without_engine']))
"
W=$(hz | python3 -c "import sys,json;print(json.load(sys.stdin)['inspection']['engines_warming'])")
U=$(hz | python3 -c "import sys,json;print(len(json.load(sys.stdin)['inspection']['sites_without_engine']))")
[ "$W" = "False" ] && ok "not warming at rest" || bad "engines_warming is true at rest — a reload is stuck"
[ "$U" = "0" ] && ok "every site that expects an engine has one" \
  || bad "$U site(s) are being served with NO signature protection (see sites_without_engine)"

echo
echo "=== 2. THE DECIDING CHECK — a blocking-mode site under SQLi across its creation ==="
$PSQL "delete from sites where name='$NAME'" >/dev/null 2>&1
# Clone Juice Shop's policy so the probe gets the same CRS corpus, but force
# BLOCKING — the exact posture the defect report named.
$PSQL "insert into sites (id, tenant_id, name, domains, upstream, waf_policy, status)
       select gen_random_uuid(), tenant_id, '$NAME', ARRAY['$DOMAIN'], upstream,
              jsonb_set(waf_policy, '{mode}', '\"blocking\"'), 'active'
       from sites where name='Juice Shop'" >/dev/null 2>&1
CREATED=1
$PSQL "select name||' mode='||(waf_policy->>'mode') from sites where name='$NAME'" | sed 's/^/    created: /'

PROBE=$(mktemp)
( for _ in $(seq 1 400); do
    C=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 4 -H "Host: $DOMAIN" "https://127.0.0.1$SQLI" 2>/dev/null)
    echo "$(date +%s%3N) $C" >> "$PROBE"
    sleep 0.1
  done ) &
PROBE_PID=$!
sleep 1
# Restart the control plane: bumps the in-memory configVersion so the data plane
# hot-syncs and sees the new site.
docker compose -p sentinel -f /opt/sentinel-src/deploy/docker/compose.prod.yml \
  -f /opt/sentinel-src/deploy/docker/compose.cluster.yml \
  -f /opt/sentinel-src/deploy/docker/compose.ha.yml \
  up -d --no-deps --force-recreate controlplane >/dev/null 2>&1
# Wait for the engine to load for the probe site on any node.
LOADED=""
for _ in $(seq 1 60); do
  LOADED=$(docker logs --since 3m sentinel-waf1-1 2>&1 | grep '"rule engine loaded"' | grep "$NAME" | tail -1)
  [ -n "$LOADED" ] && break
  sleep 2
done
sleep 3
kill $PROBE_PID 2>/dev/null; wait $PROBE_PID 2>/dev/null

if [ -z "$LOADED" ]; then
  note "no 'rule engine loaded' line for $NAME within 2 min — the probe site never compiled"
else
  echo "$LOADED" | python3 -c "import sys,json; print('    engine loaded:', json.loads(sys.stdin.readline())['timestamp'])" 2>/dev/null
fi
LOAD_MS=$(echo "$LOADED" | python3 -c "
import sys, json, datetime
l = sys.stdin.readline().strip()
if not l: print(0); raise SystemExit
try:
    t = json.loads(l)['timestamp'].replace('Z', '+00:00')
    print(int(datetime.datetime.fromisoformat(t).timestamp() * 1000))
except Exception: print(0)
" 2>/dev/null)

echo "    observed status sequence:"
awk '{print $2}' "$PROBE" | uniq -c | awk '{printf "      %sx %s\n", $1, $2}'
N503=$(awk '$2==503' "$PROBE" | wc -l)
N403=$(awk '$2==403' "$PROBE" | wc -l)
EARLY200=$(awk -v L="$LOAD_MS" '$2==200 && L>0 && $1 < L' "$PROBE" | wc -l)

[ "$N503" -gt 0 ] \
  && ok "the warming gate fired (${N503}x 503) — a matchable-but-uninspectable site was REFUSED" \
  || note "no 503 seen: the engine compiled faster than the probe interval, so the window was never sampled"
if [ "$LOAD_MS" -gt 0 ]; then
  [ "$EARLY200" -eq 0 ] \
    && ok "ZERO requests were forwarded to the origin before the engine loaded — no fail-open window" \
    || bad "$EARLY200 SQLi request(s) returned 200 BEFORE the engine loaded — forwarded uninspected, the defect is live"
else
  note "engine-load timestamp unavailable; cannot time-order the 200s"
fi
[ "$N403" -gt 0 ] \
  && ok "once inspected, the SQLi is BLOCKED (${N403}x 403) — the site is genuinely protected, not just refused" \
  || bad "no 403 after the engine loaded: the probe site never actually inspected the SQLi"
rm -f "$PROBE"

echo
echo "=== 3. cleanup ==="
cleanup
sleep 8
UA=$(hz | python3 -c "import sys,json;print(len(json.load(sys.stdin)['inspection']['sites_without_engine']))" 2>/dev/null)
$PSQL "select count(*) from sites where name='$NAME'" | sed 's/^/    probe site rows remaining: /'
[ "${UA:-1}" = "0" ] && ok "back to a clean baseline (no site left without an engine)" \
  || note "sites_without_engine=$UA after cleanup"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
