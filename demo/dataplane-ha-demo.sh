#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Sentinel WAF — Data-plane HA demo (active-active fleet + load balancer)
#
# Shows: 3 WAF proxy nodes serve traffic together behind a load balancer. Turn
# off WAF nodes one by one — the load balancer routes around them in ~1s and
# legitimate traffic keeps flowing with ZERO dropped requests, while attacks stay
# blocked. This is the cloud-WAF model (stateless fleet + LB), which beats an
# active/standby appliance pair (idle standby, no horizontal scale).
#
# Run on the VM from /opt/sentinel-src:  bash demo/dataplane-ha-demo.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose -f deploy/docker/compose.prod.yml -f deploy/docker/compose.ha.yml"
STATS="http://127.0.0.1:8404/stats;csv"
H="Host: localhost"
SQLI="http://127.0.0.1/?a=1%27%20OR%20%271%27=%271"
BENIGN="http://127.0.0.1/"
LOOPLOG=$(mktemp)

bar(){ printf '─%.0s' {1..70}; echo; }
step(){ echo; bar; echo "▶ $*"; bar; }
code(){ curl -s -o /dev/null -w '%{http_code}' --max-time 3 -H "$H" "$1"; }

fleet_health(){
  local csv; csv=$(curl -s "$STATS" 2>/dev/null)
  for n in waf1 waf2 waf3; do
    printf "   %-6s %s\n" "$n" "$(echo "$csv" | awk -F, -v s="$n" '$1=="waf_fleet"&&$2==s{print $18}')"
  done
}
up_count(){ curl -s "$STATS" 2>/dev/null | awk -F, '$1=="waf_fleet"&&$2~/^waf[0-9]/&&$18=="UP"{c++} END{print c+0}'; }

# Benign availability loop: hammer the LB with legitimate traffic and record
# every status code. (Benign only — mixing a flood of attacks would trip the
# WAF's own repeat-offender defence and block this single source IP, which is
# correct behaviour but would muddy the availability measurement.)
start_loop(){ ( while :; do printf '%s\n' "$(code "$BENIGN")" >>"$LOOPLOG"; sleep 0.08; done ) & LOOP_PID=$!; }
stop_loop(){ kill "$LOOP_PID" 2>/dev/null; wait "$LOOP_PID" 2>/dev/null; }
loop_report(){
  local total ok fail
  total=$(wc -l <"$LOOPLOG"); ok=$(grep -c '^200' "$LOOPLOG"); fail=$(grep -cv '^200' "$LOOPLOG")
  echo "   legitimate requests sent : $total"
  echo "   succeeded (200)          : $ok"
  echo "   DROPPED (5xx/timeout)    : $fail"
}

# ── 1. Start the fleet + LB ──────────────────────────────────────────────────
step "1/6  Starting the active-active WAF fleet (3 nodes) + load balancer"
docker stop sentinel-dataplane-1 >/dev/null 2>&1     # free :80 for the LB
$COMPOSE up -d waf1 waf2 waf3 lb >/dev/null 2>&1
echo "   waiting for all 3 nodes to be READY (config synced, health check green)…"
for _ in $(seq 1 60); do [ "$(up_count)" = "3" ] && break; sleep 1; done
# The health check goes green when sites sync; the rule engines finish compiling
# (~1500 CRS rules) a moment later. Small settle so protection is fully active.
for _ in $(seq 1 20); do [ "$(code "$SQLI")" = "403" ] && break; sleep 1; done

# ── 2. Fleet health ──────────────────────────────────────────────────────────
step "2/6  Fleet health (via the load balancer)"
fleet_health
echo "   ➜ $(up_count)/3 WAF nodes serving traffic (all active)"

# ── 3. Protection is on ──────────────────────────────────────────────────────
step "3/6  WAF is protecting (through the load balancer)"
echo "   benign  GET /            → $(code "$BENIGN")   (expect 200)"
echo "   SQLi    GET /?a=1' OR..  → $(code "$SQLI")   (expect 403 — blocked)"

# ── 4. Live legitimate traffic running — kill a node ─────────────────────────
step "4/6  Legitimate traffic flowing — now TURNING OFF a WAF node"
start_loop
echo "   continuous legitimate traffic is flowing through the LB…"
sleep 2
echo "   ✗ killing waf1"
docker kill sentinel-waf1-1 >/dev/null 2>&1
sleep 3
echo "   fleet now:"; fleet_health

# ── 5. Kill a SECOND node ────────────────────────────────────────────────────
step "5/6  Turning OFF a SECOND node (an active/standby pair would be dead here)"
echo "   ✗ killing waf2"
docker kill sentinel-waf2-1 >/dev/null 2>&1
sleep 3
echo "   fleet now:"; fleet_health
echo "   attack through LB (only waf3 left) → $(code "$SQLI")   (expect 403 — still blocked)"

# ── 6. Report + recover ──────────────────────────────────────────────────────
step "6/6  Zero-downtime report (whole time 2 of 3 nodes were killed)"
sleep 1
stop_loop
loop_report
rm -f "$LOOPLOG"
echo
echo "   bringing the 2 killed nodes back…"
$COMPOSE up -d waf1 waf2 waf3 >/dev/null 2>&1
for _ in $(seq 1 60); do [ "$(up_count)" = "3" ] && break; sleep 1; done
fleet_health

step "Restore: back to the single-node data plane on :80"
$COMPOSE stop waf1 waf2 waf3 lb >/dev/null 2>&1
$COMPOSE rm -f waf1 waf2 waf3 lb >/dev/null 2>&1
docker compose -f deploy/docker/compose.prod.yml up -d dataplane >/dev/null 2>&1
echo "   single-node data plane restarted."
echo; echo "Demo complete."
