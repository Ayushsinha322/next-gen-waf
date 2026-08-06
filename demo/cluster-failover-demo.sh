#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Sentinel WAF — Raft cluster leader-failover demo
#
# Shows: a 3-node control-plane Raft cluster elects a leader; when the leader
# node is turned off, a surviving node becomes leader within ~0.5s, and the WAF
# keeps protecting traffic throughout.
#
# Run on the deployment VM from /opt/sentinel-src:
#   bash demo/cluster-failover-demo.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose -f deploy/docker/compose.prod.yml -f deploy/docker/compose.cluster.yml"
NODES=(sentinel-controlplane-1 sentinel-cp2-1 sentinel-cp3-1)
HOST_HDR="Host: localhost"
SQLI="http://127.0.0.1/?a=1%27%20OR%20%271%27=%271"
BENIGN="http://127.0.0.1/"

bar() { printf '─%.0s' {1..70}; echo; }
step() { echo; bar; echo "▶ $*"; bar; }

nname() { echo "$1" | sed -E 's/^sentinel-//; s/-1$//'; }

running() { docker ps --format '{{.Names}}' | grep -qx "$1"; }
count_leaderships() { docker logs "$1" 2>&1 | grep -ciE "becoming leader"; }
# Highest raft term at which this node announced leadership (0 = never).
lead_term() {
  local t
  t=$(docker logs "$1" 2>&1 | grep -iE "becoming leader" | grep -oE '"term": *[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1)
  echo "${t:-0}"
}
# The current leader = the running node with the highest leadership term (Raft
# guarantees at most one leader per term, and terms only increase).
find_leader() {
  local best="" bestt=-1 t
  for n in "${NODES[@]}"; do
    running "$n" || continue
    t=$(lead_term "$n")
    if [ "$t" -gt "$bestt" ]; then bestt=$t; best=$n; fi
  done
  [ -n "$best" ] && [ "$bestt" -gt 0 ] && { echo "$best"; return 0; }
  return 1
}
leader_term() { echo "term $(lead_term "$1")"; }

waf() { curl -s -o /dev/null -w "%{http_code}" --max-time 4 -H "$HOST_HDR" "$1"; }

show_roles() {
  local ldr; ldr=$(find_leader || true)
  for n in "${NODES[@]}"; do
    if ! running "$n"; then
      printf "   %-14s %s\n" "$(nname "$n")" "(stopped)"
    elif [ "$n" = "$ldr" ]; then
      printf "   %-14s %s\n" "$(nname "$n")" "LEADER (term $(lead_term "$n"))"
    else
      printf "   %-14s %s\n" "$(nname "$n")" "follower"
    fi
  done
}

# ── 1. Bring up the 3-node cluster ───────────────────────────────────────────
step "1/6  Starting the 3-node Raft control-plane cluster"
$COMPOSE up -d controlplane cp2 cp3 >/dev/null 2>&1
echo "   waiting for leader election (election timeout 400–700ms)…"
sleep 8

# ── 2. Show cluster roles + leader ───────────────────────────────────────────
step "2/6  Cluster state"
show_roles
LEADER=$(find_leader) || { echo "   ✗ no leader found in logs — check 'docker logs sentinel-controlplane-1'"; exit 1; }
echo
echo "   ➜ LEADER is: $(nname "$LEADER")   [$(leader_term "$LEADER")]"

# ── 3. Protection is on ──────────────────────────────────────────────────────
step "3/6  WAF is protecting (before failover)"
echo "   benign  GET /            → $(waf "$BENIGN")   (expect 200)"
echo "   SQLi    GET /?a=1' OR..  → $(waf "$SQLI")   (expect 403)"

# ── 4. Turn off the leader ───────────────────────────────────────────────────
step "4/6  Turning OFF the leader node: $(nname "$LEADER")"
declare -A BASE
for n in "${NODES[@]}"; do [ "$n" != "$LEADER" ] && BASE[$n]=$(count_leaderships "$n"); done
T0=$(date +%s.%N)
docker stop "$LEADER" >/dev/null 2>&1
echo "   stopped $(nname "$LEADER") — watching survivors for a new leader…"

# ── 5. A survivor takes over ─────────────────────────────────────────────────
NEWLEADER=""
for _ in $(seq 1 100); do   # up to ~10s
  for n in "${NODES[@]}"; do
    [ "$n" = "$LEADER" ] && continue
    if [ "$(count_leaderships "$n")" -gt "${BASE[$n]:-0}" ]; then NEWLEADER="$n"; break; fi
  done
  [ -n "$NEWLEADER" ] && break
  sleep 0.1
done
T1=$(date +%s.%N)
step "5/6  Failover result"
if [ -n "$NEWLEADER" ]; then
  MS=$(awk "BEGIN{printf \"%.0f\", ($T1-$T0)*1000}")
  printf "   ✓ NEW LEADER: %s  (took over in %s ms)\n" "$(nname "$NEWLEADER")" "$MS"
  echo "     [$(leader_term "$NEWLEADER")]"
  echo; show_roles
else
  echo "   ✗ no new leader detected within 10s"
fi

# ── 6. Protection continues ──────────────────────────────────────────────────
step "6/6  WAF still protecting (after failover)"
echo "   benign  GET /            → $(waf "$BENIGN")   (expect 200)"
echo "   SQLi    GET /?a=1' OR..  → $(waf "$SQLI")   (expect 403)"

# ── restore ──────────────────────────────────────────────────────────────────
step "Restoring the cluster (restarting $(nname "$LEADER"))"
docker start "$LEADER" >/dev/null 2>&1
sleep 4
show_roles
echo
echo "Demo complete. To reset to a single control plane:"
echo "  docker compose -f deploy/docker/compose.prod.yml up -d controlplane && docker rm -f sentinel-cp2-1 sentinel-cp3-1"
