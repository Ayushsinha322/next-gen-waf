#!/usr/bin/env bash
# =============================================================================
#  Replace the WAF fleet ONE NODE AT A TIME, never leaving the balancer empty.
#
#  THE BUG THIS EXISTS TO PREVENT
#
#  The documented upgrade step is `docker compose -f compose.prod.yml up -d`.
#  Compose recreates every changed service at once, so all three WAF nodes stop
#  together. Measured on the deploy VM (2026-09-11, from the balancer's own log):
#
#      10:22:18  waf1, waf2, waf3 all DOWN — "0 active and 0 backup servers left"
#      10:22:32  waf1 UP
#
#  Fourteen seconds during which every request to the protected site got a 503
#  from the balancer. The product documentation claims "zero-downtime updates …
#  verified by rolling the full fleet with zero restarts", and the data plane
#  really does implement a bounded graceful drain — but the documented procedure
#  never gave the drain anything to drain INTO, because no node was left.
#
#  This script rolls one node, waits for the balancer to call it ready again,
#  and only then touches the next. It refuses to take a node out while it is the
#  last one standing.
#
#  Pair this with the matching haproxy.cfg change: the health check now polls
#  /readyz (drain-aware) instead of /healthz (liveness, which keeps answering
#  while a node is shutting down). Rolling one at a time without that change
#  still drops the in-flight requests on the node being replaced.
#
#  USAGE
#
#      ./rolling-update.sh                 # roll the data plane, then the
#                                          # control plane, then the dashboard
#      ./rolling-update.sh --check         # report whether a safe roll is
#                                          # possible; change nothing
#      ./rolling-update.sh waf2            # roll just these services
#
#      COMPOSE_FILES="-f compose.prod.yml -f compose.ha.yml" ./rolling-update.sh
#      STATS_URL=http://127.0.0.1:8404/stats  ./rolling-update.sh
#      STATS_CMD='echo "show stat" | socat stdio /var/run/haproxy.sock' \
#        ./rolling-update.sh          # stats over a unix socket instead of HTTP
#
#  The load balancer itself is never rolled here. It is a single process that
#  owns :80 and :443, so replacing it is a real blip however it is done; do that
#  deliberately, in a window, not as a side effect of a version bump.
# =============================================================================
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

COMPOSE_FILES="${COMPOSE_FILES:--f compose.prod.yml -f compose.ha.yml -f compose.cluster.yml}"
STATS_URL="${STATS_URL:-http://127.0.0.1:8404/stats}"
# How long a node may take to come back and be called ready again. A rejoining
# node reports not-ready until it has synced its config from the control plane,
# which is normally ~15s.
READY_TIMEOUT="${READY_TIMEOUT:-120}"
CHECK_ONLY=0

ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$1"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$R" "$1"; }
note() { printf '  %s%s%s\n' "$DIM" "$1" "$R"; }
hdr()  { printf '\n%s%s==> %s%s\n\n' "$B" "$YEL" "$1" "$R"; }

args=()
for a in "$@"; do
  case "$a" in
    --check) CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) args+=("$a") ;;
  esac
done

dc() { docker compose $COMPOSE_FILES "$@"; }

# ── the balancer's own view ─────────────────────────────────────────────────
# HAProxy's CSV is the authority on whether a node is taking traffic. Container
# health is not: a container can be "healthy" to Docker while the balancer still
# has it DOWN, and acting on the wrong one is how a roll walks off a cliff.
#
# Fields are located BY NAME from the header row rather than by position —
# HAProxy has added columns across versions, and a hard-coded index silently
# starts reading a different column after an image bump.
#
# STATS_CMD overrides HOW the CSV is obtained. Two real reasons, not just tests:
# a deployment whose stats live on a unix socket wants
# `STATS_CMD='echo "show stat" | socat stdio /var/run/haproxy.sock'`, and the
# guard tests feed a fixture with `STATS_CMD='cat fixture.csv'` — the CI image
# is alpine with no python, so standing up a throwaway HTTP server there is not
# an option. A guard that cannot run where it is supposed to run is worse than
# no guard.
stats_csv() {
  if [[ -n "${STATS_CMD:-}" ]]; then
    eval "$STATS_CMD" 2>/dev/null
  else
    curl -fsS --max-time 5 "${STATS_URL};csv" 2>/dev/null
  fi
}

# Print "backend server status" for every server row.
server_states() {
  stats_csv | awk -F, '
    /^# / { for (i = 1; i <= NF; i++) { h = $i; sub(/^# /, "", h); col[h] = i } ; next }
    NF < 2 { next }
    # svname BACKEND/FRONTEND are aggregate rows, not servers.
    $col["svname"] == "BACKEND" || $col["svname"] == "FRONTEND" { next }
    { print $col["pxname"], $col["svname"], $col["status"] }
  '
}

# How many servers are UP in the given backend, ignoring one name.
up_count_excluding() {
  local backend="$1" skip="${2:-}"
  server_states | awk -v b="$backend" -v s="$skip" \
    '$1 == b && $2 != s && $3 ~ /^UP/ { n++ } END { print n + 0 }'
}

backends_for() {
  local node="$1"
  server_states | awk -v n="$node" '$2 == n { print $1 }' | sort -u
}

all_backends() { server_states | awk '{ print $1 }' | sort -u; }

node_is_up_everywhere() {
  local node="$1" b
  local seen=0
  while read -r b; do
    [[ -z "$b" ]] && continue
    seen=1
    local st
    st=$(server_states | awk -v bb="$b" -v n="$node" '$1 == bb && $2 == n { print $3 }')
    [[ "$st" =~ ^UP ]] || return 1
  done < <(backends_for "$node")
  (( seen == 1 ))
}

# ── which services are rollable ─────────────────────────────────────────────
# Data-plane nodes are whatever the balancer is actually load-balancing, which
# is the only definition that cannot drift from reality. Falling back to the
# compose service names keeps --check useful on a host with no balancer.
dataplane_nodes() {
  local n
  n=$(server_states | awk '{ print $2 }' | sort -u)
  if [[ -z "$n" ]]; then
    dc config --services 2>/dev/null | grep -E '^waf[0-9]+$' | sort
  else
    printf '%s\n' "$n"
  fi
}

controlplane_nodes() {
  dc config --services 2>/dev/null | grep -E '^(controlplane|cp[0-9]+)$' | sort
}

container_of() { docker compose $COMPOSE_FILES ps -q "$1" 2>/dev/null | head -1; }

container_healthy() {
  local cid; cid=$(container_of "$1")
  [[ -z "$cid" ]] && return 1
  local st
  st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null)
  [[ "$st" == "healthy" || "$st" == "running" ]]
}

# ── preflight ───────────────────────────────────────────────────────────────
hdr "what this deployment looks like"

mapfile -t DP < <(dataplane_nodes)
mapfile -t CP < <(controlplane_nodes)

if ! stats_csv >/dev/null; then
  note "no balancer stats at ${STATS_URL} — cannot observe readiness"
  if (( ${#DP[@]} <= 1 )); then
    bad "single data-plane node and no balancer: a restart IS downtime, by construction"
    note "there is no safe roll to perform here. Add a second node (compose.ha.yml)"
    note "or accept the window and say so in the change record."
    exit 1
  fi
  bad "refusing to roll blind — start the balancer, or set STATS_URL"
  exit 1
fi

printf '  data plane:    %s\n' "${DP[*]:-none}"
printf '  control plane: %s\n' "${CP[*]:-none}"
printf '  backends:      %s\n' "$(all_backends | tr '\n' ' ')"

if (( ${#DP[@]} <= 1 )); then
  bad "only one data-plane node — replacing it is downtime whatever the order"
  note "this is a property of the deployment, not of this script"
  exit 1
fi

fleet_ok=1
for n in "${DP[@]}"; do
  if node_is_up_everywhere "$n"; then ok "$n is UP in every backend"
  else bad "$n is not UP in every backend — fix that before rolling"; fleet_ok=0; fi
done

if (( fleet_ok == 0 )); then
  note "rolling while a node is already down would take the fleet below one"
  exit 1
fi

if (( CHECK_ONLY == 1 )); then
  hdr "check only"
  ok "a one-at-a-time roll is safe right now"
  exit 0
fi

# ── the roll ────────────────────────────────────────────────────────────────
# A sampler runs for the whole roll and records the SMALLEST number of UP
# servers any backend ever had. That is the claim being made — "no request had
# nowhere to go" — so it is measured rather than assumed.
SAMPLE_MIN_FILE=$(mktemp)
echo 999 > "$SAMPLE_MIN_FILE"
sample_loop() {
  while :; do
    local b low=999
    while read -r b; do
      [[ -z "$b" ]] && continue
      local c; c=$(up_count_excluding "$b" "")
      (( c < low )) && low=$c
    done < <(all_backends)
    local prev; prev=$(cat "$SAMPLE_MIN_FILE" 2>/dev/null || echo 999)
    (( low < prev )) && echo "$low" > "$SAMPLE_MIN_FILE"
    sleep 0.2
  done
}
sample_loop & SAMPLER=$!
# Kill BY PID. `pkill -f` has matched this repo's own paths and killed the
# caller three times; never reintroduce it here.
cleanup() { kill "$SAMPLER" 2>/dev/null; rm -f "$SAMPLE_MIN_FILE"; }
trap cleanup EXIT

roll_one() {
  local svc="$1" kind="$2"
  # Never remove the last one standing.
  if [[ "$kind" == "dataplane" ]]; then
    local b
    while read -r b; do
      [[ -z "$b" ]] && continue
      local others; others=$(up_count_excluding "$b" "$svc")
      if (( others < 1 )); then
        bad "refusing to roll $svc — backend $b would be left with no server"
        return 1
      fi
    done < <(backends_for "$svc")
  fi

  printf '  %s…%s replacing %s\n' "$DIM" "$R" "$svc"
  if ! dc up -d --no-deps "$svc" >/dev/null 2>&1; then
    bad "compose could not recreate $svc"
    return 1
  fi

  local waited=0
  while (( waited < READY_TIMEOUT )); do
    if [[ "$kind" == "dataplane" ]]; then
      node_is_up_everywhere "$svc" && { ok "$svc is back and the balancer calls it ready"; return 0; }
    else
      container_healthy "$svc" && { ok "$svc is back and healthy"; return 0; }
    fi
    sleep 1; waited=$((waited + 1))
  done
  bad "$svc did not become ready within ${READY_TIMEOUT}s — stopping here"
  note "the rest of the fleet is untouched and still serving"
  return 1
}

TARGETS=()
if (( ${#args[@]} > 0 )); then
  TARGETS=("${args[@]}")
else
  TARGETS=("${DP[@]}" "${CP[@]}")
  # The dashboard is stateless and not in the traffic path; roll it last so a
  # console reload never races the nodes actually serving requests.
  dc config --services 2>/dev/null | grep -qx dashboard && TARGETS+=(dashboard)
fi

hdr "rolling ${#TARGETS[@]} service(s), one at a time"

failed=0
for svc in "${TARGETS[@]}"; do
  kind="other"
  printf '%s\n' "${DP[@]}" | grep -qx "$svc" && kind="dataplane"
  roll_one "$svc" "$kind" || { failed=1; break; }
done

# ── the claim, measured ─────────────────────────────────────────────────────
sleep 1
MIN=$(cat "$SAMPLE_MIN_FILE" 2>/dev/null || echo 999)
hdr "did any backend ever run out of servers?"

if (( MIN == 999 )); then
  note "no samples collected — cannot make the claim either way"
elif (( MIN < 1 )); then
  bad "a backend reached ZERO available servers during this roll"
  note "requests in that window got a 503 from the balancer. Do not describe"
  note "this deployment as zero-downtime until this reads 1 or more."
  failed=1
else
  ok "every backend kept at least $MIN server(s) throughout"
fi

if (( failed == 0 )); then
  printf '\n  %s✓%s rolled without emptying the pool\n\n' "$GRN" "$R"
  exit 0
fi
printf '\n  %s✗%s roll did not complete cleanly — see above\n\n' "$RED" "$R"
exit 1
