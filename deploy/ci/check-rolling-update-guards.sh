#!/usr/bin/env bash
# =============================================================================
#  rolling-update.sh must REFUSE to roll when rolling is not safe.
#
#  The script's value is entirely in what it declines to do. A deploy tool that
#  rolls happily is `docker compose up -d` with extra steps; the reason this one
#  exists is that the documented command took all three WAF nodes down together
#  and left the balancer with nothing for 14 seconds.
#
#  So the refusals are what gets tested, against fixture CSVs rather than a live
#  fleet. The interesting states — a node already down, a single-node install, a
#  node healthy in one backend and not the other — are exactly the ones you
#  cannot conveniently arrange on a real box, which is why they were never
#  tested before.
#
#  Fixtures are fed through STATS_CMD, not an HTTP server: the CI image is
#  alpine with no python, and a guard that cannot run where it is meant to run
#  is worse than no guard.
# =============================================================================
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/deploy/docker/rolling-update.sh"
fail=0

[[ -x "$SCRIPT" ]] || { printf '%s✗%s %s is missing or not executable\n' "$RED" "$R" "$SCRIPT"; exit 1; }

# Header row copied from a real HAProxy 2.9 CSV, so the by-name column lookup is
# exercised against the actual layout rather than an idealised one.
HDR='# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chk'

row() { # backend server status
  printf '%s,%s,0,0,0,0,,0,0,0,,0,,0,0,0,0,%s,1,1,0,2\n' "$1" "$2" "$3"
}

# One scenario: build a fixture, run --check against it, compare the exit status.
scenario() {
  local name="$1" want="$2"; shift 2
  local fixture; fixture=$(mktemp)
  { printf '%s\n' "$HDR"; for r in "$@"; do printf '%s\n' "$r"; done; } > "$fixture"

  # `--check` takes the data-plane node list from the balancer, so it never
  # needs compose for that. COMPOSE_FILES points at a file that does not exist,
  # so an accidental compose call fails loudly instead of reaching a real
  # deployment.
  local got=0
  COMPOSE_FILES="-f /nonexistent-compose-for-tests.yml" \
  STATS_CMD="cat '$fixture'" \
    "$SCRIPT" --check >/dev/null 2>&1 || got=$?
  rm -f "$fixture"

  if [[ "$got" == "$want" ]]; then
    printf '  %s✓%s %-52s exit %s\n' "$GRN" "$R" "$name" "$got"
  else
    printf '  %s✗%s %-52s exit %s, wanted %s\n' "$RED" "$R" "$name" "$got" "$want"
    fail=$((fail + 1))
  fi
}

printf '\n%s%s==> rolling-update.sh refuses when a roll is not safe%s\n\n' "$B" "$YEL" "$R"

scenario "healthy three-node fleet is rollable" 0 \
  "$(row waf_fleet waf1 UP)" "$(row waf_fleet waf2 UP)" "$(row waf_fleet waf3 UP)" \
  "$(row waf_fleet BACKEND UP)"

scenario "a node already DOWN blocks the roll" 1 \
  "$(row waf_fleet waf1 UP)" "$(row waf_fleet waf2 DOWN)" "$(row waf_fleet waf3 UP)" \
  "$(row waf_fleet BACKEND UP)"

scenario "single-node deployment is refused" 1 \
  "$(row waf_fleet waf1 UP)" "$(row waf_fleet BACKEND UP)"

scenario "a node in MAINT does not count as ready" 1 \
  "$(row waf_fleet waf1 UP)" "$(row waf_fleet waf2 MAINT)" "$(row waf_fleet waf3 UP)" \
  "$(row waf_fleet BACKEND UP)"

# The two backends are checked independently on purpose: HTTPS is a separate
# tcp-mode backend, and a node can be serving :80 while failing :443.
scenario "UP on one backend, DOWN on the other, is refused" 1 \
  "$(row waf_fleet waf1 UP)" "$(row waf_fleet waf2 UP)" \
  "$(row waf_fleet_tls waf1 UP)" "$(row waf_fleet_tls waf2 DOWN)"

scenario "both backends healthy is rollable" 0 \
  "$(row waf_fleet waf1 UP)" "$(row waf_fleet waf2 UP)" \
  "$(row waf_fleet_tls waf1 UP)" "$(row waf_fleet_tls waf2 UP)"

# "UP 1/2" is HAProxy's rising-but-not-yet-confirmed form. It means the node is
# taking traffic, so it counts.
scenario "a rising node reported as UP 1/2 counts as ready" 0 \
  "$(row waf_fleet waf1 UP)" "$(row waf_fleet waf2 'UP 1/2')" "$(row waf_fleet waf3 UP)"

# The balancer is the authority on the node list. If it reports nothing, the
# script must not fall back to guessing and roll blind.
scenario "empty stats output refuses rather than guessing" 1

printf '\n'
if (( fail == 0 )); then
  printf '  %s✓%s every unsafe state is refused\n\n' "$GRN" "$R"
  exit 0
fi
printf '  %s✗%s %d scenario(s) behaved wrongly\n' "$RED" "$R" "$fail"
printf '      %sa deploy tool that rolls when it should refuse is worse than none%s\n\n' "$DIM" "$R"
exit 1
