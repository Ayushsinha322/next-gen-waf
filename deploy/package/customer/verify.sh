#!/usr/bin/env bash
# =============================================================================
#  Next-Gen ESDSWAF — post-installation verification
#
#      sudo ./verify.sh
#
#  Every check prints PASS or FAIL with the evidence it used, so a green run is a
#  set of measurements rather than a reassurance. Exit non-zero if anything fails.
#  Safe to run at any time — it reads state, it does not change it.
# =============================================================================
set -uo pipefail

INSTALL_DIR=/opt/sentinel/current
ENV_FILE="$INSTALL_DIR/.env"

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi

PASS=0; FAIL=0; WARN=0
step() { printf '\n%s%s== %s%s\n' "$B" "$CYN" "$*" "$R"; }
pass() { printf '  %sPASS%s  %s\n' "$GRN" "$R" "$*"; PASS=$((PASS+1)); }
bad()  { printf '  %sFAIL%s  %s\n' "$RED" "$R" "$*"; FAIL=$((FAIL+1)); }
soft() { printf '  %sWARN%s  %s\n' "$YEL" "$R" "$*"; WARN=$((WARN+1)); }

[[ $EUID -eq 0 ]] || { echo "run with sudo (reads container state and $ENV_FILE)"; exit 2; }
[[ -f "$ENV_FILE" ]] || { echo "no installation found at $INSTALL_DIR"; exit 2; }
# shellcheck disable=SC1090
VERSION=$(grep -oP '^SENTINEL_VERSION=\K.*' "$ENV_FILE" 2>/dev/null || echo unknown)

printf '\n  %sNext-Gen ESDSWAF — verification%s   version %s\n' "$B" "$R" "$VERSION"

step "Containers"
for c in postgres redis clickhouse controlplane dataplane dashboard; do
  st=$(docker inspect "sentinel-${c}-1" --format '{{.State.Status}}' 2>/dev/null || echo absent)
  case "$st" in
    running) pass "$c is running" ;;
    absent)  bad  "$c container does not exist" ;;
    *)       bad  "$c is '$st'" ;;
  esac
done

step "Backing stores"
docker exec sentinel-postgres-1 pg_isready -U sentinel -d sentinel >/dev/null 2>&1 \
  && pass "Postgres accepting connections" || bad "Postgres not ready"
docker exec sentinel-redis-1 redis-cli ping 2>/dev/null | grep -q PONG \
  && pass "Redis responding" || bad "Redis not responding"
docker exec sentinel-clickhouse-1 wget -qO- http://127.0.0.1:8123/ping 2>/dev/null | grep -q Ok \
  && pass "ClickHouse responding" || bad "ClickHouse not responding"

step "Database schema"
n=$(docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc \
      "select count(*) from information_schema.tables where table_schema='public';" 2>/dev/null | tr -dc '0-9')
if [[ "${n:-0}" -gt 5 ]]; then pass "schema present ($n tables — migrations ran)"
else bad "schema missing or incomplete (${n:-0} tables) — check the migrate container's logs"; fi

step "Data plane"
HZ=$(curl -fsS --max-time 5 http://127.0.0.1:80/healthz 2>/dev/null)
if [[ -n "$HZ" ]]; then
  pass "/healthz answering"
  SITES=$(printf '%s' "$HZ" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sites",0))' 2>/dev/null || echo 0)
  if [[ "${SITES:-0}" -gt 0 ]]; then pass "$SITES protected site(s) loaded"
  else soft "no sites configured yet — the WAF returns 502 to everything until one exists (expected on a fresh install)"; fi
  SHED=$(printf '%s' "$HZ" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("history_shed",0))' 2>/dev/null || echo 0)
  if [[ "${SHED:-0}" -eq 0 ]]; then pass "no shed events (every block was recorded)"
  else soft "$SHED events enforced but NOT recorded — event history undercounts blocks for that window"; fi
else
  bad "/healthz not answering on :80"
fi

step "Listeners"
for p in 80 443 9443; do
  ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$" \
    && pass "port $p bound" || bad "port $p NOT bound"
done

step "Enforcement"
if [[ "${SITES:-0}" -gt 0 ]]; then
  HOSTHDR=$(grep -oP '^SENTINEL_WAF_HOSTNAME=\K.*' "$ENV_FILE" 2>/dev/null || echo localhost)
  b=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $HOSTHDR" "http://127.0.0.1/" 2>/dev/null)
  a=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $HOSTHDR" "http://127.0.0.1/?id=1%27+OR+1%3D1--" 2>/dev/null)
  [[ "$b" == "200" ]] && pass "legitimate request -> $b" || soft "legitimate request -> $b (check the upstream is reachable)"
  case "$a" in
    403) pass "SQL injection -> 403 (blocking mode)" ;;
    200) soft "SQL injection -> 200 — the site is in LEARNING mode: recorded, not blocked. Correct during a pilot." ;;
    *)   soft "SQL injection -> $a" ;;
  esac
else
  soft "enforcement not tested — no site configured"
fi

step "Certificates"
for f in /opt/sentinel-pki/root.crt /opt/sentinel-pki/pg-server.crt; do
  if [[ -f "$f" && -s "$f" ]]; then
    if openssl x509 -in "$f" -noout -checkend 604800 >/dev/null 2>&1; then
      pass "$(basename "$f") valid (>7 days remaining)"
    else
      bad "$(basename "$f") expires within 7 days or is unreadable"
    fi
  else
    bad "$(basename "$f") missing — Postgres cannot start without it"
  fi
done

printf '\n  %s%d passed, %d failed, %d warnings%s\n\n' "$B" "$PASS" "$FAIL" "$WARN" "$R"
if [[ $FAIL -gt 0 ]]; then
  printf '  %sVerification FAILED.%s Diagnose with:\n' "$RED" "$R"
  printf '    docker compose -p sentinel ps\n'
  printf '    docker compose -p sentinel logs --tail 100\n'
  printf '    cat /var/log/sentinel/install.log\n\n'
  exit 1
fi
printf '  %sAll checks passed.%s'"$([[ $WARN -gt 0 ]] && echo ' Review the warnings above.')"'\n\n' "$GRN" "$R"
