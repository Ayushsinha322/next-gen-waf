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

step "Control plane → database"
# THE FAILURE THIS EXISTS TO CATCH IS SILENT AND PERMANENT.
#
# If the control plane cannot reach Postgres within its 60s startup window it does
# NOT exit. It logs one WARN — "DB unavailable — running in degraded mode (mock
# data only)" — and serves forever with a nil store, never retrying. Every check
# above still passes: the container status is `running`, Postgres itself is
# healthy, and a fresh install legitimately has no sites. The script would print
# "All checks passed", and the operator's first login would return 503
# "authentication unavailable: no user database configured".
#
# Triggers seen in practice: Postgres slower than 60s after a host reboot (Docker's
# restart policy does not re-apply depends_on ordering), a regenerated pg-server.crt
# against the sslmode=verify-full DSN, or a plain Postgres restart.
#
# /readyz is the ONLY endpoint that reports this: it calls store.Ping and returns
# db ok|unavailable|unreachable. Do NOT use /health — it is a hardcoded
# `{"status":"ok"}` that never touches the database.
#
# 9501 is not published to the host, and the control-plane image is distroless
# with no shell, so probe from a container that has one and shares the network —
# the same trick used for the ClickHouse check above.
RDY=$(docker exec sentinel-clickhouse-1 wget -qO- --timeout=5 http://controlplane:9501/readyz 2>/dev/null)
if [[ -z "$RDY" ]]; then
  bad "control plane /readyz did not answer — it is not serving, or not on the sentinel network"
elif printf '%s' "$RDY" | grep -q '"db"[[:space:]]*:[[:space:]]*"ok"'; then
  pass "control plane is connected to its database"
else
  bad "control plane is running WITHOUT a database — every login will return 503
       $RDY
       It will not reconnect on its own. Restart it after Postgres is healthy:
         docker restart sentinel-controlplane-1"
fi
# Belt and braces: the warning is logged once at startup and is the only trace if
# the container is later restarted into a good state while the pool stays nil.
if docker logs sentinel-controlplane-1 2>&1 | grep -qE 'degraded mode|running standalone'; then
  bad "control plane logged degraded mode at startup — it has NO database
       docker logs sentinel-controlplane-1 2>&1 | grep -E 'degraded mode|running standalone'"
fi

step "Database schema"
n=$(docker exec sentinel-postgres-1 psql -U sentinel -d sentinel -tAc \
      "select count(*) from information_schema.tables where table_schema='public';" 2>/dev/null | tr -dc '0-9')
if [[ "${n:-0}" -gt 5 ]]; then pass "schema present ($n tables — migrations ran)"
else bad "schema missing or incomplete (${n:-0} tables) — check the migrate container's logs"; fi

step "Data plane"
HZ=$(curl -fsS --max-time 5 http://127.0.0.1:80/healthz 2>/dev/null)
if [[ -n "$HZ" ]]; then
  pass "/healthz answering"
  # sed, not python3 — this script is shipped to hosts that may not have python3,
  # where `|| echo 0` silently reported "no sites" on a correctly configured WAF
  # and skipped the enforcement test below entirely.
  SITES=$(printf '%s' "$HZ" | sed -n 's/.*"sites"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)
  if [[ "${SITES:-0}" -gt 0 ]]; then pass "$SITES protected site(s) loaded"
  else soft "no sites configured yet — the WAF returns 502 to everything until one exists (expected on a fresh install)"; fi
  SHED=$(printf '%s' "$HZ" | sed -n 's/.*"history_shed"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)
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
# ENFORCE_VERIFIED gates what the closing summary is allowed to claim. Previously
# EVERY outcome here was a pass or a soft warning — including a WAF that answered
# 200 to SQL injection, which was reported as "LEARNING mode … Correct during a
# pilot" without anything having checked the site's mode. A WAF failing open and a
# WAF deliberately in learning mode are indistinguishable to this test, and the
# script asserted the reassuring one. It then printed "All checks passed".
ENFORCE_VERIFIED=no
if [[ "${SITES:-0}" -gt 0 ]]; then
  # SENTINEL_WAF_HOSTNAME is the console's name, which need not be a name any
  # protected SITE declares — and site matching is exact against the site's own
  # domains. Allow the operator to name the right one.
  HOSTHDR="${SENTINEL_VERIFY_HOST:-}"
  [[ -n "$HOSTHDR" ]] || HOSTHDR=$(sed -n 's/^SENTINEL_WAF_HOSTNAME=//p' "$ENV_FILE" 2>/dev/null | head -1)
  HOSTHDR="${HOSTHDR:-localhost}"
  b=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $HOSTHDR" "http://127.0.0.1/" 2>/dev/null)
  a=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $HOSTHDR" "http://127.0.0.1/?id=1%27+OR+1%3D1--" 2>/dev/null)

  if [[ "$b" == "502" ]]; then
    # The probe Host matched no site, so neither request reached the engine and
    # NOTHING about enforcement was measured. Saying so is the whole point.
    soft "enforcement NOT measured — 'Host: $HOSTHDR' matches no configured site (502)"
    printf '        %sre-run with a hostname one of your sites declares:%s\n' "$DIM" "$R"
    printf '        %s  SENTINEL_VERIFY_HOST=app.example.com sudo ./verify.sh%s\n' "$DIM" "$R"
  else
    [[ "$b" == "200" ]] && pass "legitimate request -> $b" \
      || soft "legitimate request -> $b (check the upstream is reachable)"
    case "$a" in
      403) pass "SQL injection -> 403 — blocking is ENFORCED"; ENFORCE_VERIFIED=yes ;;
      200) soft "SQL injection -> 200 — NOT blocked. Expected in learning mode; a fault in blocking mode. This script cannot tell which, so enforcement is unverified." ;;
      *)   soft "SQL injection -> $a — inconclusive, enforcement unverified" ;;
    esac
  fi
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
printf '  %sAll checks passed.%s'"$([[ $WARN -gt 0 ]] && echo ' Review the warnings above.')"'\n' "$GRN" "$R"
# Do not let a green run imply more than was measured. Without a 403 to a real
# injection, everything above proves the stack is RUNNING — not that it BLOCKS.
if [[ "${ENFORCE_VERIFIED:-no}" != "yes" ]]; then
  printf '  %sNote: enforcement was NOT verified — this run proved the stack is running,%s\n' "$YEL" "$R"
  printf '  %snot that it blocks anything. Configure a site and re-run to measure that.%s\n' "$YEL" "$R"
fi
printf '\n'
