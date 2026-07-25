#!/usr/bin/env bash
# L3/L4 flood harness for a Sentinel WAF deployment.
#
# The point of this script is NOT to prove the WAF survives — it is to MEASURE whether
# it does, honestly, and to make "we added DDoS hardening" a claim backed by a number
# instead of by a config diff. Every hardening change in Fix 10 (HAProxy stick-tables,
# sysctl, XDP) is only real once this shows backend CPU staying flat and clean-traffic
# latency holding while a flood runs.
#
#   ./flood-test.sh --target http://waf-host --origin http://origin-host [options]
#
# It runs a flood and, concurrently, a stream of LEGITIMATE requests, then reports what
# the legitimate clients experienced. A WAF that blocks the flood but also drops
# real users has failed; the clean-traffic SLO is the actual pass/fail signal.
#
# Requires (checked at start): one of hping3 / mausezahn for L3/L4, and hey / wrk / ab
# for the clean-traffic probe.
set -euo pipefail

TARGET=""
ORIGIN=""
DURATION=30
FLOOD=syn
CLEAN_RPS=20
CLEAN_PATH="/"
SLO_P99_MS=1000
SLO_SUCCESS_PCT=99

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  cat <<EOF

Options:
  --target URL       WAF entrypoint under test (required)
  --origin URL       backend/origin to sample CPU + as clean-traffic baseline (required)
  --duration SECS    flood duration (default $DURATION)
  --flood KIND       syn | conn | udp | slowloris (default $FLOOD)
  --clean-rps N      legitimate requests/sec run alongside the flood (default $CLEAN_RPS)
  --clean-path PATH  path the legitimate probe hits (default $CLEAN_PATH)
  --slo-p99 MS       clean-traffic p99 latency budget (default $SLO_P99_MS)
  --slo-success PCT  clean-traffic success floor (default $SLO_SUCCESS_PCT)

SAFETY: only run against infrastructure you are authorised to test. A flood is
indistinguishable from an attack to anything between you and the target — never point
this at a shared network, a cloud VIP with neighbours, or anything you do not own.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --origin) ORIGIN="$2"; shift 2;;
    --duration) DURATION="$2"; shift 2;;
    --flood) FLOOD="$2"; shift 2;;
    --clean-rps) CLEAN_RPS="$2"; shift 2;;
    --clean-path) CLEAN_PATH="$2"; shift 2;;
    --slo-p99) SLO_P99_MS="$2"; shift 2;;
    --slo-success) SLO_SUCCESS_PCT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1" >&2; usage; exit 1;;
  esac
done

[[ -n "$TARGET" && -n "$ORIGIN" ]] || { echo "ERROR: --target and --origin are required." >&2; usage; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# Pick tools, or explain exactly what is missing rather than half-running.
FLOODER=""
if have hping3; then FLOODER=hping3
elif have mausezahn; then FLOODER=mausezahn
else
  echo "ERROR: need hping3 or mausezahn for the L3/L4 flood." >&2
  echo "  Debian/Ubuntu: apt-get install hping3   (mausezahn is in the 'netsniff-ng' package)" >&2
  exit 1
fi

CLEANER=""
for t in hey wrk ab; do have "$t" && { CLEANER="$t"; break; }; done
[[ -n "$CLEANER" ]] || { echo "ERROR: need one of hey / wrk / ab for the clean-traffic probe." >&2; exit 1; }

target_host() { echo "$TARGET" | sed -E 's#^https?://##; s#[:/].*$##'; }
target_port() {
  local p; p=$(echo "$TARGET" | sed -nE 's#^https?://[^:/]+:([0-9]+).*#\1#p')
  [[ -n "$p" ]] && { echo "$p"; return; }
  [[ "$TARGET" == https://* ]] && echo 443 || echo 80
}

HOST="$(target_host)"; PORT="$(target_port)"

echo "══════════════════════════════════════════════════════════════════════════════"
echo " Sentinel flood test"
echo "   target      : $TARGET  ($HOST:$PORT)"
echo "   flood       : $FLOOD for ${DURATION}s via $FLOODER"
echo "   clean probe : $CLEAN_RPS rps to ${TARGET}${CLEAN_PATH} via $CLEANER"
echo "   SLO         : p99 <= ${SLO_P99_MS}ms AND success >= ${SLO_SUCCESS_PCT}%"
echo "══════════════════════════════════════════════════════════════════════════════"
echo
echo "AUTHORISATION CHECK: this will flood $HOST. Only proceed if you own or are"
echo "explicitly authorised to test it. Type the target host to confirm:"
read -r CONFIRM
[[ "$CONFIRM" == "$HOST" ]] || { echo "confirmation mismatch — aborting."; exit 1; }

# ── Baseline: clean-traffic latency with NO flood, so the flood result has something
#    to be compared against. A p99 that is bad under flood but was also bad at rest is
#    not a flood finding.
echo
echo "── Baseline (no flood) ─────────────────────────────────────────────────────"
clean_probe() {
  local secs="$1"
  case "$CLEANER" in
    hey)  hey -z "${secs}s" -q "$CLEAN_RPS" -c "$CLEAN_RPS" "${TARGET}${CLEAN_PATH}" 2>&1;;
    wrk)  wrk -d "${secs}s" -c "$CLEAN_RPS" -t 2 --latency "${TARGET}${CLEAN_PATH}" 2>&1;;
    ab)   ab -t "$secs" -c "$CLEAN_RPS" "${TARGET}${CLEAN_PATH}" 2>&1;;
  esac
}
clean_probe 10 | tee /tmp/sentinel-baseline.txt | grep -iE "requests/sec|latency|p99|99%|non-2xx|complete" || true

# ── The flood ───────────────────────────────────────────────────────────────
start_flood() {
  case "$FLOODER:$FLOOD" in
    hping3:syn)       hping3 -S -p "$PORT" --flood --rand-source "$HOST" ;;
    hping3:conn)      hping3 -S -p "$PORT" -i u1000 --rand-source "$HOST" ;;
    hping3:udp)       hping3 --udp -p "$PORT" --flood --rand-source "$HOST" ;;
    hping3:slowloris) echo "slowloris is an L7 attack — use a dedicated tool (e.g. slowhttptest -c 1000 -H -u $TARGET)"; return 1 ;;
    mausezahn:syn)    mausezahn -t tcp "dp=$PORT,flags=syn" -c 0 "$HOST" ;;
    mausezahn:udp)    mausezahn -t udp "dp=$PORT" -c 0 "$HOST" ;;
    *) echo "unsupported $FLOODER/$FLOOD combination"; return 1 ;;
  esac
}

echo
echo "── Under flood ─────────────────────────────────────────────────────────────"
echo "starting $FLOOD flood (needs root for raw sockets)…"
sudo bash -c "$(declare -f start_flood); start_flood" &
FLOOD_PID=$!
trap 'sudo kill "$FLOOD_PID" 2>/dev/null; sudo pkill -P "$FLOOD_PID" 2>/dev/null || true' EXIT

# Sample origin CPU across the flood so "backend CPU stays flat" is a measurement.
( for _ in $(seq 1 "$((DURATION/5))"); do
    ssh_cpu=$(ssh "$(echo "$ORIGIN" | sed -E 's#^https?://##; s#[:/].*$##')" \
      "top -bn1 | awk '/Cpu/{print 100-\$8}'" 2>/dev/null || echo "n/a")
    echo "    origin CPU: ${ssh_cpu}%"
    sleep 5
  done ) &

clean_probe "$DURATION" | tee /tmp/sentinel-underflood.txt | grep -iE "requests/sec|latency|p99|99%|non-2xx|complete" || true

sudo kill "$FLOOD_PID" 2>/dev/null || true
trap - EXIT

echo
echo "── Verdict ─────────────────────────────────────────────────────────────────"
echo "Compare /tmp/sentinel-baseline.txt vs /tmp/sentinel-underflood.txt."
echo
echo "PASS requires, DURING the flood:"
echo "  • clean-traffic p99 within ${SLO_P99_MS}ms of baseline"
echo "  • clean-traffic success >= ${SLO_SUCCESS_PCT}%"
echo "  • origin CPU not materially above its idle level (the flood shed at the edge,"
echo "    not passed through to the backend)"
echo
echo "This script measures and reports; it does not auto-grade, because the pass line"
echo "depends on the deployment's own baseline. Record the numbers next to the config"
echo "they were taken against — an undated 'it survived' is not evidence."
