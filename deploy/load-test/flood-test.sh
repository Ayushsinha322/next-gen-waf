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
# Packets/sec for the flood. 0 means hping3 --flood, i.e. as fast as the kernel will
# emit. Default is BOUNDED on purpose: --flood from one core saturates a loopback
# path at >100k pps and can wedge the host it is measuring, which destroys the
# measurement (you learn the box died, not what a client experienced). Raise
# deliberately once you know the box survives the lower rate.
FLOOD_PPS=20000
# contained | spoofed. See the warning in start_flood.
SRC_MODE=contained
# Sample CPU of a docker container instead of ssh-ing to a host.
ORIGIN_CONTAINER=""
WAF_CONTAINER=""

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
  --flood-pps N      bound the flood to N pps; 0 = hping3 --flood (default $FLOOD_PPS)
  --source-mode M    contained (real source) | spoofed (--rand-source). Default
                     $SRC_MODE. spoofed makes the target answer SYN-ACKs to forged
                     addresses, i.e. it emits backscatter AT THIRD PARTIES. Only use
                     it on an isolated lab segment you own end to end.
  --origin-container N   sample CPU of docker container N instead of ssh-ing to --origin
  --waf-container N      also sample this container's CPU (the WAF itself)

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
    --flood-pps) FLOOD_PPS="$2"; shift 2;;
    --source-mode) SRC_MODE="$2"; shift 2;;
    --origin-container) ORIGIN_CONTAINER="$2"; shift 2;;
    --waf-container) WAF_CONTAINER="$2"; shift 2;;
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
# Authorisation gate. Interactive by default; CONFIRM_HOST=<host> in the
# environment satisfies it non-interactively (for a scripted run on a box you own),
# which is deliberately as explicit as typing the host — you still have to name the
# exact target, so a copy-pasted invocation cannot flood the wrong host silently.
if [[ -n "${CONFIRM_HOST:-}" ]]; then
  CONFIRM="$CONFIRM_HOST"
  echo "AUTHORISATION: CONFIRM_HOST=$CONFIRM_HOST supplied non-interactively."
else
  echo "AUTHORISATION CHECK: this will flood $HOST. Only proceed if you own or are"
  echo "explicitly authorised to test it. Type the target host to confirm:"
  read -r CONFIRM
fi
[[ "$CONFIRM" == "$HOST" ]] || { echo "confirmation mismatch ('$CONFIRM' != '$HOST') — aborting."; exit 1; }

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
# Two safety properties are enforced here, not left to the caller:
#
#   1. Source spoofing (--rand-source) is OFF unless --source-mode spoofed. A
#      SYN from a forged source makes the target send its SYN-ACK to that forged
#      address — backscatter aimed at an uninvolved third party. On a shared or
#      routed network that is both an attack on someone else and a great way to
#      get the link null-routed. Contained mode floods from the real source, which
#      is the honest test of "can the box absorb SYNs from one origin" anyway.
#
#   2. The rate is BOUNDED to FLOOD_PPS unless it is 0. Unbounded --flood from a
#      single core will happily emit >100k pps at a loopback target and can starve
#      the very host under test, so the result is "the box fell over" rather than
#      "here is what a legitimate client saw". -i uNNN sets the inter-packet gap in
#      microseconds; we derive it from the requested pps.
rand_flag=""
[ "$SRC_MODE" = spoofed ] && rand_flag="--rand-source"
rate_flag="--flood"
if [ "${FLOOD_PPS:-0}" -gt 0 ] 2>/dev/null; then
  gap_us=$(( 1000000 / FLOOD_PPS )); [ "$gap_us" -lt 1 ] && gap_us=1
  rate_flag="-i u${gap_us}"
fi
# Build the flood command as a fully-EXPANDED string in this shell. It must not be
# a function shipped through a `sudo bash -c "$(declare -f …)"` boundary: declare -f
# serialises only the function body, so every variable it reads ($FLOODER, $FLOOD,
# $HOST, $PORT, the rate/source flags) arrives EMPTY in the subshell and the case
# falls through to "unsupported" — the flood silently never starts and the whole
# test then measures nothing. Expanding here means what runs is exactly what we can
# print.
flood_cmd=""
case "$FLOODER:$FLOOD" in
  hping3:syn)       flood_cmd="hping3 -S -p $PORT $rate_flag $rand_flag $HOST" ;;
  hping3:conn)      flood_cmd="hping3 -S -p $PORT -i u1000 $rand_flag $HOST" ;;
  hping3:udp)       flood_cmd="hping3 --udp -p $PORT $rate_flag $rand_flag $HOST" ;;
  hping3:slowloris) echo "slowloris is an L7 attack — use a dedicated tool (e.g. slowhttptest -c 1000 -H -u $TARGET)"; exit 1 ;;
  mausezahn:syn)    flood_cmd="mausezahn -t tcp dp=$PORT,flags=syn -c 0 $HOST" ;;
  mausezahn:udp)    flood_cmd="mausezahn -t udp dp=$PORT -c 0 $HOST" ;;
  *) echo "unsupported $FLOODER/$FLOOD combination"; exit 1 ;;
esac
# Raw sockets need root; use sudo only if we are not already root, so this works
# both from an unprivileged operator shell and from a root-context runner.
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

echo
echo "── Under flood ─────────────────────────────────────────────────────────────"
echo "starting $FLOOD flood (needs root for raw sockets)…"
echo "  cmd: $SUDO $flood_cmd"
$SUDO $flood_cmd >/dev/null 2>&1 &
FLOOD_PID=$!
trap '${SUDO} kill "$FLOOD_PID" 2>/dev/null; ${SUDO} pkill -P "$FLOOD_PID" 2>/dev/null || true' EXIT
# Confirm it is actually emitting packets rather than having exited instantly (bad
# flag, permission, unknown host). A test whose flood died in the first second is a
# false PASS waiting to happen.
sleep 1
if ! kill -0 "$FLOOD_PID" 2>/dev/null; then
  echo "  ERROR: flood process exited immediately — check the cmd above. Aborting."
  exit 1
fi
echo "  flood PID $FLOOD_PID confirmed running"

# Sample CPU across the flood so "backend CPU stays flat" is a measurement, not a
# hope. Prefer `docker stats` when the target is a container (this deployment);
# fall back to ssh+top for a remote host. Sample the WAF too when asked — for a
# SYN flood the interesting question is whether the WAF's OWN cpu moves, since the
# flood never becomes an HTTP request the origin would see.
( for _ in $(seq 1 "$((DURATION/5))"); do
    line="    "
    if [ -n "$WAF_CONTAINER" ]; then
      line+="waf($WAF_CONTAINER) CPU: $(docker stats --no-stream --format '{{.CPUPerc}}' "$WAF_CONTAINER" 2>/dev/null || echo n/a)   "
    fi
    if [ -n "$ORIGIN_CONTAINER" ]; then
      line+="origin($ORIGIN_CONTAINER) CPU: $(docker stats --no-stream --format '{{.CPUPerc}}' "$ORIGIN_CONTAINER" 2>/dev/null || echo n/a)"
    else
      oc=$(ssh "$(echo "$ORIGIN" | sed -E 's#^https?://##; s#[:/].*$##')" \
        "top -bn1 | awk '/Cpu/{print 100-\$8}'" 2>/dev/null || echo "n/a")
      line+="origin CPU: ${oc}%"
    fi
    echo "$line"
    sleep 5
  done ) &
SAMPLER_PID=$!

clean_probe "$DURATION" | tee /tmp/sentinel-underflood.txt | grep -iE "requests/sec|latency|p99|99%|non-2xx|complete" || true

sudo kill "$FLOOD_PID" 2>/dev/null || true
sudo pkill -P "$FLOOD_PID" 2>/dev/null || true
kill "${SAMPLER_PID:-}" 2>/dev/null || true
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
