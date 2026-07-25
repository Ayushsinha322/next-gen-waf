#!/usr/bin/env bash
# =============================================================================
# Sentinel WAF — CPU scaling sweep (the Fix 3 verification)
# =============================================================================
# Fix 3 removed three per-request global locks (metrics histogram, traffic
# accumulator, isolation-forest write lock) and claimed throughput should now scale
# with core count instead of flattening. That claim was UNVERIFIED. This measures it.
#
# Method: pin the WAF to N cores with taskset and measure clean-path throughput at
# N = 1, 2, 4, 8. The load generator and origin are pinned to a DIFFERENT set of
# cores so they never compete with the WAF for CPU — without that isolation the
# generator becomes the bottleneck and the curve flattens for reasons that have
# nothing to do with the WAF, which is exactly the artefact this must avoid.
#
# The WAF's tokio runtime uses new_multi_thread() with no explicit worker_threads,
# so it sizes itself from available_parallelism(), which honours the CPU affinity
# mask. taskset therefore genuinely changes the worker count, not just scheduling.
#
# Measured on the CLEAN path (full CRS, blocking mode, PL2, real upstream fetch):
#   * it exercises the whole pipeline rather than an early-exit
#   * it is not distorted by the correlation module, which escalates the anomaly
#     score for a source IP with recent blocks — from a single-IP generator that
#     turns any attack-bearing scenario into a measurement of the block path
#
#   ./scaling-sweep.sh
#
# Env: DURATION (default 15s), CORE_LIST (default "1 2 4 8"), WARMUP (default 5s)
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WAF_BIN="${WAF_BIN:-$REPO/target/release/sentinel-bin}"
WAF_CONFIG="${WAF_CONFIG:-$HERE/waf-loadtest.yaml}"
DURATION="${DURATION:-15s}"
WARMUP="${WARMUP:-5s}"
CORE_LIST="${CORE_LIST:-1 2 4 8}"
OUT_DIR="${OUT_DIR:-$HERE/results}"
HOST_HDR=loadtest.local
UPSTREAM_PORT=18080
WAF_PORT=18081
ORIGIN_NAME=sentinel-sweep-origin

TOTAL_CORES="$(nproc)"
# Reserve the top half for generator + origin. With 16 cores: WAF 0-7,
# origin 8-11, vegeta 12-15.
HALF=$((TOTAL_CORES / 2))
ORIGIN_CPUS="$HALF-$((HALF + HALF/2 - 1))"
GEN_CPUS="$((HALF + HALF/2))-$((TOTAL_CORES - 1))"

[ -x "$WAF_BIN" ] || { echo "ERROR: no release binary at $WAF_BIN (cargo build --release -p sentinel-bin)"; exit 1; }
command -v vegeta >/dev/null || { echo "ERROR: vegeta not found"; exit 1; }
command -v taskset >/dev/null || { echo "ERROR: taskset not found (util-linux)"; exit 1; }
command -v docker  >/dev/null || { echo "ERROR: docker not found (nginx origin)"; exit 1; }

mkdir -p "$OUT_DIR"
RESULTS="$OUT_DIR/scaling-sweep.txt"
WAF_PID=""
cleanup() { [ -n "$WAF_PID" ] && kill "$WAF_PID" 2>/dev/null; docker rm -f "$ORIGIN_NAME" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

{
  echo "── Sentinel WAF CPU scaling sweep ────────────────────────────────────"
  echo "date        : $(date -Is)"
  echo "host        : $TOTAL_CORES cores · $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
  echo "memory      : $(free -h | awk '/Mem:/{print $2}') total, $(free -h | awk '/Mem:/{print $7}') available"
  echo "binary      : $WAF_BIN"
  echo "path        : clean GET through WAF -> nginx origin (full CRS, blocking, PL2)"
  echo "isolation   : WAF cores 0..N-1 | origin $ORIGIN_CPUS | vegeta $GEN_CPUS"
  echo "duration    : $DURATION per point (after ${WARMUP} warmup)"
  echo
} | tee "$RESULTS"

echo "▶ starting nginx origin (cpuset $ORIGIN_CPUS)…"
docker rm -f "$ORIGIN_NAME" >/dev/null 2>&1
docker run --rm -d --name "$ORIGIN_NAME" --cpuset-cpus="$ORIGIN_CPUS" \
  -p "$UPSTREAM_PORT:80" nginx:alpine >/dev/null
for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/" -o /dev/null 2>/dev/null && break; sleep 0.5; done
curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/" -o /dev/null || { echo "origin failed to start"; exit 1; }

printf '%-7s %-12s %-12s %-11s %-11s %-9s\n' cores rps rps/core p99 success threads | tee -a "$RESULTS"
printf '%-7s %-12s %-12s %-11s %-11s %-9s\n' ------ ----------- ----------- ---------- ---------- -------- | tee -a "$RESULTS"

BASE_RPS=""
for N in $CORE_LIST; do
  [ "$N" -le "$HALF" ] || { echo "skipping N=$N (would overlap the generator's cores)"; continue; }
  CPUS="0-$((N - 1))"; [ "$N" = 1 ] && CPUS="0"

  ( cd "$REPO" && exec taskset -c "$CPUS" "$WAF_BIN" --config "$WAF_CONFIG" ) \
    > "$OUT_DIR/waf-sweep-$N.log" 2>&1 &
  WAF_PID=$!
  for i in $(seq 1 40); do curl -fsS -H "Host: $HOST_HDR" "http://127.0.0.1:$WAF_PORT/" -o /dev/null 2>/dev/null && break; sleep 0.5; done
  if ! curl -fsS -H "Host: $HOST_HDR" "http://127.0.0.1:$WAF_PORT/" -o /dev/null; then
    echo "  N=$N: WAF failed to start; see $OUT_DIR/waf-sweep-$N.log" | tee -a "$RESULTS"
    kill "$WAF_PID" 2>/dev/null; WAF_PID=""; continue
  fi

  # Confirm tokio actually sized its pool to the affinity mask, so the sweep is
  # measuring worker count and not just scheduler pressure.
  THREADS="$(ls /proc/$WAF_PID/task 2>/dev/null | wc -l)"

  # Warm up: first requests pay rule-engine cache population and connection setup.
  taskset -c "$GEN_CPUS" vegeta attack -duration="$WARMUP" -rate=0 -max-workers=64 \
    -connections=200 -header "Host: $HOST_HDR" -targets="$HERE/traffic/clean.txt" >/dev/null 2>&1

  BIN="$OUT_DIR/sweep-$N.bin"
  taskset -c "$GEN_CPUS" vegeta attack -duration="$DURATION" -rate=0 -max-workers=64 \
    -connections=200 -header "Host: $HOST_HDR" -targets="$HERE/traffic/clean.txt" 2>/dev/null > "$BIN"
  JSON="$(vegeta report -type=json "$BIN" 2>/dev/null)"

  RPS="$(echo "$JSON"     | python3 -c "import json,sys; print(f\"{json.load(sys.stdin)['throughput']:.0f}\")" 2>/dev/null || echo n/a)"
  P99="$(echo "$JSON"     | python3 -c "import json,sys; print(f\"{json.load(sys.stdin)['latencies']['99th']/1e6:.2f}\")" 2>/dev/null || echo n/a)"
  SUCCESS="$(echo "$JSON" | python3 -c "import json,sys; print(f\"{json.load(sys.stdin)['success']*100:.2f}\")" 2>/dev/null || echo n/a)"
  PERCORE="$(python3 -c "print(f'{$RPS/$N:.0f}')" 2>/dev/null || echo n/a)"
  [ -z "$BASE_RPS" ] && BASE_RPS="$RPS"

  printf '%-7s %-12s %-12s %-11s %-11s %-9s\n' "$N" "$RPS" "$PERCORE" "$P99" "$SUCCESS" "$THREADS" | tee -a "$RESULTS"

  kill "$WAF_PID" 2>/dev/null; wait "$WAF_PID" 2>/dev/null; WAF_PID=""
  sleep 2
done

{
  echo
  echo "Scaling efficiency (vs the 1-core point):"
  for N in $CORE_LIST; do
    [ "$N" -le "$HALF" ] || continue
    r="$(grep -E "^$N " "$RESULTS" | awk '{print $2}' | head -1)"
    [ -n "$r" ] && [ -n "$BASE_RPS" ] && \
      python3 -c "print(f'  {$N:2} cores: {$r/$BASE_RPS:5.2f}x  (ideal {$N}.00x, efficiency {100*$r/($BASE_RPS*$N):5.1f}%)')" 2>/dev/null
  done
  echo
  echo "Reading it: near-linear scaling means the lock removal worked. Efficiency"
  echo "falling off sharply with core count would mean contention remains — that was"
  echo "the pre-Fix-3 behaviour and is what this exists to detect."
} | tee -a "$RESULTS"

echo
echo "Saved: $RESULTS"
