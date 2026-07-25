#!/usr/bin/env bash
# =============================================================================
# Sentinel WAF — sustained soak (the Fix 3 memory verification)
# =============================================================================
# Fix 3 replaced a metrics histogram that was a Mutex<Vec<f64>> which was NEVER
# DRAINED — it accumulated one f64 per request for the lifetime of the process, an
# unbounded leak proportional to total requests served. It was replaced with fixed
# atomic buckets, so memory should now be constant regardless of volume.
#
# That is exactly the kind of claim a short benchmark cannot test and a soak can:
# run for a long time at a steady rate and watch RSS.
#
# Deliberately run BELOW saturation (default ~50% of the pinned core count's measured
# ceiling). A saturated run confounds the measurement — queue growth and allocator
# behaviour under backpressure both move RSS for reasons unrelated to a leak.
#
#   ./soak-test.sh                    # 30 min, 4 cores, 1500 rps
#   DURATION=60m RATE=3000 ./soak-test.sh
#
# Env: DURATION (30m), RATE (1500/s), CORES (0-3), SAMPLE_SECS (30)
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WAF_BIN="${WAF_BIN:-$REPO/target/release/sentinel-bin}"
WAF_CONFIG="${WAF_CONFIG:-$HERE/waf-loadtest.yaml}"
DURATION="${DURATION:-30m}"
RATE="${RATE:-1500}"
CORES="${CORES:-0-3}"
SAMPLE_SECS="${SAMPLE_SECS:-30}"
OUT_DIR="${OUT_DIR:-$HERE/results}"
HOST_HDR=loadtest.local
UPSTREAM_PORT=18080
WAF_PORT=18081
ORIGIN_NAME=sentinel-soak-origin
GEN_CPUS="${GEN_CPUS:-12-15}"
ORIGIN_CPUS="${ORIGIN_CPUS:-8-11}"

[ -x "$WAF_BIN" ] || { echo "ERROR: no release binary at $WAF_BIN"; exit 1; }
for t in vegeta taskset docker; do command -v $t >/dev/null || { echo "ERROR: $t not found"; exit 1; }; done

mkdir -p "$OUT_DIR"
RESULTS="$OUT_DIR/soak-test.txt"
SAMPLES="$OUT_DIR/soak-rss.csv"
WAF_PID=""
cleanup() { [ -n "$WAF_PID" ] && kill "$WAF_PID" 2>/dev/null; docker rm -f "$ORIGIN_NAME" >/dev/null 2>&1; }
trap cleanup EXIT INT TERM

docker rm -f "$ORIGIN_NAME" >/dev/null 2>&1
docker run --rm -d --name "$ORIGIN_NAME" --cpuset-cpus="$ORIGIN_CPUS" -p "$UPSTREAM_PORT:80" nginx:alpine >/dev/null
for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/" -o /dev/null 2>/dev/null && break; sleep 0.5; done

( cd "$REPO" && exec taskset -c "$CORES" "$WAF_BIN" --config "$WAF_CONFIG" ) > "$OUT_DIR/waf-soak.log" 2>&1 &
WAF_PID=$!
for i in $(seq 1 40); do curl -fsS -H "Host: $HOST_HDR" "http://127.0.0.1:$WAF_PORT/" -o /dev/null 2>/dev/null && break; sleep 0.5; done
curl -fsS -H "Host: $HOST_HDR" "http://127.0.0.1:$WAF_PORT/" -o /dev/null || { echo "WAF did not start"; exit 1; }

{
  echo "── Sentinel WAF soak ─────────────────────────────────────────────────"
  echo "date     : $(date -Is)"
  echo "host     : $(nproc) cores · $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
  echo "waf cores: $CORES   generator: $GEN_CPUS   origin: $ORIGIN_CPUS"
  echo "duration : $DURATION at a bounded ${RATE}/s (below saturation, on purpose)"
  echo "purpose  : prove metrics memory is constant after the histogram fix"
  echo
} | tee "$RESULTS"

echo "elapsed_s,rss_kb,threads,fds" > "$SAMPLES"
rss_kb() { awk '/VmRSS/{print $2}' "/proc/$WAF_PID/status" 2>/dev/null || echo 0; }
START_RSS="$(rss_kb)"
echo "start RSS: ${START_RSS} kB" | tee -a "$RESULTS"

# Sampler runs alongside the attack.
(
  t=0
  while kill -0 "$WAF_PID" 2>/dev/null; do
    echo "$t,$(rss_kb),$(ls /proc/$WAF_PID/task 2>/dev/null | wc -l),$(ls /proc/$WAF_PID/fd 2>/dev/null | wc -l)" >> "$SAMPLES"
    sleep "$SAMPLE_SECS"; t=$((t + SAMPLE_SECS))
  done
) &
SAMPLER=$!

echo "▶ soaking for $DURATION …"
taskset -c "$GEN_CPUS" vegeta attack -duration="$DURATION" -rate="${RATE}/s" \
  -max-workers=64 -connections=200 -header "Host: $HOST_HDR" \
  -targets="$HERE/traffic/clean.txt" 2>/dev/null > "$OUT_DIR/soak.bin"

kill "$SAMPLER" 2>/dev/null
END_RSS="$(rss_kb)"

{
  echo
  vegeta report "$OUT_DIR/soak.bin" 2>/dev/null | grep -E "Requests|Duration|Latencies|Success|Status"
  echo
  echo "── Memory ─────────────────────────────────────────────────────────────"
  echo "start RSS : ${START_RSS} kB"
  echo "end   RSS : ${END_RSS} kB"
} | tee -a "$RESULTS"

python3 - "$SAMPLES" "$START_RSS" "$END_RSS" <<'PY' | tee -a "$RESULTS"
import csv, sys
path, start, end = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rows = [r for r in csv.DictReader(open(path)) if r.get("rss_kb", "0").isdigit()]
rows.sort(key=lambda r: int(r["elapsed_s"]))
if len(rows) < 3:
    print("  too few samples to judge a trend"); raise SystemExit

# WARMUP MUST BE EXCLUDED, or this metric answers the wrong question.
#
# RSS climbs steeply in the first minute as connection pools, rule-engine caches and
# allocator arenas populate — on a 30m run that one step was ~28 MB of a ~28 MB total
# spread. Regressing over the whole series therefore reported +7.99 MiB/hour and
# "NOT flat" on a run whose steady state was flat to within 328 kB. The slope was
# measuring startup, not leakage. A leak is a SUSTAINED slope after the working set
# settles, so the regression starts after WARMUP_S.
WARMUP_S = int(__import__("os").environ.get("WARMUP_S", "300"))
warm = [r for r in rows if int(r["elapsed_s"]) >= WARMUP_S]
if len(warm) < 3:
    print(f"  run too short to exclude {WARMUP_S}s of warmup — extend DURATION"); raise SystemExit
print(f"  (excluding first {WARMUP_S}s of warmup: {len(rows)-len(warm)} of {len(rows)} samples dropped)")
rows = warm
rss = [int(r["rss_kb"]) for r in rows]
t   = [int(r["elapsed_s"]) for r in rows]
peak, lo = max(rss), min(rss)
# Least-squares slope in kB/s, projected to kB/hour — a leak shows as a positive,
# sustained slope rather than the sawtooth of ordinary allocator churn.
n = len(rss); mt = sum(t)/n; mr = sum(rss)/n
den = sum((x-mt)**2 for x in t)
slope = (sum((t[i]-mt)*(rss[i]-mr) for i in range(n))/den) if den else 0.0
print(f"  samples   : {n} over {t[-1]}s")
print(f"  min / max : {lo} / {peak} kB   (spread {peak-lo} kB)")
print(f"  slope     : {slope*3600/1024:+.2f} MiB/hour")
growth = (rss[-1]-rss[0])/max(rss[0],1)*100
print(f"  growth    : {growth:+.2f}% across the steady-state window")
print(f"  (whole-run start->end was {start} -> {end} kB; most of that is warmup)")
print()
if abs(slope*3600/1024) < 5 and growth < 10:
    print("  VERDICT: memory is FLAT. The unbounded histogram leak is gone —")
    print("           pre-fix, one f64 per request would have grown continuously.")
else:
    print("  VERDICT: memory is NOT flat. Investigate before trusting a long run;")
    print("           a sustained positive slope is the signature of a leak.")
fds = [int(r["fds"]) for r in rows]
fmt = sum(t)/len(t); fmf = sum(fds)/len(fds)
fden = sum((x-fmt)**2 for x in t)
fslope = (sum((t[i]-fmt)*(fds[i]-fmf) for i in range(len(t)))/fden) if fden else 0.0
print(f"  threads   : {rows[0]['threads']} -> {rows[-1]['threads']} (constant is correct)")
print(f"  fds       : min {min(fds)} max {max(fds)}, slope {fslope:+.4f}/s — compare the")
print(f"              TREND, not endpoints: fd counts swing widely with connection churn,")
print(f"              so two arbitrary samples can look like growth when there is none.")
PY

echo
echo "Saved: $RESULTS  (samples: $SAMPLES)"
