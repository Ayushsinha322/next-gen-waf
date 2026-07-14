#!/usr/bin/env bash
# =============================================================================
# Sentinel WAF — end-to-end load test
# =============================================================================
# Measures the REAL throughput / latency / error-rate the WAF data plane adds
# in front of a fast static origin, using an open-loop generator (vegeta).
#
#   vegeta ──▶ WAF :18081 ──▶ nginx origin :18080
#
# Scenarios:
#   S0  baseline    direct-to-origin clean GET      (origin ceiling, WAF bypassed)
#   S1  waf-clean   clean GET through WAF            (rule-engine overhead, PASS path)
#   S2  waf-mixed   90% clean / 10% attack through WAF (realistic prod mix)
#   S3  waf-attack  100% attack through WAF          (early-exit BLOCK path)
#
# Everything measured here is real. Nothing is hard-coded or projected.
#
# Usage:
#   ./run-loadtest.sh
#
# Env overrides (all optional):
#   WAF_REPO     Sentinel repo root (has target/ + rules/).  Default: auto-detect
#   WAF_BIN      Path to sentinel-bin.  Default: $WAF_REPO/target/release/sentinel-bin
#   WAF_CONFIG   WAF config.  Default: <this dir>/waf-loadtest.yaml
#   DURATION     Per-scenario attack duration.  Default: 20s
#   MAX_WORKERS  vegeta max concurrent workers.  Default: 64
#   CONNS        vegeta max idle conns per host.  Default: 200
#   OUT_DIR      Results output dir.  Default: <this dir>/results
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Resolve the Sentinel repo (rules/ + target/). Try common locations. ──────
detect_repo() {
  for c in "${WAF_REPO:-}" "$HERE/../.." "$HOME/waf-development" "$HERE/../../.."; do
    [ -n "$c" ] && [ -d "$c/rules/owasp-crs" ] && [ -x "$c/target/release/sentinel-bin" ] && { (cd "$c" && pwd); return; }
  done
  return 1
}
WAF_REPO="$(detect_repo)" || { echo "ERROR: could not find the Sentinel repo (needs rules/owasp-crs + target/release/sentinel-bin). Set WAF_REPO."; exit 1; }
WAF_BIN="${WAF_BIN:-$WAF_REPO/target/release/sentinel-bin}"
WAF_CONFIG="${WAF_CONFIG:-$HERE/waf-loadtest.yaml}"
DURATION="${DURATION:-20s}"
MAX_WORKERS="${MAX_WORKERS:-64}"
CONNS="${CONNS:-200}"
OUT_DIR="${OUT_DIR:-$HERE/results}"

UPSTREAM_PORT=18080
WAF_PORT=18081
# Send a real hostname (not the numeric IP) so CRS 920350 ("Host header is a
# numeric IP", critical) does not fire on every clean request — that rule alone
# hits the anomaly threshold and would make us measure the block path, not the
# clean pass-through path. A real browser never sends a numeric-IP Host anyway.
HOST_HDR="${HOST_HDR:-loadtest.local}"
ORIGIN_NAME="sentinel-lt-origin"
WAF_LOG="$OUT_DIR/waf.log"
WAF_PID=""

command -v vegeta >/dev/null || { echo "ERROR: vegeta not found. Install: go install github.com/tsenart/vegeta/v12@latest"; exit 1; }
command -v docker >/dev/null || { echo "ERROR: docker not found (needed for the nginx origin)."; exit 1; }

mkdir -p "$OUT_DIR"
: > "$WAF_LOG"

cleanup() {
  [ -n "$WAF_PID" ] && kill "$WAF_PID" 2>/dev/null
  docker rm -f "$ORIGIN_NAME" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

echo "── Sentinel WAF load test ─────────────────────────────────────────────"
echo "repo=$WAF_REPO"
echo "bin=$WAF_BIN"
echo "config=$WAF_CONFIG"
echo "duration=$DURATION  max_workers=$MAX_WORKERS  conns=$CONNS"
echo "hardware: $(nproc) cores · $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) · $(free -h | awk '/Mem:/{print $2}') RAM"
echo

# ── 1. Origin (fast static nginx) ────────────────────────────────────────────
echo "▶ starting nginx origin on :$UPSTREAM_PORT …"
docker rm -f "$ORIGIN_NAME" >/dev/null 2>&1
docker run --rm -d --name "$ORIGIN_NAME" -p "$UPSTREAM_PORT:80" nginx:alpine >/dev/null
for i in $(seq 1 30); do curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/" -o /dev/null 2>/dev/null && break; sleep 0.5; done
curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/" -o /dev/null || { echo "ERROR: origin did not come up"; exit 1; }
echo "  origin up."

# ── 2. WAF data plane ─────────────────────────────────────────────────────────
echo "▶ starting WAF (sentinel-bin) on :$WAF_PORT …"
( cd "$WAF_REPO" && exec "$WAF_BIN" --config "$WAF_CONFIG" ) >>"$WAF_LOG" 2>&1 &
WAF_PID=$!
for i in $(seq 1 40); do curl -fsS -H "Host: $HOST_HDR" "http://127.0.0.1:$WAF_PORT/" -o /dev/null 2>/dev/null && break; sleep 0.5; done
curl -fsS -H "Host: $HOST_HDR" "http://127.0.0.1:$WAF_PORT/" -o /dev/null || { echo "ERROR: WAF did not proxy a clean request. Last log lines:"; tail -20 "$WAF_LOG"; exit 1; }
echo "  WAF up (pid $WAF_PID)."

# ── 3. Sanity: prove blocking actually happens (else 'clean' isn't WAF-inspected)
echo "▶ sanity check — attack must be blocked (403):"
sqli='http://127.0.0.1:'$WAF_PORT'/?id=1%27%20OR%20%271%27%3D%271%27%20--%20'
code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HDR" "$sqli")"
echo "  SQLi probe → HTTP $code $( [ "$code" = "403" ] && echo '(blocked ✓)' || echo '(NOT blocked — check ruleset!)')"
clean_code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST_HDR" "http://127.0.0.1:$WAF_PORT/")"
echo "  clean probe → HTTP $clean_code $( [ "$clean_code" = "200" ] && echo '(passed ✓)' || echo '(unexpected)')"
echo

# ── 4. Scenarios ──────────────────────────────────────────────────────────────
SUMMARY="$OUT_DIR/summary.txt"
: > "$SUMMARY"

# run_scenario <name> <targets-file> <base-url-override-for-baseline?>
run_scenario() {
  local name="$1" targets="$2" rewrite_port="${3:-}"
  local tf="$targets"
  if [ -n "$rewrite_port" ]; then
    tf="$OUT_DIR/.targets.$name.txt"
    sed "s/:$WAF_PORT/:$rewrite_port/g" "$targets" > "$tf"
  fi
  echo "▶ scenario: $name"
  vegeta attack -duration="$DURATION" -rate=0 -max-workers="$MAX_WORKERS" -connections="$CONNS" -header "Host: $HOST_HDR" -targets="$tf" \
    | tee "$OUT_DIR/$name.bin" | vegeta report > "$OUT_DIR/$name.report.txt"
  vegeta report -type=json "$OUT_DIR/$name.bin" > "$OUT_DIR/$name.json" 2>/dev/null
  # status-code distribution
  vegeta report -type='hist[0,1ms,5ms,10ms,25ms,50ms,100ms]' "$OUT_DIR/$name.bin" > "$OUT_DIR/$name.hist.txt" 2>/dev/null
  {
    echo "=== $name ==="
    cat "$OUT_DIR/$name.report.txt"
    echo
  } >> "$SUMMARY"
  sed -n '1,12p' "$OUT_DIR/$name.report.txt" | sed 's/^/    /'
  echo
}

run_scenario "s0-baseline-origin" "$HERE/traffic/clean.txt"  "$UPSTREAM_PORT"
run_scenario "s1-waf-clean"       "$HERE/traffic/clean.txt"
run_scenario "s2-waf-mixed"       "$HERE/traffic/mixed.txt"
run_scenario "s3-waf-attack"      "$HERE/traffic/attack.txt"

echo "── done ──────────────────────────────────────────────────────────────"
echo "Full reports + JSON in: $OUT_DIR"
echo "Summary: $SUMMARY"
