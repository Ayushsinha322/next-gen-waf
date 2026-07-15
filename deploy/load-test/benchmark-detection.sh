#!/usr/bin/env bash
# =============================================================================
# Sentinel WAF — FAIR detection benchmark (GoTestWAF).
#
#   GoTestWAF ──▶ WAF :18091 ──▶ all-methods-200 origin :18090
#
# Uses origin-all-methods.py (NOT a static origin) so every request reaches a
# 200 backend and block/pass is decided purely by the WAF (403 = blocked). This
# removes the nginx-405 confound that inflated TP and deflated TN in earlier runs.
#
# Correlation (repeat-offender IP scoring) is disabled for the run so a single
# scanning source IP is not escalated — this measures per-request RULE + ML
# detection, which is what GoTestWAF is designed to assess.
#
# Usage:   ./benchmark-detection.sh [waf-config.yaml]
# Env:     WAF_BIN, ORIGIN_PORT(18090), WAF_PORT(18091), OUT(./detection-reports)
# =============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
CONFIG="${1:-$HERE/waf-detection.yaml}"
WAF_BIN="${WAF_BIN:-$REPO/target/release/sentinel-bin}"
ORIGIN_PORT="${ORIGIN_PORT:-18090}"
WAF_PORT="${WAF_PORT:-18091}"
OUT="${OUT:-$HERE/detection-reports}"

command -v docker >/dev/null || { echo "ERROR: docker required (wallarm/gotestwaf image)"; exit 1; }
[ -x "$WAF_BIN" ] || { echo "ERROR: build first: cargo build --release -p sentinel-bin"; exit 1; }

OPID=""; WPID=""
cleanup() { [ -n "$WPID" ] && kill "$WPID" 2>/dev/null; [ -n "$OPID" ] && kill "$OPID" 2>/dev/null; }
trap cleanup EXIT

echo "▶ origin (all-methods 200) on :$ORIGIN_PORT"
python3 "$HERE/origin-all-methods.py" "$ORIGIN_PORT" & OPID=$!

echo "▶ WAF on :$WAF_PORT (config: $CONFIG, correlation disabled)"
( cd "$REPO" && SENTINEL_DISABLE_CORRELATION=1 exec "$WAF_BIN" --config "$CONFIG" ) >/tmp/waf-detbench.log 2>&1 & WPID=$!
for _ in $(seq 1 20); do curl -s -o /dev/null "http://localhost:$WAF_PORT/" && break; sleep 1; done

# sanity: benign must pass, obvious attacks must block, or the run is meaningless
b=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$WAF_PORT/")
s=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$WAF_PORT/?a=1%27%20OR%20%271%27=%271")
echo "  sanity: benign=$b (want 200)  sqli=$s (want 403)"

mkdir -p "$OUT"
echo "▶ GoTestWAF"
docker run --rm --network host -v "$OUT":/app/reports wallarm/gotestwaf:latest \
  --url "http://localhost:$WAF_PORT" --blockStatusCodes 403 --passStatusCodes 200,404 \
  --workers 10 --randomDelay 20 --skipWAFIdentification --noEmailReport --reportPath /app/reports

echo "✓ reports in $OUT"
