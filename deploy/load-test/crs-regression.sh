#!/usr/bin/env bash
# Run CRS's own regression suite against the release data plane, standalone —
# no control plane, database or Docker — and gate on the result.
#
#   deploy/load-test/crs-regression.sh [crs-regression.py options]
#
#   deploy/load-test/crs-regression.sh --baseline deploy/load-test/crs-regression-baseline.json
#       the CI gate: exit 1 on a case that newly fails or becomes unsupported
#   deploy/load-test/crs-regression.sh --write-baseline deploy/load-test/crs-regression-baseline.json
#       record the current non-pass cases (after a reviewed change)
#
# WAF_BIN   the data plane (default target/release/sentinel-bin)
# OUT_DIR   logs and results.json (default target/crs-regression)
#
# The site under test is deploy/load-test/crs-regression.yaml; the suite is
# rules/owasp-crs/tests/regression-<version>.json. See crs-regression.py for
# what each result means and how requests are matched to log lines.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$REPO/deploy/load-test"
WAF_BIN="${WAF_BIN:-$REPO/target/release/sentinel-bin}"
OUT="${OUT_DIR:-$REPO/target/crs-regression}"
CONFIG="$HERE/crs-regression.yaml"
SUITE="$REPO/rules/owasp-crs/tests/regression-4.7.0.json"
WAF_PORT=18095
ORIGIN_PORT=18096

[ -x "$WAF_BIN" ] || { echo "no data plane at $WAF_BIN: cargo build --release -p sentinel-bin" >&2; exit 2; }
mkdir -p "$OUT/logs"
: > "$OUT/dataplane.log"

python3 "$HERE/origin-all-methods.py" "$ORIGIN_PORT" >"$OUT/origin.log" 2>&1 &
OPID=$!
( cd "$REPO" && SENTINEL_LOG_DIR="$OUT/logs" SENTINEL_DISABLE_CORRELATION=1 \
    exec "$WAF_BIN" --config "$CONFIG" ) >>"$OUT/dataplane.log" 2>&1 &
WPID=$!
# By PID, never by pattern: `pkill -f` matches its own caller.
trap 'kill "$WPID" "$OPID" 2>/dev/null || true; wait "$WPID" "$OPID" 2>/dev/null || true' EXIT

for _ in $(seq 1 150); do
  if (echo >"/dev/tcp/127.0.0.1/$WAF_PORT") 2>/dev/null && (echo >"/dev/tcp/127.0.0.1/$ORIGIN_PORT") 2>/dev/null; then
    break
  fi
  kill -0 "$WPID" 2>/dev/null || { echo "the data plane exited:" >&2; tail -20 "$OUT/dataplane.log" >&2; exit 2; }
  sleep 0.2
done

# The rule files the site loads, so a test of a rule it does not load is
# reported as such rather than as a failure.
RULE_FILES=()
while read -r f; do RULE_FILES+=(--rule-file "$REPO/$f"); done \
  < <(sed -n 's/^ *- "\(rules\/[^"]*\.conf\)"$/\1/p' "$CONFIG")

set +e
python3 "$HERE/crs-regression.py" "$SUITE" --port "$WAF_PORT" \
  --dp-log "$OUT/dataplane.log" --waf-log "$OUT/logs/waf.log" \
  "${RULE_FILES[@]}" --binary "$WAF_BIN" --config "$CONFIG" \
  --engine "sentinel-bin $(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)" \
  --json "$OUT/results.json" "$@"
STATUS=$?
set -e
echo "results: $OUT/results.json (exit $STATUS)"
exit "$STATUS"
