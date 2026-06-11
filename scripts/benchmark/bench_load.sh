#!/usr/bin/env bash
# Benchmark script for Sentinel WAF — comparing clean vs malicious traffic
# with early-exit optimization
set -euo pipefail

REPO="/home/ayush3750/waf-development"
WAF_BIN="$REPO/target/release/sentinel-bin"
TMPDIR=$(mktemp -d /tmp/sentinel-bench-XXXXX)
trap "rm -rf $TMPDIR; kill %1 %2 2>/dev/null || true" EXIT

echo "=== Sentinel WAF Load Test ==="
echo ""

# ── 1. Build SRL rules (200 rules + threshold rule) ──
RULES_DIR="$TMPDIR/rules"
mkdir -p "$RULES_DIR"

{
echo "# 200 benchmark rules — each scores +5 on matching its pattern"
for i in $(seq 1 200); do
cat <<RULE
rule $i {
    phase    : request_body
    targets  : ARGS
    operator : rx /(?i)attack_pattern_$i/
    score    : +5
    severity : critical
    message  : "Rule $i"
    action   : score
}
RULE
done

cat <<'THRESHOLD'
rule 999999 {
    phase    : request_body
    operator : anomaly_score >= 5
    action   : block
    message  : "Anomaly threshold exceeded"
}
THRESHOLD
} > "$RULES_DIR/bench_rules.srl"

echo "  Rules: $RULES_DIR/bench_rules.srl ($(grep -c 'rule ' "$RULES_DIR/bench_rules.srl") rules)"

# ── 2. Backend ──
BACKEND_PORT=18180
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length','2')
        self.end_headers()
        self.wfile.write(b'OK')
    def do_POST(self):
        l=int(self.headers.get('Content-Length',0))
        self.rfile.read(l)
        self.send_response(200)
        self.send_header('Content-Length','2')
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self,f,*a): pass
HTTPServer(('127.0.0.1',$BACKEND_PORT),H).serve_forever()
" &
BACKEND_PID=$!
sleep 1

# ── 3. WAF config ──
WAF_PORT=19080
cat > "$TMPDIR/sentinel.yaml" <<YAML
cluster:
  name: bench
  node_id: bench-1

listeners:
  - name: http
    bind: "127.0.0.1:$WAF_PORT"
    protocol: http1

sites:
  - id: bench
    domains: ["localhost", "127.0.0.1"]
    upstream:
      load_balancer: round_robin
      servers:
        - { host: "127.0.0.1", port: $BACKEND_PORT, weight: 1 }
    waf:
      mode: blocking
      paranoia_level: 1
      anomaly_threshold: 5
      rules:
        - "$RULES_DIR/bench_rules.srl"

logging:
  level: warn
  format: json
  outputs:
    - type: stdout
YAML

# ── 4. Start WAF ──
mkdir -p /tmp/sentinel-logs
SENTINEL_CONFIG="$TMPDIR/sentinel.yaml" RUST_LOG=warn "$WAF_BIN" &
WAF_PID=$!
sleep 3

# Verify both are up
curl -sf "http://127.0.0.1:$BACKEND_PORT/" >/dev/null || { echo "ERROR: Backend down"; exit 1; }
curl -sf "http://127.0.0.1:$WAF_PORT/" >/dev/null || { echo "ERROR: WAF down"; exit 1; }
echo "  Backend :$BACKEND_PORT and WAF :$WAF_PORT responding OK"
echo ""

# ── 5. Benchmarks ──
run_siege() {
    local label="$1" url="$2"
    local result rps
    result=$(siege -b -c50 -t10s "$url" 2>&1 || true)
    rps=$(echo "$result" | grep -oP '[\d.]+(?= trans/s)' || echo "N/A")
    echo "$rps"
}

echo "  ┌──────────────────────────────────┬──────────┬──────────┐"
echo "  │ Test                             │  req/s   │ vs. Base │"
echo "  ├──────────────────────────────────┼──────────┼──────────┤"

# Baseline
B_RPS=$(run_siege "Backend direct" "http://127.0.0.1:$BACKEND_PORT/")
printf "  │ Backend directly (GET)           │ %8s │ 1.00x    │\n" "$B_RPS"

# WAF clean GET (early-exit has NO effect — no rules fire)
W_CLEAN=$(run_siege "WAF clean GET" "http://127.0.0.1:$WAF_PORT/")
ratio1=$(echo "scale=1; $B_RPS / $W_CLEAN" | bc 2>/dev/null || echo "N/A")
printf "  │ Through WAF GET (clean)          │ %8s │ %sx      │\n" "$W_CLEAN" "${ratio1}"

# WAF malicious GET — queries match rule 1 AND rule 2, score=10 > threshold=5
W_MAL=$(run_siege "WAF malicious GET" "http://127.0.0.1:$WAF_PORT/?q=attack_pattern_1&x=attack_pattern_2")
ratio2=$(echo "scale=1; $B_RPS / $W_MAL" | bc 2>/dev/null || echo "N/A")
printf "  │ Through WAF GET (malicious)      │ %8s │ %sx      │\n" "$W_MAL" "${ratio2}"

echo "  └──────────────────────────────────┴──────────┴──────────┘"

# Verify the malicious traffic IS being blocked (early-exit is doing its job)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$WAF_PORT/?q=attack_pattern_1&x=attack_pattern_2")
if [ "$STATUS" = "403" ]; then
    echo ""
    echo "  ✓ Malicious requests correctly blocked (HTTP $STATUS) — early-exit active"
else
    echo ""
    echo "  ✗ Expected HTTP 403, got $STATUS — check anomaly threshold config"
fi

# Cleanup
kill $WAF_PID 2>/dev/null || true
kill $BACKEND_PID 2>/dev/null || true
echo "  Done."