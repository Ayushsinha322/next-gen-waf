#!/usr/bin/env bash
# Run CRS's own regression suite against the REFERENCE engine — ModSecurity v2
# with the same CRS release, the owasp/modsecurity-crs image set up as CRS's own
# CI sets it up — with the same runner, suite and rule-family list as
# crs-regression.sh, so the two results compare case by case.
#
#   deploy/load-test/crs-regression-reference.sh [crs-regression.py options]
#
# OUT_DIR   logs and results.json (default target/crs-regression-ref)
# IMAGE     the reference image (default: CRS 4.7.0 on Apache, the shipped CRS)
#
# A case the reference passes and the product fails is a product gap; one both
# fail is the environment (no echo backend, a status CRS writes for Apache) or
# the suite. Needs Docker and the image (a one-time pull).
#
# Without CRS_ENABLE_TEST_MARKER: that rule (id 999999) switches every rule off
# for a request carrying `X-CRS-Test`, which is meant for go-ftw's own marker
# requests; the audit log already records each request's headers.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$REPO/deploy/load-test"
OUT="${OUT_DIR:-$REPO/target/crs-regression-ref}"
IMAGE="${IMAGE:-owasp/modsecurity-crs:4.7.0-apache-202410090410}"
SUITE="$REPO/rules/owasp-crs/tests/regression-4.7.0.json"
CONFIG="$HERE/crs-regression.yaml"
REF_PORT=18097
REF_SSL_PORT=18098
ORIGIN_PORT=18096
NAME="crs-regression-ref-$$"

mkdir -p "$OUT"
: > "$OUT/requests.jsonl"
: > "$OUT/waf.jsonl"

python3 "$HERE/origin-all-methods.py" "$ORIGIN_PORT" >"$OUT/origin.log" 2>&1 &
OPID=$!
docker run -d --name "$NAME" --network host \
  -e PORT="$REF_PORT" -e SSL_PORT="$REF_SSL_PORT" -e BACKEND="http://127.0.0.1:$ORIGIN_PORT" \
  -e SERVER_NAME=localhost -e MODSEC_RULE_ENGINE=DetectionOnly \
  -e BLOCKING_PARANOIA=4 -e DETECTION_PARANOIA=4 \
  -e VALIDATE_UTF8_ENCODING=1 -e ARG_NAME_LENGTH=100 -e ARG_LENGTH=400 \
  -e MAX_FILE_SIZE=64100 -e COMBINED_FILE_SIZES=65535 \
  -e MODSEC_AUDIT_ENGINE=On -e MODSEC_AUDIT_LOG_FORMAT=JSON -e MODSEC_AUDIT_LOG_TYPE=Serial \
  -e MODSEC_AUDIT_LOG=/dev/stdout -e MODSEC_AUDIT_LOG_PARTS=ABHZ \
  "$IMAGE" >/dev/null
# By PID and by this run's container name, never by pattern.
APID=""
trap 'kill "$OPID" ${APID:+"$APID"} 2>/dev/null || true; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 150); do
  if curl -s -o /dev/null -H 'Host: localhost' "http://127.0.0.1:$REF_PORT/"; then break; fi
  sleep 0.2
done
docker logs -f --since 1s "$NAME" 2>/dev/null \
  | python3 "$HERE/modsec-audit-adapter.py" "$OUT/requests.jsonl" "$OUT/waf.jsonl" &
APID=$!
sleep 1

RULE_FILES=()
while read -r f; do RULE_FILES+=(--rule-file "$REPO/$f"); done \
  < <(sed -n 's/^ *- "\(rules\/owasp-crs\/[^"]*\.conf\)"$/\1/p' "$CONFIG")

set +e
python3 "$HERE/crs-regression.py" "$SUITE" --port "$REF_PORT" \
  --dp-log "$OUT/requests.jsonl" --waf-log "$OUT/waf.jsonl" "${RULE_FILES[@]}" \
  --engine "reference $IMAGE" --json "$OUT/results.json" "$@"
STATUS=$?
set -e
echo "results: $OUT/results.json (exit $STATUS)"
exit "$STATUS"
