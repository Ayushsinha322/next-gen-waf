#!/usr/bin/env bash
# Wait until enough REAL traffic has accumulated since the rules went live, then
# record the false-positive verdict once and stop.
#
# Polls rather than reporting early, because "nothing fired" over a small sample
# is not evidence. Detached, so a VPN drop cannot interrupt it.
set -uo pipefail
OUT=/root/fp-verdict.log
SINCE="${1:-$(docker inspect -f '{{.State.StartedAt}}' sentinel-waf2-1 | cut -c1-19)Z}"
: >"$OUT"
{
  echo "watching for real traffic since $SINCE  (started $(date -Is))"
  echo "will record a verdict once the sample reaches 100 real human requests"
  echo
} >>"$OUT"

for i in $(seq 1 60); do          # 60 x 15 min = 15 hours
  OUTPUT=$(/root/fp-recheck.sh "$SINCE" 2>&1); RC=$?
  case $RC in
    0)  { echo "=== VERDICT: CLEAN  ($(date -Is), after $((i*15)) min) ==="; echo "$OUTPUT"; } >>"$OUT"; exit 0 ;;
    1)  { echo "=== VERDICT: FALSE POSITIVE  ($(date -Is)) ==="; echo "$OUTPUT"; } >>"$OUT"; exit 1 ;;
    *)  n=$(echo "$OUTPUT" | grep -oE 'only [0-9]+ real' | grep -oE '[0-9]+' || echo '?')
        echo "$(date -u +%H:%MZ) still inconclusive — ${n} real requests so far" >>"$OUT" ;;
  esac
  sleep 900
done
{ echo "=== TIMED OUT after 15h without a usable sample ($(date -Is)) ==="
  echo "Nobody browsed enough for this to be answerable. Not a pass."
  /root/fp-recheck.sh "$SINCE" 2>&1
} >>"$OUT"
exit 2
