#!/usr/bin/env bash
# Pull REAL evasion payloads from live public lists for ML training.
# DISCIPLINE: none of these are GoTestWAF's payloads — GoTestWAF stays a held-out
# benchmark so the score stays honest.
set -uo pipefail
OUT=/tmp/claude-1000/-home-ayush3750-waf-development/cbcb63a2-92d2-4e2b-ab24-29bdba5eb6c3/scratchpad/evasion-corpus
mkdir -p "$OUT"; cd "$OUT"
get() { # name url
  local n="$1" u="$2"
  if timeout 25 curl -fsSL "$u" -o "$n" 2>/dev/null; then
    printf "  %-28s %6s lines  %8s bytes  OK\n" "$n" "$(wc -l <"$n")" "$(wc -c <"$n")"
  else
    printf "  %-28s  --  FAILED (%s)\n" "$n" "$u"; rm -f "$n"
  fi
}
B=https://raw.githubusercontent.com
echo "=== XSS ==="
get xss_payloadbox.txt   "$B/payloadbox/xss-payload-list/master/Intruder/xss-payload-list.txt"
get xss_portswigger.txt  "$B/payloadbox/xss-payload-list/master/Intruder/xss-events.txt"
echo "=== SQLi ==="
get sqli_generic.txt     "$B/payloadbox/sql-injection-payload-list/master/Intruder/detect/Generic_SQLI.txt"
get sqli_gen_fuzz.txt    "$B/payloadbox/sql-injection-payload-list/master/Intruder/detect/GenericBlind.txt"
get sqli_mysql.txt       "$B/payloadbox/sql-injection-payload-list/master/Intruder/exploit/MySQL.txt"
get sqli_auth_bypass.txt "$B/payloadbox/sql-injection-payload-list/master/Intruder/Auth_Bypass.txt"
echo "=== command injection ==="
get cmdi_payloadbox.txt  "$B/payloadbox/command-injection-payload-list/master/command-injection-payload-list.txt"
echo "=== path traversal / LFI ==="
get lfi_traversal.txt    "$B/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory_traversal.txt"
echo "=== SSTI ==="
get ssti_all.txt         "$B/payloadbox/ssti-payloads/master/ssti.txt"
echo
echo "=== TOTAL pulled ==="
wc -l ./*.txt 2>/dev/null | tail -1
echo "(files in $OUT)"
