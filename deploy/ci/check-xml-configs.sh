#!/usr/bin/env bash
# =============================================================================
#  Every XML config this repo ships must be well-formed.
#
#  WHY THIS IS A GATE AND NOT A NICETY
#
#  These files are mounted into ClickHouse's config.d. ClickHouse validates its
#  configuration at startup and REFUSES TO BOOT if it is wrong — correct
#  behaviour, but it means a malformed drop-in does not degrade anything
#  gracefully: the event store simply does not come up, and on a customer box
#  that is the security log going dark.
#
#  Both failure modes are real and were hit while writing clickhouse-logging.xml:
#
#    * XML comments may not contain a double hyphen. A row of dashes used as a
#      visual separator inside a comment is not well-formed XML, and nothing in
#      the editing loop says so.
#
#    * A <ttl> on a system log whose packaged config already specifies an
#      <engine> is rejected outright: "If 'engine' is specified for system
#      table, TTL parameters should be specified directly inside 'engine'".
#      ClickHouse exits 36 and the container crash-loops.
#
#  This gate catches the first class, which is pure syntax and costs nothing to
#  check. The second is semantic and needs a real server, so it is verified by
#  booting the actual image when the config changes — see the notes in
#  clickhouse-logging.xml.
# =============================================================================
set -uo pipefail

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; DIM=$'\e[2m'; B=$'\e[1m'; R=$'\e[0m'

cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

printf '\n%s%s==> shipped XML configs are well-formed%s\n\n' "$B" "$YEL" "$R"

# Pick a parser. xmllint is the usual one; python3 is a fallback for a developer
# box that has it. If NEITHER is present the gate FAILS — a check that quietly
# skips is how a broken file reaches a customer.
PARSER=""
if command -v xmllint >/dev/null 2>&1; then
  PARSER=xmllint
elif command -v python3 >/dev/null 2>&1; then
  PARSER=python3
else
  printf '  %s✗%s no XML parser available (need xmllint or python3)\n' "$RED" "$R"
  printf '      %sinstall libxml2-utils in the CI image — this gate must not skip%s\n\n' "$DIM" "$R"
  exit 1
fi

check_one() {
  case "$PARSER" in
    xmllint) xmllint --noout "$1" 2>&1 ;;
    python3) python3 -c 'import sys,xml.etree.ElementTree as ET
try:
    ET.parse(sys.argv[1])
except Exception as e:
    print(e); sys.exit(1)' "$1" 2>&1 ;;
  esac
}

fail=0
found=0
while read -r f; do
  found=$((found + 1))
  if err=$(check_one "$f"); then
    printf '  %s✓%s %s\n' "$GRN" "$R" "$f"
  else
    printf '  %s✗%s %s\n' "$RED" "$R" "$f"
    printf '      %s%s%s\n' "$DIM" "$(printf '%s' "$err" | head -2 | tr '\n' ' ')" "$R"
    fail=$((fail + 1))
  fi
done < <(find deploy configs -name '*.xml' -type f 2>/dev/null | sort)

printf '\n'
if (( found == 0 )); then
  printf '  %s✗%s found no XML files — the search path is wrong\n\n' "$RED" "$R"
  exit 1
fi
if (( fail == 0 )); then
  printf '  %s✓%s %d XML config(s) parse (via %s)\n\n' "$GRN" "$R" "$found" "$PARSER"
  exit 0
fi
printf '  %s✗%s %d of %d XML config(s) are malformed\n' "$RED" "$R" "$fail" "$found"
printf '      %sa ClickHouse drop-in that will not parse means the server will not boot%s\n\n' "$DIM" "$R"
exit 1
