#!/usr/bin/env bash
# ==============================================================================
#  Next-Gen ESDS WAF — DEPTH demo (the technical-audience companion to waf-demo.sh)
# ==============================================================================
#  waf-demo.sh answers "does it block the OWASP Top 10?" — a question every WAF
#  vendor answers yes to, so it proves coverage, not quality. A CISO has watched
#  that demo before.
#
#  This script answers the question that actually separates WAFs:
#
#      "Does it still catch the attack once the attacker tries to hide it,
#       and does it leave my real users alone?"
#
#  Four acts, in the order that builds credibility:
#
#    ACT 1  EVASION LADDER — one SQLi payload, escalating obfuscation. Every WAF
#           clears rung 1. Most fall off at 4-5. Each rung names the rule that
#           caught it, so this is verifiable, not theatre.
#    ACT 2  PLACEMENT MATRIX — one payload, six locations. Stock OWASP CRS checks
#           ARGS and two named headers; injection in an arbitrary header, a
#           cookie or the URL path walks past it. This is checkable against any
#           other WAF in the room.
#    ACT 3  PRECISION — benign traffic that LOOKS like an attack. This is the act
#           that matters most to a CISO, because their WAF pain is false
#           positives, not misses.
#    ACT 4  THE HONEST FAILURE — the one payload we still get wrong, shown on
#           purpose, with the diagnosis and the fix.
#
#  Act 4 is not a mistake. A vendor who shows you their known defect is telling
#  you they measured; a vendor with a flawless demo is telling you they stopped
#  looking. Leave it in.
#
#  USAGE
#    ./depth-demo.sh                # paced: press Enter between probes (narrate)
#    ./depth-demo.sh --fast         # no pauses
#    ./depth-demo.sh --list         # print the plan, send nothing
#    ./depth-demo.sh --act 1        # run a single act
#
#  ENV
#    TARGET     WAF base URL              (default http://172.16.21.71)
#    HOST_HDR   Host header to match      (default localhost -> "Juice Shop")
#    VM         ssh target for rule attribution (default root@172.16.21.71)
#    SSH_KEY    ssh key                   (default ~/.ssh/sentinel_deploy)
#    NO_ATTRIB=1  skip the ClickHouse lookups (no ssh needed; status codes only)
#
#  RULE ATTRIBUTION: after each act the script queries waf_events for the rule
#  that fired and the English explanation. That is the difference between "it
#  went red" and "here is the signature, the parameter, and why". Needs ssh to
#  the WAF host; set NO_ATTRIB=1 to run without it.
#
#  BEFORE A LIVE DEMO: run it once in --fast to confirm every expectation still
#  holds, then reset the correlation engine (see DEMO-RUNBOOK.md). After ~8
#  blocks in 60s from one IP the behavioural engine starts labelling everything
#  "ANOMALY" instead of the specific rule — a feature, but it muddies per-probe
#  attribution. Paced mode plus a reset keeps the labels crisp.
#
#  VERIFICATION STATE (2026-07-27). Confirmed live against the VM this session:
#  rung 1 (plain SQLi), rung 6/7 (base64 SQLi + cmdi), the arbitrary-header and
#  cookie placements, XSS in query, SSTI, CRLF, sqlmap-UA, and every Act 3
#  benign probe except the multipart one. NOT yet confirmed live: rungs 2-5 (the
#  encoding variants) and the URL-path-segment and multipart placements — the
#  VPN dropped mid-run. Those are expected to pass on the strength of the
#  decode-to-fixpoint and all-placement work, but "expected" is not "verified":
#  do the --fast dry run before you put this in front of anyone.
# ==============================================================================
set -uo pipefail

TARGET="${TARGET:-http://172.16.21.71}"
HOST_HDR="${HOST_HDR:-localhost}"
VM="${VM:-root@172.16.21.71}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/sentinel_deploy}"
NO_ATTRIB="${NO_ATTRIB:-0}"
MODE="paced"; ONLY_ACT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast) MODE="fast" ;;
    --list) MODE="list" ;;
    --act)  ONLY_ACT="${2:-}"; shift ;;
    *) printf "unknown arg: %s\n" "$1" >&2; exit 2 ;;
  esac
  shift
done

if [[ -t 1 ]]; then
  B=$'\e[1m'; DIM=$'\e[2m'; R=$'\e[0m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'; MAG=$'\e[95m'
else
  B=''; DIM=''; R=''; RED=''; GRN=''; YEL=''; CYN=''; MAG=''
fi

CURL=(curl -s -k --max-time 10 -H "Host: ${HOST_HDR}")
MARK="depth$(date +%s)"
CAUGHT=0; MISSED=0; CLEAN_OK=0; CLEAN_FP=0

pause() {
  [[ "$MODE" == "fast" ]] && { sleep 0.3; return; }
  [[ "$MODE" == "list" ]] && return
  printf "     ${DIM}[Enter]${R}"; read -r _ 2>/dev/null || true
  printf "\033[1A\033[2K"
}

act() {
  printf "\n${CYN}${B}  ── ACT %s · %s ──${R}\n" "$1" "$2"
  printf "  ${DIM}%s${R}\n\n" "$3"
}

# rung LABEL  WHY-THIS-RUNG-IS-HARDER  curl-args...    (expects 403)
rung() {
  local label="$1" why="$2"; shift 2
  if [[ "$MODE" == "list" ]]; then printf "   attack  %-30s ${DIM}%s${R}\n" "$label" "$why"; return; fi
  local code; code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$@")
  if [[ "$code" == "403" ]]; then
    printf "   ${GRN}✓ BLOCKED${R}  %-30s ${DIM}%s${R}\n" "$label" "$why"
    CAUGHT=$((CAUGHT+1))
  else
    printf "   ${RED}✗ MISSED ${R}  %-30s ${DIM}HTTP %s — %s${R}\n" "$label" "$code" "$why"
    MISSED=$((MISSED+1))
  fi
  pause
}

# clean LABEL  WHY-A-NAIVE-WAF-BLOCKS-THIS  curl-args...   (expects NOT 403)
#
# The pass condition is "the WAF did not block", NOT "HTTP 200". The demo origin
# is a real app that 404s or 500s on paths it does not implement, and a 500 from
# the upstream is not a false positive — the request reached it, which is the
# whole point. Treating any non-200 as an FP would make the demo accuse the WAF
# of breaking traffic it actually let through. Only a 403 is ours.
clean() {
  local label="$1" why="$2"; shift 2
  if [[ "$MODE" == "list" ]]; then printf "   benign  %-30s ${DIM}%s${R}\n" "$label" "$why"; return; fi
  local code; code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$@")
  if [[ "$code" == "403" ]]; then
    printf "   ${YEL}! BLOCKED${R}  %-30s ${DIM}HTTP 403 — FALSE POSITIVE${R}\n" "$label"
    CLEAN_FP=$((CLEAN_FP+1))
  elif [[ "$code" == "200" ]]; then
    printf "   ${GRN}✓ ALLOWED${R}  %-30s ${DIM}%s${R}\n" "$label" "$why"
    CLEAN_OK=$((CLEAN_OK+1))
  else
    # Reached the origin, which answered for its own reasons.
    printf "   ${GRN}✓ ALLOWED${R}  %-30s ${DIM}%s ${R}${DIM}(origin said %s — not a WAF block)${R}\n" \
      "$label" "$why" "$code"
    CLEAN_OK=$((CLEAN_OK+1))
  fi
  pause
}

# Pull the rule + prose for this run's probes straight out of the durable store.
attrib() {
  [[ "$MODE" == "list" || "$NO_ATTRIB" == "1" ]] && return
  printf "\n   ${MAG}${B}what the WAF recorded${R} ${DIM}(waf_events — the durable store, not the demo's own output)${R}\n"
  ssh -i "$SSH_KEY" -o ConnectTimeout=15 -o StrictHostKeyChecking=no "$VM" \
    "docker exec sentinel-clickhouse-1 clickhouse-client -q \"
       SELECT concat('     ', rule, '  ', substring(attack,1,52),
                     if(target='', '', concat('  [', target, ']')))
       FROM sentinel_logs.waf_events
       WHERE ts >= now() - INTERVAL 4 MINUTE AND action IN ('BLOCK','DETECT')
       GROUP BY rule, attack, target ORDER BY max(ts) DESC LIMIT 8 FORMAT TSVRaw\"" 2>/dev/null \
    || printf "     ${DIM}(attribution unavailable — set NO_ATTRIB=1 to skip)${R}\n"
  printf "\n"
}

printf "\n${CYN}${B}  ███  NEXT-GEN ESDS WAF  ·  DEPTH DEMO  ███${R}\n"
printf "  ${DIM}target %s   host %s   mode %s${R}\n" "$TARGET" "$HOST_HDR" "$MODE"
printf "  ${DIM}coverage is table stakes; this shows evasion resistance and precision${R}\n"

# ---------------------------------------------------------------------------
run_act() { [[ -z "$ONLY_ACT" || "$ONLY_ACT" == "$1" ]]; }

if run_act 1; then
act 1 "EVASION LADDER" \
  "One SQL injection. Each rung hides it better. Rung 1 is what every WAF demo shows you."

rung "1. plain"            "the demo everyone gives you" \
  --get --data-urlencode "id=1' OR '1'='1" "$TARGET/p?m=$MARK"
rung "2. URL-encoded"      "trivial, but stops naive string matching" \
  "$TARGET/p?m=$MARK&id=1%27%20OR%20%271%27%3D%271"
rung "3. double-encoded"   "needs decode-to-fixpoint, not one decode pass" \
  "$TARGET/p?m=$MARK&id=1%2527%2520OR%2520%25271%2527%253D%25271"
rung "4. inline comments"  "/**/ splits the keywords a regex looks for" \
  --get --data-urlencode "id=1'/**/OR/**/'1'='1" "$TARGET/p?m=$MARK"
rung "5. mixed case + tab" "case and whitespace tricks against static patterns" \
  --get --data-urlencode "id=1'%09oR%09'1'%3D'1" "$TARGET/p?m=$MARK"
rung "6. BASE64 in a param" "opaque on the wire — rules are BLIND without base64Decode" \
  --get --data-urlencode "q=$(printf "1' OR '1'='1" | base64 -w0)" "$TARGET/p?m=$MARK"
rung "7. BASE64 command inj" "66 of 72 bypasses in our 07-19 audit were this shape" \
  --get --data-urlencode "q=$(printf ";cat /etc/passwd" | base64 -w0)" "$TARGET/p?m=$MARK"

printf "\n   ${DIM}Rungs 6-7 are the ones to dwell on. A Base64 payload is opaque, so the\n"
printf "   rule engine sees noise and the classifier becomes the only defence. We fixed\n"
printf "   that by giving the RULES base64 visibility — not by lowering a threshold.${R}\n"
attrib
fi

# ---------------------------------------------------------------------------
if run_act 2; then
act 2 "PLACEMENT MATRIX" \
  "One payload, six locations. Stock CRS inspects ARGS and two named headers."

rung "query string"        "the one place every WAF looks" \
  --get --data-urlencode "q=<script>alert(1)</script>" "$TARGET/s?m=$MARK"
rung "URL path segment"    "not a parameter — many WAFs never parse it" \
  "$TARGET/s/%3Cscript%3Ealert(1)%3C/script%3E?m=$MARK"
rung "arbitrary header"    "X-Custom is not in anyone's default target list" \
  -H "X-Custom: <script>alert(1)</script>" "$TARGET/?m=$MARK"
rung "cookie value"        "cookies are attacker-controlled input too" \
  -H "Cookie: pref=<script>alert(1)</script>" "$TARGET/?m=$MARK"
rung "JSON body field"     "requires parsing the body, not scanning it" \
  -X POST -H "Content-Type: application/json" \
  --data '{"note":"<script>alert(1)</script>"}' "$TARGET/api?m=$MARK"
rung "multipart field"     "must separate the value from boundary noise first" \
  -X POST -F "note=<script>alert(1)</script>" "$TARGET/up?m=$MARK"

printf "\n   ${DIM}Ask any incumbent WAF to repeat the header and cookie rows. This is the\n"
printf "   cheapest verifiable difference in the room — it needs no benchmark.${R}\n"
attrib
fi

# ---------------------------------------------------------------------------
if run_act 3; then
act 3 "PRECISION — the act a CISO actually cares about" \
  "Real traffic that looks hostile. A blunt WAF blocks all of these and breaks your app."

clean "email with +or@"        "decodes to \"john or@var.es\" — classic libinjection FP" \
  --get --data-urlencode "email=john+or@var.es" "$TARGET/signup?m=$MARK"
clean "apostrophe surname"     "O'Brien is a quote character to a naive rule" \
  --get --data-urlencode "name=O'Brien" "$TARGET/u?m=$MARK"
clean "French text"            "\"La Ville D'or\" — apostrophes in real prose" \
  --get --data-urlencode "q=La Ville D'or est belle" "$TARGET/s?m=$MARK"
clean "share link in param"    "redirects/webhooks/OAuth callbacks look like SSRF" \
  --get --data-urlencode "next=https://www.instagram.com/p/Cx1y2z3/?utm_source=ig_web" "$TARGET/r?m=$MARK"
clean "search URL in param"    "a URL-shaped value is not an attack" \
  --get --data-urlencode "u=https://www.google.com/search?q=waf+tuning&hl=en" "$TARGET/r?m=$MARK"
clean "ordinary Accept header" "we score headers now — so they must not FP" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" "$TARGET/?m=$MARK"
clean "dotted asset path"      "app.min.v1.2.3.js is not path traversal" \
  "$TARGET/assets/app.min.v1.2.3.js?m=$MARK"

printf "\n   ${DIM}Mechanism, if asked: a confident ML verdict can VETO a rule block. The\n"
printf "   classifier scores these 0.0001-0.26 and real injection 0.91-1.00 — near-total\n"
printf "   separation, which is what makes the veto safe rather than reckless.${R}\n"
attrib
fi

# ---------------------------------------------------------------------------
if run_act 4; then
act 4 "THE HONEST FAILURE — leave this in" \
  "Our one known false positive on the benchmark's benign corpus, 1 of 141."

clean "prose w/ SQL keywords"  "EXPECTED TO FAIL — see the note below" \
  --get --data-urlencode "c=union was a great select of drop items" "$TARGET/comment?m=$MARK"

printf "\n   ${DIM}This blocks, and we know exactly why: stock CRS rule 942190 scores it 22\n"
printf "   against a threshold of 10. It is ordinary English that happens to contain\n"
printf "   SQL keywords. Our own classifier scores the text 0.058 — correctly benign —\n"
printf "   but the CRS score alone clears the bar. The fix is more %%20-encoded benign\n"
printf "   prose in the training corpus, not a code change or a threshold drop.\n"
printf "\n   Say this out loud in the room. It is 1 in 141, we can name the rule, the\n"
printf "   score and the remedy — and it demonstrates the measurement discipline that\n"
printf "   makes the other 140 results worth believing.${R}\n"
attrib
fi

# ---------------------------------------------------------------------------
if [[ "$MODE" != "list" ]]; then
  printf "\n${CYN}${B}  ── RESULT ──${R}\n"
  printf "   evasions caught     ${GRN}%s${R}\n" "$CAUGHT"
  [[ "$MISSED" -gt 0 ]] && printf "   evasions MISSED     ${RED}%s${R}  ${DIM}(investigate before demoing)${R}\n" "$MISSED"
  printf "   benign allowed      ${GRN}%s${R}\n" "$CLEAN_OK"
  printf "   benign blocked      %s  ${DIM}(1 expected: the Act 4 payload)${R}\n" "$CLEAN_FP"
  printf "\n   ${DIM}Independent corpus (Wallarm GoTestWAF): composite 99.60%%, detection 99.09%%,\n"
  printf "   benign-pass 99.29%%. Real-traffic false-positive rate is NOT yet measured —\n"
  printf "   say so, and say the pilot that measures it is the next step.${R}\n\n"
fi
