#!/usr/bin/env bash
# Did the four previously-inert CRS encoding rules actually come alive, did the
# importer stop shouting about rules that are fine, and does a site with no mode
# fail closed?
#
# Run ON the WAF host. Read-only apart from the probe requests it sends.
#
# Why each check exists:
#   - 920220/920221/920240 compiled to `Never` because their operator sat in a
#     chain CHILD. The rule was counted as loaded and could never match, so the
#     only honest test is to send malformed encoding and look for the record.
#   - The coverage report said "zero gap" throughout, because it inspected only
#     the top-level operator. So this does NOT trust the report — it probes.
#   - 216 benign WARN lines used to bury the 10 that mattered, 20:1. A log
#     channel nobody can read is the same as no channel, so the noise level is
#     itself a check.
#
# NOTE ON MODE: .71 runs the Juice Shop site in LEARNING mode for the
# false-positive pilot. Rule hits there are recorded with action=DETECT and the
# request is served with 200. That is correct and expected — these checks look
# for the RECORD, not for a 403. Asserting 403 here would fail on a healthy box.
set -uo pipefail
H="${PROBE_HOST:-wafdemo.esds.local}"
LOGDIR="${SENTINEL_LOG_VOLUME:-/var/lib/docker/volumes/sentinel_sentinel-logs/_data}"
pass=0; fail=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mNOTE\033[0m  %s\n" "$1"; }

M="encv$$"
probe() { curl -sk -o /dev/null -w '%{http_code}' --max-time 8 -H "Host: $H" "https://127.0.0.1$1&m=$M"; }
# Was rule $1 recorded for any request carrying our marker?
#
# `|| true`, NOT `|| echo 0`: grep -c already prints 0 when it finds nothing, and
# exits 1 while doing so. The `|| echo 0` this replaces therefore emitted BOTH
# lines, so the caller received "0\n0", every [ -eq ] comparison died with
# "integer expression expected", and the && chain reported a FALSE FAILURE saying
# an encoding rule had fired on ordinary traffic. The probe data on the line above
# it said 0. A verifier that cries wolf gets ignored, which is worse than one that
# is merely absent.
recorded() {
  grep -h "$M" "$LOGDIR"/waf*/waf.log 2>/dev/null \
    | grep -c "\"rule\":\"$1\"" || true
}

echo "=== 1. the importer no longer warns about rules that are fine ==="
for n in waf1 waf2 waf3; do
  c="sentinel-$n-1"
  docker inspect "$c" >/dev/null 2>&1 || continue
  SCORE=$(docker logs "$c" 2>&1 | grep -c "action:score but no score field")
  DISABLED=$(docker logs "$c" 2>&1 | grep -c "rule disabled")
  UNKNOWN=$(docker logs "$c" 2>&1 | grep -c "unknown target token")
  printf "    %s: score-gap=%s  rule-disabled=%s  unknown-target=%s\n" "$n" "$SCORE" "$DISABLED" "$UNKNOWN"
  [ "$SCORE" -eq 0 ] \
    && ok "$n: the 216 benign score-gate warnings are gone (now debug)" \
    || bad "$n: $SCORE score-gap warnings still at WARN — they bury the ones that matter"
  [ "$DISABLED" -eq 0 ] \
    && ok "$n: no CRS rule reported as disabled by an unsupported operator" \
    || bad "$n: $DISABLED rules still disabled — run 'docker logs $c | grep \"rule disabled\"'; the message now names the rule_id"
  [ "$UNKNOWN" -eq 0 ] \
    && ok "$n: no unknown target tokens" \
    || bad "$n: $UNKNOWN unknown target tokens — the message now names the rule_id"
done

echo
echo "=== 2. a disabled-rule warning, if it ever returns, must name the RULE ==="
# Not a behaviour check — a message-format check, so the next person does not have
# to grep the CRS sources to learn which rule went silent.
SAMPLE=$(docker logs sentinel-waf1-1 2>&1 | grep -m1 "rule disabled")
if [ -z "$SAMPLE" ]; then
  ok "nothing disabled, so nothing to name"
else
  echo "$SAMPLE" | grep -q "rule_id" \
    && ok "the warning names rule_id" \
    || bad "a rule was disabled and the warning does NOT name it: $SAMPLE"
fi

echo
echo "=== 3. THE DECIDING CHECK — malformed percent-encoding is now detected ==="
echo "    (920220 was present, counted as loaded, and could never fire)"
for q in "/index.php?p=%zz" "/index.php?p=%2" "/search?q=ok%41%"; do
  CODE=$(probe "$q")
  printf "    %-28s -> %s\n" "$q" "$CODE"
done
sleep 5
N920220=$(recorded 920220)
echo "    920220 records for these probes: $N920220"
[ "$N920220" -gt 0 ] \
  && ok "920220 fires on malformed percent-encoding — the rule is genuinely live" \
  || bad "920220 did NOT fire. It is loaded and inert, which is what this change was for. \
Check that the running image is the one built from this branch."

echo
echo "=== 4. the other direction — legitimate URLs stay quiet ==="
echo "    (a protocol rule that fires on ordinary traffic is worse than a missing one)"
M="encvclean$$"
for q in "/?x=1" "/search?q=a%20b" "/rest/products/search?q=%41%42%43" "/caf%C3%A9?a=1" "/?fbclid=IwAR2--xyz-abcDEF_ghi"; do
  CODE=$(probe "$q")
  printf "    %-42s -> %s\n" "$q" "$CODE"
done
sleep 5
CLEAN220=$(recorded 920220); CLEAN221=$(recorded 920221)
echo "    920220=$CLEAN220  920221=$CLEAN221 on legitimate URLs"
{ [ "$CLEAN220" -eq 0 ] && [ "$CLEAN221" -eq 0 ]; } \
  && ok "no encoding rule fired on legitimate traffic" \
  || bad "an encoding rule fired on ordinary URLs — false-positive risk, do not leave deployed"

echo
echo "=== 5. existing protection is unchanged ==="
# The standing constraint: SQLi/XSS/traversal must still be detected. On this box
# that means a RECORD with action=DETECT, not a 403 — see the note at the top.
M="encvattack$$"
probe "/?q=1'+OR+'1'='1" >/dev/null
probe "/?q=<script>alert(1)</script>" >/dev/null
probe "/?q=../../../../etc/passwd" >/dev/null
sleep 5
HITS=$(grep -h "$M" "$LOGDIR"/waf*/waf.log 2>/dev/null | grep -cE '"rule":"(94[12]|930)[0-9]{3}"')
echo "    SQLi/XSS/traversal rule records: $HITS"
[ "$HITS" -ge 2 ] \
  && ok "SQLi/XSS/traversal still detected" \
  || bad "core attack detection regressed — only $HITS records"

echo
echo "=== 6. rule count and coverage, from the engine itself ==="
docker logs sentinel-waf1-1 2>&1 | grep -oE '"rules": [0-9]+' | tail -1 | sed 's/^/    /'
GAP=$(docker logs sentinel-waf1-1 2>&1 | grep -c "rule coverage gap")
[ "$GAP" -eq 0 ] \
  && ok "the engine reports no coverage gap (and now counts chain children)" \
  || bad "$GAP coverage-gap warnings — read them, they now list the rule ids"

echo
echo "=== 7. a site with no mode must fail CLOSED ==="
# Cannot be exercised through a live site without editing the running config, so
# this asserts the unit that governs it, inside the built binary's own crate.
note "covered by sentinel-core's config tests (a_waf_policy_with_no_mode_defaults_to_blocking)"
note "this box's Juice Shop site is explicitly 'learning' for the FPR pilot — unchanged by that fix"
MODE=$(docker logs sentinel-waf1-1 2>&1 | grep -c "has no .mode. — defaulting to BLOCKING")
[ "$MODE" -eq 0 ] \
  && ok "no site reached the fail-closed default (every site sent an explicit mode)" \
  || bad "$MODE site(s) had NO mode and were defaulted to blocking — the control plane dropped the key"

echo
echo "=== RESULT: $pass passed, $fail failed ==="
exit $(( fail > 0 ))
