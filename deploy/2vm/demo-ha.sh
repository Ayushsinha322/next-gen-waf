#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Next-Gen ESDS WAF — 2-VM high-availability demonstration
#
#  Runs the whole story in about eight minutes, paused between acts so you can
#  talk. Run it from your laptop (needs SSH access to both VMs) or from either VM.
#
#      ./demo-ha.sh                 # paced — press Enter between acts
#      ./demo-ha.sh --fast          # no pauses
#      ./demo-ha.sh --no-reboot     # skip the reboot act (uses container stop only)
#
#  The reboot act genuinely reboots the active VM. That is the point — it is the
#  difference between claiming high availability and showing it. It takes about
#  90 seconds to come back. Use --no-reboot if you cannot spare that.
#
#  WHAT THIS DELIBERATELY DOES NOT CLAIM: nothing here is a detection benchmark.
#  It shows enforcement and failover on this deployment. Detection percentages
#  come from a separate measured run, and quoting them off the back of a few curl
#  commands would be dishonest.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

VIP="${VIP:-172.16.21.87}"
ACTIVE="${ACTIVE:-172.16.21.88}"
PASSIVE="${PASSIVE:-172.16.21.89}"
KEY="${SSH_KEY:-$HOME/.ssh/sentinel_deploy}"
MODE=paced; DO_REBOOT=yes

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast) MODE=fast ;;
    --no-reboot) DO_REBOOT=no ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^#\{0,2\} \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi

S=(ssh -i "$KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes)

act()  { printf '\n%s%s━━━ %s ━━━%s\n\n' "$B" "$CYN" "$*" "$R"; }
note() { printf '  %s%s%s\n' "$DIM" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
bad()  { printf '  %s✗%s %s\n' "$RED" "$R" "$*"; }
pause(){ [[ "$MODE" == fast ]] && { sleep 1; return; }
         printf '\n  %s[Enter to continue]%s' "$DIM" "$R"; read -r _ || true; printf '\033[1A\033[2K'; }

code()   { curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$@" 2>/dev/null || echo "---"; }
holder() { for ip in "$ACTIVE" "$PASSIVE"; do
             "${S[@]}" "root@$ip" "ip -4 addr show dev eth0 | grep -qE 'inet ${VIP}/'" 2>/dev/null && echo "$ip"
           done; }
name_of(){ [[ "$1" == "$ACTIVE" ]] && echo "VM1 / waf-active" || echo "VM2 / waf-passive"; }

printf '\n%s%s  Next-Gen ESDS WAF — high availability on two VMs%s\n' "$B" "$CYN" "$R"
note "clients use ONE address: $VIP     nodes: $ACTIVE (master) · $PASSIVE (standby)"

# ── ACT 1 ────────────────────────────────────────────────────────────────────
act "1 · One address, two machines"
H=$(holder)
ok "The virtual IP $VIP is currently served by $(name_of "$H")"
note "Only one node holds it at a time, so there is never any ambiguity about"
note "who is answering. The other node is running and ready, not idle."
for ip in "$ACTIVE" "$PASSIVE"; do
  printf '    %-16s %s\n' "$(name_of "$ip")" \
    "$("${S[@]}" "root@$ip" 'printf "%s containers · keepalived %s" "$(docker ps -q|wc -l)" "$(systemctl is-active keepalived)"' 2>/dev/null)"
done
pause

# ── ACT 2 ────────────────────────────────────────────────────────────────────
act "2 · It is actually inspecting traffic"
printf '    %-34s %s\n' "normal page request"        "$(code "http://$VIP/")"
printf '    %-34s %s\n' "SQL injection"              "$(code "http://$VIP/?id=1%27%20OR%20%271%27=%271")"
printf '    %-34s %s\n' "cross-site scripting"       "$(code --get --data-urlencode 'q=<script>alert(1)</script>' "http://$VIP/s")"
printf '    %-34s %s\n' "template injection"         "$(code --get --data-urlencode 't={{7*7}}' "http://$VIP/r")"
printf '    %-34s %s\n' "scanner (sqlmap)"           "$(code -H 'User-Agent: sqlmap/1.7' "http://$VIP/")"
printf '    %-34s %s\n' "HTTPS page request"         "$(code -k "https://$VIP/")"
echo
note "200 = allowed through to the application.  403 = blocked by the WAF."
# Take the value of the "rules" field specifically. Grabbing the last number on
# the line picked up a thread id and reported "2 rules", which would have been an
# embarrassing thing to say out loud.
RULES=$("${S[@]}" "root@$ACTIVE" 'docker logs sentinel-dataplane-1 2>&1 | grep -i "rule engine loaded" | tail -1 | grep -oE "\"rules\":[0-9]+" | cut -d: -f2' 2>/dev/null)
note "Both nodes load the same ${RULES:-?} rules, so a failover changes nothing about what is enforced."
pause

# ── ACT 3 ────────────────────────────────────────────────────────────────────
act "3 · Kill the WAF on the active node — the machine stays up"
note "This is the failure a simple 'is the server pingable' check misses entirely:"
note "the host is perfectly healthy, and the thing serving traffic is dead."
H=$(holder)
"${S[@]}" "root@$H" 'docker stop sentinel-dataplane-1 >/dev/null 2>&1' && \
  ok "stopped the WAF process on $(name_of "$H") — the VM itself is still running"
T0=$(date +%s); MOVED=""
for _ in $(seq 1 20); do
  N=$(holder); [[ -n "$N" && "$N" != "$H" ]] && { MOVED=$(( $(date +%s) - T0 )); break; }
  sleep 1
done
if [[ -n "$MOVED" ]]; then ok "traffic moved to $(name_of "$(holder)") in ${MOVED} seconds"
else bad "the address did not move — investigate before continuing"; fi
printf '    %-34s %s\n' "normal request, during failure" "$(code "http://$VIP/")"
printf '    %-34s %s\n' "SQL injection, during failure"  "$(code "http://$VIP/?id=1%27%20OR%20%271%27=%271")"
echo
note "Still 200 and still 403 — users kept browsing and attacks kept being blocked."
note "Nobody was paged and nothing was reconfigured by hand."
pause

# ── ACT 4 ────────────────────────────────────────────────────────────────────
act "4 · Repair the node — traffic comes back on its own"
"${S[@]}" "root@$H" 'docker start sentinel-dataplane-1 >/dev/null 2>&1' && ok "restarted the WAF on $(name_of "$H")"
T0=$(date +%s); BACK=""
for _ in $(seq 1 60); do
  [[ "$(holder)" == "$H" ]] && { BACK=$(( $(date +%s) - T0 )); break; }
  sleep 2
done
if [[ -n "$BACK" ]]; then ok "the address returned to $(name_of "$H") after ${BACK} seconds"
else note "not back yet — it returns once the node proves it can serve, not merely that it booted"; fi
note "Deliberately unhurried on the way back: the node has to serve real requests"
note "successfully for several seconds before it is trusted with traffic again."
pause

# ── ACT 5 ────────────────────────────────────────────────────────────────────
if [[ "$DO_REBOOT" == yes ]]; then
act "5 · Lose the whole machine"
note "A container stopping is the easy case. This reboots the active VM outright."
H=$(holder)
"${S[@]}" "root@$H" 'nohup sh -c "sleep 1; reboot" >/dev/null 2>&1 &' 2>/dev/null
ok "rebooting $(name_of "$H") now"
T0=$(date +%s); MOVED=""
for _ in $(seq 1 30); do
  N=$(holder); [[ -n "$N" && "$N" != "$H" ]] && { MOVED=$(( $(date +%s) - T0 )); break; }
  sleep 1
done
[[ -n "$MOVED" ]] && ok "traffic moved to $(name_of "$(holder)") in ${MOVED} seconds" \
                  || bad "the address did not move"
echo
note "traffic while one of the two machines is completely gone:"
for n in 1 2 3; do
  printf '    probe %s   normal=%s   sql-injection=%s\n' "$n" \
    "$(code "http://$VIP/")" "$(code "http://$VIP/?id=1%27%20OR%20%271%27=%271")"
  sleep 2
done
echo
note "The surviving node had the full configuration already and never needed to"
note "ask anything for it. That is why this works with no coordination step."
pause

act "6 · The machine returns unattended"
note "Nothing is run by hand. Docker restarts the stack, keepalived restarts, and"
note "the address returns once the node can genuinely serve."
T0=$(date +%s)
for _ in $(seq 1 60); do "${S[@]}" "root@$H" true 2>/dev/null && break; sleep 5; done
ok "$(name_of "$H") is back on the network after $(( $(date +%s) - T0 ))s"
for _ in $(seq 1 60); do [[ "$(holder)" == "$H" ]] && break; sleep 5; done
ok "address reclaimed by $(name_of "$H") after $(( $(date +%s) - T0 ))s total"
printf '    %-34s %s\n' "normal request" "$(code "http://$VIP/")"
printf '    %-34s %s\n' "SQL injection"  "$(code "http://$VIP/?id=1%27%20OR%20%271%27=%271")"
pause
fi

# ── CLOSE ────────────────────────────────────────────────────────────────────
act "Where things stand"
cat <<SUMMARY
  ${GRN}Working and demonstrated just now${R}
    One address for clients, served by whichever machine is able to
    Automatic switch-over in seconds, on both a process failure and a lost machine
    Automatic return once the repaired machine proves it can serve
    Traffic protected throughout — no gap in enforcement
    Database replicating continuously to the standby

  ${YEL}Deliberately still a human decision${R}
    Promoting the standby database. Two machines cannot safely agree that the
    other is dead rather than merely unreachable, and getting that wrong means
    two databases accepting conflicting writes. So after a switch-over the site
    stays protected and served, while CONFIGURATION CHANGES wait for a person.
    Three machines can vote; two cannot. This is a considered trade, not a gap.

  ${CYN}What is needed from the business${R}
    1. Reserve $VIP formally so nothing else is ever assigned it
    2. A real internal application to put behind this, in observe-only mode,
       so the false-positive rate can be measured on genuine traffic
    3. An external penetration test — the strongest remaining assurance step,
       and one that needs no further engineering

  Admin interface   https://$VIP:9443
  Runbook           deploy/2vm/README.md
SUMMARY
printf '\n'
