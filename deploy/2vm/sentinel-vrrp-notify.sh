#!/usr/bin/env bash
# Records every VRRP transition. keepalived calls this as:
#   notify <INSTANCE|GROUP> <name> <MASTER|BACKUP|FAULT|STOP> <priority>
#
# Logging exists because a failover that nobody noticed is the hardest kind to
# debug afterwards: you are left guessing whether the VIP moved at all, when, and
# in which direction.
set -uo pipefail

TYPE="${1:-?}"; NAME="${2:-?}"; STATE="${3:-?}"; PRIO="${4:-?}"
LOG=/var/log/sentinel-vrrp.log
TS=$(date -Is)

printf '%s %s %s -> %s (priority %s)\n' "$TS" "$TYPE" "$NAME" "$STATE" "$PRIO" >> "$LOG"
logger -t sentinel-vrrp "$TYPE $NAME -> $STATE (priority $PRIO)"

# Becoming MASTER on the passive VM does NOT promote Postgres. The database stays a
# read-only standby until a human runs promote-standby.sh, so traffic is protected
# and served while configuration changes are refused. Spell that out here, because
# this log is where someone will look during an incident.
if [ "$STATE" = "MASTER" ] && [ -f /etc/sentinel/2vm-role ] &&
   grep -q '^slave$' /etc/sentinel/2vm-role 2>/dev/null; then
  printf '%s NOTE: this node now holds the VIP but its Postgres is still a READ-ONLY standby.\n' "$TS" >> "$LOG"
  printf '%s NOTE: traffic is being served and protected. Config WRITES will fail until you run promote-standby.sh.\n' "$TS" >> "$LOG"
  logger -t sentinel-vrrp "holding VIP with a read-only standby DB; run promote-standby.sh to accept config writes"
fi
