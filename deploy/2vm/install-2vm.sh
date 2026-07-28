#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  Sentinel WAF — 2-VM active/passive installer
#
#  Run it on VM 1, answer "master". Run it on VM 2, answer "slave". A virtual IP
#  follows whichever node can actually serve traffic, and moves back when the
#  master recovers.
#
#      ./install-2vm.sh                 # interactive
#      ./install-2vm.sh --role master --this 172.16.21.71 \
#                       --peer 172.16.21.72 --vip 172.16.21.70
#      ./install-2vm.sh --check         # verify an existing install, change nothing
#
#  WHAT FAILS OVER AUTOMATICALLY, AND WHAT DOES NOT
#
#  Automatic — traffic. The data plane is stateless and keeps enforcing its
#  last-synced configuration even with no control plane and no database, so the
#  surviving VM protects traffic on its own. keepalived moves the VIP within a few
#  seconds and moves it back when the master is healthy again.
#
#  Automatic — config write leadership. Both control planes contend for one
#  Postgres advisory lock; whichever holds it accepts writes and the other forwards.
#
#  NOT automatic — Postgres promotion, on purpose. Two nodes cannot establish a
#  majority, so nothing can safely decide that the peer is dead rather than merely
#  unreachable. Automating it is how you get two primaries taking divergent writes,
#  which is worse than the outage it was meant to prevent. So after the VIP moves:
#
#      traffic  → served and protected by the surviving node
#      config   → read-only until a human runs promote-standby.sh
#
#  That is the trade this topology makes. If you need automatic promotion too, it
#  takes a third arbitrator (a witness node or a shared lock) — which is the 3-VM
#  cluster, not this.
# ═══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "$SCRIPT_DIR/../docker" 2>/dev/null && pwd || echo "")"
ROLE_FILE=/etc/sentinel/2vm-role
STATE_DIR=/etc/sentinel

if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else
  B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; }
die()  { printf '\n  %s✗ %s%s\n\n' "$RED" "$*" "$R" >&2; exit 1; }

ROLE=""; THIS_IP=""; PEER_IP=""; VIP=""; IFACE=""; VIP_CIDR=""; MODE="install"
VRID="${SENTINEL_VRID:-51}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift ;;
    --this) THIS_IP="${2:-}"; shift ;;
    --peer) PEER_IP="${2:-}"; shift ;;
    --vip)  VIP="${2:-}"; shift ;;
    --iface) IFACE="${2:-}"; shift ;;
    --vrid) VRID="${2:-}"; shift ;;
    --check) MODE="check" ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^#\{0,2\} \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

# --check also needs root: the state it reads lives under /etc/sentinel, which is
# 0700 because it holds the VRRP password.
[[ $EUID -eq 0 ]] || die "run as root — this reads /etc/sentinel and manages keepalived"
[[ -n "$DOCKER_DIR" ]] || die "cannot find deploy/docker next to this script"

# ── validation helpers ───────────────────────────────────────────────────────
valid_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.; for o in $1; do (( o <= 255 )) || return 1; done; }

ask() { # ask VAR "prompt" "default"
  local __var="$1" __prompt="$2" __def="${3:-}" __ans=""
  if [[ -n "${!__var}" ]]; then return 0; fi     # already set by a flag
  if [[ -n "$__def" ]]; then
    read -r -p "  $__prompt [$__def]: " __ans || true
    __ans="${__ans:-$__def}"
  else
    read -r -p "  $__prompt: " __ans || true
  fi
  printf -v "$__var" '%s' "$__ans"
}

# ═════════════════════════════════════════════════════════════════════════════
step "Sentinel WAF — 2-VM active/passive"

if [[ "$MODE" == "check" ]]; then
  [[ -f "$ROLE_FILE" ]] || die "no install found ($ROLE_FILE missing)"
  say "  role:  $(cat "$ROLE_FILE")"
  say "  vip:   $(cat "$STATE_DIR/2vm-vip" 2>/dev/null || echo '?')"
  step "keepalived"
  systemctl is-active --quiet keepalived && ok "running" || warn "NOT running"
  ip -4 addr show | grep -q "$(cat "$STATE_DIR/2vm-vip" 2>/dev/null || echo 'no-vip')" \
    && ok "this node currently HOLDS the VIP" \
    || say "  ${DIM}this node does not hold the VIP (normal for the standby)${R}"
  step "data-plane health (what VRRP tracks)"
  if /usr/local/sbin/sentinel-vrrp-check.sh; then ok "healthy — eligible for the VIP"
  else warn "UNHEALTHY — this node would hand the VIP to its peer"; fi
  step "recent VRRP transitions"
  tail -n 8 /var/log/sentinel-vrrp.log 2>/dev/null | sed 's/^/  /' || say "  (none logged yet)"
  exit 0
fi

# ── 1. role ──────────────────────────────────────────────────────────────────
step "Step 1 of 6 — which node is this?"
if [[ -z "$ROLE" ]]; then
  say "  ${DIM}master = VM 1. Postgres PRIMARY, ClickHouse, and it prefers to hold the VIP.${R}"
  say "  ${DIM}slave  = VM 2. Postgres streaming STANDBY. Takes the VIP when VM 1 cannot serve.${R}"
  say ""
  say "  Run this on VM 1 first and answer master, then on VM 2 and answer slave."
  say ""
  while :; do
    read -r -p "  Are you [master] or [slave]? " ROLE || true
    ROLE="$(printf '%s' "${ROLE:-}" | tr '[:upper:]' '[:lower:]')"
    case "$ROLE" in
      master|m|active|primary) ROLE=master; break ;;
      slave|s|passive|standby|backup) ROLE=slave; break ;;
      *) warn "answer 'master' or 'slave'" ;;
    esac
  done
fi
ROLE="$(printf '%s' "$ROLE" | tr '[:upper:]' '[:lower:]')"
case "$ROLE" in
  master|active|primary) ROLE=master ;;
  slave|passive|standby|backup) ROLE=slave ;;
  *) die "--role must be master or slave, got '$ROLE'" ;;
esac
ok "role: ${B}${ROLE}${R}"

if [[ -f "$ROLE_FILE" ]] && [[ "$(cat "$ROLE_FILE")" != "$ROLE" ]]; then
  warn "this VM was previously installed as '$(cat "$ROLE_FILE")'"
  read -r -p "  Re-install as '$ROLE'? Type YES to continue: " c || true
  [[ "$c" == "YES" ]] || die "aborted — role unchanged"
fi

# ── 2. addressing ────────────────────────────────────────────────────────────
step "Step 2 of 6 — addressing"
DEF_IFACE="$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')"
DEF_IP="$(ip -4 -brief addr show "${DEF_IFACE:-lo}" 2>/dev/null | awk '{print $3}' | cut -d/ -f1 | head -1)"
DEF_CIDR="$(ip -4 -brief addr show "${DEF_IFACE:-lo}" 2>/dev/null | awk '{print $3}' | cut -d/ -f2 | head -1)"

ask IFACE   "Network interface carrying client traffic" "${DEF_IFACE:-eth0}"
ask THIS_IP "THIS VM's IP on $IFACE"                    "${DEF_IP:-}"
ask PEER_IP "The OTHER VM's IP"                          ""
ask VIP     "Virtual IP clients will use (must be FREE)" ""
VIP_CIDR="${VIP_CIDR:-${DEF_CIDR:-24}}"

valid_ip "$THIS_IP" || die "'$THIS_IP' is not a valid IPv4 address"
valid_ip "$PEER_IP" || die "'$PEER_IP' is not a valid IPv4 address"
valid_ip "$VIP"     || die "'$VIP' is not a valid IPv4 address"
[[ "$THIS_IP" != "$PEER_IP" ]] || die "this VM and the peer cannot share an address"
[[ "$VIP" != "$THIS_IP" && "$VIP" != "$PEER_IP" ]] || \
  die "the VIP must be a THIRD address, not either VM's own IP"
ip -4 -brief addr show | grep -q " ${IFACE} " || die "interface '$IFACE' not found"

ok "iface $IFACE · this $THIS_IP · peer $PEER_IP · vip $VIP/$VIP_CIDR · vrid $VRID"

# ── 3. preflight ─────────────────────────────────────────────────────────────
step "Step 3 of 6 — preflight"

command -v docker >/dev/null 2>&1 || die "docker is not installed"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed"
ok "docker $(docker --version | awk '{print $3}' | tr -d ,)"

if ping -c1 -W2 "$PEER_IP" >/dev/null 2>&1; then
  ok "peer $PEER_IP reachable"
else
  warn "peer $PEER_IP does not answer ping"
  say  "  ${DIM}Fine if ICMP is filtered, or if you are installing this VM first.${R}"
  say  "  ${DIM}VRRP is unicast to the peer, so the two must be able to reach each other${R}"
  say  "  ${DIM}on protocol 112 before failover will work.${R}"
fi

# A VIP that is already answering is either a stale install or, worse, an address
# in use by something else. Taking it would break whatever owns it.
if ping -c1 -W1 "$VIP" >/dev/null 2>&1; then
  if ip -4 addr show dev "$IFACE" | grep -q "inet $VIP/"; then
    ok "VIP already held by this node (re-install)"
  else
    warn "$VIP already answers and is NOT held by this node"
    say  "  ${DIM}Expected if the peer currently holds it. If nothing should own it yet,${R}"
    say  "  ${DIM}stop — that address is in use by another host.${R}"
    read -r -p "  Continue? Type YES: " c || true
    [[ "$c" == "YES" ]] || die "aborted"
  fi
else
  ok "VIP $VIP is free"
fi

MEM_GB=$(awk '/MemTotal/{printf "%d", $2/1024/1024}' /proc/meminfo)
CPUS=$(nproc)
DISK_GB=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
say "  capacity: ${CPUS} vCPU · ${MEM_GB}Gi RAM · ${DISK_GB}G free on /"
(( CPUS  >= 8 ))  || warn "8 vCPU recommended; throughput above 8 cores is unmeasured"
(( MEM_GB >= 12 )) || warn "12Gi is the floor and 16Gi recommended — ClickHouse alone is capped at 6Gi"
(( DISK_GB >= 80 )) || warn "80G free is the floor; 200G if you build images on this box"

# ── 4. .env ──────────────────────────────────────────────────────────────────
step "Step 4 of 6 — secrets and configuration"
ENV_FILE="$DOCKER_DIR/.env"

if [[ "$ROLE" == "master" ]]; then
  if [[ -f "$ENV_FILE" ]]; then
    ok ".env already present — leaving it alone"
  else
    [[ -f "$DOCKER_DIR/.env.example" ]] || die ".env.example missing; cannot generate .env"
    cp "$DOCKER_DIR/.env.example" "$ENV_FILE"
    gen() { openssl rand -hex 32; }
    set_kv() { # set_kv KEY VALUE — replace or append, never duplicate
      local k="$1" v="$2"
      if grep -qE "^${k}=" "$ENV_FILE"; then
        python3 - "$ENV_FILE" "$k" "$v" <<'PY'
import sys,re
p,k,v=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(p).read()
s=re.sub(r'^%s=.*$' % re.escape(k), k+'='+v.replace('\\','\\\\'), s, count=1, flags=re.M)
open(p,'w').write(s)
PY
      else
        printf '%s=%s\n' "$k" "$v" >> "$ENV_FILE"
      fi
    }
    PGPW="$(gen)"; REPLPW="$(gen)"; CHPW="$(gen)"
    set_kv POSTGRES_USER sentinel
    set_kv POSTGRES_DB sentinel
    set_kv POSTGRES_PASSWORD "$PGPW"
    set_kv CLICKHOUSE_USER sentinel
    set_kv CLICKHOUSE_DB sentinel_logs
    set_kv CLICKHOUSE_PASSWORD "$CHPW"
    set_kv SENTINEL_JWT_SECRET "$(gen)"
    set_kv SENTINEL_INTERNAL_SECRET "$(gen)"
    set_kv SENTINEL_AUDIT_HMAC_KEY "$(gen)"
    set_kv GRAFANA_ADMIN_PASSWORD "$(openssl rand -base64 24 | tr -d '\n/+=' | cut -c1-24)"
    set_kv SENTINEL_REPL_USER replicator
    set_kv SENTINEL_REPL_PASSWORD "$REPLPW"
    set_kv SENTINEL_STANDBY_CIDR "${PEER_IP}/32"
    set_kv SENTINEL_PG_BIND "$THIS_IP"
    set_kv SENTINEL_DB_URL "postgres://sentinel:${PGPW}@postgres:5432/sentinel?sslmode=disable"
    set_kv SENTINEL_DB_URL_PRIMARY "postgres://sentinel:${PGPW}@${THIS_IP}:5432/sentinel?sslmode=disable"
    set_kv SENTINEL_ALLOW_SUPERUSER_DB 1
    set_kv CLICKHOUSE_MEM_LIMIT 6g
    chmod 600 "$ENV_FILE"
    ok "generated .env with fresh secrets"
    warn "sslmode=disable is set for the replication DSNs. Run issue-postgres-cert.sh"
    say  "  ${DIM}and switch both DSNs to verify-full before this carries real traffic —${R}"
    say  "  ${DIM}replication streams the entire database across the network.${R}"
  fi
  say "  ${DIM}two files must be copied to the slave — exact commands are printed at the end${R}"
else
  # The slave CANNOT generate its own secrets. Different JWT/internal/HMAC values
  # would produce two stacks that reject each other's tokens and cannot verify the
  # audit chain — with no obvious symptom until something fails oddly later.
  [[ -f "$ENV_FILE" ]] || die \
"$ENV_FILE is missing.

  Copy it from the master FIRST — the slave must not generate its own secrets:

      scp root@${PEER_IP}:$ENV_FILE $ENV_FILE

  Both nodes must share SENTINEL_JWT_SECRET, SENTINEL_INTERNAL_SECRET,
  SENTINEL_AUDIT_HMAC_KEY and the database passwords. Divergent values give you two
  stacks that silently distrust each other."
  ok ".env present (copied from the master)"
  for k in SENTINEL_JWT_SECRET SENTINEL_INTERNAL_SECRET SENTINEL_AUDIT_HMAC_KEY \
           POSTGRES_PASSWORD SENTINEL_REPL_PASSWORD; do
    grep -qE "^${k}=.+" "$ENV_FILE" || die "$k is missing or empty in .env — re-copy it from the master"
  done
  ok "shared secrets present"
  # The standby's control plane and migrations must target the PRIMARY, since a
  # streaming standby is read-only.
  grep -qE "^SENTINEL_DB_URL_PRIMARY=.+" "$ENV_FILE" || \
    die "SENTINEL_DB_URL_PRIMARY missing in .env — it must point at the master's Postgres"
  ok "SENTINEL_DB_URL_PRIMARY set (writes go to the master)"
fi

# ── 5. keepalived ────────────────────────────────────────────────────────────
step "Step 5 of 6 — keepalived (the automatic part)"

if ! command -v keepalived >/dev/null 2>&1; then
  say "  installing keepalived…"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq keepalived >/dev/null 2>&1 \
      || die "apt could not install keepalived"
  else
    die "keepalived is not installed and this is not an apt system — install it, then re-run"
  fi
fi
ok "keepalived $(keepalived --version 2>&1 | head -1 | awk '{print $2}')"

install -d -m 0755 /usr/local/sbin
install -m 0755 "$SCRIPT_DIR/sentinel-vrrp-check.sh"  /usr/local/sbin/sentinel-vrrp-check.sh
install -m 0755 "$SCRIPT_DIR/sentinel-vrrp-notify.sh" /usr/local/sbin/sentinel-vrrp-notify.sh
ok "health-check and notify scripts installed"

# The master outranks the slave, so the VIP returns to VM 1 when it recovers —
# which is the failback behaviour asked for. preempt_delay holds it back for 30s
# after keepalived starts so a booting master does not snatch the VIP before its
# containers are actually serving; the health check then gates it regardless.
if [[ "$ROLE" == "master" ]]; then
  STATE=MASTER; PRIORITY=150
  PREEMPT_BLOCK="    # Reclaim the VIP on recovery, but not before this node can serve.
    preempt_delay 30"
else
  STATE=BACKUP; PRIORITY=100
  # Lower priority means the slave yields to a healthy master rather than holding
  # the VIP. The short delay only avoids a flap during its own startup.
  PREEMPT_BLOCK="    preempt_delay 5"
fi

VRRP_PASS_FILE="$STATE_DIR/2vm-vrrp-pass"
install -d -m 0700 "$STATE_DIR"
if [[ -f "$VRRP_PASS_FILE" ]]; then
  VRRP_PASS="$(cat "$VRRP_PASS_FILE")"
else
  # VRRP PASS auth is 8 characters maximum; longer values are silently truncated,
  # which would make the two nodes disagree and both become master.
  VRRP_PASS="$(openssl rand -hex 8 | cut -c1-8)"
  printf '%s' "$VRRP_PASS" > "$VRRP_PASS_FILE"; chmod 600 "$VRRP_PASS_FILE"
fi
if [[ "$ROLE" == "slave" ]]; then
  warn "VRRP auth password for this node: ${B}${VRRP_PASS}${R}"
  say  "  ${DIM}It must MATCH the master's (/etc/sentinel/2vm-vrrp-pass there). If it does${R}"
  say  "  ${DIM}not, copy the master's value into $VRRP_PASS_FILE and re-run.${R}"
fi

[[ -f /etc/keepalived/keepalived.conf ]] && \
  cp -a /etc/keepalived/keepalived.conf "/etc/keepalived/keepalived.conf.bak.$(date +%s)"
install -d -m 0755 /etc/keepalived
sed -e "s|__ROUTER_ID__|sentinel-$(hostname -s)|g" \
    -e "s|__STATE__|$STATE|g" \
    -e "s|__IFACE__|$IFACE|g" \
    -e "s|__VRID__|$VRID|g" \
    -e "s|__PRIORITY__|$PRIORITY|g" \
    -e "s|__THIS_IP__|$THIS_IP|g" \
    -e "s|__PEER_IP__|$PEER_IP|g" \
    -e "s|__VIP__|$VIP|g" \
    -e "s|__VIP_CIDR__|$VIP_CIDR|g" \
    -e "s|__VRRP_PASS__|$VRRP_PASS|g" \
    -e "s|__PREEMPT_BLOCK__|$PREEMPT_BLOCK|g" \
    "$SCRIPT_DIR/keepalived.conf.tmpl" > /etc/keepalived/keepalived.conf
chmod 640 /etc/keepalived/keepalived.conf
ok "/etc/keepalived/keepalived.conf written (state $STATE, priority $PRIORITY)"

printf '%s\n' "$ROLE" > "$ROLE_FILE"
printf '%s\n' "$VIP"  > "$STATE_DIR/2vm-vip"
chmod 644 "$ROLE_FILE" "$STATE_DIR/2vm-vip"

# ── 6. bring the stack up ────────────────────────────────────────────────────
step "Step 6 of 6 — starting the stack"
OVERLAY="compose.2vm-active.yml"; [[ "$ROLE" == "slave" ]] && OVERLAY="compose.2vm-passive.yml"
[[ -f "$DOCKER_DIR/$OVERLAY" ]] || die "$DOCKER_DIR/$OVERLAY missing"

C=(docker compose -p sentinel -f compose.prod.yml -f "$OVERLAY")
say "  ${DIM}cd $DOCKER_DIR && ${C[*]} up -d${R}"
( cd "$DOCKER_DIR" && "${C[@]}" config >/dev/null ) \
  || die "compose config is invalid — fix .env before starting (nothing was started)"
ok "compose config resolves"

( cd "$DOCKER_DIR" && "${C[@]}" up -d ) || die "compose up failed"
ok "containers started"

say "  waiting for the data plane to report healthy…"
HEALTHY=no
for _ in $(seq 1 30); do
  if /usr/local/sbin/sentinel-vrrp-check.sh; then HEALTHY=yes; break; fi
  sleep 2
done
if [[ "$HEALTHY" == "yes" ]]; then ok "data plane healthy"
else warn "data plane not healthy yet — keepalived will not claim the VIP until it is"
     say "  ${DIM}check: docker compose -p sentinel logs --tail=50 dataplane${R}"
fi

systemctl enable keepalived >/dev/null 2>&1 || true
systemctl restart keepalived || die "keepalived failed to start — journalctl -u keepalived"
ok "keepalived enabled and started"
sleep 3

# ── summary ──────────────────────────────────────────────────────────────────
step "Done — ${ROLE}"
if ip -4 addr show dev "$IFACE" | grep -q "inet $VIP/"; then
  ok "this node HOLDS the VIP $VIP"
else
  say "  ${DIM}this node does not hold the VIP (correct for the standby, or the master is up)${R}"
fi

cat <<SUMMARY

  ${B}Clients use: $VIP${R}

  Failover behaviour
    VM1 (master) unable to serve  →  VIP moves to VM2 in ~4-6s, traffic protected
    VM1 healthy again             →  VIP returns to VM1 (priority 150 vs 100)
    Either node's WAF container dies → VIP leaves it, even if the host is fine

  ${YEL}What does NOT fail over automatically${R}
    Postgres stays a read-only standby on the slave. Traffic keeps being served
    and protected; CONFIG CHANGES are refused until you decide to promote:

        $DOCKER_DIR/promote-standby.sh

    That is deliberate. Two nodes cannot tell "peer is dead" from "peer is
    unreachable", and guessing wrong gives you two primaries with divergent data.

  Verify        ./install-2vm.sh --check
  Transitions   tail -f /var/log/sentinel-vrrp.log
SUMMARY

if [[ "$ROLE" == "master" ]]; then
cat <<NEXT

  ${B}Next — set up the slave${R}

  1. Copy BOTH of these to VM 2. Neither is optional:

       scp $ENV_FILE root@${PEER_IP}:$ENV_FILE
       scp $STATE_DIR/2vm-vrrp-pass root@${PEER_IP}:$STATE_DIR/2vm-vrrp-pass

     ${DIM}.env carries the shared secrets — divergent JWT/internal/audit values give${R}
     ${DIM}you two stacks that silently distrust each other. The vrrp-pass is how the${R}
     ${DIM}nodes authenticate; if it differs, each ignores the other's adverts and${R}
     ${DIM}BOTH become master — two hosts answering on one IP.${R}

  2. On VM 2:  sudo ./install-2vm.sh   →  answer ${B}slave${R}

  3. Then run the failover drill in ./README.md before relying on this.
NEXT
else
cat <<NEXT

  ${B}Both nodes are installed.${R} Confirm the pair actually works:

    ip -4 addr show | grep $VIP        # on BOTH — exactly one must hold it
    ./install-2vm.sh --check           # on both
    docker exec sentinel-postgres-1 psql -U sentinel -d sentinel \
      -c "SELECT pg_is_in_recovery();"   # here: expect 't'

  Then run the failover drill in ./README.md. An untested failover is an
  assumption, not a capability.
NEXT
fi
