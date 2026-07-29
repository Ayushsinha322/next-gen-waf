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
# Skips the role-change confirmation. It never suppresses a VIP conflict — that one
# is a genuine "two hosts on one address" hazard and stays fatal.
ASSUME_YES="${ASSUME_YES:-no}"
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
    --yes|-y) ASSUME_YES=yes ;;
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
  _vip="$(cat "$STATE_DIR/2vm-vip" 2>/dev/null || echo '')"
  if [[ -n "$_vip" ]] && ip -4 addr show | grep -qE "inet ${_vip}/"; then
    ok "this node currently HOLDS the VIP"
  else
    say "  ${DIM}this node does not hold the VIP (normal for the standby)${R}"
  fi
  step "data-plane health (what VRRP tracks)"
  if /usr/local/sbin/sentinel-vrrp-check.sh; then ok "healthy — eligible for the VIP"
  else warn "UNHEALTHY — this node would hand the VIP to its peer"; fi
  step "recent VRRP transitions"
  tail -n 8 /var/log/sentinel-vrrp.log 2>/dev/null | sed 's/^/  /' || say "  (none logged yet)"
  exit 0
fi

# ── 1. role ──────────────────────────────────────────────────────────────────
step "Step 1 of 7 — which node is this?"
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
  if [[ "$ASSUME_YES" != "yes" ]]; then
    read -r -p "  Re-install as '$ROLE'? Type YES to continue: " c || true
    [[ "$c" == "YES" ]] || die "aborted — role unchanged"
  fi
fi

# ── 2. addressing ────────────────────────────────────────────────────────────
step "Step 2 of 7 — addressing"
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
ip -o link show "$IFACE" >/dev/null 2>&1 || die "interface '$IFACE' not found"

ok "iface $IFACE · this $THIS_IP · peer $PEER_IP · vip $VIP/$VIP_CIDR · vrid $VRID"

# ── 3. preflight ─────────────────────────────────────────────────────────────
step "Step 3 of 7 — preflight"

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
# A VIP that already answers is either this node (re-install), the PEER holding it
# (entirely normal — it is why the pair exists), or a stranger using the address.
# Only the third case is a problem, and the three are distinguishable by MAC: ARP
# tells us WHO answers, so the second node no longer has to ask a human whether
# its own partner is allowed to be up.
mac_of() { ping -c1 -W1 "$1" >/dev/null 2>&1
  ip neigh show "$1" 2>/dev/null | grep -oE 'lladdr [0-9a-f:]+' | awk '{print $2}'; }

if ping -c1 -W1 "$VIP" >/dev/null 2>&1; then
  if ip -4 addr show dev "$IFACE" | grep -qE "inet ${VIP}/"; then
    ok "VIP already held by this node (re-install)"
  else
    VIP_MAC="$(mac_of "$VIP")"; PEER_MAC="$(mac_of "$PEER_IP")"
    if [[ -n "$VIP_MAC" && "$VIP_MAC" == "$PEER_MAC" ]]; then
      ok "VIP is held by the peer ($PEER_IP) — expected, that is the active node"
    else
      warn "$VIP answers from ${VIP_MAC:-an unknown host}, which is NOT this node or the peer"
      say  "  ${DIM}Another host is using this address. Continuing would create a duplicate${R}"
      say  "  ${DIM}IP: two machines answering for $VIP, with traffic split unpredictably.${R}"
      if [[ "$ASSUME_YES" == "yes" ]]; then
        die "refusing to continue with a conflicting VIP (remove --yes to override interactively)"
      fi
      read -r -p "  Continue anyway? Type YES: " c || true
      [[ "$c" == "YES" ]] || die "aborted"
    fi
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
step "Step 4 of 7 — secrets and configuration"
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
    # Written here too so the file is complete if it is later reused after a role
    # swap; the slave overwrites it with its own peer address.
    set_kv SENTINEL_PRIMARY_HOST "$THIS_IP"
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

  # SENTINEL_PRIMARY_HOST is what the standby entrypoint clones and streams from.
  # It is NODE-SPECIFIC — from the slave, the primary is its peer — so it cannot
  # come from the master's copy of .env and has to be written here. The passive
  # overlay declares it with no default, so compose refuses to start without it.
  if grep -qE "^SENTINEL_PRIMARY_HOST=" "$ENV_FILE"; then
    python3 - "$ENV_FILE" "$PEER_IP" <<'PYEOF'
import sys, re
p, v = sys.argv[1], sys.argv[2]
s = open(p).read()
s = re.sub(r'^SENTINEL_PRIMARY_HOST=.*$', 'SENTINEL_PRIMARY_HOST=' + v, s, count=1, flags=re.M)
open(p, 'w').write(s)
PYEOF
  else
    printf 'SENTINEL_PRIMARY_HOST=%s\n' "$PEER_IP" >> "$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"
  ok "SENTINEL_PRIMARY_HOST=$PEER_IP (the standby streams from here)"
fi

# ── 4b. Postgres TLS ─────────────────────────────────────────────────────────
step "Step 5 of 7 — Postgres server certificate"

# compose.prod.yml starts Postgres with ssl=on and mounts
# /opt/sentinel-pki/pg-server.{crt,key}. Without those files Postgres exits at
# startup with "could not load server certificate file", the container is marked
# unhealthy, and every service that depends on it refuses to start — so this is
# mandatory, not an optional hardening step. (Found the hard way: the first real
# run of this installer died exactly here.)
PKI_DIR=/opt/sentinel-pki
# Docker creates a missing bind-mount source as a DIRECTORY. compose.prod.yml
# mounts these two paths, so a failed first start leaves directories where the
# cert and key should be — and `-s` is TRUE for a directory, which is how an
# absent certificate reported itself as present. Require regular files, and sweep
# away anything Docker fabricated before issuing.
for _f in pg-server.crt pg-server.key root.crt; do
  if [[ -d "$PKI_DIR/$_f" ]]; then
    rmdir "$PKI_DIR/$_f" 2>/dev/null && warn "removed empty directory Docker created at $PKI_DIR/$_f" \
      || die "$PKI_DIR/$_f is a non-empty directory — inspect it by hand"
  fi
done
if [[ -f "$PKI_DIR/pg-server.crt" && -s "$PKI_DIR/pg-server.crt" \
   && -f "$PKI_DIR/pg-server.key" && -s "$PKI_DIR/pg-server.key" ]]; then
  ok "certificate already present in $PKI_DIR"
else
  if [[ "$ROLE" == "slave" ]]; then
    die \
"$PKI_DIR/pg-server.crt is missing.

  Copy the PKI directory from the master, so both nodes share ONE trust root:

      rsync -a root@${PEER_IP}:$PKI_DIR/ $PKI_DIR/

  Two independently generated CAs cannot verify each other, so the standby's
  replication connection to the primary would fail to validate."
  fi
  # SANs must cover every name/address a client will dial: the compose service
  # name, loopback for local psql, BOTH VMs (the standby connects to the primary
  # by address), and the VIP in case a client follows it.
  ( cd "$DOCKER_DIR" && \
    PG_HOSTS="postgres,localhost,$(hostname -s)" \
    PG_IPS="127.0.0.1,${THIS_IP},${PEER_IP},${VIP}" \
    ./issue-postgres-cert.sh >/tmp/pgcert.log 2>&1 ) \
    || { sed -e 's/^/    /' /tmp/pgcert.log | tail -12; die "issue-postgres-cert.sh failed"; }
  ok "issued — SAN covers postgres, localhost, ${THIS_IP}, ${PEER_IP}, ${VIP}"
fi
# Postgres refuses to start if its key is readable beyond its owner (uid 70).
if [[ "$(stat -c '%a' "$PKI_DIR/pg-server.key")" != "600" ]]; then
  chmod 600 "$PKI_DIR/pg-server.key"; chown 70:70 "$PKI_DIR/pg-server.key" 2>/dev/null || true
  ok "tightened key permissions to 0600 uid 70"
fi

# ── 5. keepalived ────────────────────────────────────────────────────────────
step "Step 6 of 7 — keepalived (the automatic part)"

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
#
# BOTH nodes start as BACKUP, including the master. This is deliberate and it is
# the only way preempt_delay works. keepalived refuses the combination of
# `state MASTER` with preempt_delay and drops the setting, logging:
#
#     Warning - preempt delay will not work with initial state MASTER - clearing
#
# Measured on this deployment 2026-07-29: with state MASTER the master's
# preempt_delay 30 was silently absent for the whole life of the install, so a
# rebooting master could reclaim the VIP the instant its check first passed.
# preempt_delay governs a BACKUP->MASTER *preemption*, so a node that declares
# itself MASTER at startup has nothing to delay — hence keepalived clearing it.
#
# Starting both as BACKUP costs nothing: `state` sets only the INITIAL state, and
# the election then hands mastership to the higher priority anyway. The one
# tradeoff is a cold start with both nodes down takes a few advert intervals to
# elect a master instead of VM 1 claiming instantly — irrelevant here, because
# `rise 5` plus origin warm-up already dominates that by an order of magnitude.
if [[ "$ROLE" == "master" ]]; then
  STATE=BACKUP; PRIORITY=150
  # Single line on purpose: sed cannot substitute a replacement containing a
  # newline, and a multi-line value here silently dropped the setting entirely.
  PREEMPT_BLOCK="    preempt_delay 30"
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
# The health check sends this as the Host header when it probes a real request. An
# unmatched Host returns 502 whatever the node's actual health, so the probe must
# use a name the site claims — and the VIP always is one in this topology.
printf '%s\n' "$VIP"  > "$STATE_DIR/2vm-probe-host"
chmod 644 "$ROLE_FILE" "$STATE_DIR/2vm-vip" "$STATE_DIR/2vm-probe-host"

# ── 6. bring the stack up ────────────────────────────────────────────────────
step "Step 7 of 7 — starting the stack"
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
if [[ "$HEALTHY" == "yes" ]]; then
  ok "data plane healthy"
else
  # Distinguish "nothing configured yet" from "actually broken". On a first
  # install there are no sites, so the data plane reports "sites":0 and the health
  # check deliberately refuses — a WAF with no configuration would 502 everything,
  # and a node that cannot serve must not hold the VIP. That is correct behaviour,
  # not a fault, but "not healthy" alone reads like a failure and sends the
  # operator hunting for a bug that is not there.
  _hz="$(curl -fsS --max-time 3 http://127.0.0.1:80/healthz 2>/dev/null || true)"
  if [[ "$_hz" == *'"sites":0'* ]]; then
    warn "no sites configured yet, so the data plane is intentionally not eligible for the VIP"
    say  "  ${DIM}This is expected on a first install — a WAF with no sites would 502${R}"
    say  "  ${DIM}every request, so keepalived correctly refuses to send traffic here.${R}"
    say  "  ${DIM}Add your first site, and the VIP comes up within a few seconds:${R}"
    say  "  ${DIM}  dashboard  https://${THIS_IP}:9443  (admin@sentinel.local)${R}"
    say  "  ${DIM}  password   docker logs sentinel-controlplane-1 2>&1 | grep -A2 'GENERATED password'${R}"
  elif [[ -z "$_hz" ]]; then
    warn "data plane is not answering on :80 — this one IS a fault"
    say  "  ${DIM}check: docker compose -p sentinel logs --tail=50 dataplane${R}"
  else
    warn "data plane answered but is not reporting healthy"
    say  "  ${DIM}$_hz${R}"
  fi
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
       rsync -a $PKI_DIR/ root@${PEER_IP}:$PKI_DIR/

     ${DIM}.env carries the shared secrets — divergent JWT/internal/audit values give${R}
     ${DIM}you two stacks that silently distrust each other. The vrrp-pass is how the${R}
     ${DIM}nodes authenticate; if it differs, each ignores the other's adverts and${R}
     ${DIM}BOTH become master — two hosts answering on one IP. The PKI directory is${R}
     ${DIM}the shared trust root: two independently generated CAs cannot verify each${R}
     ${DIM}other, so replication would fail to validate.${R}

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
