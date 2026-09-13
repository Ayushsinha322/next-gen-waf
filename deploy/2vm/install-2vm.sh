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
ROLE_FILE=/etc/sentinel/2vm-role
STATE_DIR=/etc/sentinel

# ── where things live ────────────────────────────────────────────────────────
#
# This script is run from three trees that do NOT have the same shape:
#
#   repo checkout     deploy/2vm/install-2vm.sh
#                     compose files, helper scripts and .env.example all sit
#                     together in deploy/docker/
#
#   customer bundle   scripts/2vm/install-2vm.sh
#                     compose/ , scripts/ and configs/ are THREE SEPARATE dirs
#
#   installed tree    /opt/sentinel/current/
#                     compose at the root, helpers under scripts/
#
# The original code resolved a single DOCKER_DIR="$SCRIPT_DIR/../docker" and died
# if it was absent. In the customer bundle that path resolves to scripts/docker,
# which build-bundle.sh never creates — so the shipped active/passive installer
# aborted on its first check, before doing anything, with a message about a repo
# directory the customer does not have. Resolve the three ROLES independently
# rather than assuming one directory fills all of them.
#
#   COMPOSE_DIR    compose.prod.yml + the 2vm overlays. docker compose runs here
#                  and .env lives beside them.
#   HELPER_DIR     issue-postgres-cert.sh, issue-clickhouse-cert.sh,
#                  promote-standby.sh
#   ENV_EXAMPLE    template that a fresh .env is seeded from
#   BUNDLE_IMAGES  images.tar.gz, when we were run out of a bundle
COMPOSE_DIR="${SENTINEL_COMPOSE_DIR:-}"
HELPER_DIR="${SENTINEL_HELPER_DIR:-}"
ENV_EXAMPLE=""
BUNDLE_IMAGES=""
BUNDLE_ROOT=""
LAYOUT="unknown"

if [[ -z "$COMPOSE_DIR" ]]; then
  if [[ -f "$SCRIPT_DIR/../docker/compose.prod.yml" ]]; then
    LAYOUT="repo"
    COMPOSE_DIR="$(cd "$SCRIPT_DIR/../docker" && pwd)"
    HELPER_DIR="$COMPOSE_DIR"
    ENV_EXAMPLE="$COMPOSE_DIR/.env.example"
  elif [[ -f "$SCRIPT_DIR/../../compose/compose.prod.yml" ]]; then
    LAYOUT="bundle"
    BUNDLE_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
    COMPOSE_DIR="$BUNDLE_ROOT/compose"
    HELPER_DIR="$BUNDLE_ROOT/scripts"
    ENV_EXAMPLE="$BUNDLE_ROOT/configs/env.example"
    [[ -f "$BUNDLE_ROOT/bundle/images.tar.gz" ]] && BUNDLE_IMAGES="$BUNDLE_ROOT/bundle/images.tar.gz"
  elif [[ -f /opt/sentinel/current/compose.prod.yml ]]; then
    LAYOUT="installed"
    COMPOSE_DIR=/opt/sentinel/current
    HELPER_DIR=/opt/sentinel/current/scripts
    ENV_EXAMPLE=/opt/sentinel/current/env.example
  fi
fi
[[ -n "$HELPER_DIR" ]] || HELPER_DIR="$COMPOSE_DIR"

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

# env_set KEY VALUE — set a key in $ENV_FILE, replacing in place or appending.
#
# One helper for all three callers (master secrets, the slave's node-specific
# rewrites, and image pinning), because they were three near-identical copies and
# two of them shelled out to python3 with NO error guard. On a minimal Ubuntu
# image, which does not ship python3, those silently did nothing: the key kept its
# .env.example placeholder, the install reported success, and the failure only
# surfaced later as an inexplicable authentication or replication error.
#
# The value is escaped before it reaches sed. This is not paranoia: in a sed
# replacement `&` expands to THE ENTIRE MATCHED TEXT, so a Postgres DSN written the
# way this file's own warning recommends —
#     ...?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt
# — would silently expand to the whole `KEY=oldvalue` line in the middle of the new
# value, producing a corrupt DSN that looks plausible in the file. `\` and the `|`
# delimiter are escaped for the same reason.
env_set() {
  local k="$1" v="$2" esc
  [[ -n "${ENV_FILE:-}" ]] || die "env_set called before ENV_FILE was set (internal error)"
  esc="$(printf '%s' "$v" | sed -e 's/[\\&|]/\\&/g')"
  if grep -qE "^${k}=" "$ENV_FILE"; then
    sed -i "s|^${k}=.*|${k}=${esc}|" "$ENV_FILE" || die "could not update $k in $ENV_FILE"
  else
    printf '%s=%s\n' "$k" "$v" >> "$ENV_FILE" || die "could not append $k to $ENV_FILE"
  fi
}

ROLE=""; THIS_IP=""; PEER_IP=""; VIP=""; IFACE=""; VIP_CIDR=""; MODE="install"
# Hostname the VRRP health check sends as the Host header when it probes a real
# request. It MUST be a name one of your sites claims, or the data plane answers
# 502 (no matching site) and the node is judged unable to serve. Defaults to the
# VIP, which is only correct if a site actually lists the VIP as a domain.
PROBE_HOST=""
# Skips the role-change confirmation. It never suppresses a VIP conflict — that one
# is a genuine "two hosts on one address" hazard and stays fatal.
ASSUME_YES="${ASSUME_YES:-no}"
VRID="${SENTINEL_VRID:-51}"
# Set when a post-start check finds a genuine fault. The script used to print the
# full success summary and exit 0 even on the branch whose own message says "this
# one IS a fault" — so any automation wrapping it recorded a clean install.
INSTALL_FAULT=no
# Set when the ClickHouse firewall data-path check has to be deferred because
# nothing was listening on :443 at the time the rules were installed.
CH_FW_VERIFY=no

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift ;;
    --this) THIS_IP="${2:-}"; shift ;;
    --peer) PEER_IP="${2:-}"; shift ;;
    --vip)  VIP="${2:-}"; shift ;;
    --iface) IFACE="${2:-}"; shift ;;
    --vrid) VRID="${2:-}"; shift ;;
    --probe-host) PROBE_HOST="${2:-}"; shift ;;
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
[[ -n "$COMPOSE_DIR" && -f "$COMPOSE_DIR/compose.prod.yml" ]] || die \
"cannot locate compose.prod.yml.

  Looked in, relative to this script ($SCRIPT_DIR):
    ../docker/compose.prod.yml        (repo checkout)
    ../../compose/compose.prod.yml    (customer bundle)
    /opt/sentinel/current/compose.prod.yml   (installed tree)

  If your layout differs, point at it explicitly:
    SENTINEL_COMPOSE_DIR=/path/to/compose $0 ..."

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
  # --check used to print its findings and exit 0 unconditionally: a node with
  # keepalived dead and the data plane down still "passed", so it could not be used
  # in a script, a monitor, or a go-live gate. It now reports the same information
  # AND returns a status that reflects it.
  [[ -f "$ROLE_FILE" ]] || die "no install found ($ROLE_FILE missing)"
  CHECK_FAIL=0
  _vip="$(cat "$STATE_DIR/2vm-vip" 2>/dev/null || echo '')"
  _probe="$(cat "$STATE_DIR/2vm-probe-host" 2>/dev/null || echo '')"
  say "  role:   $(cat "$ROLE_FILE")"
  say "  vip:    ${_vip:-?}"
  say "  probe:  ${_probe:-?}   ${DIM}(a site must claim this name, or health always fails)${R}"
  if [[ -f "$STATE_DIR/2vm-vrrp-pass" ]]; then
    say "  vrrp:   $(sha256sum < "$STATE_DIR/2vm-vrrp-pass" | cut -c1-12)   ${DIM}(must be IDENTICAL on the peer)${R}"
  else
    warn "VRRP password file missing — keepalived cannot authenticate with the peer"
    CHECK_FAIL=1
  fi

  step "keepalived"
  if systemctl is-active --quiet keepalived; then
    ok "running"
  else
    warn "NOT running — this node can neither take nor hold the VIP"
    CHECK_FAIL=1
  fi

  step "containers"
  for _c in dataplane controlplane postgres; do
    _st="$(docker inspect -f '{{.State.Status}}' "sentinel-${_c}-1" 2>/dev/null || echo absent)"
    if [[ "$_st" == "running" ]]; then ok "sentinel-${_c}-1 running"
    else warn "sentinel-${_c}-1 is ${_st}"; CHECK_FAIL=1; fi
  done

  step "VIP"
  if [[ -n "$_vip" ]] && ip -4 addr show | grep -qE "inet ${_vip}/"; then
    ok "this node currently HOLDS the VIP"
    say "  ${DIM}Run --check on the peer too: exactly ONE node may hold it. Both holding${R}"
    say "  ${DIM}it means VRRP authentication is failing — compare the vrrp fingerprint.${R}"
  else
    say "  ${DIM}this node does not hold the VIP (normal for the standby)${R}"
  fi

  # The control plane is checked SEPARATELY from VRRP, because VRRP does not
  # watch it. The data plane serves traffic from a cached config and needs no
  # database, so a control plane with no database at all leaves every VRRP probe
  # green — which is how a 2-VM master could finish installing, report success,
  # and refuse every login with a 503.
  #
  # /readyz is the only endpoint that answers this: it calls store.Ping and
  # reports db ok|unavailable|unreachable. /health is a hardcoded {"status":"ok"}
  # that never touches the database. 9501 is not published to the host and the
  # control-plane image is distroless with no shell, so probe from a container
  # that has one and shares the network.
  step "control-plane database connectivity"
  _rdy=$(docker exec sentinel-clickhouse-1 wget -qO- --timeout=5 \
           http://controlplane:9501/readyz 2>/dev/null)
  if [[ -z "$_rdy" ]]; then
    warn "control plane /readyz did not answer — not serving, or not on the network"
    CHECK_FAIL=1
  elif printf '%s' "$_rdy" | grep -q '"db"[[:space:]]*:[[:space:]]*"ok"'; then
    ok "control plane is connected to its database"
  else
    warn "control plane is running WITHOUT a database — every login returns 503"
    say  "  ${DIM}$_rdy${R}"
    say  "  ${DIM}Check SENTINEL_DB_URL in the deployment .env: Postgres accepts TLS${R}"
    say  "  ${DIM}only (pg_hba is hostssl-only), so sslmode must be verify-full.${R}"
    CHECK_FAIL=1
  fi

  step "data-plane health (what VRRP tracks)"
  if /usr/local/sbin/sentinel-vrrp-check.sh; then
    ok "healthy — eligible for the VIP"
  else
    warn "UNHEALTHY — this node would hand the VIP to its peer"
    CHECK_FAIL=1
  fi

  step "recent VRRP transitions"
  tail -n 8 /var/log/sentinel-vrrp.log 2>/dev/null | sed 's/^/  /' || say "  (none logged yet)"

  echo
  if [[ $CHECK_FAIL -eq 0 ]]; then ok "all checks passed on this node"
  else warn "one or more checks FAILED on this node"; fi
  exit "$CHECK_FAIL"
fi

# ── 1. role ──────────────────────────────────────────────────────────────────
step "Step 1 of 8 — which node is this?"
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
step "Step 2 of 8 — addressing"
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
step "Step 3 of 8 — preflight"

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
step "Step 4 of 8 — secrets and configuration"
ENV_FILE="$COMPOSE_DIR/.env"

if [[ "$ROLE" == "master" ]]; then
  if [[ -f "$ENV_FILE" ]]; then
    ok ".env already present — leaving it alone"
  else
    [[ -n "$ENV_EXAMPLE" && -f "$ENV_EXAMPLE" ]] \
      || die "the .env template is missing (looked for ${ENV_EXAMPLE:-<unresolved>}); cannot generate .env"
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    gen() { openssl rand -hex 32; }
    set_kv() { env_set "$@"; }   # see env_set near the top
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
    set_kv SENTINEL_REPL_USER replicator
    set_kv SENTINEL_REPL_PASSWORD "$REPLPW"
    set_kv SENTINEL_STANDBY_CIDR "${PEER_IP}/32"
    set_kv SENTINEL_PG_BIND "$THIS_IP"
    # Written here too so the file is complete if it is later reused after a role
    # swap; the slave overwrites it with its own peer address.
    set_kv SENTINEL_PRIMARY_HOST "$THIS_IP"
    # verify-full, NOT sslmode=disable.
    #
    # This is not a hardening preference, it is the difference between working
    # and not. compose.prod.yml points Postgres at our own pg_hba.conf, which
    # has no plain `host` line at all — only `hostssl … scram-sha-256`. A TCP
    # client that disables TLS is refused outright with "no pg_hba.conf entry
    # for host …, SSL off". So the control plane and migrate could not connect
    # on a fresh 2-VM master: the control plane came up in degraded mode, every
    # login returned 503, and the installer still exited 0 because its only
    # health probe watches the data plane, which does not use Postgres.
    #
    # install.sh has written exactly this DSN for the single-host path all
    # along; only this file disagreed, and its own warning below described the
    # result as a security posture to improve later rather than a stack that
    # cannot start.
    #
    # Both forms verify: the certificate issued a few steps down carries SANs
    # for `postgres`, this node, the peer and the VIP, and root.crt is mounted
    # into controlplane and migrate at the path sslrootcert names.
    set_kv SENTINEL_DB_URL "postgres://sentinel:${PGPW}@postgres:5432/sentinel?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt"
    set_kv SENTINEL_DB_URL_PRIMARY "postgres://sentinel:${PGPW}@${THIS_IP}:5432/sentinel?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt"
    set_kv SENTINEL_ALLOW_SUPERUSER_DB 1
    set_kv CLICKHOUSE_MEM_LIMIT 6g
    # ClickHouse runs only here, and the slave's data plane must reach it or its
    # event history is never recorded at all. Bind to the peer-facing address
    # (NOT 0.0.0.0) — this port is plaintext HTTP, so reachability is the only
    # control protecting it until the Rust client can speak TLS.
    set_kv SENTINEL_CH_BIND "$THIS_IP"
    set_kv SENTINEL_CLICKHOUSE_URL_PRIMARY "https://${THIS_IP}:8443"
    chmod 600 "$ENV_FILE"
    ok "generated .env with fresh secrets"
    say  "  ${DIM}database DSNs use sslmode=verify-full against the CA issued below.${R}"
    say  "  ${DIM}Replication streams the whole database across the peer link, so this${R}"
    say  "  ${DIM}is also what keeps it off the wire in cleartext.${R}"
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
  env_set SENTINEL_PRIMARY_HOST "$PEER_IP"
  # Same node-specific reasoning for the remote ClickHouse: this VM has none, so
  # both its planes must point at the master's. The master writes its own address
  # here, which is already correct once copied — but rewrite it anyway so a role
  # swap or a re-run cannot leave the slave pointing at itself, where there is no
  # ClickHouse and history would silently go nowhere all over again.
  env_set SENTINEL_CLICKHOUSE_URL_PRIMARY "https://${PEER_IP}:8443"
  chmod 600 "$ENV_FILE"
  ok "SENTINEL_PRIMARY_HOST=$PEER_IP (the standby streams from here)"
  ok "SENTINEL_CLICKHOUSE_URL_PRIMARY=https://${PEER_IP}:8443 (event history lands there)"
fi

# ── 4b. Postgres TLS ─────────────────────────────────────────────────────────
step "Step 5 of 8 — Postgres server certificate"

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
  ( cd "$HELPER_DIR" && \
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

# ── 4c. ClickHouse TLS (master only — it is the only node running ClickHouse) ──
#
# MANDATORY on the master, not hardening. compose.2vm-active.yml bind-mounts
# ch-server.{crt,key} and Docker CREATES A MISSING BIND SOURCE AS A DIRECTORY, so
# without these files ClickHouse gets two directories where certificates should
# be, fails to load a cert, and the passive node's history has nowhere to go —
# reintroducing the exact silent-loss bug this replaced. Same trap as the Postgres
# cert in the first install, where a directory also satisfied `-s`.
if [[ "$ROLE" == "master" ]]; then
  step "Step 5b of 8 — ClickHouse server certificate"
  _ch_ok=no
  if [[ -f "$PKI_DIR/ch-server.crt" && -s "$PKI_DIR/ch-server.crt" \
     && -f "$PKI_DIR/ch-server.key" && -s "$PKI_DIR/ch-server.key" ]]; then
    # -f AND -s: a directory passes -s, which is how an absent cert once reported
    # itself present.
    if openssl x509 -in "$PKI_DIR/ch-server.crt" -noout -checkend 0 >/dev/null 2>&1; then
      ok "existing ClickHouse certificate is present and unexpired"
      _ch_ok=yes
    else
      warn "existing ClickHouse certificate is expired — reissuing"
    fi
  fi
  if [[ "$_ch_ok" != "yes" ]]; then
    # SANs cover BOTH VMs and the VIP, not just this one: after a role swap the
    # other node serves ClickHouse, and a cert naming only the original master
    # then fails verification for no visible reason.
    ( cd "$HELPER_DIR" && \
      CH_HOSTS="clickhouse,sentinel-clickhouse-1,localhost,$(hostname -s)" \
      CH_IPS="127.0.0.1,${THIS_IP},${PEER_IP},${VIP}" \
      ./issue-clickhouse-cert.sh >/tmp/chcert.log 2>&1 ) \
      || { sed -e 's/^/    /' /tmp/chcert.log | tail -12; die "issue-clickhouse-cert.sh failed"; }
    ok "issued — SAN covers clickhouse, localhost, ${THIS_IP}, ${PEER_IP}, ${VIP}"
  fi
  # ClickHouse runs as uid 101 and cannot read a root-owned 0600 key.
  chmod 600 "$PKI_DIR/ch-server.key"; chmod 644 "$PKI_DIR/ch-server.crt"
  chown 101:101 "$PKI_DIR/ch-server.key" "$PKI_DIR/ch-server.crt" 2>/dev/null || \
    warn "could not chown the ClickHouse key to 101:101 — TLS may not come up"
fi

# ── 5. keepalived ────────────────────────────────────────────────────────────
step "Step 6 of 8 — keepalived (the automatic part)"

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
  ok "VRRP authentication password loaded from $VRRP_PASS_FILE"
elif [[ "$ROLE" == "slave" ]]; then
  # Generating one here IS the split-brain bug. keepalived discards every advert
  # authenticated with a different password ("receive an invalid passwd!"), so each
  # node sees no master, both transition BACKUP->MASTER, and BOTH add the VIP. Two
  # hosts then answer for the traffic address on one L2 segment and ARP decides who
  # gets each client — while the installer exits 0, prints "Both nodes are
  # installed", and --check on each node reports it holds the VIP.
  #
  # A missing .env twenty lines up is already a hard die with copy instructions.
  # This file is no less load-bearing and used to get only a warning — one that was
  # printed whether or not the copy had been done, so it carried no signal at all.
  die "$VRRP_PASS_FILE is missing.

  Copy it from the master FIRST — the slave must not invent its own:

      scp root@${PEER_IP}:$VRRP_PASS_FILE $VRRP_PASS_FILE

  Both nodes must authenticate VRRP with the SAME password. If they differ, each
  node ignores the other's adverts, both become MASTER, and two hosts answer on
  $VIP with traffic split unpredictably between them."
else
  # VRRP PASS auth is 8 characters maximum; longer values are silently truncated,
  # which would make the two nodes disagree and both become master.
  VRRP_PASS="$(openssl rand -hex 8 | cut -c1-8)"
  printf '%s' "$VRRP_PASS" > "$VRRP_PASS_FILE"; chmod 600 "$VRRP_PASS_FILE"
  ok "VRRP authentication password generated — it must be copied to the slave"
fi
# Print a fingerprint on BOTH roles so the two can be compared without moving the
# secret around or trusting that the copy worked. Mismatched passwords are the
# split-brain case and nothing else in this install detects them.
VRRP_FP="$(printf '%s' "$VRRP_PASS" | sha256sum | cut -c1-12)"
say "  ${DIM}VRRP password fingerprint: ${VRRP_FP}${R}"
say "  ${DIM}It must be IDENTICAL on both nodes. Compare with, on the peer:${R}"
say "  ${DIM}  sha256sum < $VRRP_PASS_FILE | cut -c1-12${R}"

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
# The health check probes a real request with this as the Host header, and treats
# 502 as "cannot serve". Site matching is exact-or-wildcard against the site's
# declared domains, with no default-site fallback — so if this name is not one a
# site claims, the data plane answers 502 no matter how healthy it is, BOTH nodes
# go FAULT, and the VIP is never claimed by anyone. The product then serves nothing
# on its advertised address while every component is fine.
#
# The VIP is only a sensible default when a site actually lists the VIP as a
# domain. An operator who serves app.example.com and points DNS at the VIP needs
# --probe-host app.example.com.
#
# Do NOT clobber an existing value on re-run: this line was unconditional, so an
# operator who diagnosed the 502 and corrected the file by hand had the fix
# silently overwritten the next time the installer ran.
PROBE_HOST_FILE="$STATE_DIR/2vm-probe-host"
if [[ -n "$PROBE_HOST" ]]; then
  printf '%s\n' "$PROBE_HOST" > "$PROBE_HOST_FILE"
  ok "health-check probe host: $PROBE_HOST"
elif [[ -f "$PROBE_HOST_FILE" ]]; then
  ok "health-check probe host: $(cat "$PROBE_HOST_FILE") (existing, left alone)"
else
  printf '%s\n' "$VIP" > "$PROBE_HOST_FILE"
  warn "health-check probe host defaulted to the VIP ($VIP)"
  say  "  ${DIM}This only works if one of your sites lists $VIP as a domain. If your${R}"
  say  "  ${DIM}site is named e.g. app.example.com, re-run with:${R}"
  say  "  ${DIM}  --probe-host app.example.com${R}"
  say  "  ${DIM}otherwise the probe gets a 502, BOTH nodes are judged unhealthy, and${R}"
  say  "  ${DIM}the VIP never comes up.${R}"
fi
chmod 644 "$ROLE_FILE" "$STATE_DIR/2vm-vip" "$PROBE_HOST_FILE"

# ── 5b. restrict the published ClickHouse port to the peer ───────────────────
#
# The master publishes ClickHouse so the slave's data plane has somewhere to send
# event history. That port is plaintext HTTP (the Rust client has no TLS
# connector), so unlike Postgres next door it is NOT protected by crypto —
# reachability is the whole control, and binding to the peer-facing address is
# only half of it.
#
# The rule goes in DOCKER-USER, not INPUT and not ufw. Docker publishes ports by
# DNAT in its own chains, which bypass INPUT entirely and are invisible to ufw —
# the single most common way an operator believes a container port is firewalled
# when it is wide open. DOCKER-USER is the documented hook that runs before
# Docker's own rules.
#
# Deliberately narrow: one chain, one port, one interface, allow the peer /32 and
# drop the rest. Nothing in raw/PREROUTING and no NOTRACK — a previous attempt at
# network hardening here broke Docker's DNAT that way.
if [[ "$ROLE" == "master" ]]; then
  step "Step 6b of 8 — firewalling the published ClickHouse port"
  if command -v iptables >/dev/null 2>&1; then
    # MATCH ON THE ORIGINAL DESTINATION PORT, NOT --dport.
    #
    # Docker DNATs before the FORWARD chain, so by the time DOCKER-USER sees a
    # packet its dport is the CONTAINER's port — and two containers here share
    # container port 8443:
    #
    #   ClickHouse   host 8443 -> container 8443    must be peer-only
    #   data plane   host  443 -> container 8443    must stay open to the world
    #
    # A plain `--dport 8443` cannot tell them apart, so it silently blackholes
    # every client's HTTPS request to the WAF. Measured: it did exactly that on
    # .88 on 2026-07-30 — https through the VIP went to a connection timeout while
    # every other check still looked healthy, because the data path was being
    # dropped in a chain nobody associates with the WAF's own listener.
    #
    # `-m conntrack --ctorigdstport` matches the port the CLIENT dialed, which is
    # the distinction that actually exists.
    _ch_rule_present() {
      iptables -C DOCKER-USER -i "$IFACE" -p tcp -m conntrack \
        --ctorigdstport 8443 -s "${PEER_IP}/32" -j RETURN 2>/dev/null
    }
    if _ch_rule_present; then
      ok "ClickHouse peer allow-rule already present (idempotent re-run)"
    else
      # Order matters: the peer RETURNs before the catch-all DROP is reached, so
      # insert the DROP first and the allow above it.
      iptables -I DOCKER-USER 1 -i "$IFACE" -p tcp -m conntrack --ctorigdstport 8443 -j DROP 2>/dev/null \
        && iptables -I DOCKER-USER 1 -i "$IFACE" -p tcp -m conntrack --ctorigdstport 8443 -s "${PEER_IP}/32" -j RETURN 2>/dev/null \
        && ok "ClickHouse :8443 on $IFACE restricted to ${PEER_IP}/32 (matched pre-DNAT)" \
        || warn "could not install the ClickHouse firewall rules — restrict :8443 yourself"
      # Prove the data path still works rather than assuming it: this rule pair is
      # one typo away from a silent HTTPS outage.
      #
      # But this step runs BEFORE the stack is started, so on a first install
      # nothing is listening on :443 yet and the probe failed every time — printing
      # a scary warning about an iptables trap that was not happening. Only probe
      # when there is something to probe; otherwise defer it until after `up`.
      if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE '[:.]443$'; then
        if ! curl -sk -m5 -o /dev/null "https://${THIS_IP}/" 2>/dev/null; then
          warn "HTTPS to this node FAILED right after adding the firewall rules"
          say  "  ${DIM}That is the --dport-vs-ctorigdstport trap. Inspect:${R}"
          say  "  ${DIM}  iptables -L DOCKER-USER -n --line-numbers${R}"
        else
          ok "client HTTPS to this node still works (data path not caught by the rule)"
        fi
      else
        CH_FW_VERIFY=yes
        say "  ${DIM}nothing listening on :443 yet — data-path check deferred until the stack is up${R}"
      fi
    fi
    # Belt and braces: an older install of this stack published PLAINTEXT 8123 to
    # the network. Leave a DROP behind so upgrading does not silently keep that
    # exposure if a stale container is still bound there.
    iptables -C DOCKER-USER -i "$IFACE" -p tcp --dport 8123 -j DROP 2>/dev/null \
      || iptables -A DOCKER-USER -i "$IFACE" -p tcp --dport 8123 -j DROP 2>/dev/null \
      && ok "legacy plaintext :8123 blocked from $IFACE"
    warn "iptables rules are NOT persistent across a reboot on their own"
    say  "  ${DIM}install netfilter-persistent (or re-run this installer) so the${R}"
    say  "  ${DIM}restriction survives: apt-get install -y iptables-persistent${R}"
    say  "  ${DIM}verify from a THIRD host: curl -mk3 https://${THIS_IP}:8443/ping → must fail${R}"
    say  "  ${DIM}verify TLS from the peer:  curl --cacert $PKI_DIR/root.crt \\${R}"
    say  "  ${DIM}                            https://${THIS_IP}:8443/ping → Ok.${R}"
  else
    warn "iptables not found — :8443 is published and UNFILTERED"
    say  "  ${DIM}TLS protects it in transit, but restrict it to ${PEER_IP}/32 anyway${R}"
    say  "  ${DIM}with whatever firewall this host uses — defence in depth.${R}"
  fi
fi

# ── 6. bring the stack up ────────────────────────────────────────────────────
# ── 6c. container images ─────────────────────────────────────────────────────
#
# compose.prod.yml asks for ${SENTINEL_IMAGE_PREFIX:-sentinel}/<svc>:${SENTINEL_VERSION:-latest}
# AND carries a build: stanza for the same services. Those two facts combine
# badly: when the requested tag is absent, `docker compose up` does not fail — it
# quietly falls back to BUILDING from context ../.., which exists in a repo
# checkout and does not exist in a customer bundle. There it dies partway through
# `up`, with containers already created.
#
# .env.example sets neither variable, so a bundle install resolved :latest while
# the bundle ships :1.0.0. The images were sitting on disk under a tag nobody
# asked for. Pin the tag, load the bundle's images if they are not loaded yet, and
# refuse to reach `up` without them rather than letting compose improvise a build.
step "Step 7 of 8 — container images"

IMG_PREFIX="$(sed -n 's/^SENTINEL_IMAGE_PREFIX=//p' "$ENV_FILE" 2>/dev/null | head -1)"
IMG_PREFIX="${IMG_PREFIX:-sentinel}"
IMG_VERSION="$(sed -n 's/^SENTINEL_VERSION=//p' "$ENV_FILE" 2>/dev/null | head -1)"
if [[ -z "$IMG_VERSION" ]]; then
  if [[ -n "$BUNDLE_ROOT" && -f "$BUNDLE_ROOT/bundle/manifest.json" ]]; then
    IMG_VERSION="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
                     "$BUNDLE_ROOT/bundle/manifest.json" | head -1)"
  elif [[ -f "$SCRIPT_DIR/../../VERSION" ]]; then
    IMG_VERSION="$(tr -d '[:space:]' < "$SCRIPT_DIR/../../VERSION")"
  fi
fi
IMG_VERSION="${IMG_VERSION:-latest}"

# Pin both into .env so compose, the slave's copied .env, and any later re-run all
# agree on one tag. Without this the answer depends on who last exported what.
env_set SENTINEL_IMAGE_PREFIX "$IMG_PREFIX"
env_set SENTINEL_VERSION      "$IMG_VERSION"
ok "images pinned to ${IMG_PREFIX}/<service>:${IMG_VERSION}"

img_missing() {
  local out=() svc
  for svc in dataplane controlplane dashboard migrate; do
    docker image inspect "${IMG_PREFIX}/${svc}:${IMG_VERSION}" >/dev/null 2>&1 || out+=("$svc")
  done
  printf '%s\n' "${out[@]:-}"
}
MISSING="$(img_missing | tr -d '\n' | tr -s ' ')"
if [[ -n "${MISSING// /}" && -n "$BUNDLE_IMAGES" ]]; then
  say "  loading images from the bundle — pre-built, about a minute…"
  docker load -i "$BUNDLE_IMAGES" >>/tmp/2vm-load.log 2>&1 \
    || die "docker load failed for $BUNDLE_IMAGES — see /tmp/2vm-load.log"
  MISSING="$(img_missing | tr -d '\n' | tr -s ' ')"
fi
if [[ -n "${MISSING// /}" ]]; then
  die "missing container images at tag '${IMG_VERSION}': ${MISSING}

  The stack cannot start without them, and compose would otherwise try to BUILD
  them from source that is not present here.

  From a customer bundle:  the images ship in bundle/images.tar.gz — run this
                           script from inside the extracted bundle so it can find
                           and load them.
  From a repo checkout:    build them first —
                             cd $COMPOSE_DIR
                             SENTINEL_VERSION=$IMG_VERSION docker compose \\
                               -f compose.prod.yml build dataplane controlplane dashboard migrate
  Already loaded elsewhere: docker images | grep ${IMG_PREFIX}/
                           then re-run with the tag you actually have:
                             SENTINEL_VERSION=<tag> $0 --role $ROLE ..."
fi
ok "all four images present at ${IMG_VERSION}"

# ── 6d. bring the stack up ───────────────────────────────────────────────────
step "Step 8 of 8 — starting the stack"
OVERLAY="compose.2vm-active.yml"; [[ "$ROLE" == "slave" ]] && OVERLAY="compose.2vm-passive.yml"
[[ -f "$COMPOSE_DIR/$OVERLAY" ]] || die "$COMPOSE_DIR/$OVERLAY missing"

C=(docker compose -p sentinel -f compose.prod.yml -f "$OVERLAY")
say "  ${DIM}cd $COMPOSE_DIR && ${C[*]} up -d${R}"
( cd "$COMPOSE_DIR" && "${C[@]}" config >/dev/null ) \
  || die "compose config is invalid — fix .env before starting (nothing was started)"
ok "compose config resolves"

( cd "$COMPOSE_DIR" && "${C[@]}" up -d ) || die "compose up failed"
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
  _probe="$(cat "$PROBE_HOST_FILE" 2>/dev/null || echo "$VIP")"
  if [[ "$_hz" == *'"sites":0'* ]]; then
    warn "no sites configured yet, so the data plane is intentionally not eligible for the VIP"
    say  "  ${DIM}This is expected on a first install — a WAF with no sites would 502${R}"
    say  "  ${DIM}every request, so keepalived correctly refuses to send traffic here.${R}"
    say  "  ${DIM}Add your first site, and the VIP comes up within a few seconds.${R}"
    say  "  ${DIM}Console is loopback-only: ssh -L 9443:127.0.0.1:9443 root@${THIS_IP}${R}"
    say  "  ${DIM}then https://127.0.0.1:9443  (admin@sentinel.local)${R}"
    say  "  ${DIM}password: docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'${R}"
  elif [[ -z "$_hz" ]]; then
    warn "data plane is not answering on :80 — this one IS a fault"
    say  "  ${DIM}check: docker compose -p sentinel logs --tail=50 dataplane${R}"
    INSTALL_FAULT=yes
  else
    # Sites exist but the probe still fails. The overwhelmingly likely cause is that
    # the probe Host matches no site, which is indistinguishable from a dead origin
    # at the HTTP layer — both are 502 — so say so explicitly rather than leaving
    # the operator to guess. Getting this wrong means NEITHER node takes the VIP.
    _code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 \
               -H "Host: $_probe" http://127.0.0.1:80/ 2>/dev/null || echo 000)"
    warn "data plane is up with sites configured, but the health probe fails (HTTP $_code)"
    say  "  ${DIM}The probe sends 'Host: $_probe'. If no site claims that name, the${R}"
    say  "  ${DIM}data plane answers 502 however healthy it is — and then NEITHER node${R}"
    say  "  ${DIM}will ever take the VIP.${R}"
    say  "  ${DIM}Fix by pointing the probe at a hostname one of your sites declares:${R}"
    say  "  ${DIM}  $0 --role $ROLE --this $THIS_IP --peer $PEER_IP --vip $VIP \\${R}"
    say  "  ${DIM}      --probe-host <a domain your site claims>${R}"
    say  "  ${DIM}Otherwise check the origin: docker compose -p sentinel logs --tail=50 dataplane${R}"
    INSTALL_FAULT=yes
  fi
fi

# The deferred half of the ClickHouse firewall check (see Step 6b). Now that the
# data plane is listening, prove the DOCKER-USER rules did not swallow client
# HTTPS — the failure mode that took https through the VIP down on .88 while every
# other check still looked healthy.
if [[ "$CH_FW_VERIFY" == "yes" ]]; then
  step "verifying the ClickHouse firewall did not catch the data path"
  if curl -sk -m5 -o /dev/null "https://${THIS_IP}/" 2>/dev/null; then
    ok "client HTTPS to this node works — the rules match only ClickHouse"
  else
    warn "HTTPS to this node FAILS with the firewall rules in place"
    say  "  ${DIM}This is the --dport-vs-ctorigdstport trap: a rule intended for${R}"
    say  "  ${DIM}ClickHouse:8443 is swallowing client traffic to the WAF on :443.${R}"
    say  "  ${DIM}  iptables -L DOCKER-USER -n --line-numbers${R}"
    INSTALL_FAULT=yes
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

        $HELPER_DIR/promote-standby.sh

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

  3. Then run the failover drill in ACTIVE-PASSIVE.md before relying on this.
     ${DIM}(docs/ inside the installation bundle, deploy/ in a source checkout)${R}
NEXT
else
cat <<NEXT

  ${B}Both nodes are installed.${R} Confirm the pair actually works:

    ip -4 addr show | grep $VIP        # on BOTH — exactly one must hold it
    ./install-2vm.sh --check           # on both
    docker exec sentinel-postgres-1 psql -U sentinel -d sentinel \
      -c "SELECT pg_is_in_recovery();"   # here: expect 't'

  Then run the failover drill in ACTIVE-PASSIVE.md — docs/ inside the installation
  bundle, deploy/ in a source checkout. An untested failover is an assumption,
  not a capability.
NEXT
fi

# Exit code must reflect what the checks actually found. Printing "Done" and
# exiting 0 after reporting a fault is how a broken node gets signed off.
if [[ "$INSTALL_FAULT" == "yes" ]]; then
  printf '\n  %s✗ Completed with a FAILING data-plane check — see the warning above.%s\n' "$RED" "$R" >&2
  printf '  %sThe stack is installed; this node is NOT currently eligible for the VIP.%s\n\n' "$DIM" "$R" >&2
  exit 1
fi
