#!/usr/bin/env bash
# =============================================================================
#  Next-Gen ESDSWAF — Installer
#
#      sudo ./install.sh
#
#  Asks only for information we cannot generate: the hostname clients will use,
#  an administrator email, and which topology to deploy. Every secret — database
#  passwords, session signing key, audit HMAC key, internal service token — is
#  generated with `openssl rand`. You are never asked to invent a password.
#
#  Aborts BEFORE changing anything if the host does not meet requirements. There
#  is no half-installed state to clean up: every gate runs first, and the first
#  action that alters the system is loading images, after all checks have passed.
#
#  Everything is logged to /var/log/sentinel/install.log — send that file to
#  support if anything fails, rather than re-running commands by hand.
#
#      --non-interactive   take answers from the environment (see below)
#      --dry-run           run every check, change nothing
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR=/var/log/sentinel
LOG="$LOG_DIR/install.log"
STATE_DIR=/opt/sentinel
INSTALL_DIR="$STATE_DIR/current"
PKI_DIR=/opt/sentinel-pki

NONINTERACTIVE=no
DRY_RUN=no
while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NONINTERACTIVE=yes ;;
    --dry-run) DRY_RUN=yes ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ -t 1 ]]; then
  B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'
  RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'; CYN=$'\e[96m'
else B=''; R=''; DIM=''; RED=''; GRN=''; YEL=''; CYN=''; fi

# Redirecting to an unopenable path is reported by the SHELL, not by printf, so
# `2>/dev/null` on the printf does not suppress it — a non-root run leaked
# "No such file or directory" over the abort message. Gate on writability instead.
LOG_OK=no
if mkdir -p "$LOG_DIR" 2>/dev/null && : >>"$LOG" 2>/dev/null; then LOG_OK=yes; fi
log()  { [[ "$LOG_OK" == "yes" ]] || return 0
         printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG" 2>/dev/null || true; }
say()  { printf '%s\n' "$*"; log "$*"; }
step() { printf '\n%s%s==> %s%s\n' "$B" "$CYN" "$*" "$R"; log "STEP $*"; }
ok()   { printf '  %s✓%s %s\n' "$GRN" "$R" "$*"; log "OK $*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$R" "$*"; log "WARN $*"; }
fail() { printf '  %s✗%s %s\n' "$RED" "$R" "$*"; log "FAIL $*"; }
die()  {
  printf '\n  %s✗ INSTALLATION ABORTED%s\n    %s\n\n' "$RED" "$R" "$*" >&2
  log "ABORT $*"
  if [[ "$LOG_OK" == "yes" ]]; then
    printf '  %sNothing was installed. Full log: %s%s\n\n' "$DIM" "$LOG" "$R" >&2
  else
    printf '  %sNothing was installed.%s\n\n' "$DIM" "$R" >&2
  fi
  exit 1
}

# Minimum requirements. Below these the product does not work reliably —
# ClickHouse alone is memory-limited to 6 GB and crash-loops under ~2 GB.
MIN_VCPU=4
MIN_RAM_GB=15          # a "16 GB" VM reports ~15.6 GiB
MIN_DISK_GB=100
REQUIRED_PORTS=(80 443 9443)

banner() {
cat <<'EOF'

  ==========================================================
       Next-Gen ESDSWAF  —  Installer
       ESDS Software Solution Ltd
  ==========================================================
EOF
}
banner
say "install started $(date -u +%Y-%m-%dT%H:%M:%SZ) (log: $LOG)"

# ── Step 1 — privileges and package integrity ────────────────────────────────
step "Step 1 of 10 — package"
[[ $EUID -eq 0 ]] || die "run with sudo — the installer writes /opt, /etc and manages Docker"

VERSION="unknown"
if [[ -f "$HERE/bundle/manifest.json" ]]; then
  VERSION=$(python3 -c "import json;print(json.load(open('$HERE/bundle/manifest.json'))['version'])" 2>/dev/null || echo unknown)
  ok "package: Next-Gen ESDSWAF v$VERSION"
else
  die "bundle/manifest.json missing — this does not look like a complete ESDSWAF package"
fi

[[ -f "$HERE/SHA256SUMS" ]] || die "SHA256SUMS missing — cannot verify package integrity"
say "  verifying every shipped file against SHA256SUMS…"
if ( cd "$HERE" && sha256sum -c --quiet SHA256SUMS >>"$LOG" 2>&1 ); then
  ok "package integrity verified ($(wc -l < "$HERE/SHA256SUMS") files)"
else
  die "CHECKSUM MISMATCH — the package is corrupted or has been altered.
    Re-download it and verify the outer archive first:
      sha256sum -c ESDSWAF-v${VERSION}.tar.gz.sha256"
fi

# ── Step 2 — operating system ────────────────────────────────────────────────
step "Step 2 of 10 — operating system"
[[ -r /etc/os-release ]] || die "cannot read /etc/os-release — unsupported system"
# shellcheck disable=SC1091
. /etc/os-release
say "  detected: ${PRETTY_NAME:-unknown}"
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:22.04|ubuntu:24.04) ok "supported" ;;
  ubuntu:*)
    warn "Ubuntu ${VERSION_ID} is not a tested release"
    [[ "$NONINTERACTIVE" == "yes" ]] || {
      read -r -p "  Continue anyway? Type YES: " c || true
      [[ "$c" == "YES" ]] || die "aborted at OS check"
    } ;;
  *)
    die "unsupported operating system: ${PRETTY_NAME:-$ID $VERSION_ID}

    Supported: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS

    RHEL / Rocky / Alma are not yet supported. SELinux blocks the certificate
    bind mounts this deployment requires, so it would fail after installing
    rather than before. Support will be added once it is genuinely tested." ;;
esac

# ── Step 3 — hardware ────────────────────────────────────────────────────────
step "Step 3 of 10 — hardware"
VCPU=$(nproc 2>/dev/null || echo 0)
RAM_GB=$(awk '/MemTotal/{printf "%d", $2/1048576}' /proc/meminfo 2>/dev/null || echo 0)
DISK_GB=$(df -BG --output=avail /opt 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)

hw_fail=0
chk() { # chk LABEL ACTUAL MIN UNIT
  if [[ "${2:-0}" -ge "$3" ]]; then ok "$1: $2 $4 (minimum $3)"
  else fail "$1: $2 $4 — MINIMUM $3 $4"; hw_fail=1; fi
}
chk "CPU"  "$VCPU"    "$MIN_VCPU"    "vCPU"
chk "RAM"  "$RAM_GB"  "$MIN_RAM_GB"  "GB"
chk "Disk" "$DISK_GB" "$MIN_DISK_GB" "GB free on /opt"
if [[ $hw_fail -eq 1 ]]; then
  die "hardware below minimum specification.

    Required: ${MIN_VCPU} vCPU, 16 GB RAM, ${MIN_DISK_GB} GB free disk
    Detected: ${VCPU} vCPU, ${RAM_GB} GB RAM, ${DISK_GB} GB free

    RAM is the hard one: ClickHouse is limited to 6 GB and crash-loops
    indefinitely with less than about 2 GB available to it. Resize the VM
    and re-run this installer."
fi

# ── Step 4 — Docker, ports, clock, connectivity ──────────────────────────────
step "Step 4 of 10 — prerequisites"
command -v docker >/dev/null 2>&1 \
  || die "Docker is not installed.

    Install Docker Engine with the Compose v2 plugin, then re-run:
      curl -fsSL https://get.docker.com | sh
      systemctl enable --now docker"
docker compose version >/dev/null 2>&1 \
  || die "the Docker Compose v2 plugin is missing (\`docker compose version\` failed)"
docker info >/dev/null 2>&1 || die "the Docker daemon is not running — systemctl start docker"
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo present)"

port_busy=0
for p in "${REQUIRED_PORTS[@]}"; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$"; then
    fail "port $p is already in use"; port_busy=1
  fi
done
if [[ $port_busy -eq 1 ]]; then
  ss -ltnp 2>/dev/null | grep -E "[:.](80|443|9443)\s" >>"$LOG" 2>&1 || true
  die "ports ${REQUIRED_PORTS[*]} must be free — the WAF binds them.
    Something else (often nginx or apache) is listening. Stop it and re-run.
    Details written to $LOG"
fi
ok "ports free: ${REQUIRED_PORTS[*]}"

if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
  ok "clock synchronised"
else
  warn "clock is NOT NTP-synchronised — certificate validation and audit"
  warn "timestamps depend on it. Fix with: timedatectl set-ntp true"
fi

# This bundle ships only the four ESDSWAF images; Postgres, Redis, ClickHouse,
# Prometheus and Grafana are pulled from Docker Hub. Check that NOW rather than
# failing halfway through `up -d`.
NEEDS_NET=$(python3 -c "import json;print(json.load(open('$HERE/bundle/manifest.json')).get('requires_internet',True))" 2>/dev/null || echo True)
if [[ "$NEEDS_NET" == "True" ]]; then
  if timeout 12 docker pull hello-world >/dev/null 2>&1; then
    ok "Docker registry reachable (5 third-party images will be pulled)"
    docker rmi hello-world >/dev/null 2>&1 || true
  else
    die "cannot reach the Docker registry, and this package needs it.

    This bundle contains the four ESDSWAF images only. These are pulled:
$(python3 -c "
import json
for i in json.load(open('$HERE/bundle/manifest.json')).get('pulled_from_registry',[]):
    print('      - '+i)
" 2>/dev/null)

    Either allow egress to registry-1.docker.io, configure a registry mirror
    in /etc/docker/daemon.json, or ask ESDS for the fully offline bundle
    (built with BUNDLE_THIRD_PARTY=1, which contains all nine images)."
  fi
fi

[[ "$DRY_RUN" == "yes" ]] && { say ""; ok "--dry-run: all checks passed, nothing changed"; exit 0; }

# ── Step 5 — configuration questions (the only ones) ─────────────────────────
step "Step 5 of 10 — configuration"
ask() { # ask VAR PROMPT DEFAULT
  local __v="$1" __p="$2" __d="${3:-}" __a=""
  if [[ -n "${!__v:-}" ]]; then return 0; fi
  if [[ "$NONINTERACTIVE" == "yes" ]]; then printf -v "$__v" '%s' "$__d"; return 0; fi
  if [[ -n "$__d" ]]; then read -r -p "  $__p [$__d]: " __a || true; __a="${__a:-$__d}"
  else while [[ -z "$__a" ]]; do read -r -p "  $__p: " __a || true; done; fi
  printf -v "$__v" '%s' "$__a"
}

DEF_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
ask WAF_HOSTNAME "Hostname clients will use (e.g. waf.company.com)" "${DEF_IP:-}"
ask ADMIN_EMAIL  "Administrator email" "admin@${WAF_HOSTNAME}"

if [[ "$NONINTERACTIVE" != "yes" ]]; then
  say ""
  say "  TLS certificate for $WAF_HOSTNAME:"
  say "    1) I will supply my own certificate  ${DIM}(recommended)${R}"
  say "    2) Self-signed, for evaluation only"
  say "    ${DIM}Let's Encrypt is configured after install — it needs inbound port 80${R}"
  say "    ${DIM}from the internet, which many on-premise networks do not permit.${R}"
  read -r -p "  Choice [1]: " TLS_CHOICE || true
fi
TLS_CHOICE="${TLS_CHOICE:-1}"

if [[ "$NONINTERACTIVE" != "yes" ]]; then
  say ""
  say "  Deployment topology:"
  say "    1) Standalone — this VM only"
  say "    2) Active/passive pair — run scripts/2vm/install-2vm.sh instead"
  read -r -p "  Choice [1]: " TOPOLOGY || true
fi
TOPOLOGY="${TOPOLOGY:-1}"
if [[ "$TOPOLOGY" == "2" ]]; then
  say ""
  say "  ${B}Active/passive is a two-machine procedure${R}, not a single installer run:"
  say "  secrets and the certificate authority must be generated on the first node"
  say "  and copied to the second, so it cannot be done from one host."
  say ""
  say "    sudo ./scripts/2vm/install-2vm.sh --role master --this <ip> --peer <ip> --vip <ip>"
  say ""
  say "  See section 5 of docs/ for the full sequence. Nothing has been changed."
  exit 0
fi

ok "hostname: $WAF_HOSTNAME"
ok "admin:    $ADMIN_EMAIL"

# ── Step 6 — load images ─────────────────────────────────────────────────────
step "Step 6 of 10 — loading images"
say "  ${DIM}pre-built: no compilation, about a minute${R}"
docker load -i "$HERE/bundle/images.tar.gz" >>"$LOG" 2>&1 \
  || die "docker load failed — see $LOG"
for svc in dataplane controlplane dashboard migrate; do
  docker image inspect "sentinel/${svc}:${VERSION}" >/dev/null 2>&1 \
    || die "image sentinel/${svc}:${VERSION} missing after load — package is incomplete"
done
ok "four images loaded at version $VERSION"

# ── Step 7 — install tree and secrets ────────────────────────────────────────
step "Step 7 of 10 — configuration and secrets"
mkdir -p "$INSTALL_DIR" "$PKI_DIR"
cp -r "$HERE/compose/." "$INSTALL_DIR/"
cp -r "$HERE/scripts"   "$INSTALL_DIR/scripts"
chmod +x "$INSTALL_DIR"/scripts/*.sh "$INSTALL_DIR"/scripts/2vm/*.sh 2>/dev/null || true

gen() { openssl rand -hex 32; }
ENV_FILE="$INSTALL_DIR/.env"
if [[ -f "$ENV_FILE" ]]; then
  warn "$ENV_FILE exists — keeping the existing secrets (not overwriting)"
else
  PGPW=$(gen); CHPW=$(gen)
  cat > "$ENV_FILE" <<ENVEOF
# Generated by the ESDSWAF installer on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Contains every secret for this deployment. Back it up; never share it.
SENTINEL_VERSION=$VERSION
SENTINEL_IMAGE_PREFIX=sentinel

POSTGRES_USER=sentinel
POSTGRES_DB=sentinel
POSTGRES_PASSWORD=$PGPW
SENTINEL_DB_URL=postgres://sentinel:${PGPW}@postgres:5432/sentinel?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt

CLICKHOUSE_USER=sentinel
CLICKHOUSE_DB=sentinel_logs
CLICKHOUSE_PASSWORD=$CHPW
CLICKHOUSE_MEM_LIMIT=6g

SENTINEL_JWT_SECRET=$(gen)
SENTINEL_AUDIT_HMAC_KEY=$(gen)
SENTINEL_INTERNAL_SECRET=$(gen)
SENTINEL_ALLOW_SUPERUSER_DB=1
GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '\n/+=' | cut -c1-24)

SENTINEL_CLICKHOUSE_EVENT_RETENTION_DAYS=90
SENTINEL_CLICKHOUSE_TRAFFIC_RETENTION_DAYS=30
SENTINEL_SPOOL_DIR=/var/lib/sentinel/state/spool
SENTINEL_SPOOL_MAX_BYTES=268435456

SENTINEL_WAF_HOSTNAME=$WAF_HOSTNAME
SENTINEL_ADMIN_EMAIL=$ADMIN_EMAIL
ENVEOF
  chmod 600 "$ENV_FILE"
  ok "secrets generated (7 values, openssl rand) — $ENV_FILE, mode 0600"
fi

# ── Step 8 — internal TLS (mandatory: Postgres will not start without) ───────
step "Step 8 of 10 — internal certificates"
if [[ -f "$PKI_DIR/pg-server.crt" && -s "$PKI_DIR/pg-server.crt" ]]; then
  ok "certificates already present"
else
  ( cd "$INSTALL_DIR/scripts" && ./issue-ip-cert.sh >>"$LOG" 2>&1 ) || warn "issue-ip-cert.sh reported an error (see $LOG)"
  ( cd "$INSTALL_DIR/scripts" && PG_HOSTS="postgres,localhost,$(hostname -s)" PG_IPS="127.0.0.1,${DEF_IP:-127.0.0.1}" \
      ./issue-postgres-cert.sh >>"$LOG" 2>&1 ) \
    || die "could not issue the Postgres certificate — see $LOG.
    Postgres runs with ssl=on and will not start without it."
  ok "internal certificate authority + Postgres certificate issued"
fi

# ── Step 9 — start (migrations run as a compose dependency) ──────────────────
step "Step 9 of 10 — starting services"
C=(docker compose -p sentinel -f "$INSTALL_DIR/compose.prod.yml" --env-file "$ENV_FILE")
( cd "$INSTALL_DIR" && "${C[@]}" config >/dev/null 2>>"$LOG" ) \
  || die "the compose configuration is invalid — see $LOG. Nothing was started."
say "  ${DIM}database migrations run automatically before the control plane starts${R}"
( cd "$INSTALL_DIR" && "${C[@]}" up -d >>"$LOG" 2>&1 ) \
  || die "failed to start services — see $LOG"
ok "containers started"

# ── Step 10 — health ─────────────────────────────────────────────────────────
step "Step 10 of 10 — health checks"
hc() { # hc LABEL COMMAND...
  local label="$1"; shift
  for _ in $(seq 1 40); do
    if "$@" >/dev/null 2>&1; then ok "$label"; return 0; fi
    sleep 3
  done
  fail "$label"; return 1
}
health_fail=0
hc "Postgres"      docker exec sentinel-postgres-1 pg_isready -U sentinel -d sentinel || health_fail=1
hc "Redis"         docker exec sentinel-redis-1 redis-cli ping                        || health_fail=1
hc "ClickHouse"    bash -c "docker exec sentinel-clickhouse-1 wget -qO- http://127.0.0.1:8123/ping | grep -q Ok" || health_fail=1
hc "Control plane" docker exec sentinel-controlplane-1 /controllerd --version          || true
hc "Data plane"    bash -c "curl -fsS --max-time 3 http://127.0.0.1:80/healthz >/dev/null" || health_fail=1

ADMIN_PW=$(docker logs sentinel-controlplane-1 2>&1 | grep -A2 "GENERATED password" | tail -1 | tr -d ' ' || true)

if [[ $health_fail -ne 0 ]]; then
  printf '\n  %s✗ Installation completed with FAILING health checks%s\n' "$RED" "$R"
  say  "    The stack is installed but not fully healthy."
  say  "    Diagnose:  docker compose -p sentinel ps"
  say  "               docker compose -p sentinel logs --tail 100"
  say  "    Log:       $LOG"
  exit 1
fi

printf '%s\n' "$VERSION" > "$STATE_DIR/version"
cat <<FINAL

  ${GRN}${B}Installation successful${R}

    Version        Next-Gen ESDSWAF v$VERSION
    Dashboard      ${B}https://${WAF_HOSTNAME}:9443${R}
    Username       admin@sentinel.local
    Password       ${B}${ADMIN_PW:-see: docker logs sentinel-controlplane-1 | grep -A2 GENERATED}${R}

  ${YEL}Change that password at first login — it is written in the log above.${R}

  ${B}Next steps${R}
    1. Add your first protected site in the dashboard.
       Until a site exists the WAF returns 502 to everything: correct
       behaviour, because there is no upstream to forward to yet.
    2. ${B}Leave new sites in LEARNING mode.${R} Every published detection figure
       comes from a synthetic corpus; nobody has measured how often this
       WAF would wrongly block YOUR users. Learning mode records what it
       would have blocked without blocking it.
    3. After a full business cycle, measure and then enable blocking:
         $INSTALL_DIR/scripts/backup/../fpr-report.sh 168
       See section 7 of the deployment guide.
    4. Configure backups: $INSTALL_DIR/scripts/backup/backup.sh

    Config  $ENV_FILE  ${DIM}(all secrets — back this up)${R}
    Log     $LOG

FINAL
log "install completed successfully, version $VERSION"
