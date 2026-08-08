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
FORCE=no
ALLOW_UNDERSIZED=no
while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NONINTERACTIVE=yes ;;
    --dry-run) DRY_RUN=yes ;;
    --force) FORCE=yes ;;
    --allow-undersized) ALLOW_UNDERSIZED=yes ;;
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
# Every gate runs before the first change, so "Nothing was installed" is true for
# most aborts — but it was printed UNCONDITIONALLY, including after images were
# loaded, /opt was written and containers were started. An operator told nothing had
# happened has no reason to clean up, and the next run then trips the
# already-installed guard for reasons they were explicitly told did not exist.
# CHANGED flips at the first mutation; the message follows the truth.
CHANGED=no
cleanup_hint() {
  if [[ "$CHANGED" == "yes" ]]; then
    printf '  %sThis host HAS been modified — images loaded, %s written, containers possibly started.%s\n' \
      "$YEL" "$STATE_DIR" "$R" >&2
    printf '  %sInspect:  docker compose -p sentinel ps%s\n' "$DIM" "$R" >&2
    printf '  %sClean up: sudo ./uninstall.sh%s\n' "$DIM" "$R" >&2
  else
    printf '  %sNothing was installed.%s\n' "$DIM" "$R" >&2
  fi
  [[ "$LOG_OK" == "yes" ]] && printf '  %sFull log: %s%s\n' "$DIM" "$LOG" "$R" >&2
  printf '\n' >&2
}
die()  {
  printf '\n  %s✗ INSTALLATION ABORTED%s\n    %s\n\n' "$RED" "$R" "$*" >&2
  log "ABORT $*"
  cleanup_hint
  exit 1
}
# Ctrl-C left no message at all, and no indication of what had already happened.
on_signal() {
  printf '\n\n  %s✗ INTERRUPTED%s\n\n' "$RED" "$R" >&2
  log "ABORT interrupted by signal"
  cleanup_hint
  exit 130
}
trap on_signal INT TERM

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

# An existing installation makes every later gate misleading. Our own containers
# hold 80/443/9443, so the port check reported "something else is listening" and
# advised stopping nginx — on a host where the only listener was this product.
# Detect it here, where we can say something true, and route the operator to the
# tool that actually does what they want.
if [[ -f "$STATE_DIR/version" || -f "$INSTALL_DIR/.env" ]]; then
  EXISTING="$(cat "$STATE_DIR/version" 2>/dev/null || echo 'unknown version')"
  if [[ "$FORCE" == "yes" ]]; then
    warn "existing installation detected ($EXISTING) — continuing because --force was given"
    warn "existing secrets in $INSTALL_DIR/.env will be KEPT, not regenerated"
  elif [[ "$DRY_RUN" == "yes" ]]; then
    warn "an installation is already present ($EXISTING) — a real run would stop here"
  else
    die "Next-Gen ESDSWAF $EXISTING is already installed on this host.

    This installer will not modify an existing deployment: regenerating secrets
    against a database that already exists would lock you out of your own data.

      upgrade to this version    sudo ./upgrade.sh
      remove it completely       sudo ./uninstall.sh    then re-run this installer
      see what is running        docker compose -p sentinel ps

    If the previous attempt failed partway and you want to continue over it:
      sudo ./install.sh --force        (keeps the existing .env and certificates)"
  fi
fi

# manifest.json is read with sed, not python3, ON PURPOSE. Ubuntu cloud and
# minimal images ship without python3, and the previous version shelled out to it
# with `|| echo unknown` — so on such a host VERSION silently became the literal
# string "unknown", the install continued, and it died five steps later looking for
# an image tagged `sentinel/dataplane:unknown`. The operator got a missing-image
# error that said nothing about the real cause. The manifest is written by
# build-bundle.sh one key per line, so a line-oriented parse is exact here.
manifest_str() { # manifest_str KEY — value of a top-level string key
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
    "$HERE/bundle/manifest.json" 2>/dev/null | head -1
}
manifest_bool() { # manifest_bool KEY — true/false of a top-level boolean key
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p" \
    "$HERE/bundle/manifest.json" 2>/dev/null | head -1
}

[[ -f "$HERE/bundle/manifest.json" ]] \
  || die "bundle/manifest.json missing — this does not look like a complete ESDSWAF package"
BUNDLE_VERSION="$(manifest_str version)"
[[ -n "$BUNDLE_VERSION" ]] \
  || die "could not read the version from bundle/manifest.json — the package is malformed.
    Re-download it; do not attempt to install this copy."
ok "package: Next-Gen ESDSWAF v$BUNDLE_VERSION"

[[ -f "$HERE/SHA256SUMS" ]] || die "SHA256SUMS missing — cannot verify package integrity"
say "  verifying every shipped file against SHA256SUMS…"
if ( cd "$HERE" && sha256sum -c --quiet SHA256SUMS >>"$LOG" 2>&1 ); then
  ok "package integrity verified ($(wc -l < "$HERE/SHA256SUMS") files)"
else
  die "CHECKSUM MISMATCH — the package is corrupted or has been altered.
    Re-download it and verify the outer archive first:
      sha256sum -c ESDSWAF-v${BUNDLE_VERSION}.tar.gz.sha256"
fi

# ── Step 2 — operating system ────────────────────────────────────────────────
step "Step 2 of 10 — operating system"
[[ -r /etc/os-release ]] || die "cannot read /etc/os-release — unsupported system"

# Read the three fields we need in SUBSHELLS rather than sourcing os-release into
# this one.
#
# `. /etc/os-release` imports every variable that file defines — NAME, VERSION,
# ID, VERSION_ID, VERSION_CODENAME, HOME_URL and more — straight over whatever
# this script already had. It silently overwrote our package VERSION (read from
# the manifest in Step 1) with Ubuntu's own
# VERSION="24.04.2 LTS (Noble Numbat)", so Step 6 went looking for an image
# tagged `sentinel/dataplane:24.04.2 LTS (Noble Numbat)` and aborted with
# "package is incomplete" — blaming the bundle for a variable collision. Found on
# the first real end-to-end install; no amount of reading caught it.
#
# The package version is now BUNDLE_VERSION, which os-release cannot define, and
# sourcing happens in subshells so nothing else can be clobbered either.
OS_ID="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")"
OS_VERSION_ID="$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID:-}")"
OS_PRETTY="$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}")"

say "  detected: ${OS_PRETTY:-unknown}"
case "${OS_ID}:${OS_VERSION_ID}" in
  ubuntu:22.04|ubuntu:24.04) ok "supported" ;;
  ubuntu:*)
    warn "Ubuntu ${OS_VERSION_ID} is not a tested release"
    [[ "$NONINTERACTIVE" == "yes" ]] || {
      read -r -p "  Continue anyway? Type YES: " c || true
      [[ "$c" == "YES" ]] || die "aborted at OS check"
    } ;;
  *)
    die "unsupported operating system: ${OS_PRETTY:-$OS_ID $OS_VERSION_ID}

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
  # An evaluation VM a few GB under spec is a real and common case — a 100 GB disk
  # reports ~98 GB free once formatted, which failed a 100 GB gate by 2%. Refusing
  # outright forces the operator to either resize or edit the installer, and
  # editing it breaks its own SHA256SUMS check. Offer an explicit, logged override
  # instead, and be specific about what each shortfall actually costs — the two are
  # nothing alike.
  if [[ "$ALLOW_UNDERSIZED" == "yes" ]]; then
    warn "PROCEEDING UNDER SPEC because --allow-undersized was given"
    [[ "$VCPU"    -lt "$MIN_VCPU" ]] && \
      warn "  CPU ${VCPU} < ${MIN_VCPU}: throughput will be well below published figures"
    [[ "$DISK_GB" -lt "$MIN_DISK_GB" ]] && \
      warn "  Disk ${DISK_GB}GB < ${MIN_DISK_GB}GB: fine to start, but event history fills
       the disk sooner. Lower SENTINEL_CLICKHOUSE_*_RETENTION_DAYS accordingly."
    if [[ "$RAM_GB" -lt "$MIN_RAM_GB" ]]; then
      warn "  RAM ${RAM_GB}GB < ${MIN_RAM_GB}GB: THIS ONE ACTUALLY BREAKS THINGS."
      warn "       ClickHouse is capped at 6GB and crash-loops with under ~2GB free."
      warn "       Expect a stack that installs cleanly and then restarts forever."
    fi
    say ""
    say "  ${DIM}This is acceptable for an evaluation. It is not a supported${R}"
    say "  ${DIM}production configuration, and the shortfall is recorded in $LOG.${R}"
    log "UNDERSIZED override: cpu=$VCPU ram=$RAM_GB disk=$DISK_GB"
  else
    die "hardware below minimum specification.

    Required: ${MIN_VCPU} vCPU, ${MIN_RAM_GB}+ GB RAM, ${MIN_DISK_GB} GB free disk on /opt
    Detected: ${VCPU} vCPU, ${RAM_GB} GB RAM, ${DISK_GB} GB free

    RAM is the one that genuinely breaks: ClickHouse is limited to 6 GB and
    crash-loops indefinitely with less than about 2 GB available to it. Disk and
    CPU shortfalls degrade rather than break.

    Resize the VM and re-run — or, for an EVALUATION only, proceed anyway:

        sudo ./install.sh --allow-undersized"
  fi
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
manifest_list() { # manifest_list KEY — the quoted strings of a top-level array
  awk -v k="\"$1\"" '
    index($0, k) { inlist = 1; next }
    inlist && /\]/ { exit }
    inlist && match($0, /"[^"]+"/) { print "      - " substr($0, RSTART + 1, RLENGTH - 2) }
  ' "$HERE/bundle/manifest.json" 2>/dev/null
}
# Default to "needs the internet" when the key is unreadable: assuming an offline
# bundle we do not have turns a clear preflight abort into a failure partway
# through `up`, which is much harder to diagnose.
NEEDS_NET="$(manifest_bool requires_internet)"
if [[ "$NEEDS_NET" != "false" ]]; then
  PULL_COUNT="$(manifest_list pulled_from_registry | wc -l)"
  if timeout 12 docker pull hello-world >/dev/null 2>&1; then
    ok "Docker registry reachable (${PULL_COUNT:-5} third-party images will be pulled)"
    docker rmi hello-world >/dev/null 2>&1 || true
  else
    die "cannot reach the Docker registry, and this package needs it.

    This bundle contains the four ESDSWAF images only. These are pulled:
$(manifest_list pulled_from_registry)

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

# `route get 1.1.1.1` returns nothing on a host with no default route — common on
# exactly the isolated management networks this product is installed into. The
# default then became empty, and in --non-interactive mode `ask` accepts the empty
# default silently: the install proceeded with no hostname and an admin address of
# literally "admin@". Fall back to the first configured address, and refuse to
# continue with nothing.
DEF_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
[[ -n "$DEF_IP" ]] || DEF_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
ask WAF_HOSTNAME "Hostname clients will use (e.g. waf.company.com)" "${DEF_IP:-}"
[[ -n "$WAF_HOSTNAME" ]] || die "no hostname given, and this host has no address to fall back to.
    Re-run with an explicit value:
      sudo WAF_HOSTNAME=waf.company.com ./install.sh --non-interactive"
ask ADMIN_EMAIL  "Administrator email" "admin@${WAF_HOSTNAME}"

# This used to be a question — "1) I will supply my own certificate / 2) Self-signed"
# — whose answer was read into TLS_CHOICE, defaulted, and then never referenced
# again anywhere in the script. Both answers produced identical behaviour. Asking
# an operator to make a decision the installer discards is worse than not asking:
# someone who chose 1 reasonably believed the installer was waiting for their
# certificate. State what actually happens instead.
if [[ "$NONINTERACTIVE" != "yes" ]]; then
  say ""
  say "  ${B}TLS${R}"
  say "    This installer issues a certificate from an internal CA it generates"
  # Printed "valid for 172.16.21.95 and 172.16.21.95" when the operator answered
  # the hostname prompt with the host's own IP — which is the common case on an
  # internal deployment with no DNS name. issue-ip-cert.sh already drops the
  # duplicate before it reaches the SAN; only the message repeated it.
  say "    here, valid for ${DEF_IP:-this host}$([[ -n "$WAF_HOSTNAME" && "$WAF_HOSTNAME" != "$DEF_IP" ]] && printf ' and %s' "$WAF_HOSTNAME")."
  say "    ${DIM}Clients that import /opt/sentinel-pki/root.crt get a green lock;${R}"
  say "    ${DIM}others see the usual untrusted-issuer warning.${R}"
  say ""
  say "    ${DIM}To use a publicly-trusted certificate instead, upload it in the${R}"
  say "    ${DIM}console after install (Certificates → Upload). Let's Encrypt needs${R}"
  say "    ${DIM}inbound port 80 from the internet, which many on-premise networks${R}"
  say "    ${DIM}do not permit — check before promising it to a customer.${R}"
fi

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
  say "  Run it on the MASTER first and let it finish: it prints the three artifacts"
  say "  that must be copied to the second node before that node can be installed."
  say ""
  say "  Full procedure: ${B}docs/ACTIVE-PASSIVE.md${R} in this bundle."
  say "  Nothing has been changed on this host."
  exit 0
fi

ok "hostname: $WAF_HOSTNAME"
ok "admin:    $ADMIN_EMAIL"

# ── Step 6 — load images ─────────────────────────────────────────────────────
step "Step 6 of 10 — loading images"
say "  ${DIM}pre-built: no compilation, about a minute${R}"
# First mutation of the host. Everything above this line is a check.
CHANGED=yes
docker load -i "$HERE/bundle/images.tar.gz" >>"$LOG" 2>&1 \
  || die "docker load failed — see $LOG"
for svc in dataplane controlplane dashboard migrate; do
  docker image inspect "sentinel/${svc}:${BUNDLE_VERSION}" >/dev/null 2>&1 \
    || die "image sentinel/${svc}:${BUNDLE_VERSION} missing after load — package is incomplete"
done
ok "four images loaded at version $BUNDLE_VERSION"

# ── Step 7 — install tree and secrets ────────────────────────────────────────
step "Step 7 of 10 — configuration and secrets"
# These four were unguarded. This script runs without `set -e` (errors are handled
# explicitly), so a failed mkdir or cp did not stop anything: the install carried
# on and reported success over an install tree that was empty or half-written.
mkdir -p "$INSTALL_DIR" "$PKI_DIR" "$INSTALL_DIR/scripts" \
  || die "could not create the install tree under $STATE_DIR — check free space and permissions"
cp -r "$HERE/compose/." "$INSTALL_DIR/" \
  || die "could not copy the compose files into $INSTALL_DIR"
# The trailing "/." copies the CONTENTS. Without it, a second run over an existing
# tree lands them in $INSTALL_DIR/scripts/scripts, and every path printed later
# points at a directory that does not contain what it claims to.
cp -r "$HERE/scripts/." "$INSTALL_DIR/scripts/" \
  || die "could not copy the operational scripts into $INSTALL_DIR/scripts"
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
SENTINEL_VERSION=$BUNDLE_VERSION
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

# The two certificates are gated SEPARATELY. A single `if pg-server.crt exists`
# guard covered both, so any re-run over an existing Postgres certificate skipped
# issuing the data plane's default certificate entirely — leaving :443 with
# whatever was there before, or nothing.
CERT_VOL_DEFAULT=/var/lib/docker/volumes/sentinel_sentinel-certs/_data/default

# Default TLS certificate presented on :443 to clients that send no SNI.
#
# This call previously passed NO environment, so issue-ip-cert.sh fell back to its
# hardcoded default of 172.16.21.71 — an ESDS development VM. Every customer host
# therefore served HTTPS with a certificate for a machine on another network, and
# because the failure was `|| warn` the install still reported success. Pass the
# real address and the hostname the operator just gave us, and treat failure as
# fatal: a WAF with no usable certificate on :443 is not an installed WAF.
if [[ -f "$CERT_VOL_DEFAULT/cert.pem" && -s "$CERT_VOL_DEFAULT/cert.pem" ]]; then
  ok "default TLS certificate already present"
else
  ( cd "$INSTALL_DIR/scripts" && \
      WAF_IP="${DEF_IP:-127.0.0.1}" WAF_HOSTNAME="$WAF_HOSTNAME" \
      ./issue-ip-cert.sh >>"$LOG" 2>&1 ) \
    || die "could not issue the default TLS certificate — see $LOG.
    The data plane would have no certificate to present on :443."
  ok "default TLS certificate issued for ${DEF_IP:-127.0.0.1}$([[ -n "$WAF_HOSTNAME" && "$WAF_HOSTNAME" != "$DEF_IP" ]] && printf ' / %s' "$WAF_HOSTNAME")"
fi

if [[ -f "$PKI_DIR/pg-server.crt" && -s "$PKI_DIR/pg-server.crt" ]]; then
  ok "Postgres certificate already present"
else
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
# These two replace `docker exec ... /controllerd --version || true`, which could
# not fail for two separate reasons: `--version` only proved the BINARY was in the
# image (true even for a container crash-looping on a bad DSN), and the `|| true`
# discarded the verdict anyway. The installer could therefore report a successful
# install with no working control plane — i.e. no console, which is the whole
# management interface.
hc "Control plane" bash -c 'test "$(docker inspect -f "{{.State.Status}}" sentinel-controlplane-1 2>/dev/null)" = running' || health_fail=1
hc "Data plane"    bash -c "curl -fsS --max-time 3 http://127.0.0.1:80/healthz >/dev/null" || health_fail=1
# :443 was never probed by any check, which is how a default certificate issued for
# the wrong network shipped unnoticed. No -f here on purpose: with no sites yet the
# WAF correctly answers 502, and a 502 still proves the TLS handshake completed and
# a certificate was served. Only a handshake or connection failure fails this.
hc "TLS on :443"   bash -c 'curl -sk --max-time 5 -o /dev/null https://127.0.0.1:443/' || health_fail=1
# End-to-end: the management listener answering proves the data plane's console
# is up AND proxying to the control plane. It is the first thing the operator will
# touch, so failing here now beats them discovering it themselves.
hc "Console :9443" bash -c 'curl -sk --max-time 5 -o /dev/null -w "%{http_code}" https://127.0.0.1:9443/ | grep -qE "^[234]"' || health_fail=1

# The generated password is the SECOND line of the seed banner emitted by
# control-plane/internal/db/seed.go:
#
#     [sentinel] Seeded initial admin '...' with a GENERATED password:
#     [sentinel]     <48 hex chars>
#     [sentinel] Log in and change it immediately. Set SENTINEL_BOOTSTRAP_...
#
# `grep -A2 | tail -1` took the THIRD line — the advisory sentence — and printed it
# to the operator as the password. Because that string is non-empty it also
# defeated the `${ADMIN_PW:-<hint>}` fallback further down, so they were not even
# told where to look. Every fresh install ended with a green success banner and an
# unusable credential.
#
# Take the second line, strip only the log prefix (`tr -d ' '` would have glued
# "[sentinel]" onto the value), and REQUIRE the result to look like what seed.go
# actually generates — 24 random bytes, hex-encoded. Anything else is treated as a
# failed scrape so the fallback hint fires instead of printing garbage.
ADMIN_PW=$(docker logs sentinel-controlplane-1 2>&1 \
  | grep -A1 'GENERATED password' | tail -1 \
  | sed -n 's/^\[sentinel\][[:space:]]*//p' | tr -d '[:space:]' || true)
[[ "$ADMIN_PW" =~ ^[0-9a-f]{48}$ ]] || ADMIN_PW=""

if [[ $health_fail -ne 0 ]]; then
  printf '\n  %s✗ Installation completed with FAILING health checks%s\n' "$RED" "$R"
  say  "    The stack is installed but not fully healthy."
  say  "    Diagnose:  docker compose -p sentinel ps"
  say  "               docker compose -p sentinel logs --tail 100"
  say  "    Log:       $LOG"
  exit 1
fi

printf '%s\n' "$BUNDLE_VERSION" > "$STATE_DIR/version"
cat <<FINAL

  ${GRN}${B}Installation successful${R}

    Version        Next-Gen ESDSWAF v$BUNDLE_VERSION
    Username       admin@sentinel.local
    Password       ${B}${ADMIN_PW:-NOT CAPTURED — recover it with the command below}${R}

  ${YEL}Change this password at first login.${R}
  ${DIM}It is NOT in $LOG. The control plane prints it once, to its container log:${R}
    ${DIM}docker logs sentinel-controlplane-1 2>&1 | grep -A1 'GENERATED password'${R}

  ${B}Reaching the console${R}

    The management console is bound to ${B}127.0.0.1 only${R}, deliberately: it is a
    security appliance's admin UI, and on 0.0.0.0 it would be exposed to whatever
    network this host sits on — and to the internet the moment the host gets a
    public IP. So it is NOT reachable at https://${WAF_HOSTNAME}:9443 from your
    laptop, and that is the intended behaviour, not a fault.

    From this host          ${B}https://127.0.0.1:9443${R}
    From your workstation   ${B}ssh -L 9443:127.0.0.1:9443 ${SUDO_USER:-root}@${DEF_IP:-<this-host>}${R}
                            then open ${B}https://127.0.0.1:9443${R}

    ${DIM}Ports 80 and 443 ARE published on all interfaces — that is the WAF's${R}
    ${DIM}traffic path, and it is what your protected sites are served on.${R}

  ${B}Next steps${R}
    1. Add your first protected site in the dashboard.
       Until a site exists the WAF returns 502 to everything: correct
       behaviour, because there is no upstream to forward to yet.
    2. ${B}Leave new sites in LEARNING mode.${R} Every published detection figure
       comes from a synthetic corpus; nobody has measured how often this
       WAF would wrongly block YOUR users. Learning mode records what it
       would have blocked without blocking it.
    3. After a full business cycle, measure and then enable blocking:
         $INSTALL_DIR/scripts/fpr-report.sh 168
       See section 7 of the deployment guide.
    4. Configure backups: $INSTALL_DIR/scripts/backup/backup.sh

    Config  $ENV_FILE  ${DIM}(all secrets — back this up)${R}
    Log     $LOG

FINAL
log "install completed successfully, version $BUNDLE_VERSION"
