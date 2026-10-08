#!/usr/bin/env bash
# =============================================================================
#  Swaraj Kavach — Installer (standalone node)
#
#      sudo ./install.sh
#
#  Asks only for information we cannot generate: the hostname clients will use,
#  an administrator email, and whether users arrive through a shared NAT/VPN
#  address. Every secret — database passwords, session signing key, audit HMAC
#  key, internal service token — is generated with `openssl rand`. You are never
#  asked to invent a password.
#
#  Aborts BEFORE changing anything if the host does not meet requirements. There
#  is no half-installed state to clean up: every gate runs first, and the first
#  action that alters the system is loading images, after all checks have passed.
#
#  Sizes itself to the host it lands on: the event store's memory limit, the
#  per-request log ceiling and the event spool are derived from the detected
#  RAM and disk and written into .env with the numbers they came from.
#
#  Everything is logged to /var/log/sentinel/install.log, and a one-page
#  /opt/sentinel/install-report.txt is written on success — send both to
#  support if anything fails, rather than re-running commands by hand.
#
#      --non-interactive         take answers from the environment:
#                                WAF_HOSTNAME, ADMIN_EMAIL, SHARED_EGRESS, CONSOLE_BIND
#      --dry-run                 run every check, change nothing
#      --force                   continue over a previous incomplete attempt
#      --allow-undersized        evaluation only: proceed below minimum spec
#      --console-bind <ip>       publish the console (9443) on a PRIVATE address
#                                of this host instead of 127.0.0.1. Public and
#                                wildcard addresses are refused.
#      --shared-egress <cidrs>   comma-separated NAT/VPN egress addresses whose
#                                block history must never punish bystanders
#      --trusted-proxies <list>  load balancers / CDN in front of this WAF whose
#                                X-Forwarded-For is believed: comma-separated
#                                IPv4 addresses or CIDRs, or `cloudflare` for
#                                Cloudflare's published ranges
#      --no-harden               skip the kernel network profile (sysctl)
#      --no-docker-tuning        do not enable Docker at boot or set live-restore
#      --no-docker-install       if Docker is absent, stop instead of installing it
#
#  Docker is installed by this script when it is missing: from the packages
#  shipped in the offline bundle (no network), otherwise from Ubuntu's own
#  repositories. No third-party script is ever piped into a shell.
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR=/var/log/sentinel
LOG="$LOG_DIR/install.log"
STATE_DIR=/opt/sentinel
INSTALL_DIR="$STATE_DIR/current"
PKI_DIR=/opt/sentinel-pki
BACKUP_ENV=/etc/sentinel/backup.env
BACKUP_KEY=/etc/sentinel/backup.key

NONINTERACTIVE=no
DRY_RUN=no
FORCE=no
ALLOW_UNDERSIZED=no
HARDEN=yes
DOCKER_TUNING=yes
DOCKER_INSTALL=yes
# CONSOLE_BIND / SHARED_EGRESS may also arrive from the environment (see
# --non-interactive); a flag wins over the environment.
CONSOLE_BIND="${CONSOLE_BIND:-}"
SHARED_EGRESS="${SHARED_EGRESS:-}"
TRUSTED_PROXIES="${TRUSTED_PROXIES:-}"
need_arg() { [[ -n "${2:-}" && "${2:0:2}" != "--" ]] || { echo "$1 needs a value" >&2; exit 2; }; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --non-interactive) NONINTERACTIVE=yes ;;
    --dry-run) DRY_RUN=yes ;;
    --force) FORCE=yes ;;
    --allow-undersized) ALLOW_UNDERSIZED=yes ;;
    --no-harden) HARDEN=no ;;
    --no-docker-tuning) DOCKER_TUNING=no ;;
    --no-docker-install) DOCKER_INSTALL=no ;;
    --console-bind)  need_arg "$1" "${2:-}"; CONSOLE_BIND="$2";  shift ;;
    --shared-egress) need_arg "$1" "${2:-}"; SHARED_EGRESS="$2"; shift ;;
    --trusted-proxies) need_arg "$1" "${2:-}"; TRUSTED_PROXIES="$2"; shift ;;
    # The header block, from its second line to the closing rule. A fixed line
    # range went stale every time the header grew and printed half a sentence.
    -h|--help) awk 'NR>2 && /^# =+$/{exit} NR>2' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
# The log accumulates across runs; the install report quotes only this run's lines.
LOG_START=$(wc -l < "$LOG" 2>/dev/null || echo 0)
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
    printf '  %sThis host HAS been modified — Docker possibly installed, images loaded, %s written, containers possibly started.%s\n' \
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

# --- sizing-begin ------------------------------------------------------------
# size_for_host RAM_GB VCPU DISK_GB — prints KEY=VALUE lines for the .env.
#
# Pure: no I/O, no globals, integer arithmetic only, so that
# deploy/ci/check-installer-sizing.sh can lift it out by these markers and assert
# the numbers for a 16, 32 and 64 GB host without a VM. Keep it that way.
#
#   CLICKHOUSE_MEM_LIMIT   ~30% of RAM, floor 6g (below which ClickHouse
#                          crash-loops), cap 16g (past which the event store gains
#                          nothing and the data plane — which has no cgroup limit
#                          of its own — loses the headroom it needs under a flood).
#   SENTINEL_LOG_MAX_MB /  the per-request NDJSON logs the console tails. On-disk
#   SENTINEL_LOG_KEEP      ceiling = MAX_MB x (KEEP+1) x 2 streams; scaled with
#                          the disk so a 200 GB host keeps ~4 GB of request history
#                          instead of the 1.2 GB that fits a 100 GB one.
#   SENTINEL_SPOOL_MAX_BYTES  events buffered on disk while ClickHouse is down.
#   TIER                   minimum | recommended | production — printed, and
#                          recorded in the install report, never enforced.
size_for_host() {
  local ram="${1:-0}" vcpu="${2:-0}" disk="${3:-0}"
  local ch=$(( ram * 30 / 100 ))
  (( ch < 6 ))  && ch=6
  (( ch > 16 )) && ch=16
  local log_mb=100 log_keep=5 spool=268435456
  if   (( disk >= 180 )); then log_mb=250; log_keep=7; spool=1073741824
  elif (( disk >= 120 )); then log_mb=150; log_keep=5; spool=536870912
  fi
  local tier=minimum
  if   (( ram >= 30 && vcpu >= 12 && disk >= 180 )); then tier=production
  elif (( ram >= 15 && vcpu >= 8  && disk >= 180 )); then tier=recommended
  fi
  printf 'TIER=%s\nCLICKHOUSE_MEM_LIMIT=%sg\nSENTINEL_LOG_MAX_MB=%s\nSENTINEL_LOG_KEEP=%s\nSENTINEL_SPOOL_MAX_BYTES=%s\n' \
    "$tier" "$ch" "$log_mb" "$log_keep" "$spool"
}
# --- sizing-end --------------------------------------------------------------

# --- validators-begin --------------------------------------------------------
# console_bind_ok IP "ADDR ADDR ..." — 0 when IP is a PRIVATE IPv4 address
# (RFC 1918 or loopback) that is configured on this host. Never 0.0.0.0, never a
# public address, and there is deliberately no flag to allow either: the console
# is a security appliance's admin UI, and the only thing meant to reach this host
# from outside is a NAT that forwards 80/443. Pure; unit-tested by the CI check.
console_bind_ok() {
  local ip="$1" local_addrs="${2:-}"
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  # 10# forces decimal: an octet such as "08" would otherwise be read as octal
  # and abort the arithmetic instead of being judged.
  local a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]}))
  local c=$((10#${BASH_REMATCH[3]})) d=$((10#${BASH_REMATCH[4]}))
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  [[ "$ip" == "0.0.0.0" ]] && return 1
  if   (( a == 10 )); then :
  elif (( a == 127 )); then :
  elif (( a == 172 && b >= 16 && b <= 31 )); then :
  elif (( a == 192 && b == 168 )); then :
  else return 1
  fi
  [[ " $local_addrs " == *" $ip "* ]]
}
# cidr_list_ok "a,b/24,..." — every comma-separated item is an IPv4 address or
# IPv4/prefix. The data plane silently drops what it cannot parse, so a typo here
# would be a shared address that is NOT forgiven — refuse it at install instead.
cidr_list_ok() {
  local items item
  # `read` drops a trailing empty field, so "a," would pass as "a". A leading,
  # trailing or doubled comma is a list with a hole in it — refuse it whole.
  [[ "${1:-}" =~ ^,|,,|,$ ]] && return 1
  IFS=',' read -ra items <<<"${1:-}"
  (( ${#items[@]} > 0 )) || return 1
  for item in "${items[@]}"; do
    item="${item// /}"
    [[ "$item" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[012]))?$ ]] || return 1
  done
}
# A trusted-proxy list: cidr_list_ok entries, or the `cloudflare` preset.
trusted_list_ok() {
  local items item
  [[ "${1:-}" =~ ^,|,,|,$ ]] && return 1
  IFS=',' read -ra items <<<"${1:-}"
  (( ${#items[@]} > 0 )) || return 1
  for item in "${items[@]}"; do
    item="${item// /}"
    [[ "$item" == cloudflare ]] && continue
    cidr_list_ok "$item" || return 1
  done
}
# --- validators-end ----------------------------------------------------------

banner() {
cat <<'EOF'

  ==========================================================
       Swaraj Kavach  —  Installer
       ESDS Software Solution Ltd
  ==========================================================
EOF
}
banner
say "install started $(date -u +%Y-%m-%dT%H:%M:%SZ) (log: $LOG)"

# ── Step 1 — privileges and package integrity ────────────────────────────────
step "Step 1 of 11 —package"
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
    die "Swaraj Kavach $EXISTING is already installed on this host.

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
ok "package: Swaraj Kavach v$BUNDLE_VERSION"
# Where the container images come from. "registry" ships none and pulls them;
# anything else (or an unreadable key, which is every bundle built before this
# existed) means they are inside bundle/images.tar.gz.
#
# Taken from the NAMED manifest field rather than inferred from whether
# images.tar.gz exists: a truncated download would otherwise look exactly like a
# registry bundle and skip loading images it was supposed to contain.
IMAGE_SOURCE="$(manifest_str image_source)"
[[ "$IMAGE_SOURCE" == "registry" ]] || IMAGE_SOURCE=bundled
if [[ "$IMAGE_SOURCE" == "registry" ]]; then
  REGISTRY_PREFIX="$(manifest_str registry_prefix)"
  THIRDPARTY_PREFIX="$(manifest_str thirdparty_prefix)"
  [[ -n "$REGISTRY_PREFIX" ]] \
    || die "this package says image_source=registry but names no registry_prefix.
    bundle/manifest.json is malformed — ask ESDS for a rebuilt package."
  ok "images come from $REGISTRY_PREFIX (nothing to load)"
else
  [[ -s "$HERE/bundle/images.tar.gz" ]] \
    || die "bundle/images.tar.gz is missing or empty, and this package does not
    say image_source=registry. The download is incomplete — verify the checksum
    and download it again."
fi

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
step "Step 2 of 11 —operating system"
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
step "Step 3 of 11 —hardware"
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

# Size the deployment to what was detected. The numbers land in .env (Step 7)
# with the facts they were derived from, so whoever reads that file later can see
# why the event store has the limit it has. Tier is descriptive: a host can pass
# the minimum gate and still be told, in plain words, that it is a minimum host.
SIZING="$(size_for_host "$RAM_GB" "$VCPU" "$DISK_GB")"
TIER="$(sed -n 's/^TIER=//p' <<<"$SIZING")"
CH_MEM="$(sed -n 's/^CLICKHOUSE_MEM_LIMIT=//p' <<<"$SIZING")"
LOG_MB="$(sed -n 's/^SENTINEL_LOG_MAX_MB=//p' <<<"$SIZING")"
LOG_KEEP="$(sed -n 's/^SENTINEL_LOG_KEEP=//p' <<<"$SIZING")"
SPOOL_BYTES="$(sed -n 's/^SENTINEL_SPOOL_MAX_BYTES=//p' <<<"$SIZING")"
say ""
case "$TIER" in
  production)  ok   "host tier: ${B}production${R} (≥12 vCPU, ≥32 GB, ≥200 GB)" ;;
  recommended) ok   "host tier: recommended (≥8 vCPU, 16 GB, ≥200 GB)" ;;
  *)           warn "host tier: MINIMUM — fine for an evaluation; production sizing is 16 vCPU / 32 GB / 200 GB SSD" ;;
esac
say "  ${DIM}sizing → event store memory ${CH_MEM}, request logs ${LOG_MB} MB × $((LOG_KEEP + 1)) × 2 streams (≈$(( LOG_MB * (LOG_KEEP + 1) * 2 / 1024 )) GB), event spool $(( SPOOL_BYTES / 1048576 )) MB${R}"
log "SIZING tier=$TIER ch=$CH_MEM log_mb=$LOG_MB log_keep=$LOG_KEEP spool=$SPOOL_BYTES"

# ── Step 4 — Docker, ports, clock, connectivity ──────────────────────────────
step "Step 4 of 11 —prerequisites"

# Ports and clock first — they need nothing installed, and a host that fails
# them should fail before Docker is touched.
# Ports held by OUR OWN running stack are not a conflict. On a --force re-run over
# an existing installation the containers are up and hold 80/443/9443; Step 10's
# `compose up` re-uses or recreates them in place. Treating that as "something
# else is listening" sent the first real operator to `docker rm -f` every
# container by hand to get past this gate — an outage, and a habit that would
# be catastrophic on a production node. Only a listener that is NOT one of our
# compose project's containers is a real conflict.
ours_hold_port() { # ours_hold_port PORT — 0 if a sentinel compose container publishes it
  command -v docker >/dev/null 2>&1 || return 1
  docker ps --filter label=com.docker.compose.project=sentinel --format '{{.Ports}}' 2>/dev/null \
    | grep -qE "[:.]${1}->"
}
port_busy=0
held_by_us=()
for p in "${REQUIRED_PORTS[@]}"; do
  if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$"; then
    if [[ "$FORCE" == "yes" ]] && ours_hold_port "$p"; then
      held_by_us+=("$p")
    else
      fail "port $p is already in use"; port_busy=1
    fi
  fi
done
if [[ $port_busy -eq 1 ]]; then
  ss -ltnp 2>/dev/null | grep -E "[:.](80|443|9443)\s" >>"$LOG" 2>&1 || true
  die "ports ${REQUIRED_PORTS[*]} must be free — the WAF binds them.
    Something else (often nginx or apache) is listening. Stop it and re-run.
    Details written to $LOG"
fi
if (( ${#held_by_us[@]} > 0 )); then
  ok "ports ${held_by_us[*]} are held by the existing Swaraj Kavach stack — kept running, re-used in Step 10"
else
  ok "ports free: ${REQUIRED_PORTS[*]}"
fi

if timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes; then
  ok "clock synchronised"
else
  warn "clock is NOT NTP-synchronised — certificate validation and audit"
  warn "timestamps depend on it. Fix with: timedatectl set-ntp true"
fi

# ── Docker ───────────────────────────────────────────────────────────────────
# Docker is the one prerequisite this product cannot run without, and the first
# real install stalled on exactly it: the host had none, and the documented
# `curl get.docker.com | sh` died on a stale cdrom apt source before it began.
# The installer now provisions Docker itself, in this order of preference:
#
#   1. the packages shipped in the offline bundle (bundle/docker/<codename>/) —
#      no network at all, and the exact version this release was tested with;
#   2. Ubuntu's own repositories (docker.io + docker-compose-v2) — only the
#      distro mirrors an enterprise VM already reaches; no third-party apt repo
#      is added and no remote script is piped into a shell;
#   3. neither possible → stop with the manual instruction.
#
# --dry-run installs nothing and reports which of these a real run would use.
# --no-docker-install turns the whole thing off for sites that manage Docker
# themselves (configuration management, a golden image).
OS_CODENAME="$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_CODENAME:-}")"
DOCKER_DEBS="$HERE/bundle/docker/${OS_CODENAME:-unknown}"
DOCKER_MISSING_DRYRUN=no
docker_ready() {
  command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 && docker info >/dev/null 2>&1
}
# A leftover install-medium source ("deb file:///cdrom …", "deb cdrom:…") makes
# EVERY apt operation fail with "no Release file" — on a VM the medium is gone
# for good. This is the ONE edit to the host's apt configuration the installer
# makes: only when it is about to run apt, with a backup, and announced.
disable_cdrom_sources() {
  local f hit=0
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
    [[ -f "$f" ]] || continue
    if grep -qE '^[[:space:]]*deb[[:space:]]+(\[[^]]*\][[:space:]]+)?(cdrom:|file:///cdrom)' "$f"; then
      cp -n "$f" "$f.bak-sentinel" 2>/dev/null || true
      sed -i -E 's|^([[:space:]]*deb[[:space:]]+(\[[^]]*\][[:space:]]+)?(cdrom:\|file:///cdrom))|# disabled by the Swaraj Kavach installer — install medium is not present: \1|' "$f"
      hit=1; log "APT disabled cdrom source in $f (backup $f.bak-sentinel)"
    fi
  done
  [[ $hit -eq 1 ]] && warn "disabled a cdrom / install-medium apt source so apt can run (backup: *.bak-sentinel)"
  return 0
}
install_docker_from_bundle() {
  say "  ${DIM}installing Docker Engine from the packages in this bundle — no network needed${R}"
  ( cd "$DOCKER_DEBS" && sha256sum -c --quiet SHA256SUMS ) >>"$LOG" 2>&1 \
    || { fail "the shipped Docker packages do not match their checksums — refusing to install them"; return 1; }
  if DEBIAN_FRONTEND=noninteractive dpkg -i "$DOCKER_DEBS"/*.deb >>"$LOG" 2>&1; then return 0; fi
  # A very minimal image can lack a shared library the packages need. One apt
  # pass resolves it from the distro mirrors if those are reachable; if not,
  # dpkg has named the missing dependency in the log.
  warn "dpkg reported unmet dependencies — trying to resolve them from Ubuntu's repositories"
  disable_cdrom_sources
  apt-get -qq update >>"$LOG" 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get -qq -y -f install >>"$LOG" 2>&1
}
install_docker_from_distro() {
  say "  ${DIM}installing Docker from Ubuntu's own repositories (docker.io + docker-compose-v2)${R}"
  disable_cdrom_sources
  apt-get -qq update >>"$LOG" 2>&1 || { fail "apt-get update failed — see $LOG"; return 1; }
  DEBIAN_FRONTEND=noninteractive apt-get -qq -y install docker.io docker-compose-v2 >>"$LOG" 2>&1
}
ensure_docker() {
  if docker_ready; then
    ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo present) with Compose v2"
    return 0
  fi
  # Installed but not usable: name the part, never reinstall over it.
  if command -v docker >/dev/null 2>&1; then
    docker info >/dev/null 2>&1 \
      || die "Docker is installed but its daemon is not running — systemctl enable --now docker, then re-run"
    docker compose version >/dev/null 2>&1 \
      || die "Docker is installed but the Compose v2 plugin is missing.
      Ubuntu repositories:  apt-get install docker-compose-v2
      Docker's repository:  apt-get install docker-compose-plugin"
  fi
  local source=distro
  [[ -d "$DOCKER_DEBS" && -s "$DOCKER_DEBS/SHA256SUMS" ]] && source=bundle
  if [[ "$DOCKER_INSTALL" != "yes" ]]; then
    die "Docker is not installed, and --no-docker-install was given.
    Install Docker Engine with the Compose v2 plugin, then re-run:
      apt-get install docker.io docker-compose-v2     (Ubuntu repositories)
      systemctl enable --now docker"
  fi
  if [[ "$DRY_RUN" == "yes" ]]; then
    DOCKER_MISSING_DRYRUN=yes
    if [[ "$source" == bundle ]]; then
      warn "Docker is not installed — a real run would install it from this bundle ($(awk '$1 == "docker-ce" {print $2}' "$DOCKER_DEBS/VERSIONS" 2>/dev/null || echo 'shipped packages')), no network needed"
    else
      warn "Docker is not installed — a real run would install docker.io + docker-compose-v2 from Ubuntu's repositories"
    fi
    warn "checks that need Docker (data-root disk, storage type, registry reachability) are skipped in this dry run"
    return 0
  fi
  # First mutation of the host in this run.
  CHANGED=yes
  log "DOCKER installing from $source"
  if [[ "$source" == bundle ]]; then
    install_docker_from_bundle \
      || die "could not install Docker from the bundled packages — see $LOG.
    docker-ce needs iptables and nftables on the host (both are standard on Ubuntu
    Server; minimal images may lack nftables). If dpkg named one of them:
      apt-get install iptables nftables        then re-run this installer
    Manual fallback:  apt-get install docker.io docker-compose-v2 && systemctl enable --now docker"
  else
    install_docker_from_distro \
      || die "could not install Docker from Ubuntu's repositories — see $LOG.
    This host may have no route to the distro mirrors. Ask ESDS for the offline
    bundle, which ships Docker's packages, or install Docker Engine by hand and re-run."
  fi
  systemctl enable --now docker >>"$LOG" 2>&1 || true
  local tries=0
  until docker info >/dev/null 2>&1 || (( tries >= 20 )); do sleep 2; tries=$((tries + 1)); done
  docker_ready \
    || die "Docker was installed but is not usable (daemon or Compose plugin) — see $LOG and: journalctl -u docker"
  ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null) installed from $source and running"
}
ensure_docker

if [[ "$DOCKER_MISSING_DRYRUN" != "yes" ]]; then
# Images and EVERY volume — the configuration database, the event store, the
# request logs — live under Docker's data-root, which is /var/lib/docker by
# default and not /opt. Step 3 measured /opt because that is where the install
# tree goes; on a host whose /var is a smaller separate filesystem that gate
# passed and the event store then filled the root disk. Measure the filesystem
# the data actually lands on, and only when it is a different one.
DOCKER_ROOT="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)"
DOCKER_ROOT="${DOCKER_ROOT:-/var/lib/docker}"
DOCKER_ROOT_FS="$(df --output=source "$DOCKER_ROOT" 2>/dev/null | tail -1)"
OPT_FS="$(df --output=source /opt 2>/dev/null | tail -1)"
if [[ -n "$DOCKER_ROOT_FS" && "$DOCKER_ROOT_FS" != "$OPT_FS" ]]; then
  DOCKER_DISK_GB=$(df -BG --output=avail "$DOCKER_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9')
  DOCKER_DISK_GB="${DOCKER_DISK_GB:-0}"
  if [[ "$DOCKER_DISK_GB" -ge "$MIN_DISK_GB" ]]; then
    ok "Docker data-root $DOCKER_ROOT: ${DOCKER_DISK_GB} GB free (separate filesystem from /opt)"
  elif [[ "$ALLOW_UNDERSIZED" == "yes" ]]; then
    warn "Docker data-root $DOCKER_ROOT has ${DOCKER_DISK_GB} GB free (< ${MIN_DISK_GB}) — images and ALL data volumes live there"
  else
    die "Docker's data-root ($DOCKER_ROOT) has ${DOCKER_DISK_GB} GB free — minimum ${MIN_DISK_GB} GB.

    /opt passed the disk check, but the images, the configuration database, the
    event store and the request logs are all stored under $DOCKER_ROOT, which is
    on a different filesystem. Either enlarge it, or move Docker's data-root onto
    the large disk (\"data-root\" in /etc/docker/daemon.json) and re-run."
  fi
else
  ok "Docker data-root $DOCKER_ROOT is on the filesystem measured in Step 3"
fi
# ClickHouse and the per-request logs are write-heavy. On spinning disks the
# event store falls behind under load and the console's Logs page lags by
# minutes; SSD is the supported medium. Best-effort: LVM and cloud volumes
# usually report it, some virtual disks report nothing, and nothing is a pass.
ROOT_DEV="$(findmnt -no SOURCE --target "$DOCKER_ROOT" 2>/dev/null | head -1)"
if [[ -n "$ROOT_DEV" && -b "$ROOT_DEV" ]]; then
  ROTA="$(lsblk -dno ROTA "$ROOT_DEV" 2>/dev/null | tr -d '[:space:]')"
  case "$ROTA" in
    0) ok "storage under $DOCKER_ROOT is non-rotational (SSD/NVMe)" ;;
    1) warn "storage under $DOCKER_ROOT reports ROTATIONAL — event ingestion and the Logs page will lag under load; SSD is the supported medium" ;;
  esac
fi
# Every service is `restart: unless-stopped`, which brings the WAF back after a
# reboot only if the Docker daemon itself starts. Reported here, fixed in Step 9.
DOCKER_BOOT=no
if systemctl is-enabled docker >/dev/null 2>&1; then
  DOCKER_BOOT=yes; ok "Docker starts at boot"
else
  warn "Docker is NOT enabled at boot — after a reboot the WAF would stay down (fixed in Step 9)"
fi

# This bundle ships only the four ESDSWAF images; Postgres, Redis, ClickHouse,
# Prometheus is pulled from Docker Hub. Check that NOW rather than
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
if [[ "$IMAGE_SOURCE" == "registry" ]]; then
  # Registry mode needs ONE host, and it is not Docker Hub. Probing Docker Hub
  # here would pass on a VM that cannot reach Harbor at all, and the install would
  # then die during `compose pull` with the host already modified.
  REG_HOST="${REGISTRY_PREFIX%%/*}"
  if timeout 15 docker pull "$REGISTRY_PREFIX/migrate:$BUNDLE_VERSION" >/dev/null 2>&1; then
    ok "registry reachable — all ten images will be pulled from $REG_HOST"
    docker image rm "$REGISTRY_PREFIX/migrate:$BUNDLE_VERSION" >/dev/null 2>&1 || true
  else
    die "cannot pull from $REG_HOST, and this package contains no images.

    Tried:  docker pull $REGISTRY_PREFIX/migrate:$BUNDLE_VERSION

    Check in this order:
      1. does the name resolve?      getent hosts $REG_HOST
      2. is TCP 443 open to it?      curl -sS -o /dev/null -w '%{http_code}\\n' https://$REG_HOST/v2/
         401 is the correct answer here. A TIMEOUT means a firewall is dropping
         it, which is a network request to make, not something to retry.
      3. is the image tag published?  it must exist at version $BUNDLE_VERSION

    If this host cannot reach the registry at all, ask ESDS for the air-gapped
    bundle (ESDSWAF-v${BUNDLE_VERSION}-offline.tar.gz), which contains all ten
    images and needs no network."
  fi
elif [[ "$NEEDS_NET" != "false" ]]; then
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
    (built with BUNDLE_THIRD_PARTY=1, which contains all nine images).

    Behind an HTTP proxy? The Docker daemon does NOT read /etc/environment or
    your shell's proxy variables. Give it its own:
      mkdir -p /etc/systemd/system/docker.service.d
      printf '[Service]\\nEnvironment=\"HTTPS_PROXY=http://proxy.example.com:3128\" \"NO_PROXY=127.0.0.1,localhost\"\\n' \\
        > /etc/systemd/system/docker.service.d/http-proxy.conf
      systemctl daemon-reload && systemctl restart docker"
  fi
fi

fi # DOCKER_MISSING_DRYRUN — the Docker-dependent checks above are skipped only in a dry run on a host without Docker

if [[ "$DRY_RUN" == "yes" ]]; then
  say ""
  if [[ "$DOCKER_MISSING_DRYRUN" == "yes" ]]; then
    ok "--dry-run: every check that could run passed; nothing changed. A real run installs Docker first."
  else
    ok "--dry-run: all checks passed, nothing changed"
  fi
  exit 0
fi

# ── Step 5 — configuration questions (the only ones) ─────────────────────────
step "Step 5 of 11 —configuration"
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

# Where the management console listens. Default: loopback only, reached over an
# SSH tunnel. On a host published through a NAT that forwards 80/443 only, the
# enterprise-normal alternative is the PRIVATE management address — reachable
# from the management network, unreachable through the forwarded ports. A public
# or wildcard address is refused, and there is deliberately no flag to allow it.
LOCAL_ADDRS="$(ip -4 -o addr show 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4}' | tr '\n' ' ')"
if [[ -n "$CONSOLE_BIND" ]]; then
  console_bind_ok "$CONSOLE_BIND" "$LOCAL_ADDRS" \
    || die "--console-bind $CONSOLE_BIND refused.

    It must be a PRIVATE IPv4 address (10/8, 172.16/12, 192.168/16 or 127.0.0.1)
    that is configured on this host. Addresses found here: ${LOCAL_ADDRS:-none}

    0.0.0.0 and public addresses are never accepted: the management console must
    not be reachable from the internet. A perimeter NAT that forwards only 80/443
    to this host is the intended boundary — keep 9443 behind it."
  MGMT_BIND="${CONSOLE_BIND}:"
else
  MGMT_BIND="127.0.0.1:"
fi

# Shared egress. Per-IP reputation assumes one address is one actor. Behind a
# corporate NAT or VPN concentrator that is false: one person's scanner gets the
# whole office's address blocked, and every colleague's clean request with it.
# Listing the address forgives its HISTORY only — an attack from it is still
# judged, and blocked, on its own merits. Asked at install because the day this
# is discovered is the day the whole office is locked out of a UAT site.
if [[ -z "$SHARED_EGRESS" && "$NONINTERACTIVE" != "yes" ]]; then
  say ""
  say "  ${B}Shared egress addresses${R}"
  say "    If your users reach this WAF through a corporate NAT or VPN, one address"
  say "    stands for many people. Listing it stops one person's scan from getting"
  say "    the whole office blocked. Comma-separated IPs or CIDRs; blank for none."
  read -r -p "  Shared egress [none]: " SHARED_EGRESS || true
fi
SHARED_EGRESS="${SHARED_EGRESS// /}"
if [[ -n "$SHARED_EGRESS" ]]; then
  cidr_list_ok "$SHARED_EGRESS" \
    || die "shared egress '$SHARED_EGRESS' is not a comma-separated list of IPv4 addresses or
    CIDRs (for example 203.0.113.7,198.51.100.0/24). The data plane silently drops
    entries it cannot parse, so a typo here would be an address that is NOT forgiven."
  SHARED_EGRESS_LINE="SENTINEL_SHARED_EGRESS_CIDRS=${SHARED_EGRESS}"
else
  SHARED_EGRESS_LINE="# SENTINEL_SHARED_EGRESS_CIDRS=          # e.g. 203.0.113.7,198.51.100.0/24 — see configs/env.example"
fi

# Trusted proxies. With a load balancer or CDN in front, every request arrives
# from it, so per-IP limits, bans and the logs saw ONE client — the balancer —
# until its X-Forwarded-For is believed. Only listed peers are believed: a
# client reaching the WAF directly cannot forge its address.
if [[ -z "$TRUSTED_PROXIES" && "$NONINTERACTIVE" != "yes" ]]; then
  say ""
  say "  ${B}Load balancer or CDN in front of this WAF${R}"
  say "    Its addresses, so the real client IP is read from X-Forwarded-For."
  say "    Comma-separated IPs or CIDRs, \`cloudflare\` for Cloudflare; blank for none."
  read -r -p "  Trusted proxies [none]: " TRUSTED_PROXIES || true
fi
TRUSTED_PROXIES="${TRUSTED_PROXIES// /}"
if [[ -n "$TRUSTED_PROXIES" ]]; then
  trusted_list_ok "$TRUSTED_PROXIES" \
    || die "trusted proxies '$TRUSTED_PROXIES' is not a comma-separated list of IPv4
    addresses or CIDRs (or \`cloudflare\`). The data plane drops entries it cannot
    parse, so a typo would leave the balancer untrusted and every client one IP."
  TRUSTED_PROXIES_LINE="SENTINEL_TRUSTED_PROXIES=${TRUSTED_PROXIES}"
else
  TRUSTED_PROXIES_LINE="# SENTINEL_TRUSTED_PROXIES=              # e.g. 10.0.0.5,cloudflare — the balancer/CDN in front"
fi

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
if [[ -n "$CONSOLE_BIND" ]]; then ok "console:  https://${CONSOLE_BIND}:9443 (private address; restrict 9443 to the management network)"
else ok "console:  127.0.0.1:9443 only (SSH tunnel)"; fi
if [[ -n "$SHARED_EGRESS" ]]; then ok "shared egress: $SHARED_EGRESS (reputation history forgiven; detection unchanged)"
else ok "shared egress: none declared"; fi

# ── Step 6 — load images ─────────────────────────────────────────────────────
step "Step 6 of 11 —obtaining images"
# First mutation of the host. Everything above this line is a check.
CHANGED=yes
if [[ "$IMAGE_SOURCE" == "registry" ]]; then
  say "  ${DIM}pulling from $REGISTRY_PREFIX — nothing was shipped in this package${R}"
  # Pulled by explicit name here rather than via `compose pull`, because compose
  # needs the generated .env (written in Step 7) to interpolate the prefix, and a
  # failure at this point should name the image that could not be fetched.
  for svc in dataplane controlplane dashboard migrate; do
    docker pull "$REGISTRY_PREFIX/${svc}:${BUNDLE_VERSION}" >>"$LOG" 2>&1 \
      || die "could not pull $REGISTRY_PREFIX/${svc}:${BUNDLE_VERSION} — see $LOG"
    say "    ${DIM}pulled ${svc}${R}"
  done
  ok "four images pulled at version $BUNDLE_VERSION"
else
  say "  ${DIM}pre-built: no compilation, about a minute${R}"
  docker load -i "$HERE/bundle/images.tar.gz" >>"$LOG" 2>&1 \
    || die "docker load failed — see $LOG"
  for svc in dataplane controlplane dashboard migrate; do
    docker image inspect "sentinel/${svc}:${BUNDLE_VERSION}" >/dev/null 2>&1 \
      || die "image sentinel/${svc}:${BUNDLE_VERSION} missing after load — package is incomplete"
  done
  ok "four images loaded at version $BUNDLE_VERSION"
fi

# ── Step 7 — install tree and secrets ────────────────────────────────────────
step "Step 7 of 11 —configuration and secrets"
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
  # The whole file is kept, so nothing decided in THIS run reaches it. Say so,
  # or --console-bind / --shared-egress / a resize look accepted and change nothing.
  warn "sizing, SENTINEL_MGMT_BIND and SENTINEL_SHARED_EGRESS_CIDRS in that file are also kept as they are;"
  warn "edit them by hand and apply with: docker compose -p sentinel up -d"
else
  PGPW=$(gen); CHPW=$(gen); CPPW=$(gen)
  cat > "$ENV_FILE" <<ENVEOF
# Generated by the Swaraj Kavach installer on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Contains every secret for this deployment. Back it up; never share it.
# Host at install: $VCPU vCPU, $RAM_GB GB RAM, $DISK_GB GB free — tier: $TIER
SENTINEL_VERSION=$BUNDLE_VERSION
SENTINEL_IMAGE_PREFIX=${REGISTRY_PREFIX:-sentinel}
# Where Postgres/Valkey/ClickHouse/Prometheus/HAProxy come from. Empty means
# Docker Hub. In registry mode it is set so the whole deployment pulls from one
# host — otherwise our four images would come from the mirror while the other six
# still reached for the internet and hung on a closed network.
SENTINEL_THIRDPARTY_PREFIX=${THIRDPARTY_PREFIX:-}

POSTGRES_USER=sentinel
POSTGRES_DB=sentinel
POSTGRES_PASSWORD=$PGPW
# The control plane connects as sentinel_cp — not a superuser, data privileges
# only — so a SQL-level compromise of it is not a superuser one. Migrations run
# as the owner above. The migrate job sets sentinel_cp's password from
# SENTINEL_CP_DB_PASSWORD on every run.
SENTINEL_CP_DB_PASSWORD=$CPPW
SENTINEL_DB_URL=postgres://sentinel_cp:${CPPW}@postgres:5432/sentinel?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt
SENTINEL_MIGRATE_DB_URL=postgres://sentinel:${PGPW}@postgres:5432/sentinel?sslmode=verify-full&sslrootcert=/etc/sentinel/pki/root.crt

CLICKHOUSE_USER=sentinel
CLICKHOUSE_DB=sentinel_logs
CLICKHOUSE_PASSWORD=$CHPW
# Sized to this host (≈30% of RAM, 6g–16g). Below 6g ClickHouse crash-loops.
CLICKHOUSE_MEM_LIMIT=$CH_MEM

SENTINEL_JWT_SECRET=$(gen)
SENTINEL_AUDIT_HMAC_KEY=$(gen)
SENTINEL_INTERNAL_SECRET=$(gen)
SENTINEL_ALLOW_SUPERUSER_DB=1

# The initial console password. seed.go honours this; left unset it invents a
# random one and prints it to the control plane's STDERR exactly once.
#
# That default is a lockout waiting to happen, and this file is the fix. Sourced
# from a container log it dies with the container: any upgrade, rollback, or
# "docker compose up --force-recreate" destroys the one copy. Generating it here
# puts it in the same 0600 file as every other secret, the one the installer
# already tells you to back up.
#
# The console now also has a real recovery path (Forgot password → emailed
# link, and Settings → Users → Send reset link for an administrator), but that
# path needs the SMTP block below to be filled in. Until it is, THIS value is
# still the only way in — so back this file up either way.
SENTINEL_BOOTSTRAP_ADMIN_PASSWORD=$(gen)
# The console login that password belongs to — the administrator email above.
# Read only when the first account is created; a lost password is reset with
#   docker exec -it sentinel-controlplane-1 controllerd reset-admin
SENTINEL_BOOTSTRAP_ADMIN_EMAIL=$ADMIN_EMAIL

SENTINEL_CLICKHOUSE_EVENT_RETENTION_DAYS=90
SENTINEL_CLICKHOUSE_TRAFFIC_RETENTION_DAYS=30
SENTINEL_SPOOL_DIR=/var/lib/sentinel/state/spool
# ── Sizing (derived from the host above at install time). After resizing the VM
#    edit these by hand and apply with: docker compose -p sentinel up -d ──────
# Per-request logs the console tails: on-disk ceiling = MAX_MB x (KEEP+1) x 2 streams.
SENTINEL_LOG_MAX_MB=$LOG_MB
SENTINEL_LOG_KEEP=$LOG_KEEP
# Events buffered on disk while ClickHouse is unreachable.
SENTINEL_SPOOL_MAX_BYTES=$SPOOL_BYTES

SENTINEL_WAF_HOSTNAME=$WAF_HOSTNAME
SENTINEL_ADMIN_EMAIL=$ADMIN_EMAIL

# ── Outbound mail — REQUIRED for password recovery ───────────────────────────
# Left blank the console still works, but "Forgot password?" cannot deliver a
# link and an administrator cannot mail one either. Fill these in with your own
# relay and re-run: docker compose -f compose.prod.yml up -d controlplane
#
# Nothing here has a default value on purpose. A shipped relay or sender address
# would route one customer's password-reset links through someone else's mail
# infrastructure.
#
#   SENTINEL_SMTP_SECURITY: starttls (default) | tls (implicit, usually :465)
#                           | none (unauthenticated internal relay only)
# Verify it from the console: Settings → Users → Send test email.
SENTINEL_SMTP_HOST=
SENTINEL_SMTP_PORT=587
SENTINEL_SMTP_USERNAME=
SENTINEL_SMTP_PASSWORD=
SENTINEL_SMTP_FROM=
SENTINEL_SMTP_FROM_NAME=Swaraj Kavach
SENTINEL_SMTP_SECURITY=starttls
SENTINEL_SMTP_INSECURE_SKIP_VERIFY=0

# Browser-reachable console origin that reset links point at, e.g.
# https://waf.example.com:9443 — no trailing slash. Reset links cannot be built
# without it. It is NOT derived from the request's Host header, because the
# forgot-password endpoint is unauthenticated and trusting that header would let
# a caller aim someone else's reset link at a server they control.
SENTINEL_PUBLIC_URL=https://$WAF_HOSTNAME:9443

# Security contact copied on every completed password reset. Defaults to the
# administrator address collected above.
SENTINEL_SECURITY_NOTIFY_EMAIL=$ADMIN_EMAIL

# ── Management console bind ─────────────────────────────────────────────────
# Host prefix for the console listener (9443). "127.0.0.1:" = this host only,
# reached over an SSH tunnel. A PRIVATE management address is the alternative
# (installer flag --console-bind). NEVER "0.0.0.0:" on a host that is reachable
# from the internet — a NAT forwarding 80/443 is the boundary; keep 9443 inside it.
SENTINEL_MGMT_BIND=$MGMT_BIND

# ── Shared egress (corporate NAT / VPN addresses shared by many users) ──────
# Forgives an address's block HISTORY so one person's scan cannot get the whole
# office blocked. Detection of each request is unchanged.
$SHARED_EGRESS_LINE
$TRUSTED_PROXIES_LINE
ENVEOF
  chmod 600 "$ENV_FILE"
  ok "secrets generated (7 values, openssl rand) — $ENV_FILE, mode 0600"
fi

# ── Step 8 — internal TLS (mandatory: Postgres will not start without) ───────
step "Step 8 of 11 —internal certificates"

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

# ── Step 9 — host: Docker at boot, live-restore, kernel network profile ──────
step "Step 9 of 11 — host"
if [[ "$DOCKER_TUNING" == "yes" ]]; then
  if [[ "$DOCKER_BOOT" == "yes" ]]; then ok "Docker already enabled at boot"
  elif systemctl enable docker >>"$LOG" 2>&1; then ok "Docker enabled at boot"
  else warn "could not enable Docker at boot — run: systemctl enable docker"
  fi
  # live-restore keeps containers running while the Docker daemon restarts or is
  # upgraded; without it `apt upgrade docker-ce` is a WAF outage. Written only
  # when no daemon.json exists: an existing file is somebody's configuration, and
  # a blind edit of JSON is how a daemon fails to start on the next boot. No
  # containers are running yet, so restarting the daemon here costs nothing.
  if [[ ! -f /etc/docker/daemon.json ]]; then
    mkdir -p /etc/docker
    printf '{\n  "live-restore": true\n}\n' > /etc/docker/daemon.json
    if systemctl restart docker >>"$LOG" 2>&1 && docker info >/dev/null 2>&1; then
      ok "Docker live-restore enabled (a daemon restart or upgrade no longer stops the WAF)"
    else
      rm -f /etc/docker/daemon.json
      systemctl restart docker >>"$LOG" 2>&1 || true
      docker info >/dev/null 2>&1 \
        || die "Docker did not come back after a daemon restart — see $LOG and: journalctl -u docker"
      warn "Docker refused the live-restore setting — removed again; the daemon runs without it"
    fi
  else
    LIVE_RESTORE="$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null)"
    if [[ "$LIVE_RESTORE" == "true" ]]; then ok "Docker live-restore already enabled"
    else warn "/etc/docker/daemon.json exists without \"live-restore\": true — a Docker daemon restart or upgrade will stop the WAF. Add it and restart Docker in a maintenance window."
    fi
  fi
else
  warn "Docker boot / live-restore tuning skipped (--no-docker-tuning)"
fi
# Kernel network profile: SYN-flood posture (syncookies, deeper backlogs), a
# conntrack table sized for a flood, redirect and source-route hygiene. It is a
# sysctl.d drop-in, so it persists by itself and re-applies at every boot.
#
# The conntrack BYPASS (NOTRACK) that scripts/hardening/harden-network.sh also
# offers is deliberately NOT applied here. Docker publishes 80/443 through an
# iptables DNAT rule, and DNAT depends on connection tracking: NOTRACK on those
# ports would send every request through the userland docker-proxy instead — a
# quiet, large performance regression rather than a visible failure. It has
# never been run on a Docker host; it belongs to the host-network and Kubernetes
# deployments, where the listener owns the port directly.
if [[ "$HARDEN" == "yes" ]]; then
  SYSCTL_SRC="$INSTALL_DIR/scripts/hardening/99-sentinel-ddos.conf"
  if [[ -r "$SYSCTL_SRC" ]]; then
    # conntrack sysctls exist only once the module is loaded; without it those
    # lines are silently ignored and the table keeps its small default.
    grep -q '^nf_conntrack ' /proc/modules 2>/dev/null || modprobe nf_conntrack >>"$LOG" 2>&1 || true
    if cp "$SYSCTL_SRC" /etc/sysctl.d/99-sentinel-ddos.conf 2>>"$LOG"; then
      sysctl --system >>"$LOG" 2>&1 || true
      SYNC="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)"
      if [[ "$SYNC" == "1" ]]; then
        ok "kernel network profile applied and persisted (/etc/sysctl.d/99-sentinel-ddos.conf)"
      else
        warn "kernel network profile written but tcp_syncookies reads '${SYNC:-unset}' — see $LOG"
      fi
    else
      warn "could not write /etc/sysctl.d/99-sentinel-ddos.conf — kernel profile skipped"
    fi
  else
    warn "kernel network profile not in this package (scripts/hardening/) — skipped"
  fi
else
  warn "kernel network profile skipped (--no-harden)"
fi

# Nightly encrypted backup. The units shipped with every bundle and nothing
# installed them, so no installation had ever taken a backup on its own. An
# existing backup.env or key is someone's configuration and is kept.
BACKUP_UNITS="$INSTALL_DIR/scripts/backup/systemd"
if [[ -r "$BACKUP_UNITS/sentinel-backup.service" ]]; then
  mkdir -p /etc/sentinel && chmod 755 /etc/sentinel
  if [[ ! -f "$BACKUP_ENV" ]]; then
    sed -e "s|^SENTINEL_BACKUP_DIR=.*|SENTINEL_BACKUP_DIR=$INSTALL_DIR/scripts/backup|" \
        -e "s|^COMPOSE_FILE=.*|COMPOSE_FILE=$INSTALL_DIR/compose.prod.yml|" \
        -e "s|^ENV_FILE=.*|ENV_FILE=$ENV_FILE|" \
        -e "s|^BACKUP_KEY_FILE=.*|BACKUP_KEY_FILE=$BACKUP_KEY|" \
        "$BACKUP_UNITS/backup.env.example" > "$BACKUP_ENV" && chmod 600 "$BACKUP_ENV"
  fi
  [[ -s "$BACKUP_KEY" ]] || ( umask 077; openssl rand -hex 32 > "$BACKUP_KEY" )
  command -v gpg >/dev/null 2>&1 \
    || warn "gpg is not installed: backups will be root-only but NOT encrypted, and never sent offsite — apt-get install gnupg"
  if cp "$BACKUP_UNITS"/sentinel-backup.{service,timer} /etc/systemd/system/ 2>>"$LOG" \
     && systemctl daemon-reload >>"$LOG" 2>&1 \
     && systemctl enable --now sentinel-backup.timer >>"$LOG" 2>&1; then
    ok "nightly encrypted backup scheduled (sentinel-backup.timer, 02:30) → /var/backups/sentinel"
  else
    warn "could not schedule the nightly backup — see $LOG; run $INSTALL_DIR/scripts/backup/backup.sh by hand"
  fi
else
  warn "backup units not in this package (scripts/backup/systemd/) — no backup is scheduled"
fi

# ── Step 10 — start (migrations run as a compose dependency) ─────────────────
step "Step 10 of 11 — starting services"
C=(docker compose -p sentinel -f "$INSTALL_DIR/compose.prod.yml" --env-file "$ENV_FILE")
( cd "$INSTALL_DIR" && "${C[@]}" config >/dev/null 2>>"$LOG" ) \
  || die "the compose configuration is invalid — see $LOG. Nothing was started."
# Can this CPU run the pinned ClickHouse? A build that needs instructions the
# (virtual) CPU hides dies with SIGILL and restarts for ever; without this the
# install timed out on a generic health check with no hint of why.
CH_IMG=$( cd "$INSTALL_DIR" && "${C[@]}" config --images 2>>"$LOG" | grep -m1 'clickhouse-server:' )
if [[ -n "$CH_IMG" && -x "$HERE/scripts/clickhouse-cpu-check.sh" ]]; then
  ch_msg=$("$HERE/scripts/clickhouse-cpu-check.sh" "$CH_IMG") \
    || die "$ch_msg. Nothing was started."
  ok "this host's CPU runs $CH_IMG"
fi
say "  ${DIM}database migrations run automatically before the control plane starts${R}"
( cd "$INSTALL_DIR" && "${C[@]}" up -d >>"$LOG" 2>&1 ) \
  || die "failed to start services — see $LOG"
ok "containers started"

# ── Step 11 — health ─────────────────────────────────────────────────────────
step "Step 11 of 11 — health checks"
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
hc "Redis"         docker exec sentinel-redis-1 valkey-cli ping                        || health_fail=1
hc "ClickHouse"    bash -c "docker exec sentinel-clickhouse-1 wget -qO- http://127.0.0.1:8123/ping | grep -q Ok" || health_fail=1
# These replace `docker exec ... /controllerd --version || true`, which could not
# fail for two separate reasons: `--version` only proved the BINARY was in the
# image (true even for a container crash-looping on a bad DSN), and the `|| true`
# discarded the verdict anyway. The installer could therefore report a successful
# install with no working control plane — i.e. no console, which is the whole
# management interface.
#
# `State.Status = running` was the next attempt and is still not enough. When the
# control plane cannot reach Postgres it does not exit: it logs one WARN ("DB
# unavailable — running in degraded mode") and serves forever with a nil store.
# The container reports `running` permanently, so this check passes on an install
# whose every login returns 503. It also passes on a crash-looping container
# caught in one of its brief running windows — compose sets `restart:
# unless-stopped` and defines no healthcheck for this service.
#
# /readyz calls store.Ping and reports db ok|unavailable|unreachable. It is the
# only endpoint that distinguishes the two. (/health is a hardcoded 200 that never
# touches the database.) 9501 is unpublished and the image is distroless, so probe
# it from a container that has a shell on the same network.
hc "Control plane → DB" bash -c '
  docker exec sentinel-clickhouse-1 wget -qO- --timeout=5 http://controlplane:9501/readyz 2>/dev/null \
    | grep -q "\"db\"[[:space:]]*:[[:space:]]*\"ok\""' || health_fail=1
hc "Data plane"    bash -c "curl -fsS --max-time 3 http://127.0.0.1:80/healthz >/dev/null" || health_fail=1
# :443 was never probed by any check, which is how a default certificate issued for
# the wrong network shipped unnoticed. No -f here on purpose: with no sites yet the
# WAF correctly answers 404, and that still proves the TLS handshake completed and
# a certificate was served. Only a handshake or connection failure fails this.
hc "TLS on :443"   bash -c 'curl -sk --max-time 5 -o /dev/null https://127.0.0.1:443/' || health_fail=1
# End-to-end: the management listener answering. It is the first thing the
# operator will touch, so failing here now beats them discovering it themselves.
#
# The path matters. `/` does NOT reach the control plane: the management listener
# routes only /api/* there and everything else to the dashboard (see the `base`
# selection in crates/sentinel-proxy/src/lib.rs), so `/` was answered by Next.js
# redirecting to /login — a 307 that matched `^[234]` while proving nothing about
# the control plane, contrary to what this comment used to claim. Probe an /api
# path so the request actually traverses proxy → control plane. 401 is the
# expected unauthenticated answer and is a pass; what is being tested is that
# something on the far side spoke HTTP at all.
#
# Probe the address the console was actually BOUND to. With --console-bind the
# listener is on the private address only, so a loopback probe cannot connect,
# waits out all 40 attempts, and fails a healthy install — the first real run
# with the flag did exactly that, two minutes after everything else had passed.
CONSOLE_PROBE_HOST="${CONSOLE_BIND:-127.0.0.1}"
hc "Console :9443 on $CONSOLE_PROBE_HOST" bash -c 'curl -sk --max-time 5 -o /dev/null -w "%{http_code}" "https://'"$CONSOLE_PROBE_HOST"':9443/api/v1/sites" | grep -qE "^[24]"' || health_fail=1

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
#
# THE SCRAPE IS NOW THE FALLBACK, NOT THE SOURCE. Step 7 generates
# SENTINEL_BOOTSTRAP_ADMIN_PASSWORD into $ENV_FILE and compose passes it to the
# control plane, so the credential is known before the container ever starts and
# survives every recreate. Reading it back from the file we just wrote is both
# authoritative and immune to log rotation, log drivers that discard stderr, and
# the container being restarted before this line runs.
#
# The log scrape is kept only for the --force path over an install predating
# this change, where the .env has no bootstrap value and the log is genuinely
# the only copy.
ADMIN_PW=$(sed -n 's/^SENTINEL_BOOTSTRAP_ADMIN_PASSWORD=//p' "$ENV_FILE" 2>/dev/null | head -1)
# The login that password belongs to. A .env from before the login was
# configurable (kept by --force) means the account was made with the old fixed one.
ADMIN_LOGIN=$(sed -n 's/^SENTINEL_BOOTSTRAP_ADMIN_EMAIL=//p' "$ENV_FILE" 2>/dev/null | head -1)
ADMIN_LOGIN=${ADMIN_LOGIN:-admin@sentinel.local}
if [[ ! "$ADMIN_PW" =~ ^[0-9a-f]{64}$ ]]; then
  ADMIN_PW=$(docker logs sentinel-controlplane-1 2>&1 \
    | grep -A1 'GENERATED password' | tail -1 \
    | sed -n 's/^\[sentinel\][[:space:]]*//p' | tr -d '[:space:]' || true)
  # seed.go's generated form is 24 random bytes hex-encoded; ours is 32.
  [[ "$ADMIN_PW" =~ ^[0-9a-f]{48}$ ]] || ADMIN_PW=""
fi

if [[ $health_fail -ne 0 ]]; then
  printf '\n  %s✗ Installation completed with FAILING health checks%s\n' "$RED" "$R"
  say  "    The stack is installed but not fully healthy."
  say  "    Diagnose:  docker compose -p sentinel ps"
  say  "               docker compose -p sentinel logs --tail 100"
  say  "    Log:       $LOG"
  exit 1
fi

printf '%s\n' "$BUNDLE_VERSION" > "$STATE_DIR/version"

# One page a support engineer can read without the log: what the host was, how
# it was sized, which options were chosen, and every check verdict of THIS run.
# No secrets in it; 0600 anyway because it names the admin address and topology.
REPORT="$STATE_DIR/install-report.txt"
{
  printf 'Swaraj Kavach — install report\n\n'
  printf '%-14s %s\n' date     "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                      version  "$BUNDLE_VERSION" \
                      host     "$(hostname -f 2>/dev/null || hostname)" \
                      os       "${OS_PRETTY:-unknown}" \
                      hardware "${VCPU} vCPU, ${RAM_GB} GB RAM, ${DISK_GB} GB free on /opt — tier ${TIER}" \
                      docker   "$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'), data-root ${DOCKER_ROOT:-?}" \
                      sizing   "clickhouse ${CH_MEM}, request logs ${LOG_MB} MB x $((LOG_KEEP + 1)) x 2, spool ${SPOOL_BYTES} bytes" \
                      hostname "$WAF_HOSTNAME" \
                      admin    "$ADMIN_EMAIL" \
                      console  "${MGMT_BIND}9443" \
                      egress   "${SHARED_EGRESS:-none declared}" \
                      options  "harden=$HARDEN docker-tuning=$DOCKER_TUNING force=$FORCE undersized=$ALLOW_UNDERSIZED images=$IMAGE_SOURCE"
  printf '\ncheck verdicts, this run\n'
  if [[ "$LOG_OK" == "yes" ]]; then
    tail -n +"$((LOG_START + 1))" "$LOG" 2>/dev/null | grep -E ' (STEP|OK|WARN|FAIL|SIZING|ABORT) ' || true
  fi
} > "$REPORT" 2>/dev/null && chmod 600 "$REPORT" || true

if [[ -n "$CONSOLE_BIND" ]]; then
  CONSOLE_HOW="    From the management network   ${B}https://${CONSOLE_BIND}:9443${R}

    ${DIM}The console listens on this PRIVATE address only. Restrict 9443 to your${R}
    ${DIM}management network in the host or perimeter firewall. A NAT that forwards${R}
    ${DIM}only 80/443 to this host must stay that way — never add 9443 to it.${R}"
else
  CONSOLE_HOW="    From this host          ${B}https://127.0.0.1:9443${R}
    From your workstation   ${B}ssh -L 9443:127.0.0.1:9443 ${SUDO_USER:-root}@${DEF_IP:-<this-host>}${R}
                            then open ${B}https://127.0.0.1:9443${R}

    ${DIM}Bound to 127.0.0.1 deliberately: it is a security appliance's admin UI.${R}
    ${DIM}To publish it on a private management address instead, set${R}
    ${DIM}SENTINEL_MGMT_BIND=<private-ip>: in $ENV_FILE and run${R}
    ${DIM}docker compose -p sentinel -f $INSTALL_DIR/compose.prod.yml up -d dataplane${R}"
fi

cat <<FINAL

  ${GRN}${B}Installation successful${R}

    Version        Swaraj Kavach v$BUNDLE_VERSION
    Host tier      $TIER (${VCPU} vCPU, ${RAM_GB} GB RAM, ${DISK_GB} GB free)
    Username       ${ADMIN_LOGIN}
    Password       ${B}${ADMIN_PW:-NOT CAPTURED — recover it with the command below}${R}

  ${YEL}${B}WRITE THIS PASSWORD DOWN NOW and sign in with it once.${R}
  ${DIM}It is stored in $ENV_FILE (mode 0600) as SENTINEL_BOOTSTRAP_ADMIN_PASSWORD,${R}
  ${DIM}so it survives container recreates and travels with a backup of that file.${R}
    Recover it        sudo grep SENTINEL_BOOTSTRAP_ADMIN_PASSWORD $ENV_FILE
    Change it         console → account menu → Change password
    Reset by email    available once the SMTP block in $ENV_FILE is filled in
    Reset on the host sudo docker exec -it sentinel-controlplane-1 controllerd reset-admin

  ${B}Reaching the console${R}

$CONSOLE_HOW

    ${DIM}Ports 80 and 443 ARE published on all interfaces — that is the WAF's${R}
    ${DIM}traffic path, and it is what your protected sites are served on.${R}

  ${B}Publishing this WAF to the internet${R}

    Forward ONLY these to ${B}${DEF_IP:-this host}${R}:   tcp/80   tcp/443   (udp/443 for HTTP/3)
    Never forward 9443 (console) or 22 (SSH). Never use a 1:1 / full NAT.
    Port 80 stays open permanently — Let's Encrypt renewals are proven on it.
    Every site on this node answers to its own Host header the moment the forward
    opens; before adding a second site to a public node read
    $INSTALL_DIR/docs/manual/SITE-ONBOARDING.md.

  ${B}Next steps${R}
    1. Add your first protected site in the console.
       Until a site exists the WAF answers 404 "No site is configured": correct
       behaviour, because there is no upstream to forward to yet.
    2. ${B}Leave new sites in LEARNING mode.${R} Every published detection figure
       comes from a synthetic corpus; nobody has measured how often this
       WAF would wrongly block YOUR users. Learning mode records what it
       would have blocked without blocking it.
    3. After a full business cycle, measure and then enable blocking:
         $INSTALL_DIR/scripts/fpr-report.sh 168
       For a real application follow $INSTALL_DIR/docs/manual/SITE-ONBOARDING.md.
    4. ${B}Copy the backup key off this host:${R} $BACKUP_KEY
       Nightly backups are encrypted with it and it is in none of them; without
       it no backup can be restored. Add an offsite target in $BACKUP_ENV.
    5. Fill in the SMTP block in $ENV_FILE so password recovery works.

    Config  $ENV_FILE  ${DIM}(all secrets — in every backup, encrypted)${R}
    Report  $REPORT
    Log     $LOG

FINAL
log "install completed successfully, version $BUNDLE_VERSION"
