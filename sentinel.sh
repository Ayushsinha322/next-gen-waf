#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Sentinel WAF — dev launcher
#
#  Usage:  sentinel <command>
#
#  sentinel start              start infra + all sites + control plane + dashboard
#  sentinel stop               stop everything (WAF stack + all site containers)
#  sentinel restart            stop then start
#  sentinel status             show what is running
#  sentinel logs               tail live logs
#  sentinel build              force-rebuild dashboard + control plane binary
#  sentinel install            install 'sentinel' command in ~/.local/bin
#  sentinel deploy <host>       build + deploy to remote server via Ansible
#
#  sentinel infra up           start Docker infra (Postgres, Redis, etc.)
#  sentinel infra down         stop Docker infra
#
#  sentinel site list          show all registered sites + running status
#  sentinel site on  <name>    start a site's Docker container
#  sentinel site off <name>    stop  a site's Docker container
#  sentinel site add <name> <image> <host_port> <container_port>
#                              register a new site (saved to sites.conf)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Locate repo root ──────────────────────────────────────────────────────────
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
REPO="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
DASH="$REPO/dashboard"
CP="$REPO/control-plane"

DASH_PORT=2222
CP_REST=9501
CP_GRPC=9500
CP_URL="http://localhost:$CP_REST"

DASH_LOG=/tmp/sentinel-dashboard.log
CP_LOG=/tmp/sentinel-controlplane.log
WAF_LOG=/tmp/sentinel-waf.log
WAF_BIN="$REPO/target/debug/sentinel-bin"
WAF_CONFIG="$REPO/configs/dev/sentinel.yaml"

# Sites config file — one line per site:  name:container:host_port:container_port:image
SITES_CONF="$REPO/configs/dev/sites.conf"

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  G="\033[0;32m"; Y="\033[0;33m"; R="\033[0;31m"; B="\033[0;34m"
  C="\033[0;36m"; W="\033[1;37m"; D="\033[0m"
else
  G=""; Y=""; R=""; B=""; C=""; W=""; D=""
fi

info()    { echo -e "${B}[sentinel]${D} $*"; }
success() { echo -e "${G}[sentinel]${D} $*"; }
warn()    { echo -e "${Y}[sentinel]${D} $*"; }
error()   { echo -e "${R}[sentinel]${D} $*" >&2; }
header()  { echo -e "\n${W}$*${D}"; }

# ── Port helpers ──────────────────────────────────────────────────────────────
port_in_use() { ss -tlnp 2>/dev/null | grep -q ":$1 "; }

wait_for_port() {
  local port=$1 label=$2 tries=0
  while ! port_in_use "$port"; do
    tries=$((tries+1))
    if [[ $tries -gt 30 ]]; then
      error "$label did not come up on :$port after 30s"
      return 1
    fi
    sleep 1
  done
  success "$label is ready  →  http://localhost:$port"
}

# ── Kill helpers ──────────────────────────────────────────────────────────────
kill_port() {
  local port=$1
  local pids
  pids=$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' || true)
  if [[ -n "$pids" ]]; then
    echo "$pids" | xargs -r kill 2>/dev/null || true
  fi
}

_stop_dashboard() {
  kill_port $DASH_PORT
  pkill -f "next-server" 2>/dev/null || true
  pkill -f "next start"  2>/dev/null || true
}

_stop_controlplane() {
  kill_port $CP_REST
  kill_port $CP_GRPC
  pkill -f "controllerd" 2>/dev/null || true
}

_stop_proxy() {
  pkill -f "sentinel-bin" 2>/dev/null || true
}

# ── Build helpers ─────────────────────────────────────────────────────────────
_need_cp_build() {
  local bin="$CP/bin/controllerd"
  [[ ! -f "$bin" ]] && return 0
  if find "$CP" -name '*.go' -newer "$bin" -print -quit 2>/dev/null | grep -q .; then
    return 0
  fi
  return 1
}

_need_dash_build() {
  local build_id="$DASH/.next/BUILD_ID"
  [[ ! -f "$build_id" ]] && return 0
  if find "$DASH/app" "$DASH/lib" "$DASH/components" "$DASH/package.json" \
       -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.json' \
       2>/dev/null | xargs -I{} find {} -newer "$build_id" -print -quit \
       2>/dev/null | grep -q .; then
    return 0
  fi
  return 1
}

_build_cp() {
  info "Building control plane…"
  mkdir -p "$CP/bin"
  if ( cd "$CP" && go build -o bin/controllerd ./cmd/controllerd ) 2>&1; then
    success "Control plane built"
  else
    error "Control plane build FAILED"
    exit 1
  fi
}

_build_dash() {
  info "Building dashboard (this takes ~30 s)…"
  cd "$DASH"
  if NEXT_PUBLIC_CONTROL_PLANE_URL=$CP_URL \
     NODE_OPTIONS="--max-old-space-size=3072" \
     npm run build 2>&1; then
    success "Dashboard built"
  else
    error "Dashboard build FAILED"
    exit 1
  fi
}

# ── Start helpers ─────────────────────────────────────────────────────────────
_start_cp() {
  info "Starting control plane…"
  mkdir -p /tmp/sentinel-logs
  nohup "$CP/bin/controllerd" > "$CP_LOG" 2>&1 &
  disown
  wait_for_port $CP_REST "Control plane"
}

_start_proxy() {
  if [[ ! -f "$WAF_BIN" ]]; then
    warn "WAF proxy binary not found at $WAF_BIN — build with: cargo build --bin sentinel-bin"
    warn "Skipping WAF proxy. Sites via WAF ports (:9095, :9080) will not work."
    return
  fi
  info "Starting WAF proxy…"
  mkdir -p /tmp/sentinel-logs
  SENTINEL_CONFIG="$WAF_CONFIG" \
  SENTINEL_LOG_DIR=/tmp/sentinel-logs \
  RUST_LOG=info,sentinel=debug \
  nohup "$WAF_BIN" > "$WAF_LOG" 2>&1 &
  disown
  # WAF proxy takes ~2s to bind ports
  sleep 3
  if port_in_use 9080; then
    success "WAF proxy ready  →  :9080 (routed)  :9095 (dvwa)  :3000 (juice)"
  else
    warn "WAF proxy did not bind ports — check $WAF_LOG"
  fi
}

_start_dash() {
  info "Starting dashboard…"
  cd "$DASH"
  NEXT_PUBLIC_CONTROL_PLANE_URL=$CP_URL \
  PORT=$DASH_PORT \
  NODE_OPTIONS="--max-old-space-size=3072" \
  nohup npm start > "$DASH_LOG" 2>&1 &
  disown
  wait_for_port $DASH_PORT "Dashboard"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Sites registry helpers
#  sites.conf format (one site per line):
#    name:container_name:host_port:container_port:docker_image
#  Example:
#    dvwa:dvwa:9096:80:vulnerables/web-dvwa
#    juiceshop:juiceshop:3001:3000:bkimminich/juice-shop
# ─────────────────────────────────────────────────────────────────────────────

_ensure_sites_conf() {
  if [[ ! -f "$SITES_CONF" ]]; then
    mkdir -p "$(dirname "$SITES_CONF")"
    cat > "$SITES_CONF" <<'EOF'
# Sentinel WAF — site registry
# Format: name:container_name:host_port:container_port:docker_image
dvwa:dvwa:9096:80:vulnerables/web-dvwa
juiceshop:juiceshop:3001:3000:bkimminich/juice-shop
EOF
    info "Created sites registry at $SITES_CONF"
  fi
}

_site_field() {
  local name=$1 field=$2
  _ensure_sites_conf
  local line
  line=$(grep -v '^#' "$SITES_CONF" | grep -v '^[[:space:]]*$' | awk -F: "\$1==\"$name\"" | head -1)
  if [[ -z "$line" ]]; then echo ""; return 1; fi
  echo "$line" | cut -d: -f"$field"
}

_container_running() {
  local cname=$1
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cname"
}

_container_exists() {
  local cname=$1
  docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$cname"
}

# Check that a TCP port is actually accepting connections (not just bound).
_check_port_alive() {
  local port=$1
  timeout 2 bash -c "echo -ne '' > /dev/tcp/127.0.0.1/$port" 2>/dev/null
}

cmd_site_on() {
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    error "Usage: sentinel site on <name>"
    echo "       Run 'sentinel site list' to see available sites."
    exit 1
  fi
  _ensure_sites_conf

  local container host_port container_port image
  container=$(_site_field "$name" 2) || { error "Site '$name' not found. Run 'sentinel site list'."; exit 1; }
  host_port=$(_site_field "$name" 3)
  container_port=$(_site_field "$name" 4)
  image=$(_site_field "$name" 5)

  if _container_running "$container"; then
    info "Site '$name' container is running — checking HTTP liveness…"
    if _check_port_alive "$host_port"; then
      success "Site '$name' is up  →  http://localhost:$host_port"
      return
    fi
    # Container is running but HTTP isn't responding.
    # For Apache-based images (DVWA), restart Apache inside the container.
    warn "Container '$container' is running but port :$host_port is not responding."
    if docker exec "$container" which apache2 >/dev/null 2>&1; then
      info "Restarting Apache inside '$container'…"
      docker exec "$container" service apache2 start >/dev/null 2>&1 || true
      sleep 2
      if _check_port_alive "$host_port"; then
        success "Site '$name' is up  →  http://localhost:$host_port"
        return
      fi
    fi
    error "Port :$host_port still not responding after recovery attempt — check container logs."
    exit 1
  fi

  if _container_exists "$container"; then
    info "Starting existing container '$container'…"
    docker start "$container" >/dev/null
  else
    info "Pulling + starting '$name' ($image)…"
    docker run -d --name "$container" -p "${host_port}:${container_port}" --restart unless-stopped "$image" >/dev/null
  fi

  local tries=0
  info "Waiting for '$name' to be ready…"
  while ! docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null | grep -q true; do
    tries=$((tries+1))
    [[ $tries -gt 20 ]] && { error "'$name' container did not start"; exit 1; }
    sleep 1
  done
  # Wait for the HTTP service to actually accept connections
  tries=0
  while ! _check_port_alive "$host_port"; do
    tries=$((tries+1))
    [[ $tries -gt 15 ]] && { warn "Port :$host_port not responding after 15s — Apache may need a manual restart."; break; }
    sleep 1
  done
  success "Site '$name' is up  →  http://localhost:$host_port"
}

cmd_site_off() {
  local name="${1:-}"
  if [[ -z "$name" ]]; then
    error "Usage: sentinel site off <name>"
    exit 1
  fi
  _ensure_sites_conf

  local container
  container=$(_site_field "$name" 2) || { error "Site '$name' not found. Run 'sentinel site list'."; exit 1; }

  if ! _container_exists "$container"; then
    warn "Site '$name' container does not exist."
    return
  fi
  if ! _container_running "$container"; then
    warn "Site '$name' is already stopped."
    return
  fi
  docker stop "$container" >/dev/null
  success "Site '$name' stopped."
}

cmd_site_list() {
  _ensure_sites_conf
  header "●  Registered sites"
  printf "  %-14s %-20s %-12s %s\n" "NAME" "CONTAINER" "PORT" "STATUS"
  printf "  %-14s %-20s %-12s %s\n" "----" "---------" "----" "------"

  grep -v '^#' "$SITES_CONF" | grep -v '^[[:space:]]*$' | while IFS=: read -r name container host_port container_port image; do
    if _container_running "$container"; then
      status="${G}● running${D}  http://localhost:$host_port"
    elif _container_exists "$container"; then
      status="${Y}○ stopped${D}"
    else
      status="${R}○ not created${D}"
    fi
    printf "  %-14s %-20s %-12s " "$name" "$container" ":$host_port"
    echo -e "$status"
  done
  echo ""
}

cmd_site_add() {
  local name="${1:-}" image="${2:-}" host_port="${3:-}" container_port="${4:-}"
  if [[ -z "$name" || -z "$image" || -z "$host_port" || -z "$container_port" ]]; then
    error "Usage: sentinel site add <name> <image> <host_port> <container_port>"
    echo "  Example: sentinel site add mutillidae webpwnized/mutillidae:latest 8888 80"
    exit 1
  fi
  _ensure_sites_conf

  if grep -v '^#' "$SITES_CONF" | grep -q "^${name}:"; then
    warn "Site '$name' already exists in registry. Edit $SITES_CONF to update it."
    return
  fi

  echo "${name}:${name}:${host_port}:${container_port}:${image}" >> "$SITES_CONF"
  success "Site '$name' added to registry."
  echo -e "  Start it with:  ${W}sentinel site on $name${D}"
}

# ─────────────────────────────────────────────────────────────────────────────
#  Infra (docker compose) helpers
# ─────────────────────────────────────────────────────────────────────────────

cmd_infra_up() {
  info "Starting infra containers…"
  docker compose -f "$REPO/deploy/docker/compose.dev.yml" up -d

  local tries=0
  info "Waiting for Postgres…"
  until docker exec sentinel-postgres pg_isready -U sentinel >/dev/null 2>&1; do
    tries=$((tries+1)); [[ $tries -gt 30 ]] && { error "Postgres did not start"; exit 1; }; sleep 1
  done
  success "Postgres ready on :5432"

  tries=0
  info "Waiting for Redis…"
  until docker exec sentinel-redis redis-cli ping >/dev/null 2>&1; do
    tries=$((tries+1)); [[ $tries -gt 30 ]] && { error "Redis did not start"; exit 1; }; sleep 1
  done
  success "Redis ready on :6379"
}

cmd_infra_down() {
  info "Stopping infra containers…"
  docker compose -f "$REPO/deploy/docker/compose.dev.yml" down
  success "Infra stopped."
}

# ─────────────────────────────────────────────────────────────────────────────
#  Main commands
# ─────────────────────────────────────────────────────────────────────────────

cmd_build() {
  header "⟳  Building Sentinel WAF"
  _build_cp
  _build_dash
  success "All builds complete."
}

cmd_start() {
  header "▶  Starting Sentinel WAF"

  # 1. Infra
  cmd_infra_up

  # 2. All registered lab sites
  _ensure_sites_conf
  info "Starting lab sites…"
  grep -v '^#' "$SITES_CONF" | grep -v '^[[:space:]]*$' | while IFS=: read -r name container host_port container_port image; do
    cmd_site_on "$name"
  done

  # 3. WAF stack
  _stop_proxy        2>/dev/null || true
  _stop_dashboard    2>/dev/null || true
  _stop_controlplane 2>/dev/null || true
  sleep 1

  if _need_cp_build; then _build_cp; else info "Control plane binary up-to-date — skipping build"; fi
  if _need_dash_build; then _build_dash; else info "Dashboard build up-to-date — skipping build"; fi

  _start_cp
  _start_proxy
  _start_dash

  echo ""
  echo -e "  ${G}✓${D}  Dashboard    →  ${W}http://localhost:$DASH_PORT${D}"
  echo -e "  ${G}✓${D}  Control API  →  ${W}http://localhost:$CP_REST${D}"
  echo ""
  echo -e "  ${C}Login:    admin@sentinel.local${D}"
  echo -e "  ${C}Password: admin123${D}"
  echo ""
  echo -e "  Sites:   sentinel site list"
  echo -e "  Logs:    sentinel logs"
  echo -e "  Stop:    sentinel stop"
}

cmd_stop() {
  header "■  Stopping Sentinel WAF"

  # Stop WAF stack
  _stop_proxy        2>/dev/null || true
  _stop_dashboard    2>/dev/null || true
  _stop_controlplane 2>/dev/null || true

  # Stop all registered site containers
  if [[ -f "$SITES_CONF" ]]; then
    info "Stopping lab sites…"
    grep -v '^#' "$SITES_CONF" | grep -v '^[[:space:]]*$' | while IFS=: read -r name container host_port container_port image; do
      if _container_running "$container"; then
        docker stop "$container" >/dev/null 2>&1 && info "Stopped site '$name'"
      fi
    done
  fi

  success "All services stopped."
}

cmd_restart() {
  cmd_stop
  sleep 1
  cmd_start
}

cmd_status() {
  header "●  Sentinel WAF status"
  local ok="${G}● running${D}" no="${R}○ stopped${D}"

  if port_in_use $CP_GRPC;   then echo -e "  gRPC          :$CP_GRPC   $ok"; else echo -e "  gRPC          :$CP_GRPC   $no"; fi
  if port_in_use $CP_REST;   then echo -e "  Control plane :$CP_REST   $ok  →  http://localhost:$CP_REST"; else echo -e "  Control plane :$CP_REST   $no"; fi
  if port_in_use 9080;      then echo -e "  WAF proxy     :9080      $ok  →  http://localhost:9080"; else echo -e "  WAF proxy     :9080      $no"; fi
  if port_in_use $DASH_PORT; then echo -e "  Dashboard     :$DASH_PORT   $ok  →  http://localhost:$DASH_PORT"; else echo -e "  Dashboard     :$DASH_PORT   $no"; fi

  echo ""
  cmd_site_list
}

cmd_logs() {
  header "📋  Tailing logs  (ctrl-c to quit)"
  echo -e "  ${Y}control plane:${D}  $CP_LOG"
  echo -e "  ${Y}dashboard:${D}     $DASH_LOG"
  echo ""
  tail -f "$CP_LOG" "$DASH_LOG" 2>/dev/null || {
    warn "Log files not found yet — is Sentinel running? (sentinel start)"
  }
}

cmd_install() {
  local target="$HOME/.local/bin/sentinel"
  mkdir -p "$HOME/.local/bin"
  cat > "$target" <<WRAPPER
#!/usr/bin/env bash
exec "$SCRIPT_PATH" "\$@"
WRAPPER
  chmod +x "$target"
  success "Installed → $target"
  if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
    warn '~/.local/bin is not in your PATH.'
    warn 'Add this to ~/.bashrc:  export PATH="$HOME/.local/bin:$PATH"'
  else
    success "Run 'sentinel' from any directory."
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  sentinel deploy <host>  — one-command production push
# ─────────────────────────────────────────────────────────────────────────────

cmd_deploy() {
  local host="${1:-}"
  if [[ -z "$host" ]]; then
    header "🚀  Sentinel Deploy"
    echo ""
    echo "  Usage: sentinel deploy <target-host>"
    echo ""
    echo "  Deploys Sentinel WAF to a remote Ubuntu/Debian server in one command."
    echo ""
    echo "  Prerequisites:"
    echo "    - Ansible installed on this machine (pip install ansible)"
    echo "    - SSH key access to the target (ssh root@<target>)"
    echo "    - Target is Ubuntu 22.04 or Debian 12, x86-64"
    echo ""
    echo "  Example:"
    echo "    sentinel deploy 10.0.1.50"
    echo ""
    return
  fi

  header "🚀  Deploying Sentinel WAF → $host"

  # ── Build everything ──
  info "Building all components…"
  cd "$REPO"

  info "Building control plane (Go)…"
  if ! ( cd "$CP" && go build -o bin/controllerd ./cmd/controllerd ) 2>&1; then
    error "Control plane build FAILED — fix Go errors and retry"
    exit 1
  fi
  success "Control plane built"

  info "Building data plane (Rust)…"
  if ! cargo build --release --bin sentinel-bin 2>&1; then
    error "Data plane build FAILED — fix Rust errors and retry"
    exit 1
  fi
  success "Data plane built"

  info "Building dashboard (Next.js)…"
  cd "$DASH"
  if ! ( NEXT_PUBLIC_CONTROL_PLANE_URL="http://$host:9501" \
         NODE_OPTIONS="--max-old-space-size=3072" \
         npm run build 2>&1 ); then
    error "Dashboard build FAILED"
    exit 1
  fi
  success "Dashboard built"
  cd "$REPO"

  # ── Generate inventory ──
  local inv="$REPO/deploy/ansible/inventory.yml"
  cat > "$inv" <<INV
---
all:
  hosts:
    sentinel:
      ansible_host: "$host"
      ansible_user: root
INV

  # ── Run Ansible ──
  info "Running Ansible playbook…"
  local ansible_cmd=(
    ansible-playbook
    -i "$inv"
    "$REPO/deploy/ansible/deploy.yml"
    -e "proxy_binary=$REPO/target/release/sentinel-bin"
    -e "controlplane_binary=$CP/bin/controllerd"
    -e "dashboard_dir=$DASH"
  )

  if "${ansible_cmd[@]}" 2>&1; then
    echo ""
    success "Sentinel WAF deployed to $host!"
    echo ""
    echo -e "  ${W}Dashboard:${D}   http://$host:3000"
    echo -e "  ${W}API:${D}        http://$host:9501"
    echo -e "  ${W}WAF Proxy:${D}  $host:443"
    echo ""
    echo -e "  ${C}Login:    admin@sentinel.local${D}"
    echo -e "  ${C}Password: admin123${D}"
  else
    error "Ansible playbook failed — check output above"
    exit 1
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────────────────────
CMD="${1:-help}"
SUB="${2:-}"

case "$CMD" in
  start)   cmd_start   ;;
  stop)    cmd_stop    ;;
  restart) cmd_restart ;;
  status)  cmd_status  ;;
  logs)    cmd_logs    ;;
  build)   cmd_build   ;;
  install) cmd_install ;;
  deploy)  cmd_deploy  "${2:-}" ;;

  infra)
    case "$SUB" in
      up)   cmd_infra_up   ;;
      down) cmd_infra_down ;;
      *)
        error "Usage: sentinel infra [up|down]"
        exit 1
        ;;
    esac
    ;;

  site)
    case "$SUB" in
      on)   cmd_site_on  "${3:-}" ;;
      off)  cmd_site_off "${3:-}" ;;
      list) cmd_site_list        ;;
      add)  cmd_site_add "${3:-}" "${4:-}" "${5:-}" "${6:-}" ;;
      *)
        echo ""
        echo -e "  ${W}sentinel site${D} — manage lab target sites"
        echo ""
        echo -e "  ${G}sentinel site list${D}                              show all sites"
        echo -e "  ${G}sentinel site on  <name>${D}                        start a site"
        echo -e "  ${G}sentinel site off <name>${D}                        stop  a site"
        echo -e "  ${G}sentinel site add <name> <image> <hport> <cport>${D} register new site"
        echo ""
        echo "  Examples:"
        echo "    sentinel site on  dvwa"
        echo "    sentinel site off juiceshop"
        echo "    sentinel site add mutillidae webpwnized/mutillidae:latest 8888 80"
        echo ""
        ;;
    esac
    ;;

  *)
    echo ""
    echo -e "  ${W}Sentinel WAF${D} — dev launcher"
    echo ""
    echo "  Usage: sentinel <command>"
    echo ""
    echo -e "  ${G}start${D}                   start everything (infra + sites + WAF + dashboard)"
    echo -e "  ${G}stop${D}                    stop everything"
    echo -e "  ${G}restart${D}                 stop + start"
    echo -e "  ${G}status${D}                  show what is running"
    echo -e "  ${G}logs${D}                    tail live logs"
    echo -e "  ${G}build${D}                   force rebuild dashboard + control plane"
    echo -e "  ${G}install${D}                 install 'sentinel' command globally"
    echo -e "  ${G}deploy <host>${D}           build + deploy to remote server via Ansible"
    echo ""
    echo -e "  ${G}infra up${D}                start Docker infra (Postgres, Redis, etc.)"
    echo -e "  ${G}infra down${D}              stop  Docker infra"
    echo ""
    echo -e "  ${G}site list${D}               show all registered sites + status"
    echo -e "  ${G}site on  <name>${D}         start a site's Docker container"
    echo -e "  ${G}site off <name>${D}         stop  a site's Docker container"
    echo -e "  ${G}site add <n> <img> <hp> <cp>${D}  register a new site"
    echo ""
    ;;
esac
