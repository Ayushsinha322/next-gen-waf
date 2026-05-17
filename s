#!/usr/bin/env bash
# Sentinel WAF — quick server control
# Usage: ./s <command>
#
# Commands:
#   start           start dashboard + control plane (background)
#   stop            kill dashboard + control plane
#   restart         stop then start
#   dashboard       start dashboard only (foreground, rebuilds first)
#   dashboard start start dashboard in background (no rebuild)
#   dashboard build rebuild + start dashboard in background
#   dashboard stop  kill dashboard only
#   cp              start control plane (foreground)
#   cp start        start control plane in background
#   cp stop         kill control plane only
#   status          show what's running on each port
#   logs            tail all logs

REPO="$(cd "$(dirname "$0")" && pwd)"
DASH="$REPO/dashboard"
CP="$REPO/control-plane"

DASH_PORT=2222
CP_REST=9501
CP_GRPC=9500
CP_URL="http://localhost:$CP_REST"

_kill_dash() {
  fuser -k ${DASH_PORT}/tcp 2>/dev/null; pkill -f "next-server" 2>/dev/null; pkill -f "next start" 2>/dev/null
  echo "dashboard stopped"
}

_kill_cp() {
  fuser -k ${CP_REST}/tcp ${CP_GRPC}/tcp 2>/dev/null; pkill -f "controllerd" 2>/dev/null
  echo "control plane stopped"
}

_build_dash() {
  echo "→ building dashboard…"
  cd "$DASH"
  NEXT_PUBLIC_CONTROL_PLANE_URL=$CP_URL NODE_OPTIONS="--max-old-space-size=3072" npm run build
}

_start_dash_bg() {
  cd "$DASH"
  NEXT_PUBLIC_CONTROL_PLANE_URL=$CP_URL PORT=$DASH_PORT NODE_OPTIONS="--max-old-space-size=3072" nohup npm start > /tmp/dashboard.log 2>&1 &
  echo "dashboard started → http://localhost:$DASH_PORT  (logs: /tmp/dashboard.log)"
}

_start_cp_bg() {
  cd "$CP"
  GOTOOLCHAIN=local go build -o bin/controllerd ./cmd/controllerd 2>&1 | grep -v "^$" || true
  nohup ./bin/controllerd > /tmp/controllerd.log 2>&1 &
  echo "control plane started → http://localhost:$CP_REST  (logs: /tmp/controllerd.log)"
}

CMD="${1:-help}"
SUB="${2:-}"

case "$CMD" in

  start)
    _kill_dash; _kill_cp; sleep 1
    _start_cp_bg
    _start_dash_bg
    ;;

  stop)
    _kill_dash; _kill_cp
    ;;

  restart)
    _kill_dash; _kill_cp; sleep 1
    _start_cp_bg
    _start_dash_bg
    ;;

  dashboard|dash)
    case "$SUB" in
      start)
        _kill_dash
        _start_dash_bg
        ;;
      build)
        _kill_dash
        _build_dash
        _start_dash_bg
        ;;
      stop)
        _kill_dash
        ;;
      "")
        # foreground with rebuild
        _kill_dash
        _build_dash
        cd "$DASH"
        NEXT_PUBLIC_CONTROL_PLANE_URL=$CP_URL PORT=$DASH_PORT NODE_OPTIONS="--max-old-space-size=3072" npm start
        ;;
      *)
        echo "unknown: ./s dashboard [start|build|stop]"
        ;;
    esac
    ;;

  cp)
    case "$SUB" in
      start)
        _kill_cp
        _start_cp_bg
        ;;
      stop)
        _kill_cp
        ;;
      "")
        # foreground
        _kill_cp
        cd "$CP"
        GOTOOLCHAIN=local go run ./cmd/controllerd
        ;;
      *)
        echo "unknown: ./s cp [start|stop]"
        ;;
    esac
    ;;

  status)
    echo "PORT $CP_GRPC  (gRPC):  $(lsof -ti:$CP_GRPC 2>/dev/null | xargs -I{} ps -p {} -o comm= 2>/dev/null || echo "free")"
    echo "PORT $CP_REST  (REST):  $(lsof -ti:$CP_REST 2>/dev/null | xargs -I{} ps -p {} -o comm= 2>/dev/null || echo "free")"
    echo "PORT $DASH_PORT (dash):  $(lsof -ti:$DASH_PORT 2>/dev/null | xargs -I{} ps -p {} -o comm= 2>/dev/null || echo "free")"
    ;;

  logs)
    tail -f /tmp/controllerd.log /tmp/dashboard.log 2>/dev/null
    ;;

  *)
    echo "Usage: ./s <command>"
    echo ""
    echo "  start              start everything (background)"
    echo "  stop               stop everything"
    echo "  restart            restart everything"
    echo ""
    echo "  dashboard          rebuild + start dashboard (foreground)"
    echo "  dashboard start    start dashboard, no rebuild (background)"
    echo "  dashboard build    rebuild + start dashboard (background)"
    echo "  dashboard stop     stop dashboard"
    echo ""
    echo "  cp                 start control plane (foreground)"
    echo "  cp start           start control plane (background)"
    echo "  cp stop            stop control plane"
    echo ""
    echo "  status             show running processes on each port"
    echo "  logs               tail /tmp/controllerd.log + /tmp/dashboard.log"
    ;;
esac
