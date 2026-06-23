# `sentinel.sh` — One-Command Launcher

`sentinel.sh` brings the whole Sentinel stack up or down with a single command.
It is the fastest way to run the WAF locally for development or a demo.

## Install (optional)

```bash
./sentinel.sh install      # symlinks the script to ~/.local/bin/sentinel
```

After installing you can call `sentinel <cmd>` from any directory. The examples
below use `sentinel`; substitute `./sentinel.sh` if you have not installed it.

## Commands

| Command | What it does |
|---|---|
| `sentinel start` | Build if stale, then bring up infra → lab sites → WAF proxy → control plane → dashboard |
| `sentinel stop` | Stop all Sentinel processes |
| `sentinel restart` | `stop` then `start` |
| `sentinel status` | Show what is running on each port |
| `sentinel logs` | Tail the control-plane, dashboard, and proxy logs |
| `sentinel build` | Force-rebuild the control plane (Go) and dashboard (Next.js) |
| `sentinel install` | (Re)install the `sentinel` command to `~/.local/bin` |
| `sentinel deploy <host>` | Build all components and deploy to a remote host via Ansible |
| `sentinel infra up\|down` | Start/stop only the Docker infra (Postgres, Redis, etc.) |
| `sentinel site on\|off\|list\|add` | Manage local lab target sites (DVWA, Juice Shop, …) |

## Default Ports

| Service | Port | URL |
|---|---|---|
| Dashboard | `2222` | http://localhost:2222 |
| Control plane (REST) | `9501` | http://localhost:9501 |
| Control plane (gRPC) | `9500` | — |
| WAF proxy (shared, Host-routed) | `9080` | http://localhost:9080 |
| WAF proxy (transparent, DVWA) | `9095` | http://localhost:9095 |

Default dashboard login for the dev seed: `admin@sentinel.local` / `admin123`.

## Build Behaviour

- The control plane is rebuilt only when `bin/controllerd` is older than the Go
  sources; otherwise startup is instant.
- The dashboard is rebuilt only when `.next/BUILD_ID` is older than the source.
- The proxy prefers the optimized `target/release/sentinel-bin` and falls back
  to the debug build.

## Useful Environment Variables

| Variable | Effect |
|---|---|
| `SENTINEL_DB_URL` | Postgres DSN for the control plane (required for real data) |
| `SENTINEL_CORS_ORIGINS` | Comma-separated allowed dashboard origins |
| `SENTINEL_PROXY_BIN` | Explicit path to the `sentinel-bin` proxy binary |
| `SENTINEL_AUTOSTART_DATAPLANE=0` | Stop the control plane from spawning its own proxy (the launcher owns it) |

## After a Reboot

```bash
sentinel start
```

That single command restores the full stack — Docker infra, lab sites (with
upstream liveness checks), WAF proxy, control plane, and dashboard.
