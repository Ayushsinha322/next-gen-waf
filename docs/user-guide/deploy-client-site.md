# Deploy a Client Site in 5 Minutes

This runbook walks you through adding a new protected site to Sentinel WAF
using the Dashboard UI. After these steps, traffic will be inspected, logged,
and optionally blocked by the WAF proxy — no config files needed.

## Prerequisites

- Sentinel WAF running (`sentinel start` or systemd units active)
- Dashboard accessible (default `http://localhost:2222`)
- Your upstream application is reachable from the WAF host

## Step-by-step

### 1. Log into the Dashboard

```
URL:      http://<sentinel-host>:2222
Login:    admin@sentinel.local
Password:  admin123
```

### 2. Go to Sites → "＋ Add Site"

Navigation: **Protected Sites** (left sidebar) → click **＋ Add Site**

Fill in:

| Field         | Example                     | Notes                            |
|---------------|-----------------------------|----------------------------------|
| Site Name     | `myapp`                     | Short internal label             |
| Domain        | `myapp.example.com`         | Must match the Host header       |
| Upstream Host | `10.0.1.50`                 | IP or hostname of your app       |
| Upstream Port | `8080`                      | Port your app listens on         |
| WAF Mode      | `BLOCKING` (or `LEARNING`)  | BLOCKING = deny attacks; LEARNING = log only |

Click **Add Site**.

### 3. Update /etc/hosts (first time only)

On any machine that will browse THROUGH the WAF, add the domain pointing to
the WAF proxy's IP:

```bash
echo '<waf-host-ip>  myapp.example.com' | sudo tee -a /etc/hosts
```

> **Important:** Always browse `http://myapp.example.com:9080` (the WAF proxy)
> — never directly to the upstream port. Direct access bypasses the WAF and
> generates no security logs.

### 4. Browse your site through the WAF

Open your browser to: **`http://myapp.example.com:9080`**

All traffic now goes through the full WAF pipeline:
- Anti-DDoS + IP reputation
- Rate limiting + bot detection
- OWASP CRS v4 rule engine (13 request rulesets)
- ML anomaly scoring (if enabled)
- DLP response body scanning

### 5. Verify in the Dashboard

1. **Overview** page — check the WAF status badge shows "WAF active · N sites"
2. **Logs** page — filter by your site name to see live access + WAF logs
3. **Alerts** page — any blocked attacks appear here in real time

### 🔁 Updating a site

- Pause/resume: click ⏸️/▶️ on the Sites table
- Change mode: edit the site's WAF policy (BLOCKING → LEARNING → OFF)
- Delete: 🗑️ button (must confirm)

Changes take effect within ~5 seconds — the proxy polls the control plane
every 5 s and hot-swaps its site list without restarting.

## Troubleshooting

| Symptom                       | Fix                                                       |
|-------------------------------|-----------------------------------------------------------|
| "Site deployed" but no logs   | Check `sentinel status` — WAF proxy may not be running    |
| 502 Bad Gateway               | Upstream not reachable; check host:port and container     |
| WAF status badge shows "NOT running" | Run `sentinel start` or `systemctl start sentinel-proxy` |
| Can't browse `:9080`          | Verify `/etc/hosts` entry; check `sentinel status`        |

## Production deployment

To push Sentinel to a real server in one command:

```bash
sentinel deploy 10.0.1.50
```

This builds everything (Go + Rust + Next.js), generates an Ansible inventory,
and runs the playbook that installs Postgres, systemd units, firewall rules,
and starts all services. See `deploy/ansible/deploy.yml` for details.