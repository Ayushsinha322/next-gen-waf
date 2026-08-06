#!/usr/bin/env bash
# Apply kernel + firewall DDoS hardening to a Sentinel WAF host.
#
#   sudo deploy/hardening/harden-network.sh            # apply
#   sudo deploy/hardening/harden-network.sh --dry-run  # show what would change
#
# Idempotent: re-running does not duplicate rules.
#
# Two parts:
#   1. sysctl values from 99-sentinel-ddos.conf (see that file for the reasoning)
#   2. a NOTRACK rule keeping the public WAF ports out of conntrack
#
# The NOTRACK part is the one that matters most under volumetric load. Conntrack's table
# is a far lower ceiling than any socket limit — when it fills, the kernel drops NEW
# connections and logs "nf_conntrack: table full", which looks like packet loss and is
# usually misdiagnosed as an upstream problem. The WAF's public listeners do not need
# connection tracking (no NAT, no stateful firewall decisions on them), so exempting
# them removes the ceiling instead of merely raising it.
set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

HERE="$(cd "$(dirname "$0")" && pwd)"
SYSCTL_SRC="$HERE/99-sentinel-ddos.conf"
SYSCTL_DST=/etc/sysctl.d/99-sentinel-ddos.conf

# Public WAF ports. Keep in sync with compose.prod.yml / the k8s Services.
WAF_PORTS="${WAF_PORTS:-80,443,9443}"

run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "  would run: $*"
  else
    "$@"
  fi
}

if [[ $DRY_RUN -eq 0 && $EUID -ne 0 ]]; then
  echo "must run as root (or use --dry-run)" >&2
  exit 1
fi

echo "── sysctl ────────────────────────────────────────────────────────────────"
[[ -r "$SYSCTL_SRC" ]] || { echo "missing $SYSCTL_SRC" >&2; exit 1; }

# conntrack sysctls only exist once the module is loaded; without this the
# nf_conntrack_* lines are silently ignored and the table stays at its default.
if ! lsmod 2>/dev/null | grep -q '^nf_conntrack'; then
  echo "  nf_conntrack not loaded — loading so its limits can be set"
  run modprobe nf_conntrack || echo "  ! could not load nf_conntrack; its settings will be skipped"
fi

run cp "$SYSCTL_SRC" "$SYSCTL_DST"
if [[ $DRY_RUN -eq 0 ]]; then
  # --system re-reads everything; report only failures so the output stays readable.
  sysctl --system 2>&1 | grep -iE "cannot|error|unknown" || true
  echo "  applied (verify: sysctl net.ipv4.tcp_syncookies net.netfilter.nf_conntrack_max)"
else
  echo "  would run: sysctl --system"
fi

echo
echo "── conntrack bypass for the public WAF ports ──────────────────────────────"
if ! command -v iptables >/dev/null; then
  echo "  ! iptables not found — skipping NOTRACK. Install iptables, or add an"
  echo "    equivalent nftables rule, or the conntrack table stays a hard ceiling."
else
  # -t raw / PREROUTING runs BEFORE conntrack, which is the only place NOTRACK works.
  # A comment makes the rule identifiable so this stays idempotent.
  for chain in PREROUTING OUTPUT; do
    if iptables -t raw -C "$chain" -p tcp -m multiport --dports "$WAF_PORTS" \
         -j NOTRACK -m comment --comment "sentinel-waf-notrack" 2>/dev/null; then
      echo "  $chain: already present"
    else
      run iptables -t raw -A "$chain" -p tcp -m multiport --dports "$WAF_PORTS" \
        -j NOTRACK -m comment --comment "sentinel-waf-notrack"
      echo "  $chain: NOTRACK added for tcp/$WAF_PORTS"
    fi
  done
  echo
  echo "  NOTE: iptables rules are NOT persistent across reboot. Install"
  echo "        iptables-persistent (Debian/Ubuntu) or add this script to a boot unit,"
  echo "        or the ceiling silently returns on the next restart."
fi

echo
echo "── Verify ────────────────────────────────────────────────────────────────"
cat <<'EOF'
  sysctl net.ipv4.tcp_syncookies net.ipv4.tcp_max_syn_backlog net.core.somaxconn
  sysctl net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_tcp_timeout_established
  iptables -t raw -L PREROUTING -n --line-numbers | grep sentinel-waf-notrack
  # conntrack usage under load (should stay near zero for WAF ports once NOTRACK is on):
  cat /proc/sys/net/netfilter/nf_conntrack_count

  Then actually test it — configuration is not protection:
  deploy/load-test/flood-test.sh --help
EOF
