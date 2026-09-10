#!/usr/bin/env bash
# =============================================================================
#  Sync this working tree to a deployment host — safely.
#
#      deploy/sync-to-host.sh root@172.16.21.71 [/opt/sentinel-src]
#      DRY_RUN=1 deploy/sync-to-host.sh root@172.16.21.71     # show, change nothing
#
#  WHY THIS EXISTS
#
#  `rsync -a --delete` of this repo onto a host has destroyed live state twice:
#
#    * 2026-09-06  it overwrote deploy/docker/.env, taking the deployment's
#                  secrets and SENTINEL_VERSION with it.
#    * 2026-09-09  it DELETED deploy/docker/geoip/dbip-country-lite.mmdb. That
#                  directory is a bind mount into every data plane, and the
#                  .mmdb is gitignored, so rsync saw a file the source did not
#                  have and removed it. GeoIP went inert with no error anywhere
#                  and the console just said "country database not loaded".
#
#  Both were the same mistake: the synced tree contains directories that hold
#  RUNTIME state, not source. Those paths must be excluded, and remembering them
#  by hand does not work. They live in RUNTIME_PATHS below.
#
#  Add to RUNTIME_PATHS whenever a new bind mount is pointed inside the tree.
#  `--list-runtime-mounts` prints what the host currently mounts from inside it,
#  so drift is detectable rather than discovered by an outage.
# =============================================================================
set -uo pipefail

HOST="${1:-}"
DEST="${2:-/opt/sentinel-src}"
KEY="${SSH_KEY:-$HOME/.ssh/sentinel_deploy}"
DRY_RUN="${DRY_RUN:-0}"

# Runtime state that lives inside the source tree. NEVER synced, NEVER deleted.
RUNTIME_PATHS=(
  '.env'                       # deployment secrets + SENTINEL_VERSION
  '.env.*'
  'deploy/docker/geoip/'       # bind mount -> /var/lib/sentinel/geoip on every node
  'deploy/docker/origin-ca/'   # bind mount -> /etc/sentinel/origin-ca (customer CA anchors)
)
# Build artefacts and local-only content: excluded to keep the transfer small.
BUILD_PATHS=( 'target/' 'node_modules/' '.next/' 'dist/' 'docs/' '.git/' )

usage() {
  cat <<USAGE
usage: $0 <user@host> [dest]           sync the tree (excludes runtime state)
       DRY_RUN=1 $0 <user@host>        show what would change, touch nothing
       $0 --list-runtime-mounts <host> what the host bind-mounts from inside the tree
env:   SSH_KEY (default ~/.ssh/sentinel_deploy)
USAGE
}

if [ "$HOST" = "--list-runtime-mounts" ]; then
  H="${2:-}"; [ -z "$H" ] && { usage; exit 2; }
  ROOT="${3:-/opt/sentinel-src}"
  echo "Bind mounts on $H whose SOURCE is inside $ROOT:"
  ssh -o BatchMode=yes -i "$KEY" "$H" '
    for c in $(docker ps --format "{{.Names}}"); do
      docker inspect "$c" -f "{{range .Mounts}}{{if eq .Type \"bind\"}}{{.Source}} -> {{.Destination}}{{\"\n\"}}{{end}}{{end}}" \
        | grep "^/opt/sentinel-src" | sed "s|^|  $c: |"
    done | sort -u'
  echo
  echo "Every SOURCE above must match an entry in RUNTIME_PATHS, or the next"
  echo "--delete sync will remove whatever the repo does not carry."
  exit 0
fi

[ -z "$HOST" ] && { usage; exit 2; }
[ -f "$KEY" ] || { echo "ERROR: ssh key not found: $KEY"; exit 1; }
[ -f deploy/docker/compose.prod.yml ] || { echo "ERROR: run this from the repository root"; exit 1; }

EXCLUDES=()
for p in "${RUNTIME_PATHS[@]}" "${BUILD_PATHS[@]}"; do EXCLUDES+=( --exclude "$p" ); done

echo "host      : $HOST"
echo "dest      : $DEST"
echo "commit    : $(git rev-parse --short HEAD 2>/dev/null || echo '?')$([ -n "$(git status --porcelain 2>/dev/null)" ] && echo ' (DIRTY)')"
echo "protecting: ${RUNTIME_PATHS[*]}"
[ "$DRY_RUN" = "1" ] && echo "mode      : DRY RUN — nothing will be written"
echo

FLAGS=( -az --delete --human-readable )
[ "$DRY_RUN" = "1" ] && FLAGS+=( --dry-run --itemize-changes )

rsync "${FLAGS[@]}" "${EXCLUDES[@]}" \
  -e "ssh -o ConnectTimeout=15 -o BatchMode=yes -i $KEY" \
  ./ "$HOST:$DEST/"
rc=$?
[ $rc -ne 0 ] && { echo "rsync FAILED (exit $rc) — nothing further attempted"; exit $rc; }

if [ "$DRY_RUN" = "1" ]; then echo; echo "dry run complete."; exit 0; fi

# Prove the runtime state survived, rather than assuming it did.
echo
echo "post-sync check:"
ssh -o BatchMode=yes -o ConnectTimeout=15 -i "$KEY" "$HOST" "
  cd '$DEST' || exit 1
  printf '  .env                 %s\n' \"\$([ -f deploy/docker/.env ] && echo present || echo 'MISSING !!')\"
  printf '  SENTINEL_VERSION     %s\n' \"\$(grep -m1 '^SENTINEL_VERSION=' deploy/docker/.env 2>/dev/null | cut -d= -f2 || echo '?')\"
  printf '  geoip *.mmdb         %s\n' \"\$(ls deploy/docker/geoip/*.mmdb 2>/dev/null | wc -l) file(s)\"
  printf '  origin-ca *.pem      %s\n' \"\$(ls deploy/docker/origin-ca/*.pem 2>/dev/null | wc -l) file(s)\"
"
echo
echo "Source is in place. Nothing was built or restarted — do that explicitly."
