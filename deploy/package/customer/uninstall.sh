#!/usr/bin/env bash
# =============================================================================
#  Next-Gen ESDSWAF — uninstaller
#
#      sudo ./uninstall.sh              # remove containers, KEEP all data
#      sudo ./uninstall.sh --purge      # also destroy data volumes (IRREVERSIBLE)
#
#  Keeping data is the default deliberately. An uninstall that silently destroys
#  the configuration database, the attack history and the certificate authority
#  is not recoverable, and "I only wanted to reinstall" is the common case.
# =============================================================================
set -uo pipefail

INSTALL_DIR=/opt/sentinel/current
STATE_DIR=/opt/sentinel
PKI_DIR=/opt/sentinel-pki
PURGE=no

[[ "${1:-}" == "--purge" ]] && PURGE=yes
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 2; }

if [[ -t 1 ]]; then B=$'\e[1m'; R=$'\e[0m'; RED=$'\e[91m'; GRN=$'\e[92m'; YEL=$'\e[93m'
else B=''; R=''; RED=''; GRN=''; YEL=''; fi

VOLUMES=(sentinel_pgdata sentinel_chdata sentinel_sentinel-logs
         sentinel_sentinel-certs sentinel_sentinel-state
         sentinel_promdata)

printf '\n  %sNext-Gen ESDSWAF — uninstall%s\n\n' "$B" "$R"

if [[ "$PURGE" == "yes" ]]; then
  printf '  %s%sTHIS WILL PERMANENTLY DESTROY:%s\n' "$B" "$RED" "$R"
  printf '    - the configuration database (sites, rules, users, audit log)\n'
  printf '    - all attack history in ClickHouse\n'
  printf '    - the internal certificate authority at %s\n' "$PKI_DIR"
  printf '    - every generated secret in %s/.env\n\n' "$INSTALL_DIR"
  printf '  %sIf you have no verified backup, stop now and run:%s\n' "$YEL" "$R"
  printf '    %s/scripts/backup/backup.sh\n\n' "$INSTALL_DIR"
  read -r -p "  Type DESTROY to confirm: " c || true
  [[ "$c" == "DESTROY" ]] || { echo; echo "  Aborted — nothing was removed."; echo; exit 1; }
fi

echo "  stopping containers…"
if [[ -f "$INSTALL_DIR/compose.prod.yml" ]]; then
  ( cd "$INSTALL_DIR" && docker compose -p sentinel --profile demo \
      -f compose.prod.yml --env-file .env down --remove-orphans >/dev/null 2>&1 ) || true
fi
# Belt and braces: catch containers from a partial or differently-named install.
docker ps -aq --filter "name=sentinel-" | xargs -r docker rm -f >/dev/null 2>&1 || true
printf '  %s✓%s containers removed\n' "$GRN" "$R"

if [[ "$PURGE" == "yes" ]]; then
  for v in "${VOLUMES[@]}"; do docker volume rm "$v" >/dev/null 2>&1 || true; done
  rm -rf "$STATE_DIR" "$PKI_DIR"
  printf '  %s✓%s data volumes, configuration and certificate authority destroyed\n' "$GRN" "$R"
else
  # The install marker goes even though the data stays. Every container has just
  # been removed, so leaving it behind states that a version is installed when
  # none is running — and `upgrade.sh` and the version banner both read it.
  #
  # The .env deliberately REMAINS (that is the point of a non-purge uninstall), so
  # install.sh's guard still fires on its `-f "$INSTALL_DIR/.env"` arm. That is
  # correct: regenerating secrets against surviving volumes would lock the
  # operator out of their own data. The reinstall path is therefore --force, and
  # this message now says so. It used to promise "re-running install.sh reuses
  # both", which aborted with "already installed — remove it completely: sudo
  # ./uninstall.sh", i.e. the command they had just run.
  rm -f "$STATE_DIR/version"
  printf '  %s✓%s data volumes KEPT: %s\n' "$GRN" "$R" "$(printf '%s ' "${VOLUMES[@]}")"
  printf '      configuration kept at %s/.env\n' "$INSTALL_DIR"
  printf '      your sites and history return when you reinstall — reuse them with:\n'
  printf '        %ssudo ./install.sh --force%s\n' "$B" "$R"
  printf '      (--force is required BECAUSE the .env survived; a plain install.sh\n'
  printf '       stops rather than regenerate secrets against the existing database)\n'
  printf '      to destroy everything instead: sudo ./uninstall.sh --purge\n'
fi

# Images are left in place on purpose: they are large, and a reinstall or a
# rollback to this version needs them. `docker image prune` is the operator's call.
printf '\n  Images left in place (needed for reinstall/rollback). To remove:\n'
printf '    docker images "sentinel/*" -q | xargs -r docker rmi\n\n'
