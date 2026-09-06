#!/usr/bin/env bash
# =============================================================================
# One product, one version number.
#
# The console once printed v4.2.1 on the login page, "Enterprise v3.1.0" in the
# top bar, 0.1.0 in the cluster footer (the data plane's Cargo version) while the
# VERSION file said 1.1.0 — four numbers for one deployment, because each was a
# separate hard-coded string. This check pins every place a version lives to the
# repo-root VERSION file and fails the pipeline on the first drift.
#
# Sources checked:
#   VERSION                                   the source of truth
#   Cargo.toml [workspace.package].version    -> data plane /healthz "version"
#   dashboard/package.json "version"          -> NEXT_PUBLIC_PRODUCT_VERSION (login, top bar)
#   control-plane/internal/version/version.go -> /api/v1/cluster/status "build"
#
# Also refuses a hard-coded vN.N.N literal anywhere in the dashboard source, so
# the next "v4.2.1" cannot come back.
#
# Runs in the alpine deploy-shell CI job: bash + grep + sed only, no python.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/../.."

fail=0
want="$(tr -d '[:space:]' < VERSION)"
case "$want" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "✗ VERSION file does not hold a semver: '$want'"; exit 1 ;;
esac
echo "VERSION = $want"

cargo="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\([^"]*\)".*/\1/p}' Cargo.toml | head -1)"
pkg="$(sed -n 's/^  *"version": *"\([^"]*\)".*/\1/p' dashboard/package.json | head -1)"
gover="$(sed -n 's/^const Product = "\([^"]*\)".*/\1/p' control-plane/internal/version/version.go | head -1)"

check() { # name value
  if [ "$2" = "$want" ]; then echo "✓ $1 = $2"; else echo "✗ $1 = '$2' (VERSION says $want)"; fail=1; fi
}
check "Cargo.toml [workspace.package].version" "$cargo"
check "dashboard/package.json version"          "$pkg"
check "control-plane/internal/version Product"  "$gover"

# No hard-coded product version literals in UI source. Allow-list nothing: a
# component that needs the version imports PRODUCT_VERSION from lib/version.
if hits="$(grep -rnE '(^|[^A-Za-z0-9_.])v[0-9]+\.[0-9]+\.[0-9]+([^0-9]|$)' dashboard/app dashboard/components --include='*.tsx' --include='*.ts' \
      | grep -vE 'CRS v4|crs v4|OWASP|TLS ?v1|HTTP/|version\.ts' )"; then
  echo "✗ hard-coded version literal(s) in dashboard source:"; echo "$hits" | sed 's/^/    /'; fail=1
else
  echo "✓ no hard-coded vN.N.N literals in dashboard source"
fi

[ $fail -eq 0 ] && echo "version consistency OK" || { echo "version consistency FAILED"; exit 1; }
