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
#
# `grep --include` was used here and BusyBox grep does not support it. In the
# alpine CI image the grep therefore exited 2, the `if` took the else branch,
# and this check printed "✓ no hard-coded literals" WITHOUT HAVING LOOKED — a
# gate that passes because it failed. Found 2026-09-07 by running this script
# inside the CI image, which is the only way that class of bug shows up.
# Enumerate with find (portable), and treat a search that cannot run as a
# failure rather than a pass.
ui_files="$(find dashboard/app dashboard/components \( -name '*.tsx' -o -name '*.ts' \) 2>/dev/null)"
if [ -z "$ui_files" ]; then
  echo "✗ could not enumerate dashboard sources — refusing to report this check as passed"
  fail=1
else
  # grep exit 1 = no matches (good), 0 = matches (bad), >1 = the search itself broke.
  hits="$(printf '%s\n' "$ui_files" | xargs grep -nE '(^|[^A-Za-z0-9_.])v[0-9]+\.[0-9]+\.[0-9]+([^0-9]|$)' 2>/dev/null | grep -vE 'CRS v4|crs v4|OWASP|TLS ?v1|HTTP/|version\.ts')"
  rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "✗ the version-literal search failed to run (exit $rc) — not treating that as a pass"
    fail=1
  elif [ -n "$hits" ]; then
    echo "✗ hard-coded version literal(s) in dashboard source:"; echo "$hits" | sed 's/^/    /'; fail=1
  else
    echo "✓ no hard-coded vN.N.N literals in dashboard source ($(printf '%s\n' "$ui_files" | wc -l | tr -d ' ') files scanned)"
  fi
fi

# Every symbol the Dockerfile injects with `go build -X` must actually exist in
# version.go. `-X` on a name the linker cannot find is a SILENT no-op: on
# 2026-09-07 those two variables were renamed, the injection stopped working,
# and every control-plane binary reported commit "unknown" while the build logs
# looked perfectly normal. Nothing failed, nothing warned. This is the guard.
for sym in $(grep -oE '\-X [^ ]*internal/version\.[A-Za-z_][A-Za-z0-9_]*=' deploy/docker/Dockerfile \
             | sed 's/.*internal\/version\.//; s/=$//' | sort -u); do
  if grep -qE "^[[:space:]]*(var[[:space:]]+)?${sym}[[:space:]]*=" control-plane/internal/version/version.go; then
    echo "✓ ldflags symbol ${sym} exists in version.go"
  else
    echo "✗ Dockerfile injects ${sym} with -X, but version.go declares no such variable — the"
    echo "   injection is a silent no-op and the binary will report 'unknown'"
    fail=1
  fi
done

[ $fail -eq 0 ] && echo "version consistency OK" || { echo "version consistency FAILED"; exit 1; }
