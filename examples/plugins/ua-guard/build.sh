#!/usr/bin/env bash
# Build ua-guard into an uploadable Sentinel plugin archive.
#
# Produces ua-guard.zip containing sentinel-plugin.toml + plugin.wasm, which is
# exactly what the Plugins page (or POST /api/v1/plugins) accepts.
set -euo pipefail
cd "$(dirname "$0")"

TARGET=wasm32-unknown-unknown

if ! rustup target list --installed | grep -qx "$TARGET"; then
    echo "installing Rust target $TARGET"
    rustup target add "$TARGET"
fi

echo "building for $TARGET"
cargo build --release --target "$TARGET"

# The crate is excluded from the workspace, so its artifacts land in a local
# target/ directory rather than the workspace one.
WASM="target/$TARGET/release/ua_guard.wasm"
[[ -f "$WASM" ]] || { echo "expected $WASM to exist" >&2; exit 1; }

rm -f plugin.wasm ua-guard.zip
cp "$WASM" plugin.wasm

# Store the manifest and module at the archive root. `zip -j` junks paths so the
# archive has no directory prefix at all.
zip -j -q ua-guard.zip sentinel-plugin.toml plugin.wasm
rm -f plugin.wasm

echo
echo "built ua-guard.zip ($(stat -c%s ua-guard.zip) bytes)"
echo "  module: $(stat -c%s "$WASM") bytes, sha256 $(sha256sum "$WASM" | cut -d' ' -f1)"
echo
echo "Upload it in the dashboard under Plugins, or:"
echo "  curl -X POST -H \"Authorization: Bearer \$TOKEN\" \\"
echo "       -F file=@ua-guard.zip http://localhost:9501/api/v1/plugins"
