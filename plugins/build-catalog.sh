#!/usr/bin/env bash
# Build the bundled plugin catalogue: every example under plugins/examples/<name>
# with a sentinel-plugin.toml is compiled to WebAssembly and zipped (manifest +
# plugin.wasm) into control-plane/cmd/controllerd/plugincatalog/<name>.zip, which
# the control plane embeds and offers on the Plugins page as one-click installs.
#
# The .zip files ARE committed: the control-plane image is built from a Go
# stage with no Rust toolchain, and the modules are a few KB each. Re-run this
# after changing an example and commit the result.
set -euo pipefail
cd "$(dirname "$0")"
OUT=../control-plane/cmd/controllerd/plugincatalog
mkdir -p "$OUT"
rustup target list --installed | grep -q wasm32-unknown-unknown || rustup target add wasm32-unknown-unknown
for dir in examples/*/; do
  name=$(basename "$dir")
  [ -f "$dir/sentinel-plugin.toml" ] || continue
  [ -f "$dir/Cargo.toml" ] || { echo "skip $name (not a Rust example)"; continue; }
  echo "== $name"
  (cd "$dir" && cargo build --target wasm32-unknown-unknown --release --quiet)
  wasm=$(ls "$dir"/target/wasm32-unknown-unknown/release/*.wasm | head -1)
  tmp=$(mktemp -d); cp "$dir/sentinel-plugin.toml" "$tmp/"; cp "$wasm" "$tmp/plugin.wasm"
  rm -f "$OUT/$name.zip"; (cd "$tmp" && zip -q -X "$OLDPWD/$OUT/$name.zip" sentinel-plugin.toml plugin.wasm)
  rm -rf "$tmp"; ls -la "$OUT/$name.zip"
done
