#!/usr/bin/env bash
# Run the Next.js dashboard natively.
set -euo pipefail
cd "$(dirname "$0")/../../dashboard"

export NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-http://localhost:8443}"

if [ ! -d node_modules ]; then
  echo "→ Installing deps…"
  npm install
fi

exec npm run dev
