#!/usr/bin/env bash
# Public surface gate: the public remote must carry exactly one branch (main).
# Usage: tools/check_public_surface.sh [remote]   (default: origin)
set -euo pipefail
heads=$(git ls-remote --heads "${1:-origin}" | awk '{print $2}')
if [ "$heads" != "refs/heads/main" ]; then
    echo "unexpected public branches beyond main:" >&2
    printf '%s\n' "$heads" >&2
    exit 1
fi
echo "public surface OK: main only"
