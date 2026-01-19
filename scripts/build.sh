#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/../build"

cmake -S "$SCRIPT_DIR/../backend" -B "$BUILD_DIR"

cmake --build "$BUILD_DIR" --config Release -j$(nproc)

cd "$SCRIPT_DIR/../frontend"

export NODE_ENV=production

[ ! -d node_modules ] && bun install --production
rm -rf "$BUILD_DIR/public"
bun run build

"$SCRIPT_DIR/sign-assets.sh"
