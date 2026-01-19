#!/bin/bash
set -e

SCRIPT_DIR="$(dirname "$0")"
PROJECT_DIR="$SCRIPT_DIR/../"
BUILD_DIR="$SCRIPT_DIR/../build"
PUBLIC_DIR="$BUILD_DIR/public"

mkdir -p "$PUBLIC_DIR"

if [ ! -f "$PROJECT_DIR/private.pem" ] || [ ! -f "$PROJECT_DIR/public.pem" ]; then
  echo "Key pair missing; generating..."
  "$SCRIPT_DIR/gen-sig-keys.sh"
fi

for file in "$PUBLIC_DIR"/*; do
  if [ -f "$file" ] && [ "$(basename "$file")" != "public.pem" ] && [[ "$file" != *.map ]] && [[ "$file" != *.sig ]]; then
    openssl dgst -sha256 -sign "$PROJECT_DIR/private.pem" -out "$file.sig" "$file"
    echo "Signed $file"
  fi
done
