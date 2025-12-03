#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(dirname "$0")"
PROTO_DIR="$SCRIPT_DIR/../proto"
BACKEND_GEN="$SCRIPT_DIR/../backend/generated"
FRONTEND_GEN="$SCRIPT_DIR/../frontend/generated"

mkdir -p "$BACKEND_GEN" "$FRONTEND_GEN"

PROTOC_GEN_C="$SCRIPT_DIR/../build/third_party/protobuf-c/build-cmake/protoc-gen-c"
PROTOC_GEN_TS="$SCRIPT_DIR/../frontend/node_modules/.bin/protoc-gen-ts"

echo "Generating C code..."
protoc \
  --plugin=protoc-gen-c="$PROTOC_GEN_C" \
  --c_out="$BACKEND_GEN" \
  --proto_path="$PROTO_DIR" \
  "$PROTO_DIR"/*.proto

echo "Generating TypeScript code..."
protoc \
  --plugin=protoc-gen-ts="$PROTOC_GEN_TS" \
  --ts_out="$FRONTEND_GEN" \
  --proto_path="$PROTO_DIR" \
  "$PROTO_DIR"/*.proto

echo "Protobuf code generated!"
