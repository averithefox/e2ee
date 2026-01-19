#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/../"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$PROJECT_DIR/private.pem"
openssl pkey -in "$PROJECT_DIR/private.pem" -pubout -out "$PROJECT_DIR/public.pem"
