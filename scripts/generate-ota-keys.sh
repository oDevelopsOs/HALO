#!/usr/bin/env bash
# generate-ota-keys.sh — generate Ed25519 signing keypair for OTA profiles.
#
# Usage: generate-ota-keys.sh [output_dir]
#
# Outputs:
#   <output_dir>/ota-signing.key  — 32-byte Ed25519 seed (KEEP SECRET)
#   <output_dir>/ota-public.key   — 32-byte Ed25519 public key (embed in binary)
#   <output_dir>/ota-public.hex   — hex-encoded public key for env var

set -euo pipefail

OUTPUT_DIR="${1:-./ota-keys}"

mkdir -p "$OUTPUT_DIR"

echo "Generating Ed25519 keypair..."

# Try Python cryptography first
generate_python() {
    python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import os

sk = Ed25519PrivateKey.generate()
pk = sk.public_key()

# Private key: raw 32-byte seed
with open('$OUTPUT_DIR/ota-signing.key', 'wb') as f:
    f.write(sk.private_bytes_raw())

# Public key: raw 32-byte
with open('$OUTPUT_DIR/ota-public.key', 'wb') as f:
    f.write(pk.public_bytes_raw())

# Hex for convenience
with open('$OUTPUT_DIR/ota-public.hex', 'w') as f:
    f.write(pk.public_bytes_raw().hex())
" 2>/dev/null
}

# Fallback: openssl
generate_openssl() {
    openssl genpkey -algorithm ed25519 -out "$OUTPUT_DIR/ota-signing.pem" 2>/dev/null
    openssl pkey -in "$OUTPUT_DIR/ota-signing.pem" -pubout -out "$OUTPUT_DIR/ota-public.pem" 2>/dev/null
    # Extract raw 32-byte public key (last 32 bytes of DER SPKI)
    openssl pkey -in "$OUTPUT_DIR/ota-public.pem" -pubout -outform DER 2>/dev/null | tail -c 32 > "$OUTPUT_DIR/ota-public.key"
    openssl pkey -in "$OUTPUT_DIR/ota-signing.pem" -outform DER 2>/dev/null | tail -c 32 > "$OUTPUT_DIR/ota-signing.key"
    xxd -p -c 32 "$OUTPUT_DIR/ota-public.key" > "$OUTPUT_DIR/ota-public.hex"
}

if generate_python 2>/dev/null; then
    echo "Keys generated with Python/cryptography"
elif generate_openssl 2>/dev/null; then
    echo "Keys generated with OpenSSL"
else
    echo "ERROR: Neither Python/cryptography nor OpenSSL available"
    echo "Install: pip install cryptography   OR   apt install openssl"
    exit 1
fi

# Set restrictive permissions on private key
chmod 600 "$OUTPUT_DIR/ota-signing.key"

echo ""
echo "Keys generated in $OUTPUT_DIR/:"
ls -la "$OUTPUT_DIR/"
echo ""
echo "To embed the public key in the binary, set at build time:"
echo "  export AGENTGUARD_OTA_PUBLIC_KEY=$(cat "$OUTPUT_DIR/ota-public.hex")"
echo ""
echo "The private key ($OUTPUT_DIR/ota-signing.key) must be stored offline"
echo "and added as a GitHub secret: OTA_SIGNING_KEY"
