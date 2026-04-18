#!/usr/bin/env bash
set -euo pipefail   
PKI_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CA_DIR="$PKI_DIR/ca"

echo "[*] Generating CA private key (4096-bit RSA)..."

openssl genrsa \
  -out "$CA_DIR/ca.key" \
  4096

chmod 600 "$CA_DIR/ca.key"   

echo "[*] Self-signing the CA certificate..."

openssl req \
  -new -x509 \
  -days 3650 \
  -key  "$CA_DIR/ca.key" \
  -out  "$CA_DIR/ca.crt" \
  -subj "/CN=MyVPN-CA/O=MyVPN/C=US"

echo "[+] Done!"
echo "    ca.key → KEEP SECRET, never commit to git"
echo "    ca.crt → public, distribute to all clients"