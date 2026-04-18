#!/usr/bin/env bash
set -euo pipefail

PKI_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CA_DIR="$PKI_DIR/ca"
SRV_DIR="$PKI_DIR/server"

echo "[*] Generating server private key..."

openssl genrsa \
  -out "$SRV_DIR/server.key" \
  4096

chmod 600 "$SRV_DIR/server.key"

echo "[*] Creating Certificate Signing Request (CSR)..."

openssl req -new \
  -key  "$SRV_DIR/server.key" \
  -out  "$SRV_DIR/server.csr" \
  -subj "/CN=myvpn-server/O=MyVPN/C=US"

echo "[*] CA signing the CSR → server certificate..."

openssl x509 -req \
  -days           3650 \
  -in             "$SRV_DIR/server.csr" \
  -CA             "$CA_DIR/ca.crt" \
  -CAkey          "$CA_DIR/ca.key" \
  -CAcreateserial \
  -out            "$SRV_DIR/server.crt"

echo "[*] Generating Diffie-Hellman parameters (this takes ~30s)..."

openssl dhparam \
  -out "$SRV_DIR/dh.pem" \
  2048

echo "[+] Done! Files in pki/server/:"
echo "    server.key → secret, stays on the server"
echo "    server.csr → can be deleted after signing"
echo "    server.crt → public, loaded by C daemon"
echo "    dh.pem     → public, loaded by C daemon"