#!/usr/bin/env bash
set -euo pipefail

# Usage: ./03_gen_client.sh <clientname>
# e.g.   ./03_gen_client.sh alice

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <clientname>"; exit 1
fi

CLIENT="$1"
PKI_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CA_DIR="$PKI_DIR/ca"
CLI_DIR="$PKI_DIR/clients/$CLIENT"

mkdir -p "$CLI_DIR"

echo "[*] Generating key for client: $CLIENT"

openssl genrsa \
  -out "$CLI_DIR/$CLIENT.key" \
  4096

chmod 600 "$CLI_DIR/$CLIENT.key"

echo "[*] Creating CSR for: $CLIENT"

openssl req -new \
  -key  "$CLI_DIR/$CLIENT.key" \
  -out  "$CLI_DIR/$CLIENT.csr" \
  -subj "/CN=$CLIENT/O=MyVPN/C=US"

echo "[*] Signing with CA..."

openssl x509 -req \
  -days           365 \
  -in             "$CLI_DIR/$CLIENT.csr" \
  -CA             "$CA_DIR/ca.crt" \
  -CAkey          "$CA_DIR/ca.key" \
  -CAcreateserial \
  -out            "$CLI_DIR/$CLIENT.crt"

cp "$CA_DIR/ca.crt" "$CLI_DIR/ca.crt"

echo "[+] Client '$CLIENT' ready in pki/clients/$CLIENT/"
echo "    Ship to the client device: $CLIENT.key, $CLIENT.crt, ca.crt"