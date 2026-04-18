#!/bin/bash
# new_client.sh — onboard a new VPN client
# Usage: ./new_client.sh <name> <vpn_ip>
# Example: ./new_client.sh bob 10.8.0.3

set -e

# ── Args ──────────────────────────────────────────────────────
NAME="${1:?Usage: $0 <name> <vpn_ip>}"
VPN_IP="${2:?Usage: $0 <name> <vpn_ip>}"
PKI_DIR="$(cd "$(dirname "$0")/.." && pwd)/pki"
CONFIG_DIR="$(cd "$(dirname "$0")/.." && pwd)/config"

if [ -d "$PKI_DIR/clients/$NAME" ]; then
    echo "[!] Client '$NAME' already exists"
    exit 1
fi

# ── Generate cert (reuse Phase 1 script) ──────────────────────
echo "[*] Generating cert for $NAME..."
"$PKI_DIR/scripts/03_gen_client.sh" "$NAME"

# ── Generate client.conf ───────────────────────────────────────
OUT="$CONFIG_DIR/${NAME}.conf"
cat > "$OUT" << EOF
# vpnc config for $NAME — generated $(date)
port      = 9000
server    = YOUR_SERVER_IP
ca_cert   = $PKI_DIR/ca/ca.crt
cli_cert  = $PKI_DIR/clients/$NAME/$NAME.crt
cli_key   = $PKI_DIR/clients/$NAME/$NAME.key
tun_ip    = $VPN_IP/24
EOF

echo "[+] Client '$NAME' created"
echo "[+] Config written to: $OUT"
echo "[+] Cert at: $PKI_DIR/clients/$NAME/"
echo ""
echo "Give the client:"
echo "  - $PKI_DIR/clients/$NAME/$NAME.crt"
echo "  - $PKI_DIR/clients/$NAME/$NAME.key"
echo "  - $PKI_DIR/ca/ca.crt"
echo "  - ${NAME}.conf"