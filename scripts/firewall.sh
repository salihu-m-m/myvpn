VPN_SUBNET="10.8.0.0/24"     # VPN tunnel subnet
OUTBOUND_IF="eth0"           # outbound network interface

set -e   # exit on any error

echo "[*] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
# Makes this permanent across reboots:
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

echo "[*] Setting up NAT masquerade..."
# MASQUERADE = rewrite source IP of VPN packets to server's real IP
# so replies know how to get back
iptables -t nat -A POSTROUTING \
    -s "$VPN_SUBNET" \
    -o "$OUTBOUND_IF" \
    -j MASQUERADE

echo "[*] Allowing forwarded traffic..."
# Allow VPN subnet traffic to be forwarded
iptables -A FORWARD \
    -s "$VPN_SUBNET" \
    -j ACCEPT

iptables -A FORWARD \
    -d "$VPN_SUBNET" \
    -j ACCEPT

echo "[+] Firewall rules applied"
echo "[+] IP forwarding enabled"