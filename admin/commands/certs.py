import os
import subprocess

# Find project root relative to this file
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
PKI  = os.path.join(ROOT, 'pki')

def new_client(name, ip):
    """Generate cert + config for a new client."""
    script = os.path.join(ROOT, 'scripts', 'new_client.sh')
    result = subprocess.run([script, name, ip], check=False)
    if result.returncode != 0:
        print(f"[!] Failed to create client '{name}'")
    else:
        print(f"[+] Client '{name}' created with IP {ip}")

def list_clients():
    """List all clients with certs."""
    clients_dir = os.path.join(PKI, 'clients')
    if not os.path.exists(clients_dir):
        print("[!] No clients directory found")
        return
    clients = [d for d in os.listdir(clients_dir)
               if os.path.isdir(os.path.join(clients_dir, d))]
    if not clients: 
        print("[*] No clients found")
        return
    print(f"[*] {len(clients)} client(s):")
    for c in sorted(clients):
        cert = os.path.join(clients_dir, c, f"{c}.crt")
        exists = "✓" if os.path.exists(cert) else "✗"
        print(f"    {exists}  {c}")

def revoke_client(name):
    """Revoke a client certificate."""
    script = os.path.join(PKI, 'scripts', '04_revoke.sh')
    if not os.path.exists(script):
        print("[!] 04_revoke.sh not found — write it first")
        return
    subprocess.run([script, name], check=False)
    print(f"[+] Revoked cert for '{name}'")
