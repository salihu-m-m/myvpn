import subprocess

def show():
    """Show active TUN interfaces and connected clients."""
    print("[*] Active TUN interfaces:")
    result = subprocess.run(
        ['ip', 'addr', 'show'],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if 'tun' in line:
            print(f"    {line.strip()}")

    print("\n[*] Listening on port 9000:")
    result = subprocess.run(
        ['ss', '-tlnp'],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        if '9000' in line:
            print(f"    {line.strip()}")