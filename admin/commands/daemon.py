import os
import subprocess
import signal

ROOT    = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
VPND    = os.path.join(ROOT, 'src', 'server', 'vpnd')
PIDFILE = '/tmp/vpnd.pid'

def start():
    """Start the vpnd daemon."""
    if os.path.exists(PIDFILE):
        print("[!] vpnd already running (pidfile exists)")
        return
    if not os.path.exists(VPND):
        print(f"[!] vpnd binary not found at {VPND} — run make first")
        return
    proc = subprocess.Popen(['sudo', VPND],
                             stdout=None, stderr=None)
    with open(PIDFILE, 'w') as f:
        f.write(str(proc.pid))
    print(f"[+] vpnd started — PID {proc.pid}")

def stop():
    """Stop the vpnd daemon via SIGTERM."""
    if not os.path.exists(PIDFILE):
        print("[!] vpnd not running (no pidfile)")
        return
    with open(PIDFILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        os.remove(PIDFILE)
        print(f"[+] vpnd stopped (PID {pid})")
    except ProcessLookupError:
        print("[!] Process not found — removing stale pidfile")
        os.remove(PIDFILE)

def status():
    """Show whether vpnd is running."""
    if not os.path.exists(PIDFILE):
        print("[*] vpnd is not running")
        return
    with open(PIDFILE) as f:
        pid = int(f.read().strip())
    try:
        os.kill(pid, 0)   # signal 0 = just check if process exists
        print(f"[+] vpnd is running — PID {pid}")
    except ProcessLookupError:
        print("[*] vpnd is not running (stale pidfile)")