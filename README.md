[README (1).md](https://github.com/user-attachments/files/26852473/README.1.md)
# myvpn

A fully functional OpenVPN-style VPN built from scratch in C, Bash, and Python — no VPN libraries, no shortcuts. Every layer implemented manually: PKI, TCP sockets, TLS, packet framing, kernel TUN interface, daemon infrastructure, and a management CLI.

---

## What This Is

Most VPN projects wrap an existing library. This one doesn't. `myvpn` is built layer by layer from first principles, with exactly one new concept introduced per phase so every line of code is understood before it's written.

The result is a working VPN daemon that:

- Authenticates clients using mutual TLS with a self-signed CA
- Encrypts all traffic with AES-256-GCM (TLS 1.3)
- Routes real IP packets through a Linux TUN device
- Handles multiple clients via `fork()`
- Shuts down gracefully on `SIGINT`/`SIGTERM`
- Loads configuration from a file
- Provides a Python CLI for cert and daemon management

Tested: 1000-packet flood ping at 0% packet loss, sub-millisecond latency on localhost.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Core daemon | C (POSIX sockets, pthreads, OpenSSL) |
| Kernel interface | Linux TUN/TAP (`/dev/net/tun`, `ioctl`) |
| Encryption | TLS 1.3 via OpenSSL (`libssl`, `libcrypto`) |
| PKI | Raw OpenSSL CLI — no EasyRSA |
| Ops scripts | Bash |
| Management CLI | Python 3 (`argparse`) |

---

## Project Structure

```
myvpn/
├── pki/
│   ├── scripts/          # 01-04 cert generation scripts
│   ├── ca/               # ca.crt (public), ca.key (gitignored)
│   ├── server/           # server.crt, server.key, dh.pem
│   └── clients/          # per-client certs
├── learn/
│   ├── tcp/              # Phase 2 — plain TCP echo
│   ├── tls/              # Phase 3 — TLS echo
│   └── fake_tunnel/      # Phase 4 — length-prefix framing
├── src/
│   ├── core/             # Phase 5 — TUN device + real routing
│   ├── server/           # Phase 6 — vpnd daemon
│   └── client/           # Phase 6 — vpnc client
├── scripts/
│   ├── firewall.sh       # iptables NAT + IP forwarding
│   └── new_client.sh     # onboard a new VPN user
├── admin/
│   ├── vpnadmin.py       # CLI entry point
│   └── commands/         # cert, daemon, status subcommands
└── config/
    ├── server.conf
    └── client.conf
```

---

## Build

**Dependencies:**

```bash
sudo apt install build-essential libssl-dev -y
```

**Build the daemon and client:**

```bash
cd src/server && make
cd ../client && make
```

---

## PKI Setup

Generate your CA, server cert, and client cert before running anything:

```bash
# Bootstrap the CA
./pki/scripts/01_gen_ca.sh

# Generate server cert + DH params
./pki/scripts/02_gen_server.sh

# Generate a client cert
./pki/scripts/03_gen_client.sh mubby
```

Verify:

```bash
openssl verify -CAfile pki/ca/ca.crt pki/server/server.crt   # → OK
openssl verify -CAfile pki/ca/ca.crt pki/clients/mubby/mubby.crt  # → OK
```

---

## Running

```bash
# Terminal 1 — start the daemon
cd src/server
sudo ./vpnd

# Terminal 2 — connect a client
cd src/client
sudo ./vpnc

# Terminal 3 — verify the tunnel
ping -c 4 10.8.0.1
```

Press `Ctrl+C` on either side for a graceful shutdown.

---

## Management CLI

```bash
cd admin

# List all client certs
python3 vpnadmin.py cert list

# Onboard a new client
python3 vpnadmin.py cert new bob 10.8.0.3

# Check daemon status
python3 vpnadmin.py daemon status

# Show active TUN interfaces
python3 vpnadmin.py status
```

---

## How It Works

```
CLIENT SIDE                          SERVER SIDE

kernel sends packet to 10.8.0.1
        │
        ▼
read(tun_fd)                         write(tun_fd)
        │                                  ▲
        ▼                                  │
send_packet()  ── TLS 1.3 tunnel ──► recv_packet()
  [4B length][N bytes encrypted]
```

1. A packet destined for `10.8.0.1` hits the client's TUN interface
2. The client reads it with `read(tun_fd)` — a raw IP packet
3. It's framed with a 4-byte length prefix and encrypted via `SSL_write()`
4. The server receives it, decrypts it, and injects it into its TUN device with `write(tun_fd)`
5. The kernel routes it as if it arrived from a real network interface
6. The reply travels the same path in reverse

Both directions run simultaneously in separate pthreads.

---

## Build Phases

The project was built in 7 phases — one new concept per phase:

| Phase | Concept | Location |
|-------|---------|----------|
| 1 | Raw PKI with OpenSSL | `pki/scripts/` |
| 2 | POSIX socket API | `learn/tcp/` |
| 3 | TLS on TCP (OpenSSL) | `learn/tls/` |
| 4 | Length-prefix packet framing | `learn/fake_tunnel/` |
| 5 | Linux TUN device + real routing | `src/core/` |
| 6 | Production daemon (signals, fork, config) | `src/server/`, `src/client/` |
| 7 | Bash ops + Python CLI | `scripts/`, `admin/` |

---

## Security Notes

- Private keys are gitignored — never committed
- Mutual TLS: both server and client present certificates signed by the CA
- Clients without a valid CA-signed cert are rejected at the TLS handshake
- `SO_REUSEADDR` set on server socket
- Signal handlers only set a flag — no unsafe functions called inside handlers

---

## Author

Salihu-m-m · Built on WSL2 (Ubuntu) · 2026
