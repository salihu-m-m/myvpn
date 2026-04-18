#!/usr/bin/env python3
"""
vpnadmin — management CLI for myvpn
Usage:
    python3 vpnadmin.py cert new <name> <ip>
    python3 vpnadmin.py cert list
    python3 vpnadmin.py cert revoke <name>
    python3 vpnadmin.py daemon start
    python3 vpnadmin.py daemon stop
    python3 vpnadmin.py daemon status
    python3 vpnadmin.py status
"""

import argparse
import sys
import os

# Add admin/ to path so we can import commands/
sys.path.insert(0, os.path.dirname(__file__))

from commands import certs, daemon, status

def main():
    # ── Root parser ───────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog='vpnadmin',
        description='myvpn management CLI'
    )
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    # ── cert subcommand ───────────────────────────────────────
    cert_parser = subparsers.add_parser('cert',
                                        help='manage client certificates')
    cert_sub = cert_parser.add_subparsers(dest='cert_action')
    cert_sub.required = True

    # cert new <name> <ip>
    new_p = cert_sub.add_parser('new', help='create a new client cert')
    new_p.add_argument('name', help='client name')
    new_p.add_argument('ip',   help='VPN tunnel IP e.g. 10.8.0.3')

    # cert list
    cert_sub.add_parser('list', help='list all client certs')

    # cert revoke <name>
    rev_p = cert_sub.add_parser('revoke', help='revoke a client cert')
    rev_p.add_argument('name', help='client name to revoke')

    # ── daemon subcommand ─────────────────────────────────────
    daemon_parser = subparsers.add_parser('daemon',
                                          help='control the vpnd daemon')
    daemon_sub = daemon_parser.add_subparsers(dest='daemon_action')
    daemon_sub.required = True
    daemon_sub.add_parser('start',  help='start vpnd')
    daemon_sub.add_parser('stop',   help='stop vpnd')
    daemon_sub.add_parser('status', help='show daemon status')

    # ── status subcommand ─────────────────────────────────────
    subparsers.add_parser('status', help='show connected clients')

    # ── Dispatch ──────────────────────────────────────────────
    args = parser.parse_args()

    if args.command == 'cert':
        if args.cert_action == 'new':
            certs.new_client(args.name, args.ip)
        elif args.cert_action == 'list':
            certs.list_clients()
        elif args.cert_action == 'revoke':
            certs.revoke_client(args.name)

    elif args.command == 'daemon':
        if args.daemon_action == 'start':
            daemon.start()
        elif args.daemon_action == 'stop':
            daemon.stop()
        elif args.daemon_action == 'status':
            daemon.status()

    elif args.command == 'status':
        status.show()

if __name__ == '__main__':
    main()
