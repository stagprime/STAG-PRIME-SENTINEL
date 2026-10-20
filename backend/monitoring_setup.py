"""Local-only CLI to approve monitoring for a database server (Step 36.8).

No HTTP write endpoint is provided until Sentinel has login/RBAC.
SSH keys remain local files; only their locations and connection settings are stored.

Usage:
  python -m backend.monitoring_setup configure --server-name EU-01 \
    --key-path 'D:\\sentinel_monitor_openssh.ppk' \
    --vpn-service 'openvpn-server@eu01' --vpn-interface tun-eu01 \
    --wan-interface eth0
"""

from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path
from datetime import datetime, timezone

from sqlalchemy import select

from backend.monitoring_discovery import DiscoveryError, discover_ssh_server

from backend.database import (
    Base, Client, Server, ServerMonitoringConfig, SessionLocal, engine, DATA_DIR, BASE_DIR,
)


def _check_identifier(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,80}", value):
        raise ValueError(f"Invalid {label}: use letters, digits, _, ., @ or -")
    return value


def _resolve_file_path(value: str, label: str) -> str:
    path = Path(value).expanduser()
    if not path.is_file():
        raise ValueError(f"{label} file does not exist on this computer")
    return str(path.resolve())


def _create_safe_db_backup() -> str | None:
    """SQLite online backup, before adding a table or changing any approval."""
    db_path = DATA_DIR / "sentinel.db"
    if not db_path.is_file():
        return None
    backup_dir = BASE_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup_path = backup_dir / f"sentinel-before-step36-8-{stamp}.db"
    try:
        with sqlite3.connect(str(db_path)) as source, sqlite3.connect(str(backup_path)) as output:
            source.backup(output)
    except Exception:
        backup_path.unlink(missing_ok=True)
        raise
    return str(backup_path)


def configure(args: argparse.Namespace) -> None:
    key_path = _resolve_file_path(args.key_path, "SSH private key")
    known_hosts_path = (
        _resolve_file_path(args.known_hosts_path, "SSH known_hosts")
        if args.known_hosts_path else None
    )
    vpn_service = _check_identifier(args.vpn_service, "VPN service")
    vpn_interface = _check_identifier(args.vpn_interface, "VPN tunnel interface")
    wan_interface = _check_identifier(args.wan_interface, "WAN network interface")

    backup = _create_safe_db_backup()
    if backup:
        print("Local SQLite backup created safely in project backups folder")

    # Additive operation ONLY: SQLAlchemy will not drop/change the existing
    # clients or servers tables and will not delete current inventory records.
    Base.metadata.create_all(bind=engine, tables=[ServerMonitoringConfig.__table__])

    with SessionLocal() as db:
        if args.server_id:
            servers = [db.get(Server, args.server_id)]
        else:
            stmt = select(Server).where(Server.name == args.server_name)
            if args.client_name:
                stmt = stmt.join(Client, Client.id == Server.client_id).where(
                    Client.name == args.client_name
                )
            servers = db.scalars(stmt).all()

        servers = [server for server in servers if server is not None]
        if len(servers) != 1:
            raise ValueError(
                "Server not found or name is ambiguous. Use --server-id (from GET /api/servers)."
            )
        server = servers[0]
        if server.archived_at is not None:
            raise ValueError("Archived servers cannot be enabled for monitoring")
        if not server.host or not server.host.strip():
            raise ValueError("Inventory server has no SSH hostname/IP")
        username = (server.ssh_username or "").strip()
        if not username:
            raise ValueError("Set SSH username in existing Server Inventory first")
        ssh_port = server.ssh_port or 22
        if not 1 <= ssh_port <= 65535:
            raise ValueError("SSH port must be 1..65535")

        existing = db.get(ServerMonitoringConfig, server.id)
        if existing is not None and not args.replace:
            raise ValueError("Monitoring already configured; use --replace to approve changes")

        if existing is None:
            existing = ServerMonitoringConfig(server_id=server.id)
            db.add(existing)

        existing.enabled = True
        existing.approved_host = server.host.strip()
        existing.approved_ssh_username = username
        existing.approved_ssh_port = ssh_port
        existing.ssh_key_path = key_path
        existing.known_hosts_path = known_hosts_path
        existing.vpn_service = vpn_service
        existing.vpn_interface = vpn_interface
        existing.network_interface = wan_interface
        existing.approved_at = datetime.now(timezone.utc)
        db.commit()
        print("=== SENTINEL MONITORING PROFILE APPROVED ===")
        print(f"Server: {server.name}")
        print(f"Server ID: {server.id}")
        print("Key file: present (contents are not shown)")
        print("Database: existing client/server records preserved")
        print("Live SSH health check: pending")



def _locate_active_server(args: argparse.Namespace) -> tuple[str, str, str, int]:
    """Read only. Resolve an exact authorized inventory record (not an arbitrary IP)."""
    with SessionLocal() as db:
        if args.server_id:
            servers = [db.get(Server, args.server_id)]
        else:
            statement = select(Server).where(Server.name == args.server_name)
            if args.client_name:
                statement = statement.join(Client, Client.id == Server.client_id).where(
                    Client.name == args.client_name
                )
            servers = db.scalars(statement).all()
        servers = [server for server in servers if server is not None]
        if len(servers) != 1:
            raise ValueError('Server not found or ambiguous; use --server-id from inventory')
        record = servers[0]
        if record.archived_at is not None:
            raise ValueError('Archived servers cannot be monitored')
        if not record.host or not record.host.strip():
            raise ValueError('Server does not have a valid SSH host')
        if not record.ssh_username or not record.ssh_username.strip():
            raise ValueError('Set SSH username in Server Inventory first')
        port = record.ssh_port or 22
        if not 1 <= port <= 65535:
            raise ValueError('Invalid SSH port')
        return record.id, record.host.strip(), record.ssh_username.strip(), port


def _discover_for_inventory(args: argparse.Namespace) -> tuple[str, str, str, int, str, str | None, dict]:
    server_id, host, username, port = _locate_active_server(args)
    key_path = _resolve_file_path(args.key_path, 'SSH private key')
    known_hosts = (_resolve_file_path(args.known_hosts_path, 'SSH known_hosts')
                   if args.known_hosts_path else None)
    print('Connecting with strict SSH host-key verification (read-only)...')
    discovered = discover_ssh_server(
        host=host, username=username, port=port,
        private_key_path=key_path, known_hosts_path=known_hosts,
    )
    return server_id, host, username, port, key_path, known_hosts, discovered


def discover(args: argparse.Namespace) -> None:
    """Show server observations only. No approval, DB write, VPS changes or sudo."""
    import json
    server_id, host, username, port, _key, _known, data = _discover_for_inventory(args)
    print('=== SENTINEL AUTOMATIC DISCOVERY (READ-ONLY) ===')
    print('Inventory server ID:', server_id)
    print('SSH host:', host, '| User:', username, '| Port:', port)
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print('No monitoring approvals or server settings were modified.')
    print('Any protected status file must be made readable by an authorized admin.')


def configure_auto(args: argparse.Namespace) -> None:
    """Explicit local approval, using validated discovery from one trusted host."""
    if not args.approve:
        raise ValueError('Missing --approve. Run discover first, then explicitly approve.')
    server_id, host, username, port = _locate_active_server(args)
    # Refuse replacement BEFORE connecting, while still guarding it again below.
    with SessionLocal() as db:
        existing = db.get(ServerMonitoringConfig, server_id)
        if existing is not None and not args.replace:
            raise ValueError('Monitoring already approved. Use --replace only to re-approve.')
    probed_id, probed_host, probed_username, probed_port, key_path, known_hosts, meta = _discover_for_inventory(args)
    if not meta['ready_for_approval']:
        raise DiscoveryError('Ambiguous or missing OpenVPN configuration: ' + '; '.join(meta['warnings']))
    if (server_id, host, username, port) != (probed_id, probed_host, probed_username, probed_port):
        raise ValueError('Inventory changed during discovery. No approval saved.')

    backup = _create_safe_db_backup()
    if backup:
        print('Local SQLite backup created safely in project backups folder')
    Base.metadata.create_all(bind=engine, tables=[ServerMonitoringConfig.__table__])
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None or server.archived_at is not None or (
            server.host.strip(), (server.ssh_username or '').strip(), server.ssh_port or 22
        ) != (host, username, port):
            raise ValueError('Inventory changed since discovery. No approval saved.')
        profile = db.get(ServerMonitoringConfig, server_id)
        if profile is not None and not args.replace:
            raise ValueError('Monitoring already configured; pass --replace to re-approve')
        if profile is None:
            profile = ServerMonitoringConfig(server_id=server_id)
            db.add(profile)
        profile.enabled = True
        profile.approved_host = host
        profile.approved_ssh_username = username
        profile.approved_ssh_port = port
        profile.ssh_key_path = key_path
        profile.known_hosts_path = known_hosts
        profile.vpn_service = meta['vpn_service']
        profile.vpn_interface = meta['vpn_interface']
        profile.network_interface = meta['network_interface']
        profile.approved_at = datetime.now(timezone.utc)
        db.commit()

    print('=== SENTINEL AUTOMATED MONITORING PROFILE APPROVED ===')
    print('Server ID:', server_id)
    print('OpenVPN service:', meta['vpn_service'])
    print('VPN tunnel:', meta['vpn_interface'])
    print('WAN interface:', meta['network_interface'])
    print('Session status access:', meta['status_access'])
    print('SSH key: local file present, contents not shown')
    print('Database: existing clients and servers preserved')
    print('Next step: test live health endpoint. No VPS configuration changed.')


def _discovery_subcommand(parent: argparse.ArgumentParser) -> None:
    group = parent.add_mutually_exclusive_group(required=True)
    group.add_argument('--server-id', help='Exact existing inventory server UUID')
    group.add_argument('--server-name', help='Exact existing server name')
    parent.add_argument('--client-name', help='Resolve duplicate server names within a client')
    parent.add_argument('--key-path', required=True, help='Path to local SSH private key file')
    parent.add_argument('--known-hosts-path', help='Optional pinned SSH known_hosts file')


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Configure approved SSH monitoring locally (no HTTP write API)."
    )
    subcommands = parser.add_subparsers(dest="action", required=True)
    configure_parser = subcommands.add_parser(
        "configure", help="Register or re-approve monitoring for one inventory server"
    )
    target = configure_parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--server-id", help="Inventory server UUID")
    target.add_argument("--server-name", help="Exact inventory server name")
    configure_parser.add_argument("--client-name", help="Client name if server name repeats")
    configure_parser.add_argument("--key-path", required=True, help="Local SSH private key file")
    configure_parser.add_argument("--known-hosts-path", help="Optional trusted SSH known_hosts file")
    configure_parser.add_argument("--vpn-service", required=True, help="systemd OpenVPN unit")
    configure_parser.add_argument("--vpn-interface", required=True, help="VPN tunnel interface")
    configure_parser.add_argument("--wan-interface", required=True, help="WAN network interface")
    configure_parser.add_argument("--replace", action="store_true", help="Explicit re-approval of a configured server")
    # Discovery is read-only; it never needs an approval flag.
    discovery_parser = subcommands.add_parser(
        'discover', help='Read-only SSH discovery: active OpenVPN, tunnel, WAN and status accessibility'
    )
    _discovery_subcommand(discovery_parser)
    automatic_parser = subcommands.add_parser(
        'configure-auto', help='Discover AND explicitly approve a new monitoring profile locally'
    )
    _discovery_subcommand(automatic_parser)
    automatic_parser.add_argument('--approve', action='store_true', help='Explicitly approve discovered SSH target')
    automatic_parser.add_argument('--replace', action='store_true', help='Explicitly reapprove an existing monitoring profile')
    args = parser.parse_args()
    try:
        if args.action == 'configure':
            configure(args)  # Original manual workflow preserved.
        elif args.action == 'discover':
            discover(args)
        elif args.action == 'configure-auto':
            configure_auto(args)
    except (ValueError, OSError, RuntimeError) as exc:
        print(f'STOP: {exc}', file=sys.stderr)
        return 1
    except Exception as exc:
        # SSH libraries have their own exception hierarchy; avoid dumping key paths
        # or server details in an unauthenticated terminal exception traceback.
        if exc.__class__.__module__.startswith('paramiko'):
            print(f'STOP: SSH authentication or host-key verification failed ({type(exc).__name__})', file=sys.stderr)
            return 1
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
