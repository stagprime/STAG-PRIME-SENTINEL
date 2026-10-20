"""LOCAL-ONLY, explicit enrollment of pinned administrative SSH profiles.

Example (project root; Windows CMD):
  .venv\\Scripts\\python.exe -m backend.admin_access_cli enroll --server-name EU-01 --from-monitoring --approve

Or supply --key-path ... (optional --known-hosts-path ...) for a separate admin identity.
Nothing here connects to the server or changes it. No key bytes stored in DB.
"""
from __future__ import annotations

import argparse
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select, inspect

from backend.admin_access import ServerAdminProfile, ServerAdminAudit
from backend.database import (BASE_DIR, DATA_DIR, Client, Server, ServerMonitoringConfig,
                              SessionLocal, engine)


def _local_file(value: str, label: str) -> str:
    if not value:
        raise ValueError(f'{label} required')
    file = Path(value).expanduser().resolve()
    if not file.is_file():
        raise ValueError(f'{label} file not found on backend computer')
    return str(file)


def _backup_db() -> Path:
    source = DATA_DIR / 'sentinel.db'
    if not source.is_file():
        raise ValueError('Existing sentinel database not found')
    backup_dir = BASE_DIR / 'backups'
    backup_dir.mkdir(parents=True, exist_ok=True)
    path = backup_dir / ('sentinel-before-admin-access-' + datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f') + '.db')
    try:
        with closing(sqlite3.connect(str(source))) as original, closing(sqlite3.connect(str(path))) as backup:
            original.backup(backup)
            if backup.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Backup integrity check failed')
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def enroll(args: argparse.Namespace) -> None:
    if not args.approve:
        raise ValueError('Explicit --approve is required for administrative enrollment')
    with SessionLocal() as db:
        if args.server_id:
            candidates = [db.get(Server, args.server_id)]
        else:
            query = select(Server).where(Server.name == args.server_name)
            if args.client_name:
                query = query.join(Client, Server.client_id == Client.id).where(Client.name == args.client_name)
            candidates = db.scalars(query).all()
        matches = [record for record in candidates if record is not None]
        if len(matches) != 1:
            raise ValueError('Server missing or ambiguous; supply --server-id')
        server = matches[0]
        if server.archived_at is not None:
            raise ValueError('Cannot approve archived server')
        if not server.host or not (server.ssh_username or '').strip():
            raise ValueError('Set host and SSH user in Server Inventory first')
        if not 1 <= (server.ssh_port or 22) <= 65535:
            raise ValueError('Invalid SSH port')
        monitoring = db.get(ServerMonitoringConfig, server.id) if args.from_monitoring else None
        if args.from_monitoring:
            if not monitoring or not monitoring.enabled:
                raise ValueError('Approved monitoring profile required for --from-monitoring')
            if (server.host.strip(), server.ssh_username.strip(), server.ssh_port or 22) != (
                monitoring.approved_host, monitoring.approved_ssh_username, monitoring.approved_ssh_port
            ):
                raise ValueError('Monitoring SSH pin differs from current inventory')
        key = _local_file(monitoring.ssh_key_path if monitoring else args.key_path, 'Private SSH key')
        known = (monitoring.known_hosts_path if monitoring else args.known_hosts_path)
        known = _local_file(known, 'SSH known_hosts') if known else None
        tables_exist = inspect(engine).has_table('server_admin_profiles')
        existing = db.get(ServerAdminProfile, server.id) if tables_exist else None
        if existing and not args.replace:
            raise ValueError('Admin profile already enrolled; use --replace to reapprove')

        backup = _backup_db()
        # Additive schema creation only: existing inventory and auth tables untouched.
        ServerAdminProfile.__table__.create(bind=engine, checkfirst=True)
        ServerAdminAudit.__table__.create(bind=engine, checkfirst=True)
        profile = existing or ServerAdminProfile(server_id=server.id)
        if not existing:
            db.add(profile)
        profile.enabled = True
        profile.approved_host = server.host.strip()
        profile.approved_username = server.ssh_username.strip()
        profile.approved_port = server.ssh_port or 22
        profile.private_key_path = key
        profile.known_hosts_path = known
        profile.approved_at = datetime.now(timezone.utc)
        db.commit()
        print('BACKUP SUCCESS: ' + str(backup))
        print('ADMINISTRATIVE SSH PROFILE APPROVED: ' + server.name)
        print('Pinned server ID: ' + server.id)
        print('Private key contents: never stored or printed')
        print('Remote privilege verification: PENDING (no SSH connection made)')
        print('Installation and command execution: DISABLED')


def main() -> int:
    parser = argparse.ArgumentParser(description='Local administrative SSH profile enrollment')
    subs = parser.add_subparsers(dest='action', required=True)
    p = subs.add_parser('enroll')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--server-id')
    g.add_argument('--server-name')
    p.add_argument('--client-name')
    keys = p.add_mutually_exclusive_group(required=True)
    keys.add_argument('--from-monitoring', action='store_true')
    keys.add_argument('--key-path')
    p.add_argument('--known-hosts-path')
    p.add_argument('--replace', action='store_true')
    p.add_argument('--approve', action='store_true')
    args = parser.parse_args()
    try:
        enroll(args)
    except (ValueError, OSError, RuntimeError) as exc:
        print('STOP: ' + str(exc))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
