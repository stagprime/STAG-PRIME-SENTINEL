"""Stag Prime Sentinel — explicitly approved TWO-VPS local development inventory cleanup.

Non-networking, direct SQLite operation; cannot modify any real VPS. Must stop
FastAPI and monitoring worker before --apply. The DB, not source ZIP, is backed up.
Protected accounts, client grants, encrypted credentials and SSH profiles for the
TWO specified test VPS are never changed. Historical admin/security audit rows are
kept (including any old server IDs); the full original DB is kept in a backup.

Do not use on a production Sentinel database.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / 'data' / 'sentinel.db'
BACKUPS = ROOT / '.sentinel_backups'
KEEP = {
    'sentinel-test-key': ('161.118.172.56', 22, 'opc'),
    'sentinel-test-password': ('152.67.0.221', 22, 'sentineladmin'),
}
# Server-owned, volatile/fixture/test data. Security/admin audit is intentionally
# NOT in this list: audit records must not be silently rewritten or erased.
SERVER_DEPENDENT = (
    'server_monitoring_configs', 'server_admin_verifications',
    'onboarding_scans', 'openvpn_setup_preflights',
    'reviewed_command_previews', 'reviewed_command_runs',
    'controlled_diagnostic_jobs', 'sentinel_telemetry_samples',
    'sentinel_monitor_states', 'sentinel_monitor_incidents',
    'sentinel_session_transitions',
)
# These records contain secret/authorization material. Only remove for obsolete
# demo servers; explicitly preserve for both tested VPSes.
SERVER_ACCESS = ('server_admin_profiles', 'encrypted_ssh_credentials', 'encrypted_openvpn_client_profiles')
IMMUTABLE_AUDIT = ('server_admin_audit', 'auth_audit_events')
KNOWN_FK_USER_TABLES = ('auth_users', 'auth_sessions', 'auth_client_grants')
DEMO_CLIENT_NAMES = frozenset({'Stag VPN', 'Stag Prime Demo Client', 'Sentinel Test Company', 'Demo Client'})


def _tables(con):
    return {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _ids(con, table: str, ids: list[str]):
    if not ids:
        return 0
    return con.execute(f'DELETE FROM "{table}" WHERE server_id IN ({",".join("?" for _ in ids)})', ids).rowcount


def _read_inventory(con):
    if 'servers' not in _tables(con):
        raise RuntimeError('Missing servers table; no changes made.')
    return list(con.execute('SELECT id, name, host, ssh_port, ssh_username, archived_at, client_id FROM servers ORDER BY name, id'))


def _plan(con):
    servers = _read_inventory(con)
    preserved = {}
    for name, (host, port, account) in KEEP.items():
        matches = [s for s in servers if s[1] == name]
        if len(matches) != 1:
            raise RuntimeError(f'Expected exactly one {name}; found {len(matches)}. Database unchanged.')
        s = matches[0]
        if (s[2], s[3], s[4], s[5]) != (host, port, account, None):
            raise RuntimeError(f'Identity mismatch for {name}; refusing cleanup. Database unchanged.')
        if not isinstance(s[0], str) or not s[0]:
            raise RuntimeError('Missing immutable server ID.')
        preserved[name] = s[0]
    targets = [s for s in servers if s[0] not in preserved.values()]
    if len({s[0] for s in servers}) != len(servers):
        raise RuntimeError('Duplicate server IDs detected.')
    known = _tables(con)
    server_owned = set(SERVER_DEPENDENT + SERVER_ACCESS + IMMUTABLE_AUDIT)
    # Fail closed if a newer schema adds a server-scoped table that cleanup has
    # not been reviewed for. Also inspect actual FK relationships, not name only.
    exceptions = {'servers'}
    for table in sorted(known):
        if table.startswith('sqlite_') or table in exceptions or table in IMMUTABLE_AUDIT:
            continue
        cols = {r[1] for r in con.execute(f'PRAGMA table_info("{table}")')}
        refs_server = any(row[2] == 'servers' for row in con.execute(f'PRAGMA foreign_key_list("{table}")'))
        if ('server_id' in cols or refs_server) and table not in server_owned:
            raise RuntimeError(f'Unknown server-scoped table: {table}. Stop and review schema before cleanup.')
    return preserved, targets


def _backup(con, backup_dir: Path):
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup_path = backup_dir / 'sentinel-before-test-inventory-reset.db'
    # Online SQLite backup API: includes WAL safely, unlike file copy.
    to = sqlite3.connect(str(backup_path))
    try:
        con.backup(to)
        if to.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Backup SQLite integrity check failed; no changes made.')
    finally:
        to.close()
    digest = hashlib.sha256(backup_path.read_bytes()).hexdigest()
    (backup_dir / 'SHA256.txt').write_text(f'{digest}  {backup_path.name}\n', encoding='utf-8')
    return backup_path, digest


def run(db_path: Path, *, apply: bool = False, backup_root: Path | None = None):
    path = db_path.resolve()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError('Existing regular SQLite database not found; refusing to initialize a new one.')
    if not apply:
        con = sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True)
    else:
        con = sqlite3.connect(f'{path.as_uri()}?mode=rw', uri=True, timeout=2)
    try:
        if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Source SQLite integrity check failed.')
        preserved, targets = _plan(con)
        print('PRESERVE exact test VPSes:')
        for name in KEEP: print('  ', name, KEEP[name][0], '(SSH credentials remain intact)')
        print('REMOVE from inventory (including archived):')
        for s in targets: print('  ', s[1], s[2])
        print('No VPS/network/firewall/SSH commands; authenticated user records are retained.')
        if apply and not targets:
            print('ALREADY CLEAN — exactly two preserved VPSes; no telemetry or credentials altered.')
            return {'preserved': 2, 'removed': 0, 'already_clean': True}
        if not apply:
            print('DRY RUN PASS; no database changes. Use --apply only after stopping the backend AND worker.')
            return {'preserved': len(preserved), 'remove': len(targets), 'dry_run': True}
        # First backup before any changes. The user has approved the scoped purge,
        # but a separate --apply is required as a deliberate local confirmation.
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup_root = backup_root or BACKUPS
        backup_dir = backup_root / f'Step42_TestInventoryReset_{stamp}_{uuid.uuid4().hex[:7]}'
        backup_path, digest = _backup(con, backup_dir)
        print('Verified SQLite backup:', backup_path)
        print('SHA256:', digest)
        known = _tables(con)
        con.execute('PRAGMA foreign_keys=ON')
        con.execute('BEGIN IMMEDIATE')
        try:
            second_keep, second_targets = _plan(con)
            if second_keep != preserved or [x[0] for x in second_targets] != [x[0] for x in targets]:
                raise RuntimeError('Concurrent inventory edit detected. Rolled back.')
            to_drop = [x[0] for x in targets]
            all_ids = to_drop + list(preserved.values())
            removed_counts = {}
            # Clear old telemetry and stale verification evidence on both test VPSes.
            # Does not clear credential vault or approved SSH host profiles on kept VPSes.
            for name in SERVER_DEPENDENT:
                if name in known:
                    removed_counts[name] = _ids(con, name, all_ids)
            # Remove access records for retired demo VPSes only.
            for name in SERVER_ACCESS:
                if name in known:
                    removed_counts[name] = _ids(con, name, to_drop)
            if to_drop:
                con.execute(f'DELETE FROM servers WHERE id IN ({",".join("?" for _ in to_drop)})', to_drop)
            # Old transient inventory monitoring label no longer means live health.
            con.execute('UPDATE servers SET monitoring_status=? WHERE id IN (?, ?)', ('not_connected', *preserved.values()))
            # Clear worker heartbeat so dashboard never labels prior test runs as live.
            if 'sentinel_monitor_worker_pulse' in known:
                con.execute('DELETE FROM sentinel_monitor_worker_pulse')
            # Delete orphaned known DEMO clients only if no user/grant/server refers to them.
            if {'clients','auth_users','auth_client_grants'} <= known:
                for client_id, client_name in con.execute('SELECT id,name FROM clients').fetchall():
                    if client_name not in DEMO_CLIENT_NAMES:
                        continue
                    if con.execute('SELECT 1 FROM servers WHERE client_id=? LIMIT 1', (client_id,)).fetchone(): continue
                    if con.execute('SELECT 1 FROM auth_users WHERE client_id=? LIMIT 1', (client_id,)).fetchone(): continue
                    if con.execute('SELECT 1 FROM auth_client_grants WHERE client_id=? LIMIT 1', (client_id,)).fetchone(): continue
                    con.execute('DELETE FROM clients WHERE id=?', (client_id,))
            remaining = _read_inventory(con)
            if len(remaining) != 2 or {s[1] for s in remaining} != set(KEEP):
                raise RuntimeError('Post-cleanup inventory mismatch; transaction rolled back.')
            fk_errors = con.execute('PRAGMA foreign_key_check').fetchall()
            if fk_errors:
                raise RuntimeError('Foreign key check failed; transaction rolled back. Review the backup.')
            con.commit()
        except BaseException:
            con.rollback()
            raise
        print('TEST INVENTORY RESET PASS — 2 preserved,', len(targets), 'removed.')
        print('Preserved historical security audit rows; clean monitoring history starts on next approved enrollment.')
        return {'preserved': 2, 'removed': len(targets), 'backup': str(backup_path), 'sha256': digest, 'counts': removed_counts}
    finally:
        con.close()


def main():
    parser = argparse.ArgumentParser(description='Stag Prime Sentinel — approved local two-test-VPS cleanup')
    parser.add_argument('--apply', action='store_true', help='Requires backend/worker stopped. Make integrity-verified DB backup, then clean.')
    args = parser.parse_args()
    try:
        run(DEFAULT_DB, apply=args.apply)
    except (RuntimeError, sqlite3.Error, OSError) as exc:
        print('STOP —', str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
