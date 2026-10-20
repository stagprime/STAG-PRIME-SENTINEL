"""Step 37.7: explicit, local-operator, read-only SSH discovery for approved servers.

Invocation requires CLI confirmation. No HTTP action can initiate SSH. No sudo,
remote file writes, provisioning or service restarts. Reports exclude SSH keys,
VPN credentials, file paths, VPN client details and raw exception text.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from backend.database import Client, DATA_DIR, Server, ServerMonitoringConfig, SessionLocal
from backend.monitoring_discovery import discover_ssh_server

REPORT_DIR = DATA_DIR / 'onboarding_discovery'
MAX_REPORT_AGE_SECONDS = 15 * 60
UUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def _utc_now():
    return datetime.now(timezone.utc)


def _profile_fingerprint(server: Server, profile: ServerMonitoringConfig) -> str:
    # Hash used only to invalidate reports when approved SSH identity or credentials change.
    # Never send this fingerprint or the input fields to the browser.
    fields = [server.id, profile.approved_host, profile.approved_ssh_username,
              str(profile.approved_ssh_port), profile.ssh_key_path or '',
              profile.known_hosts_path or '', str(profile.approved_at or '')]
    return hashlib.sha256(json.dumps(fields, separators=(',', ':')).encode()).hexdigest()


def locally_authorized(server: Server, profile: ServerMonitoringConfig | None) -> bool:
    """Only SSH endpoints already pinned and approved by the local operator."""
    if server.archived_at is not None or profile is None or not profile.enabled:
        return False
    if not server.host or not server.ssh_username:
        return False
    if (server.host.strip() != profile.approved_host or
        server.ssh_username.strip() != profile.approved_ssh_username or
        (server.ssh_port or 22) != profile.approved_ssh_port):
        return False
    if not 1 <= profile.approved_ssh_port <= 65535:
        return False
    if not profile.ssh_key_path or not Path(profile.ssh_key_path).expanduser().is_file():
        return False
    if profile.known_hosts_path and not Path(profile.known_hosts_path).expanduser().is_file():
        return False
    return True


def _report_path(server_id: str) -> Path:
    if not UUID_PATTERN.fullmatch(server_id):
        raise ValueError('Invalid server UUID')
    return REPORT_DIR / (server_id.lower() + '.json')


def _safe_observation(data: dict[str, Any]) -> dict[str, Any]:
    """Allowlist validated discovery fields; never return paths or secrets."""
    fields = ('hostname', 'vpn_service', 'vpn_interface', 'vpn_ipv4',
              'network_interface', 'status_access', 'ready_for_approval')
    result = {key: data.get(key) for key in fields}
    result['active_openvpn_services'] = data.get('active_openvpn_services', [])
    result['warnings'] = data.get('warnings', [])
    return result


def _write_report(server_id: str, data: dict[str, Any]) -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(REPORT_DIR, 0o700)
    except OSError:
        pass  # Windows ACLs are used on Windows; do not weaken them.
    target = _report_path(server_id)
    content = json.dumps(data, ensure_ascii=True, separators=(',', ':'))
    temp = target.with_suffix('.tmp')
    try:
        with temp.open('w', encoding='utf-8') as fp:
            fp.write(content)
        try:
            os.chmod(temp, 0o600)
        except OSError:
            pass
        temp.replace(target)
    finally:
        temp.unlink(missing_ok=True)


def probe_server(server: Server, profile: ServerMonitoringConfig, *, discovery=None) -> dict[str, Any]:
    """Return sanitized record; refuses SSH before local approval checks pass."""
    if not locally_authorized(server, profile):
        raise ValueError('SSH profile is not locally approved or no longer matches inventory')
    discovery = discover_ssh_server if discovery is None else discovery
    record = {
        'server_id': server.id,
        'approved_fingerprint': _profile_fingerprint(server, profile),
        'checked_at_utc': _utc_now().isoformat(),
        'state': 'error',
        'observation': None,
    }
    try:
        observed = discovery(
            host=profile.approved_host,
            username=profile.approved_ssh_username,
            port=profile.approved_ssh_port,
            private_key_path=profile.ssh_key_path,
            known_hosts_path=profile.known_hosts_path,
        )
        # Do not expose raw exceptions (can include sensitive paths),
        # and accept only the allowlisted fields from validated discover_ssh_server.
        from backend.monitoring_discovery import validate_discovery
        cleaned = validate_discovery(observed)
        record['state'] = 'success'
        record['observation'] = _safe_observation(cleaned)
    except Exception:
        record['state'] = 'error'
        record['observation'] = None
    return record


def public_snapshot(server: Server, profile: ServerMonitoringConfig | None,
                    *, now: datetime | None = None) -> dict[str, Any] | None:
    """Serve only snapshots for still-approved hosts. No remote SSH is performed."""
    if not locally_authorized(server, profile):
        return None
    assert profile is not None
    try:
        data = json.loads(_report_path(server.id).read_text(encoding='utf-8'))
        if not isinstance(data, dict) or data.get('server_id') != server.id:
            return None
        if data.get('approved_fingerprint') != _profile_fingerprint(server, profile):
            return None
        checked = datetime.fromisoformat(data['checked_at_utc'])
        if checked.tzinfo is None:
            return None
        age = ((now or _utc_now()) - checked).total_seconds()
        if age < -60 or age > MAX_REPORT_AGE_SECONDS:
            return {'state': 'stale', 'checked_at_utc': data['checked_at_utc']}
        if data.get('state') not in ('success', 'error'):
            return None
        observed = data.get('observation') if data['state'] == 'success' else None
        # Files may be edited locally. Only explicitly public values survive.
        result: dict[str, Any] = {'state': data['state'], 'checked_at_utc': data['checked_at_utc']}
        if isinstance(observed, dict):
            result['observation'] = {key: observed.get(key) for key in (
                'hostname', 'vpn_service', 'vpn_interface', 'vpn_ipv4',
                'network_interface', 'status_access', 'ready_for_approval', 'warnings')}
        return result
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        return None


def probe_selected(*, server_id: str | None = None, all_approved: bool = False,
                   session_factory=None, discovery=None, save=True) -> list[dict[str, Any]]:
    if bool(server_id) == bool(all_approved):
        raise ValueError('Choose exactly one of --server-id or --all-approved')
    session_factory = SessionLocal if session_factory is None else session_factory
    with session_factory() as db:
        stmt = select(Server).where(Server.archived_at.is_(None)).order_by(Server.name)
        if server_id:
            stmt = stmt.where(Server.id == server_id)
        servers = db.scalars(stmt).all()
        if server_id and not servers:
            raise ValueError('Active server ID not found')
        results = []
        for server in servers:
            profile = db.get(ServerMonitoringConfig, server.id)
            if not locally_authorized(server, profile):
                results.append({'server_name': server.name, 'state': 'skipped_not_approved'})
                continue
            assert profile is not None
            result = probe_server(server, profile, discovery=discovery)
            if save:
                _write_report(server.id, result)
            results.append({'server_name': server.name,
                            'state': result['state'],
                            'service': (result['observation'] or {}).get('vpn_service'),
                            'status_access': (result['observation'] or {}).get('status_access')})
        return results


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Approved-server read-only OpenVPN discovery (local CLI only)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--all-approved', action='store_true', help='Probe all eligible approved servers')
    group.add_argument('--server-id', help='Probe exactly one existing inventory server UUID')
    parser.add_argument('--confirm-read-only', action='store_true', help='Explicit consent to SSH read-only collection')
    args = parser.parse_args(argv)
    if not args.confirm_read_only:
        parser.error('Specify --confirm-read-only to contact approved SSH hosts')
    try:
        results = probe_selected(server_id=args.server_id, all_approved=args.all_approved)
    except ValueError as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        return 2
    print('=== SENTINEL READ-ONLY DISCOVERY ===')
    for result in results:
        print(f"{result['server_name']}: {result['state']} | "
              f"service: {result.get('service') or '-'} | "
              f"status file access: {result.get('status_access') or '-'}")
    print('No remote installation, sudo, firewall changes or service restarts performed.')
    return 0 if all(r['state'] != 'error' for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
