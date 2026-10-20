"""Step 40.10: explicit, audited, host-key-verified, read-only onboarding scan.

A newly registered inventory host is NOT permission to contact that host. Only a
pinned admin SSH identity can be probed, by an authenticated administrator POST.
Results are small, sanitized and scoped by the existing onboarding/preflight API.
Never classifies a missing VPN service as definitely safe for installation.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import DateTime, String, Text, inspect
from sqlalchemy.orm import Mapped, mapped_column

from backend.admin_access import ServerAdminAudit, ServerAdminProfile, _require_admin, _safe_profile
from backend.database import Base, Server, SessionLocal, engine
from backend.read_only_jobs import _acquire, _release, _bounded_output
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified

router = APIRouter(prefix='/api/server-operations', tags=['Verified onboarding classification'])
TTL = timedelta(minutes=15)

# Hard-coded read-only commands. No user-controlled shell strings or arguments.
REMOTE_SCRIPT = r'''import json, pathlib, re, subprocess

def call(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=3, check=False)
        return {'ok': p.returncode == 0, 'output': p.stdout[:3500]}
    except (OSError, subprocess.TimeoutExpired):
        return {'ok': False, 'output': ''}

os_id = 'unknown'
os_major = ''
try:
    release = pathlib.Path('/etc/os-release').read_text(encoding='utf-8')[:4000]
    for line in release.splitlines():
        if line.startswith('ID='):
            os_id = line[3:].strip('"\'').lower()
        elif line.startswith('VERSION_ID='):
            os_major = line[11:].strip('"\'').split('.')[0]
except (OSError, UnicodeError):
    pass

if os_id in ('ol', 'rhel', 'centos', 'rocky', 'almalinux', 'fedora'):
    p = call(['rpm', '-q', '--quiet', 'openvpn'])
    package_state = 'installed' if p['ok'] else 'absent'
elif os_id in ('ubuntu', 'debian'):
    p = call(['dpkg-query', '-W', '-f=${db:Status-Abbrev}', 'openvpn'])
    package_state = 'installed' if p['ok'] and p['output'].startswith('ii ') else 'absent' if not p['ok'] else 'unknown'
else:
    package_state = 'unknown'

units = call(['systemctl', 'list-units', '--all', '--type=service', '--no-legend', '--no-pager', 'openvpn*'])
unit_files = call(['systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager', 'openvpn*'])
active_count = 0
unit_count = 0
if units['ok']:
    for line in units['output'].splitlines():
        parts = line.lstrip('● ').split()
        if parts and re.fullmatch(r'openvpn[A-Za-z0-9@_.-]*\.service', parts[0]):
            unit_count += 1
            if len(parts) >= 4 and parts[2:4] == ['active', 'running']:
                active_count += 1
if unit_files['ok']:
    for line in unit_files['output'].splitlines():
        parts = line.split()
        if parts and re.fullmatch(r'openvpn[A-Za-z0-9@_.-]*\.service', parts[0]):
            unit_count += 1

print(json.dumps({'os_id':os_id,'os_major':os_major,'package_state':package_state,
    'systemd_checked':units['ok'] and unit_files['ok'],
    'service_units_found':min(unit_count,99),'active_services_found':min(active_count,99)},
    separators=(',',':')))
'''
COMMAND = "python3 - <<'SENTINEL_READONLY_ONBOARDING_V1'\n" + REMOTE_SCRIPT + "\nSENTINEL_READONLY_ONBOARDING_V1\n"


class OnboardingScan(Base):
    __tablename__ = 'onboarding_scans'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    pinned_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(18), nullable=False)
    public_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def _pin(server: Server, profile: ServerAdminProfile) -> str:
    blob = json.dumps([server.id, profile.approved_host, profile.approved_username,
       profile.approved_port, profile.private_key_path, profile.known_hosts_path,
       str(profile.approved_at)], separators=(',', ':'))
    return hashlib.sha256(blob.encode('utf-8')).hexdigest()


def classify(payload: object) -> dict:
    """Fail closed on incomplete OS, package or service evidence."""
    if not isinstance(payload, dict):
        raise ValueError('Invalid scan structure')
    os_id = payload.get('os_id')
    major = payload.get('os_major')
    pkg = payload.get('package_state')
    systemd = payload.get('systemd_checked')
    units = payload.get('service_units_found')
    active = payload.get('active_services_found')
    if (not isinstance(os_id, str) or not re.fullmatch(r'[a-z0-9_-]{1,30}', os_id)
        or not isinstance(major, str) or not re.fullmatch(r'[0-9]{0,3}', major)
        or pkg not in ('installed', 'absent', 'unknown') or not isinstance(systemd, bool)
        or type(units) is not int or type(active) is not int
        or not 0 <= active <= units <= 99):
        raise ValueError('Malformed remote scan')
    if os_id not in ('ol', 'rhel', 'centos', 'rocky', 'almalinux', 'fedora', 'ubuntu', 'debian') or not systemd or pkg == 'unknown':
        status, advice = 'needs_review', 'Package or service state could not be verified; review before installing.'
    elif active > 0:
        status, advice = 'openvpn_service_active', 'OpenVPN appears active. Verify configuration and live status source before declaring sessions healthy.'
    elif pkg == 'installed' or units > 0:
        status, advice = 'openvpn_detected', 'OpenVPN components exist; inspect configuration and status before any installation.'
    else:
        status, advice = 'fresh_candidate', 'No OpenVPN package or systemd service found; confirm other deployments and backups before installation.'
    return {'classification': status, 'os_family': os_id, 'os_major': major,
            'openvpn_package': pkg, 'systemd_checked': systemd, 'service_units_found': units,
            'active_services_found': active, 'next_step': advice,
            'read_only': True, 'installation_authorized': False}


def _tables() -> bool:
    return 'onboarding_scans' in inspect(engine).get_table_names()


def _ensure_table():
    OnboardingScan.__table__.create(bind=engine, checkfirst=True)


def public_scan(server: Server, profile: ServerAdminProfile | None, *, now=None):
    """Only the most recent scan for unchanged, approved server identity."""
    if not profile or not _safe_profile(server, profile)['verification_ready'] or not _tables():
        return None
    with SessionLocal() as db:
        from sqlalchemy import select
        snap = db.scalars(select(OnboardingScan).where(OnboardingScan.server_id == server.id)
            .order_by(OnboardingScan.checked_at.desc())).first()
        if not snap or snap.pinned_fingerprint != _pin(server, profile):
            return None
        checked = snap.checked_at
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        checked_iso = checked.isoformat()
        if checked > (now or datetime.now(timezone.utc)) + timedelta(minutes=1) or (now or datetime.now(timezone.utc)) - checked > TTL:
            return {'state': 'stale', 'checked_at_utc': checked_iso}
        if snap.state != 'success':
            return {'state': 'error', 'checked_at_utc': checked_iso}
        try:
            result = classify(json.loads(snap.public_json or 'null'))
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        return {'state': 'success', 'checked_at_utc': checked_iso, **result}


def scan_host(config: SSHConnectionConfig) -> dict:
    client = _connect_verified(config)
    try:
        raw = _bounded_output(client, COMMAND)
        return classify(json.loads(raw))
    finally:
        client.close()


@router.post('/servers/{server_id}/onboarding/scan')
def request_onboarding_scan(server_id: str, admin=Depends(_require_admin)):
    if not {'server_admin_profiles', 'server_admin_audit'}.issubset(inspect(engine).get_table_names()):
        raise HTTPException(503, 'Administrative profile registry is not initialized')
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None or server.archived_at is not None:
            raise HTTPException(404, 'Server not found')
        profile = db.get(ServerAdminProfile, server_id)
        if not _safe_profile(server, profile)['inventory_pinned']:
            raise HTTPException(409, 'SSH profile requires administrator enrollment or reapproval')
        if not _safe_profile(server, profile)['verification_ready']:
            raise HTTPException(503, 'Approved private key or host trust is unavailable')
    if not _acquire(server_id):
        raise HTTPException(409, 'Another server diagnostic is running')
    audit_id = None
    try:
        with SessionLocal() as db:
            server = db.get(Server, server_id)
            profile = db.get(ServerAdminProfile, server_id)
            if not server or server.archived_at is not None or not _safe_profile(server, profile)['verification_ready']:
                raise HTTPException(409, 'Approval changed; repeat enrollment')
            pin = _pin(server, profile)
            config = SSHConnectionConfig(host=profile.approved_host, port=profile.approved_port,
                                        username=profile.approved_username, private_key_path=profile.private_key_path,
                                        known_hosts_path=profile.known_hosts_path)
            audit = ServerAdminAudit(server_id=server_id, actor_id=admin.id,
                operation='onboarding_scan', result='attempted')
            db.add(audit)
            db.commit()
            db.refresh(audit)
            audit_id = audit.id
        state, scan = 'error', None
        try:
            scan = scan_host(config)
            state = 'success'
        except Exception:
            pass  # Never disclose raw remote output, remote paths, or exception details.
        _ensure_table()
        with SessionLocal() as db:
            item = OnboardingScan(id=str(uuid4()), server_id=server_id,
                pinned_fingerprint=pin, state=state,
                public_json=json.dumps({
                    'os_id': scan['os_family'], 'os_major': scan['os_major'],
                    'package_state': scan['openvpn_package'], 'systemd_checked': scan['systemd_checked'],
                    'service_units_found': scan['service_units_found'],
                    'active_services_found': scan['active_services_found']
                }) if scan else None, checked_at=datetime.now(timezone.utc))
            db.add(item)
            record = db.get(ServerAdminAudit, audit_id)
            if record:
                record.result = 'verified' if scan else 'scan_failed'
            db.commit()
        if not scan:
            raise HTTPException(502, 'Read-only SSH scan failed; verify approved identity and SSH trust')
        return {'server_id': server_id, 'state': 'success', **scan}
    finally:
        _release(server_id)
