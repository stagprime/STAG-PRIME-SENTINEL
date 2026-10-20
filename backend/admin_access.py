"""Step 40.2.1: administrator-only, pinned SSH capability preflight.

No arbitrary shell endpoints, passwords, key upload, sudo writes or remote repair.
The local administrator explicitly enrolls a profile using admin_access_cli.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, inspect
from sqlalchemy.orm import Mapped, mapped_column

from backend.auth_api import require_current_session
from backend.database import Base, Server, SessionLocal, engine
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified


class ServerAdminProfile(Base):
    __tablename__ = 'server_admin_profiles'
    server_id: Mapped[str] = mapped_column(ForeignKey('servers.id', ondelete='CASCADE'), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    approved_host: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_username: Mapped[str] = mapped_column(String(100), nullable=False)
    approved_port: Mapped[int] = mapped_column(Integer, nullable=False)
    private_key_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    known_hosts_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc), nullable=False)


class AdminSSHVerification(Base):
    """Recent bounded SSH verification evidence, never credentials or raw output."""
    __tablename__ = 'server_admin_verifications'
    server_id: Mapped[str] = mapped_column(ForeignKey('servers.id', ondelete='CASCADE'), primary_key=True)
    identity_pin: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[str] = mapped_column(String(20), nullable=False)
    privilege_state: Mapped[str] = mapped_column(String(40), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


VERIFICATION_TTL = timedelta(minutes=15)


def _identity_pin(server: Server, profile: ServerAdminProfile) -> str:
    """Invalidate cached success upon an inventory or credential re-enrollment change."""
    fields = [server.id, server.host, server.ssh_username, server.ssh_port,
              profile.approved_host, profile.approved_username, profile.approved_port,
              profile.private_key_path, profile.known_hosts_path, str(profile.approved_at)]
    return hashlib.sha256(json.dumps(fields, separators=(',', ':')).encode('utf-8')).hexdigest()


def public_admin_verification(server: Server, profile: ServerAdminProfile | None, *, now=None):
    """Local-only cached capability. Never makes SSH contact or grants execution."""
    if (profile is None or not _safe_profile(server, profile)['verification_ready']
            or not inspect(engine).has_table('server_admin_verifications')):
        return None
    with SessionLocal() as db:
        record = db.get(AdminSSHVerification, server.id)
        if not record or record.identity_pin != _identity_pin(server, profile):
            return None
        checked = record.checked_at
        if checked.tzinfo is None:
            checked = checked.replace(tzinfo=timezone.utc)
        reference = now or datetime.now(timezone.utc)
        if checked > reference + timedelta(minutes=1) or reference - checked > VERIFICATION_TTL:
            return {'state': 'stale', 'checked_at_utc': checked.isoformat()}
        return {'state': record.result, 'checked_at_utc': checked.isoformat(),
                'privilege_state': record.privilege_state,
                'ssh_verified': record.result == 'success',
                'administration_ready': record.result == 'success' and
                record.privilege_state in ('root', 'sudo_nopasswd'),
                'password_sudo_supported': False}


def _store_admin_verification(server_id: str, pin: str, result: str, privilege: str):
    AdminSSHVerification.__table__.create(bind=engine, checkfirst=True)
    with SessionLocal() as db:
        record = db.get(AdminSSHVerification, server_id)
        if record is None:
            record = AdminSSHVerification(server_id=server_id)
            db.add(record)
        record.identity_pin = pin
        record.result = result
        record.privilege_state = privilege
        record.checked_at = datetime.now(timezone.utc)
        db.commit()


class ServerAdminAudit(Base):
    __tablename__ = 'server_admin_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    result: Mapped[str] = mapped_column(String(40), nullable=False)
    happened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc), nullable=False)


router = APIRouter(prefix='/api/server-operations', tags=['Controlled Administrative SSH'])


def _require_admin(current=Depends(require_current_session)):
    user, _session = current
    if user.role != 'admin':
        raise HTTPException(status_code=403, detail='Administrator role required')
    return user


def _require_reader(current=Depends(require_current_session)):
    user, _session = current
    if user.role not in ('admin', 'viewer') or not user.is_active:
        raise HTTPException(status_code=403, detail='This view is limited to administrators and view accounts')
    return user


def _tables_ready() -> bool:
    existing = set(inspect(engine).get_table_names())
    return {'server_admin_profiles', 'server_admin_audit'} <= existing


@router.get('/operations-audit')
def list_operations_audit(limit: int = 80, admin=Depends(_require_reader)):
    """Recent privileged-operation audit rows. No keys, hosts, or command text."""
    from sqlalchemy import select
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail='Limit must be between 1 and 200')
    if not _tables_ready():
        return {'events': [], 'total': 0}
    with SessionLocal() as db:
        rows = db.scalars(select(ServerAdminAudit).order_by(ServerAdminAudit.id.desc()).limit(limit)).all()
        server_ids = {row.server_id for row in rows}
        names = {
            server.id: server.name
            for server in db.scalars(select(Server).where(Server.id.in_(server_ids))).all()
        } if server_ids else {}
        events = [{
            'id': row.id,
            'server_id': row.server_id,
            'server_name': names.get(row.server_id) or row.server_id[:8],
            'actor_id': row.actor_id,
            'operation': row.operation,
            'result': row.result,
            'happened_at_utc': row.happened_at.isoformat() if row.happened_at else None,
        } for row in rows]
    return {'events': events, 'total': len(events)}


def _safe_profile(server: Server, profile: ServerAdminProfile | None) -> dict[str, Any]:
    """Never return private key path, file names, or host key material."""
    pinned = bool(profile and profile.enabled
        and server.host.strip() == profile.approved_host
        and (server.ssh_username or '').strip() == profile.approved_username
        and (server.ssh_port or 22) == profile.approved_port)
    return {
        'server_id': server.id, 'server_name': server.name,
        'profile_configured': profile is not None,
        'profile_enabled': bool(profile.enabled) if profile else False,
        'inventory_pinned': pinned,
        'verification_ready': pinned and bool(profile and (
            (__import__('backend.credential_vault', fromlist=['credential_ready']).credential_ready(server.id)
             if profile.private_key_path.startswith('sentinel-vault:') else
             Path(profile.private_key_path).expanduser().is_file())))
            and bool(profile and (not profile.known_hosts_path or Path(profile.known_hosts_path).expanduser().is_file())),
        'privilege_state': 'not_checked',
    }


@router.get('/admin-profiles')
def admin_profiles(admin=Depends(_require_reader)):
    if not _tables_ready():
        return {'total': 0, 'profiles': [], 'initialized': False}
    with SessionLocal() as db:
        from sqlalchemy import select
        servers = db.scalars(select(Server).where(Server.archived_at.is_(None)).order_by(Server.name)).all()
        results = []
        for s in servers:
            profile = db.get(ServerAdminProfile, s.id)
            entry = _safe_profile(s, profile)
            entry['recent_verification'] = public_admin_verification(s, profile)
            results.append(entry)
    return {'total': len(results), 'profiles': results, 'initialized': True}


def _simple_command(client: Any, command: str, *, max_output: int = 64) -> tuple[int, str]:
    """Only called with two hardcoded read-only commands; output stays private."""
    _stdin, stdout, stderr = client.exec_command(command, timeout=10)
    try:
        out = stdout.read(max_output + 1)
        err = stderr.read(512)
        code = stdout.channel.recv_exit_status()
        if len(out) > max_output or len(err) > 512:
            raise RuntimeError('Unexpected SSH command output size')
        return code, out.decode('utf-8', errors='replace').strip()
    finally:
        stdout.close()
        stderr.close()


def _sudo_requires_password(client: Any) -> bool:
    """Detect password-required sudo from a fixed, NONINTERACTIVE probe.

    Never send a password, request a TTY or relay the raw stderr to the browser.
    An ambiguous result is classified as unavailable, never elevated-ready.
    """
    _stdin, stdout, stderr = client.exec_command('sudo -n -l', timeout=10)
    try:
        output = stdout.read(513)
        diagnostic = stderr.read(513)
        code = stdout.channel.recv_exit_status()
        if len(output) > 512 or len(diagnostic) > 512 or code == 0:
            return False
        normalized = diagnostic.lower()
        return b'password' in normalized and (b'required' in normalized or b'necessary' in normalized)
    finally:
        stdout.close()
        stderr.close()


def verify_administrative_ssh(config: SSHConnectionConfig) -> dict[str, Any]:
    """Read-only SSH identity check with honest sudo capability reporting.

    Password-required sudo is detected, but NEVER exercised or considered
    approved for automatic privileged execution.
    """
    client = _connect_verified(config)
    try:
        code, uid = _simple_command(client, 'id -u')
        if code != 0 or not uid.isdecimal():
            raise RuntimeError('Remote identity check failed')
        if uid == '0':
            privilege = 'root'
        else:
            sudo_code, sudo_uid = _simple_command(client, 'sudo -n id -u')
            privilege = ('sudo_nopasswd' if sudo_code == 0 and sudo_uid == '0'
                         else 'sudo_password_required' if _sudo_requires_password(client)
                         else 'sudo_unavailable')
        return {
            'ssh_verified': True,
            'host_key_verified': True,
            'privilege_state': privilege,
            'administration_ready': privilege in ('root', 'sudo_nopasswd'),
        }
    finally:
        client.close()


def _audit(db, *, server_id: str, actor_id: str, result: str) -> int:
    item = ServerAdminAudit(server_id=server_id, actor_id=actor_id,
        operation='capability_verify', result=result)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item.id


@router.post('/servers/{server_id}/admin/verify')
def verify_server_administration(server_id: str, admin=Depends(_require_admin)):
    if not _tables_ready():
        raise HTTPException(status_code=503, detail='Admin SSH registry not initialized. Enroll a profile locally.')

    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if not server or server.archived_at is not None:
            raise HTTPException(status_code=404, detail='Server not found')
        profile = db.get(ServerAdminProfile, server_id)
        if not profile or not profile.enabled:
            raise HTTPException(status_code=409, detail='Administrative SSH profile not approved')
        status = _safe_profile(server, profile)
        if not status['inventory_pinned']:
            raise HTTPException(status_code=409, detail='Server inventory changed; local reapproval required')
        if not status['verification_ready']:
            raise HTTPException(status_code=503, detail='Administrative SSH profile local files unavailable')
        config = SSHConnectionConfig(host=profile.approved_host,
            port=profile.approved_port, username=profile.approved_username,
            private_key_path=profile.private_key_path,
            known_hosts_path=profile.known_hosts_path)
        server_name = server.name
        pin = _identity_pin(server, profile)
        audit_id = _audit(db, server_id=server_id, actor_id=admin.id, result='attempted')

    result = None
    try:
        result = verify_administrative_ssh(config)
        audit_result = ('verified' if result['administration_ready'] else
                        'sudo_password_required' if result['privilege_state'] == 'sudo_password_required'
                        else 'insufficient_privileges')
    except BadHostKeyException:
        audit_result = 'host_key_failed'
        issue_code = 'SSH_HOST_KEY_MISMATCH'
    except AuthenticationException:
        audit_result = 'authentication_failed'
        issue_code = 'SSH_AUTHENTICATION_FAILED'
    except (SSHException, TimeoutError, OSError, FileNotFoundError, RuntimeError, ValueError):
        audit_result = 'connection_failed'
        issue_code = 'SSH_CONNECTION_OR_CAPABILITY_FAILED'
    # The attempt was recorded before network use; never transmit raw exception messages.
    with SessionLocal() as db:
        entry = db.get(ServerAdminAudit, audit_id)
        if entry:
            entry.result = audit_result
            db.commit()
    _store_admin_verification(server_id, pin, 'success' if result is not None else 'error',
                              result['privilege_state'] if result else 'unverified')
    if result is None:
        auth_hint = (
            'The SSH account or enrolled credential was not accepted. '
            'Linux usernames are case-sensitive (use tariq not Tariq). '
            'Confirm username, key, and whether this host needs key-only or key+password.'
        )
        raise HTTPException(status_code=502, detail={
            'code': issue_code,
            'message': {
                'SSH_HOST_KEY_MISMATCH': 'SSH host key differs from the trusted fingerprint. Verify identity out of band; never auto-accept.',
                'SSH_AUTHENTICATION_FAILED': auth_hint,
                'SSH_CONNECTION_OR_CAPABILITY_FAILED': 'SSH connection or bounded capability check failed. Check service reachability, host trust, and server-side SSH policy.',
            }[issue_code],
        })
    return {'server_id': server_id, 'server_name': server_name,
        'source': 'verified_administrative_ssh', **result,
        'note': 'Password-required sudo is not automatic admin execution approval. No sudo password was sent and command execution remains disabled.'}
