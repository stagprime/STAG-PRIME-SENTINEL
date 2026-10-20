"""Step 40.10-E.4: reviewed, one-time, bounded diagnostic commands.

Includes ONE narrowly scoped sudo root-identity proof for approved test servers.
No arbitrary commands, installation, repairs, firewall/VPN changes, PTYs or
unrestricted sudo. Secrets stay in the backend vault and never appear in audit.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, update, inspect
from sqlalchemy.orm import Mapped, mapped_column

from backend.admin_access import (
    AdminSSHVerification, ServerAdminAudit, ServerAdminProfile,
    _identity_pin, _require_admin, _safe_profile, public_admin_verification,
)
from backend.database import Base, Server, SessionLocal, engine
from backend.read_only_jobs import _acquire, _release
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified

router = APIRouter(prefix='/api/server-operations', tags=['Reviewed SSH command preflight'])

# All remote command text is backend-owned, fixed, read-only and never
# built from user input. Results are strictly parsed/normalized below.
_COMMANDS = {
    'identity_uid': ('Remote UID', 'id -u'),
    'kernel_name': ('Kernel family', 'uname -s'),
    'root_disk': ('Root filesystem usage', 'df -Pk /'),
    'openvpn_binary': ('OpenVPN binary discovery',
        'if command -v openvpn >/dev/null 2>&1; then printf INSTALLED; else printf NOT_FOUND; fi'),
    # No user-controlled argument can be appended. sudo -S takes a password
    # strictly via a non-PTY SSH channel's stdin; never via argv or shell text.
    'sudo_root_identity': ('Sudo root identity (privileged proof)',
        "sudo -S -k -p '' -- /usr/bin/id -u"),
}
_PRIVILEGED_CHECKS = frozenset({'sudo_root_identity'})
_SUDO_CONFIRMATION = 'APPROVE SUDO READ ONLY'

_DEADLINE_SECONDS = 10.0
_MAX_OUTPUT = 1024
_PREVIEW_TTL = timedelta(seconds=90)
_guard = threading.Lock()


class ReviewedCommandPreview(Base):
    __tablename__ = 'reviewed_command_previews'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(36), ForeignKey('servers.id'), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    check_id: Mapped[str] = mapped_column(String(40), nullable=False)
    identity_pin: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ReviewedCommandRun(Base):
    __tablename__ = 'reviewed_command_runs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(36), ForeignKey('servers.id'), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    check_id: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_category: Mapped[str | None] = mapped_column(String(40), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PreviewInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    check_id: str = Field(min_length=1, max_length=40)


class ExecuteInput(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    preview_id: str = Field(min_length=36, max_length=36)
    approve: bool
    privileged_confirmation: str | None = Field(default=None, max_length=64)


def _now():
    return datetime.now(timezone.utc)


def _canonical_uuid(value: str) -> str:
    try:
        if str(UUID(value)) != value:
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise HTTPException(404, 'Command preview not found') from None


def _ensure_tables():
    # Additive tables only; no database migrations or modifications of existing rows.
    ReviewedCommandPreview.__table__.create(bind=engine, checkfirst=True)
    ReviewedCommandRun.__table__.create(bind=engine, checkfirst=True)


def _approved(db, server_id: str):
    server = db.get(Server, server_id)
    if not server or server.archived_at is not None:
        raise HTTPException(404, 'Server not found')
    profile = db.get(ServerAdminProfile, server_id)
    if not _safe_profile(server, profile)['verification_ready']:
        raise HTTPException(409, 'Approved SSH credential or inventory pin is not ready')
    evidence = public_admin_verification(server, profile)
    if not evidence or evidence.get('state') != 'success' or not evidence.get('ssh_verified'):
        raise HTTPException(409, 'Run Verify admin SSH before reviewing a command')
    return server, profile, _identity_pin(server, profile)


def _parse(check_id: str, raw: str) -> dict:
    # No raw shell output or names/IPs from a VPS are returned or stored.
    output = raw.strip()
    if check_id == 'sudo_root_identity':
        if output != '0':
            raise ValueError('root identity not verified')
        return {'effective_uid': 0, 'sudo_verified': True}
    if check_id == 'identity_uid':
        if not output.isdecimal() or len(output) > 10:
            raise ValueError('invalid uid')
        return {'uid': int(output)}
    if check_id == 'kernel_name':
        if output not in {'Linux', 'FreeBSD', 'OpenBSD', 'NetBSD'}:
            raise ValueError('unrecognized kernel')
        return {'kernel': output}
    if check_id == 'openvpn_binary':
        if output not in {'INSTALLED', 'NOT_FOUND'}:
            raise ValueError('invalid discovery')
        return {'openvpn_binary': 'present' if output == 'INSTALLED' else 'absent'}
    if check_id == 'root_disk':
        lines = output.splitlines()
        if len(lines) != 2:
            raise ValueError('malformed df')
        fields = lines[1].split()
        if len(fields) < 6 or not all(part.isdecimal() for part in fields[1:4]):
            raise ValueError('malformed df numbers')
        total, used, available = [int(n) for n in fields[1:4]]
        if not (0 < total < 10**13 and 0 <= used <= total and 0 <= available <= total):
            raise ValueError('df range')
        return {'total_mib': total // 1024, 'used_mib': used // 1024,
                'available_mib': available // 1024}
    raise ValueError('unsupported command')


def _run_ssh(config: SSHConnectionConfig, check_id: str) -> dict:
    # Keep SSH transport bounded and never request a TTY or elevation.
    client = _connect_verified(config)
    try:
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError('transport closed')
        channel = transport.open_session(timeout=5)
        try:
            channel.settimeout(2)
            channel.exec_command(_COMMANDS[check_id][1])
            output = bytearray()
            stderr_size = 0
            deadline = time.monotonic() + _DEADLINE_SECONDS
            while time.monotonic() < deadline:
                progress = False
                while channel.recv_ready():
                    chunk = channel.recv(512)
                    output.extend(chunk)
                    progress = True
                    if len(output) > _MAX_OUTPUT:
                        raise ValueError('oversize output')
                while channel.recv_stderr_ready():
                    stderr_size += len(channel.recv_stderr(256))
                    progress = True
                    if stderr_size > 256:
                        raise ValueError('oversize stderr')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    if channel.recv_exit_status() != 0:
                        raise ValueError('nonzero exit')
                    return _parse(check_id, bytes(output).decode('ascii', 'strict'))
                if not progress:
                    time.sleep(.025)
            raise TimeoutError('command deadline exceeded')
        finally:
            channel.close()
    finally:
        client.close()


class SudoProofFailure(Exception):
    """Only public error category survives. Never include secrets/raw stderr."""
    def __init__(self, category: str):
        self.category = category
        super().__init__('Privileged check unavailable')


def _run_sudo_proof(config: SSHConnectionConfig) -> dict:
    """Fixed sudo id -u proof. NEVER uses PTY or user-authored remote command.

    sudo reads SSH login password from stdin when that credential is password
    based. Private-key-only users must have passwordless sudo or enroll a
    separate sudo secret in a future milestone; we never guess a password.
    Remote raw output/stderr is checked privately, but never persisted/returned.
    """
    password_payload = None
    client = _connect_verified(config)
    try:
        if config.private_key_path.startswith('sentinel-vault:'):
            from backend.credential_vault import load_ssh_secret
            server_id = config.private_key_path.removeprefix('sentinel-vault:')
            auth_method, secret = load_ssh_secret(
                server_id, host=config.host, port=config.port, username=config.username)
            if auth_method == 'password':
                if not secret or '\n' in secret or '\r' in secret or len(secret) > 1024:
                    raise SudoProofFailure('SUDO_CREDENTIAL_UNAVAILABLE')
                password_payload = bytearray(secret.encode('utf-8') + b'\n')
            elif auth_method != 'private_key':
                raise SudoProofFailure('SUDO_CREDENTIAL_UNAVAILABLE')
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise SudoProofFailure('SSH_TRANSPORT_FAILED')
        channel = transport.open_session(timeout=5)
        try:
            # Host policy is enforced by _connect_verified. No PTY means
            # password echo/interactive prompt cannot enter the browser.
            channel.settimeout(2)
            channel.exec_command(_COMMANDS['sudo_root_identity'][1])
            if password_payload is not None:
                channel.sendall(bytes(password_payload))
            channel.shutdown_write()
            output = bytearray()
            stderr_count = 0
            deadline = time.monotonic() + _DEADLINE_SECONDS
            while time.monotonic() < deadline:
                progress = False
                while channel.recv_ready():
                    output.extend(channel.recv(256))
                    progress = True
                    if len(output) > 64:
                        raise SudoProofFailure('SUDO_OUTPUT_INVALID')
                while channel.recv_stderr_ready():
                    # Consume error stream without exposing the remote text.
                    stderr_count += len(channel.recv_stderr(256))
                    progress = True
                    if stderr_count > 1024:
                        raise SudoProofFailure('SUDO_OUTPUT_INVALID')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    if channel.recv_exit_status() != 0:
                        raise SudoProofFailure('SUDO_AUTHORIZATION_FAILED')
                    try:
                        return _parse('sudo_root_identity', bytes(output).decode('ascii','strict'))
                    except (ValueError, UnicodeError):
                        raise SudoProofFailure('SUDO_OUTPUT_INVALID') from None
                if not progress:
                    time.sleep(.025)
            raise SudoProofFailure('SUDO_PROOF_TIMEOUT')
        finally:
            channel.close()
    finally:
        if password_payload is not None:
            password_payload[:] = b'\x00' * len(password_payload)
        client.close()


def _failure_category(exc: Exception) -> str:
    if isinstance(exc, SudoProofFailure):
        return exc.category
    if isinstance(exc, AuthenticationException):
        return 'SSH_AUTHENTICATION_FAILED'
    if isinstance(exc, BadHostKeyException):
        return 'SSH_HOST_KEY_MISMATCH'
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return 'SSH_OR_COMMAND_TIMEOUT'
    if isinstance(exc, (OSError, SSHException)):
        return 'SSH_TRANSPORT_FAILED'
    return 'COMMAND_RESULT_UNAVAILABLE'


@router.get('/command-runner/catalog')
def reviewed_catalog(admin=Depends(_require_admin)):
    return {'mode': 'explicit_preview_read_only_with_scoped_sudo_proof', 'arbitrary_shell_enabled': False,
            'sudo_enabled': True, 'sudo_scope': 'fixed_root_identity_proof_only',
            'install_enabled': False, 'repair_enabled': False,
            'checks': [{'check_id': key, 'label': name, 'command': command,
                        'read_only': True, 'privileged': key in _PRIVILEGED_CHECKS,
                        'requires_preview': True}
                       for key, (name, command) in _COMMANDS.items()]}


@router.post('/servers/{server_id}/command-runner/preview')
def create_preview(server_id: str, request: PreviewInput, admin=Depends(_require_admin)):
    if request.check_id not in _COMMANDS:
        raise HTTPException(422, 'Unsupported read-only command')
    _ensure_tables()
    with SessionLocal() as db:
        server, profile, pin = _approved(db, server_id)
        if request.check_id in _PRIVILEGED_CHECKS:
            evidence = public_admin_verification(server, profile)
            if evidence is None or evidence.get('privilege_state') not in (
                    'root', 'sudo_nopasswd', 'sudo_password_required'):
                raise HTTPException(409, 'Sudo capability must be freshly verified')
        now = _now()
        item = ReviewedCommandPreview(id=str(uuid4()), server_id=server_id,
            actor_id=admin.id, check_id=request.check_id, identity_pin=pin,
            created_at=now, consumed=False)
        db.add(item)
        db.add(ServerAdminAudit(server_id=server_id, actor_id=admin.id,
                                operation=('privileged_preview' if request.check_id in _PRIVILEGED_CHECKS else 'command_preview'), result='review_requested'))
        db.commit()
        return {'preview_id': item.id, 'server_id': server_id,
                'check_id': request.check_id, 'label': _COMMANDS[request.check_id][0],
                'exact_command': _COMMANDS[request.check_id][1],
                'read_only': True, 'sudo': request.check_id in _PRIVILEGED_CHECKS,
                'privileged': request.check_id in _PRIVILEGED_CHECKS,
                'required_confirmation': (_SUDO_CONFIRMATION if request.check_id in _PRIVILEGED_CHECKS else None),
                'one_time': True,
                'expires_at_utc': (now + _PREVIEW_TTL).isoformat(),
                'requires_explicit_approval': True}


@router.post('/servers/{server_id}/command-runner/execute')
def execute_reviewed(server_id: str, request: ExecuteInput, admin=Depends(_require_admin)):
    _canonical_uuid(request.preview_id)
    if request.approve is not True:
        raise HTTPException(422, 'Explicit command approval required')
    if not _acquire(server_id):
        raise HTTPException(409, 'Another diagnostic is running for this server')
    try:
        _ensure_tables()
        with SessionLocal() as db:
            server, profile, pin = _approved(db, server_id)
            preview = db.get(ReviewedCommandPreview, request.preview_id)
            if (not preview or preview.server_id != server_id or preview.actor_id != admin.id
                or preview.identity_pin != pin or preview.check_id not in _COMMANDS
                or preview.consumed):
                raise HTTPException(409, 'Preview missing, used or server identity changed')
            created = preview.created_at
            if created.tzinfo is None: created = created.replace(tzinfo=timezone.utc)
            if created > _now() + timedelta(minutes=1) or _now() - created > _PREVIEW_TTL:
                raise HTTPException(409, 'Preview expired; review again')
            # Atomic redemption: one preview can never execute twice, even if
            # another request races in a different process.
            count = db.execute(update(ReviewedCommandPreview)
                .where(ReviewedCommandPreview.id == request.preview_id)
                .where(ReviewedCommandPreview.consumed.is_(False))
                .values(consumed=True)).rowcount
            if count != 1:
                raise HTTPException(409, 'Command approval already consumed')
            check_id = preview.check_id
            privileged = check_id in _PRIVILEGED_CHECKS
            if privileged:
                # Wrong confirmation must NOT consume approval or contact VPS.
                if request.privileged_confirmation != _SUDO_CONFIRMATION:
                    raise HTTPException(422, 'Separate privileged confirmation required')
                evidence = public_admin_verification(server, profile)
                if not evidence or evidence.get('privilege_state') not in (
                        'root','sudo_nopasswd','sudo_password_required'):
                    raise HTTPException(409,'Privileged readiness has changed')
            config = SSHConnectionConfig(host=profile.approved_host, port=profile.approved_port,
                username=profile.approved_username, private_key_path=profile.private_key_path,
                known_hosts_path=profile.known_hosts_path)
            job_id = str(uuid4())
            db.add(ServerAdminAudit(server_id=server_id, actor_id=admin.id,
                                    operation=('privileged_execute' if privileged else 'command_execute'), result='attempted'))
            db.commit()  # Reserve single use BEFORE contacting remote host.
        try:
            metrics = _run_sudo_proof(config) if privileged else _run_ssh(config, check_id)
            status, category = 'succeeded', None
        except Exception as error:
            metrics = None
            status, category = 'failed', _failure_category(error)
        with SessionLocal() as db:
            db.add(ReviewedCommandRun(id=job_id,server_id=server_id,actor_id=admin.id,
                check_id=check_id,status=status,result_json=json.dumps(metrics) if metrics else None,
                failure_category=category,completed_at=_now()))
            db.add(ServerAdminAudit(server_id=server_id,actor_id=admin.id,
                operation=('privileged_result' if privileged else 'command_result'),result=status))
            db.commit()
        return {'run_id': job_id,'server_id': server_id, 'check_id': check_id,
                'status': status, 'result': metrics, 'failure_category': category,
                'read_only': True, 'privileged': privileged, 'sudo_used': privileged,
                'audit_recorded': True,
                'remote_write_performed': False}
    finally:
        _release(server_id)


@router.get('/servers/{server_id}/command-runner/runs')
def list_reviewed_runs(server_id: str, admin=Depends(_require_admin)):
    if not inspect(engine).has_table('reviewed_command_runs'):
        return {'server_id': server_id, 'runs': []}
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if not server or server.archived_at is not None:
            raise HTTPException(404, 'Server not found')
        from sqlalchemy import select
        records = db.scalars(select(ReviewedCommandRun).where(ReviewedCommandRun.server_id == server_id)
            .order_by(ReviewedCommandRun.completed_at.desc()).limit(20)).all()
        return {'server_id': server_id, 'runs': [
            {'run_id': r.id, 'check_id': r.check_id, 'status': r.status,
             'privileged': r.check_id in _PRIVILEGED_CHECKS,
             'result': json.loads(r.result_json) if r.result_json else None,
             'failure_category': r.failure_category,
             'completed_at_utc': r.completed_at.isoformat()} for r in records]}
