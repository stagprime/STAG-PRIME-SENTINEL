"""Step 40.10B. Encrypted, endpoint-pinned admin SSH credentials (LOCAL DEV ONLY).

No secret is logged or returned to clients. An external Fernet master key is
mandatory. The Windows installer creates one in the user's LOCALAPPDATA with
restricted NTFS permissions, never within the source tree or SQLite backup.
Linux deployment requires the operator to supply SENTINEL_VAULT_MASTER_KEY
through a dedicated secret manager. Master key loss prevents recovery.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import DateTime, ForeignKey, String, LargeBinary, Integer, inspect
from sqlalchemy.orm import Mapped, mapped_column

from backend.admin_access import ServerAdminAudit, ServerAdminProfile, _require_admin
from backend.database import Base, Server, SessionLocal, engine

router = APIRouter(prefix='/api/server-operations', tags=['Secure SSH credential enrollment'])


class EncryptedSSHCredential(Base):
    __tablename__ = 'encrypted_ssh_credentials'
    server_id: Mapped[str] = mapped_column(ForeignKey('servers.id', ondelete='CASCADE'), primary_key=True)
    auth_method: Mapped[str] = mapped_column(String(32), nullable=False)
    approved_host: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_port: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_username: Mapped[str] = mapped_column(String(100), nullable=False)
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    credential_version: Mapped[str] = mapped_column(String(36), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CredentialEnrollment(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    # password = SSH password only
    # private_key = key only
    # key_and_password = key + SSH login password (hosts that require both)
    auth_method: str = Field(pattern=r'^(password|private_key|key_and_password)$')
    # Kept out of Pydantic representations and response serialization.
    secret: SecretStr
    # Optional: only used when secret is an encrypted PuTTY .ppk.
    ppk_passphrase: SecretStr | None = None
    # Required when auth_method is key_and_password (SSH account password after/with key).
    login_password: SecretStr | None = None


_DUAL_FMT = 'sentinel-dual-v1'


def pack_key_and_password(private_key: str, login_password: str) -> str:
    """Serialize dual-auth material for a single Fernet blob. Never log the result."""
    return json.dumps(
        {'fmt': _DUAL_FMT, 'private_key': private_key, 'password': login_password},
        separators=(',', ':'),
        ensure_ascii=False,
    )


def unpack_key_and_password(raw: str) -> tuple[str, str]:
    try:
        data = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError('Dual SSH credential corrupt') from exc
    if not isinstance(data, dict) or data.get('fmt') != _DUAL_FMT:
        raise RuntimeError('Dual SSH credential format unsupported')
    key = data.get('private_key')
    password = data.get('password')
    if not isinstance(key, str) or not key.strip() or not isinstance(password, str) or not password:
        raise RuntimeError('Dual SSH credential incomplete')
    if '\x00' in key or '\x00' in password:
        raise RuntimeError('Dual SSH credential invalid')
    return key, password


def _master_key():
    provided = os.environ.get('SENTINEL_VAULT_MASTER_KEY', '').strip()
    if provided:
        raw = provided.encode('ascii')
    elif os.name == 'nt':
        home = os.environ.get('LOCALAPPDATA', '')
        if not home:
            raise RuntimeError('Credential vault not configured')
        keyfile = Path(home) / 'StagPrimeSentinel' / 'credentials.master.key'
        if not keyfile.is_file():
            raise RuntimeError('Credential vault not configured')
        raw = keyfile.read_bytes().strip()
    else:
        raise RuntimeError('Credential vault not configured')
    try:
        return Fernet(raw)
    except (ValueError, TypeError) as exc:
        raise RuntimeError('Credential vault key invalid') from exc


def _ensure_tables():
    EncryptedSSHCredential.__table__.create(bind=engine, checkfirst=True)


def credential_status(server_id: str) -> dict:
    if not inspect(engine).has_table('encrypted_ssh_credentials'):
        return {'configured': False, 'auth_method': None, 'host_pinned': False}
    with SessionLocal() as db:
        item = db.get(EncryptedSSHCredential, server_id)
        server = db.get(Server, server_id)
        if not server or not item:
            return {'configured': False, 'auth_method': None, 'host_pinned': False}
        pinned = bool(server.archived_at is None and server.host == item.approved_host
            and (server.ssh_port or 22) == item.approved_port
            and (server.ssh_username or '') == item.approved_username)
        return {'configured': True, 'auth_method': item.auth_method,
                'host_pinned': pinned}


def credential_ready(server_id: str) -> bool:
    """Local encrypted credential ready, not proof of live SSH connectivity."""
    try:
        _master_key()
    except RuntimeError:
        return False
    state = credential_status(server_id)
    return bool(state['configured'] and state['host_pinned'])


def credential_public_health(server_id: str) -> dict:
    """Safe, read-only vault persistence check. Never returns credential bytes.

    'vault_accessible' proves authenticated decryption under the current master
    key, not that the SSH credential works on the remote host. This is deliberately
    separated from live SSH verification and never initiates a connection.
    """
    status = credential_status(server_id)
    status.update({'vault_accessible': False, 'last_updated_at_utc': None})
    if not status['configured']:
        return status
    with SessionLocal() as db:
        item = db.get(EncryptedSSHCredential, server_id)
        if item is None:
            return status
        ciphertext = item.encrypted_secret
        updated_at = item.updated_at
    status['last_updated_at_utc'] = (updated_at.replace(tzinfo=timezone.utc)
        if updated_at.tzinfo is None else updated_at.astimezone(timezone.utc)).isoformat()
    if status['host_pinned']:
        try:
            # Decrypt and immediately discard locally; never log or serialize it.
            _master_key().decrypt(ciphertext)
            status['vault_accessible'] = True
        except (RuntimeError, InvalidToken, ValueError):
            pass
    return status


def load_ssh_secret(server_id: str, *, host: str, port: int, username: str):
    """Access only for a server ID whose stored endpoint still matches."""
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        cred = db.get(EncryptedSSHCredential, server_id) if server else None
        if (not server or server.archived_at is not None or not cred
            or server.host != host or (server.ssh_port or 22) != port
            or (server.ssh_username or '') != username
            or cred.approved_host != host or cred.approved_port != port
            or cred.approved_username != username):
            raise RuntimeError('SSH credential approval changed')
        ciphertext = cred.encrypted_secret
        method = cred.auth_method
    try:
        raw = _master_key().decrypt(ciphertext).decode('utf-8')
    except (InvalidToken, UnicodeError) as exc:
        raise RuntimeError('SSH credential unavailable') from exc
    if method not in ('private_key', 'password', 'key_and_password'):
        raise RuntimeError('Unsupported authentication mode')
    return method, raw


def _configured_origin_hosts() -> set[str]:
    hosts: set[str] = set()
    for item in os.environ.get('SENTINEL_ALLOWED_ORIGINS', '').split(','):
        host = urlsplit(item.strip()).hostname if item.strip() else None
        if host:
            hosts.add(host)
    return hosts


def _local_only(request: Request):
    """Admin routes only. Local dev stays gated; a configured site origin may enroll."""
    origin = request.headers.get('origin', '')
    origin_host = urlsplit(origin).hostname if origin else None
    if origin_host and origin_host in _configured_origin_hosts():
        return
    if request.client is None or request.client.host not in ('127.0.0.1', '::1', 'testclient'):
        raise HTTPException(403, 'Credential enrollment is limited to the local development server')
    if origin_host and origin_host not in ('127.0.0.1', 'localhost'):
        raise HTTPException(403, 'Credential enrollment requires localhost browser origin')
    if os.name != 'nt' and os.environ.get('SENTINEL_CREDENTIAL_DEV_ALLOW_LOCAL') != '1':
        raise HTTPException(403, 'Credential enrollment requires explicit local development mode')


def normalize_private_key_material(raw: str, passphrase: str = '') -> str:
    """Accept OpenSSH/PEM or PuTTY .ppk; return OpenSSH private key text."""
    value = raw.replace('\r\n', '\n').replace('\r', '\n').strip().lstrip('\ufeff')
    if not value or '\x00' in value:
        raise ValueError('Invalid authentication value')
    if len(value.encode('utf-8')) > 256 * 1024:
        raise ValueError('Private key file is too large (max 256 KB)')
    if len(value) < 80:
        raise ValueError('Private key content is too short')
    looks_like_ppk = (
        'PuTTY-User-Key-File' in value
        or ('Private-MAC:' in value and 'Public-Lines:' in value and 'Private-Lines:' in value)
    )
    if looks_like_ppk:
        try:
            from backend.ppk_convert import ppk_to_openssh
            converted = ppk_to_openssh(value, passphrase or '')
            if not converted or 'PRIVATE KEY' not in converted:
                raise ValueError('Converter returned empty result')
            value = converted.replace('\r\n', '\n').replace('\r', '\n').strip()
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(
                'Could not convert PuTTY .ppk. Use the full private .ppk file (not .pub). '
                f'Detail: {type(exc).__name__}: {exc}'
            ) from exc
    first = value.split('\n', 1)[0]
    if re.match(r'^(ssh-(?:rsa|ed25519|dss|ecdsa)|ecdsa-sha2-|sk-ssh-)\s', first):
        raise ValueError(
            'This is a PUBLIC key (.pub). Upload the PRIVATE key file '
            '(OpenSSH / .pem / PuTTY .ppk) — not the .pub file.'
        )
    if not re.match(
        r'^-----BEGIN (?:(?:RSA|DSA|EC|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----',
        value,
        re.MULTILINE,
    ):
        raise ValueError(
            'Unrecognized key file. Need OpenSSH/PEM PRIVATE key or full PuTTY .ppk '
            '(File-2 or File-3).'
        )
    return value


def persist_credential(server_id: str, method: str, secret: str, actor_id: str) -> dict:
    """Encrypt and pin credential for a server. Does not verify live SSH."""
    try:
        cipher = _master_key().encrypt(secret.encode('utf-8'))
    except RuntimeError as exc:
        raise RuntimeError('Secure credential vault unavailable') from exc
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if not server or server.archived_at is not None:
            raise LookupError('Server not found')
        if not server.ssh_username or not server.ssh_username.strip():
            raise ValueError('Set an SSH username on the inventory record first')
        if not {'server_admin_profiles', 'server_admin_audit'}.issubset(inspect(engine).get_table_names()):
            raise RuntimeError('Administrative registry not initialized')
        _ensure_tables()
        cred = db.get(EncryptedSSHCredential, server_id)
        if cred is None:
            cred = EncryptedSSHCredential(server_id=server_id)
            db.add(cred)
        cred.auth_method = method
        cred.approved_host = server.host
        cred.approved_port = server.ssh_port or 22
        cred.approved_username = server.ssh_username
        cred.encrypted_secret = cipher
        cred.credential_version = str(uuid4())
        cred.updated_at = datetime.now(timezone.utc)
        profile = db.get(ServerAdminProfile, server_id)
        if profile is None:
            profile = ServerAdminProfile(server_id=server_id)
            db.add(profile)
        profile.enabled = True
        profile.approved_host = server.host
        profile.approved_port = server.ssh_port or 22
        profile.approved_username = server.ssh_username
        profile.private_key_path = 'sentinel-vault:' + server_id
        profile.known_hosts_path = None
        profile.approved_at = datetime.now(timezone.utc)
        db.add(ServerAdminAudit(server_id=server_id, actor_id=actor_id,
                                operation='credential_enroll', result='enrolled_unverified'))
        db.commit()
    return {'server_id': server_id, 'configured': True, 'auth_method': method,
            'verification_required': True, 'host_key_verified': False}


def enroll_private_key_from_path(server_id: str, key_path: Path | str, actor_id: str,
                                 passphrase: str = '') -> dict:
    path = Path(key_path)
    if not path.is_file():
        raise FileNotFoundError(f'Key file not found: {path}')
    raw = path.read_text(encoding='utf-8', errors='replace')
    openssh = normalize_private_key_material(raw, passphrase)
    return persist_credential(server_id, 'private_key', openssh, actor_id)


@router.get('/local-default-key')
def get_local_default_key(admin=Depends(_require_admin)):
    from backend.local_default_key import describe_default_key
    return describe_default_key()


class LocalDefaultKeySet(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    path: str = Field(min_length=3, max_length=512)


@router.post('/local-default-key')
def set_local_default_key(data: LocalDefaultKeySet, request: Request, admin=Depends(_require_admin)):
    _local_only(request)
    from backend.local_default_key import describe_default_key, set_default_key_path
    try:
        set_default_key_path(data.path)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return describe_default_key()


class EnrollFromLocalDefault(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    ppk_passphrase: SecretStr | None = None


@router.post('/servers/{server_id}/credentials/from-local-default')
def enroll_from_local_default(server_id: str, data: EnrollFromLocalDefault, request: Request,
                              admin=Depends(_require_admin)):
    """Enroll using the remembered local path (e.g. D:\\stagvpn_server_Private_Key.ppk)."""
    _local_only(request)
    from backend.local_default_key import get_default_key_path
    path = get_default_key_path()
    if path is None:
        raise HTTPException(
            404,
            'No default local key path saved. Set it once (D:\\….ppk), then reuse this button.',
        )
    passphrase = data.ppk_passphrase.get_secret_value() if data.ppk_passphrase is not None else ''
    try:
        return enroll_private_key_from_path(server_id, path, admin.id, passphrase)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from None
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from None


@router.get('/servers/{server_id}/credentials/status')
def get_credential_status(server_id: str, admin=Depends(_require_admin)):
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if not server or server.archived_at is not None:
            raise HTTPException(404, 'Server not found')
    from backend.local_default_key import describe_default_key
    return {'server_id': server_id, **credential_public_health(server_id),
            'verification_required': True,
            'local_default_key': describe_default_key(),
            'note': 'Enrolled is not verified SSH connectivity.'}


def _validate_login_password(value: str) -> str:
    if not value or '\x00' in value or '\n' in value or '\r' in value:
        raise HTTPException(422, 'Login password format invalid')
    if len(value) > 1024 or len(value) < 1:
        raise HTTPException(422, 'Login password length invalid')
    return value


@router.post('/servers/{server_id}/credentials')
def enroll_credential(server_id: str, data: CredentialEnrollment, request: Request,
                      admin=Depends(_require_admin)):
    _local_only(request)
    method, value = data.auth_method, data.secret.get_secret_value()
    if not value or '\x00' in value:
        raise HTTPException(422, 'Invalid authentication value')
    if method == 'password':
        if len(value) > 1024 or len(value) < 8 or '\n' in value or '\r' in value:
            raise HTTPException(422, 'Password length or format invalid')
    elif method == 'private_key':
        passphrase = (
            data.ppk_passphrase.get_secret_value()
            if getattr(data, 'ppk_passphrase', None) is not None else ''
        )
        try:
            value = normalize_private_key_material(value, passphrase)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
    else:  # key_and_password — key establishes identity; password completes login
        login = data.login_password.get_secret_value() if data.login_password is not None else ''
        login = _validate_login_password(login)
        passphrase = (
            data.ppk_passphrase.get_secret_value()
            if getattr(data, 'ppk_passphrase', None) is not None else ''
        )
        try:
            key_material = normalize_private_key_material(value, passphrase)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        value = pack_key_and_password(key_material, login)
    try:
        return persist_credential(server_id, method, value, admin.id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from None
