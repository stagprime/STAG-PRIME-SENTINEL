"""Step 43: protected optional OpenVPN client profile vault.

Monitoring the OpenVPN server DOES NOT use uploaded client profiles. Upload is
restricted to local-development administrators until a reviewed production
secret-ingestion service is available. Profiles are encrypted at rest, never
returned to the browser or executed. No subprocess/VPN connection is started.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, mapped_column

from backend.admin_access import ServerAdminAudit, _require_admin
from backend.credential_vault import _local_only, _master_key
from backend.database import Base, Server, SessionLocal, engine

router = APIRouter(prefix='/api/server-operations', tags=['Protected OpenVPN client profiles'])
MAX_PROFILE_BYTES = 128 * 1024
MAX_PROFILES_PER_SERVER = 50
NAME_RE = re.compile(r'^[\w .()-]{1,80}$', re.ASCII)
# Imported client profiles are NOT run as programs. Reject directives that
# could execute commands, load plugins, or expose a local control socket if
# later handed to a VPN client. Fail closed until a separate execution review.
FORBIDDEN = frozenset('''up down down-pre route-up route-pre-down ipchange script-security plugin plugin-auto-load management management-client management-external-key management-external-cert config include client-connect client-disconnect learn-address tls-verify auth-user-pass-verify tls-crypt-v2-verify setenv-safe cd daemon log log-append status writepid chroot script-internal push peer-fingerprint'''.split())
PATH_OPTIONS = {'ca', 'cert', 'key', 'pkcs12', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'crl-verify', 'auth-user-pass'}
INLINE_TAGS = frozenset(('ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'pkcs12'))


class EncryptedOpenVPNProfile(Base):
    __tablename__ = 'encrypted_openvpn_client_profiles'
    __table_args__ = (UniqueConstraint('server_id', 'display_name', name='uq_openvpn_profile_name_per_server'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_id: Mapped[str] = mapped_column(ForeignKey('servers.id', ondelete='CASCADE'), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(80), nullable=False)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    content_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    requires_external_files: Mapped[bool] = mapped_column(nullable=False, default=False)
    has_inline_private_key: Mapped[bool] = mapped_column(nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ProfileImport(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    name: str = Field(min_length=1, max_length=80)
    ovpn_content: SecretStr = Field(max_length=MAX_PROFILE_BYTES)
    vpn_username: str | None = Field(default=None, max_length=128)
    vpn_password: SecretStr | None = None


def validate_client_profile(content: str) -> dict:
    if not isinstance(content, str) or not content or '\x00' in content:
        raise ValueError('Invalid OpenVPN profile format')
    normalized = content.replace('\r\n', '\n')
    if '\r' in normalized:
        raise ValueError('Invalid OpenVPN line endings')
    size = len(content.encode('utf-8'))
    if size > MAX_PROFILE_BYTES or size < 12:
        raise ValueError('OpenVPN profile must be between 12 bytes and 128 KiB')
    active = None
    blocks = set()
    flags = set()
    external = False
    for raw in normalized.splitlines():
        line = raw.strip()
        if active:
            if line == f'</{active}>':
                active = None
            elif line.startswith('</') or (line.startswith('<') and line.endswith('>')):
                raise ValueError('Invalid nested OpenVPN profile block')
            continue
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('<') and line.endswith('>'):
            tag = line[1:-1]
            if tag not in INLINE_TAGS or tag in blocks:
                raise ValueError('Unsupported or duplicate OpenVPN inline block')
            active = tag
            blocks.add(tag)
            continue
        if line.startswith('</'):
            raise ValueError('Unmatched OpenVPN profile block')
        directive = line.split(None, 1)[0].lower()
        if directive in FORBIDDEN or not re.fullmatch(r'[a-z][a-z0-9-]{0,48}', directive):
            raise ValueError('Disallowed OpenVPN client configuration directive')
        flags.add(directive)
        if directive in PATH_OPTIONS:
            # External references are supported for archive/inspection only.
            # They cannot be executed or automatically resolved by Sentinel.
            if directive == 'auth-user-pass':
                if len(line.split()) > 1:
                    raise ValueError('External authentication file is not permitted')
            elif len(line.split()) > 1:
                external = True
    if active:
        raise ValueError('Unclosed OpenVPN profile block')
    if 'client' not in flags and 'tls-client' not in flags:
        raise ValueError('Only OpenVPN client profiles are accepted')
    if 'remote' not in flags:
        raise ValueError('Profile requires a remote server directive')
    # No embedded key/credentials will ever be returned in metadata.
    return {'content_bytes': size, 'requires_external_files': external,
            'has_inline_private_key': 'key' in blocks or 'pkcs12' in blocks}


def _metadata(item: EncryptedOpenVPNProfile) -> dict:
    return {'id':item.id, 'server_id':item.server_id, 'name':item.display_name,
            'content_bytes':item.content_bytes, 'requires_external_files':item.requires_external_files,
            'has_inline_private_key':item.has_inline_private_key,
            'created_at_utc':item.created_at.isoformat() if item.created_at else None,
            'connection_test_status':'not_supported', 'profile_content_returned':False}


def _existing_server(db, server_id):
    server = db.get(Server, server_id)
    if not server or server.archived_at is not None:
        raise HTTPException(404, 'Server not found')
    return server


@router.get('/servers/{server_id}/openvpn-profiles')
def list_openvpn_profiles(server_id: str, actor=Depends(_require_admin)):
    with SessionLocal() as db:
        _existing_server(db, server_id)
        # create if needed only after admin authentication and server existence
        EncryptedOpenVPNProfile.__table__.create(bind=engine, checkfirst=True)
        entries = db.scalars(select(EncryptedOpenVPNProfile).where(
            EncryptedOpenVPNProfile.server_id == server_id).order_by(EncryptedOpenVPNProfile.created_at.desc())).all()
        return {'server_id':server_id, 'profiles':[_metadata(x) for x in entries],
                'monitoring_requires_profile': False}


@router.post('/servers/{server_id}/openvpn-profiles', status_code=201)
def import_openvpn_profile(server_id: str, data: ProfileImport, request: Request, actor=Depends(_require_admin)):
    _local_only(request)
    name = data.name.strip()
    if not NAME_RE.fullmatch(name):
        raise HTTPException(422, 'Profile name contains unsupported characters')
    if bool(data.vpn_username) != bool(data.vpn_password):
        raise HTTPException(422, 'VPN username and password must both be supplied or both omitted')
    if data.vpn_username and (not data.vpn_username.strip() or '\x00' in data.vpn_username):
        raise HTTPException(422, 'Invalid VPN username')
    pwd = data.vpn_password.get_secret_value() if data.vpn_password else None
    if pwd is not None and (not pwd or len(pwd)>1024 or '\x00' in pwd or '\n' in pwd or '\r' in pwd):
        raise HTTPException(422, 'Invalid VPN password')
    content = data.ovpn_content.get_secret_value()
    try:
        meta = validate_client_profile(content)
        encrypted = _master_key().encrypt(json.dumps({'ovpn':content, 'username':data.vpn_username,
                                    'password':pwd},separators=(',',':')).encode('utf-8'))
    except (ValueError, UnicodeError):
        raise HTTPException(422, 'Invalid or unsupported OpenVPN client profile') from None
    except RuntimeError:
        raise HTTPException(503, 'Encrypted profile vault unavailable') from None
    with SessionLocal.begin() as db:
        _existing_server(db, server_id)
        EncryptedOpenVPNProfile.__table__.create(bind=engine, checkfirst=True)
        count = db.query(EncryptedOpenVPNProfile).filter_by(server_id=server_id).count()
        if count >= MAX_PROFILES_PER_SERVER:
            raise HTTPException(409, 'Maximum profile count reached for server')
        if db.scalar(select(EncryptedOpenVPNProfile.id).where(
            EncryptedOpenVPNProfile.server_id==server_id,
            EncryptedOpenVPNProfile.display_name==name)):
            raise HTTPException(409, 'Profile name already exists')
        item = EncryptedOpenVPNProfile(id=str(uuid4()),server_id=server_id,display_name=name,
            encrypted_payload=encrypted, content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            content_bytes=meta['content_bytes'], requires_external_files=meta['requires_external_files'],
            has_inline_private_key=meta['has_inline_private_key'], created_at=datetime.now(timezone.utc))
        db.add(item)
        db.add(ServerAdminAudit(server_id=server_id, actor_id=actor.id,
                                operation='openvpn_profile_import', result='encrypted_stored'))
        db.flush()
        response = _metadata(item)
    return response


@router.delete('/servers/{server_id}/openvpn-profiles/{profile_id}')
def remove_openvpn_profile(server_id: str, profile_id: str, request: Request, actor=Depends(_require_admin)):
    _local_only(request)
    with SessionLocal.begin() as db:
        _existing_server(db, server_id)
        EncryptedOpenVPNProfile.__table__.create(bind=engine, checkfirst=True)
        item = db.get(EncryptedOpenVPNProfile, profile_id)
        if not item or item.server_id != server_id:
            raise HTTPException(404, 'Profile not found')
        db.delete(item)
        db.add(ServerAdminAudit(server_id=server_id, actor_id=actor.id,
                                operation='openvpn_profile_remove', result='removed'))
    return {'server_id': server_id,'deleted':True}
