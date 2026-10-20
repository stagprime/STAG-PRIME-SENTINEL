"""One-click onboard: create server + vault secret + SSH verify + VPN discover + enroll."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import select

from backend.admin_access import (
    ServerAdminAudit, ServerAdminProfile, _require_admin,
    verify_server_administration,
)
from backend.credential_vault import CredentialEnrollment, _local_only, enroll_credential
from backend.database import Client, Server, ServerMonitoringConfig, SessionLocal
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified
from backend.vpn_fleet import _DISCOVERY_SCRIPT, validate_fleet_discovery

router = APIRouter(prefix='/api/server-operations', tags=['Quick onboard'])
_SAFE_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$')


class QuickOnboardRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    client_id: str = Field(min_length=8, max_length=36)
    name: str = Field(min_length=2, max_length=150)
    host: str = Field(min_length=3, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str = Field(min_length=1, max_length=100)
    auth_method: str = Field(pattern=r'^(password|private_key|key_and_password)$')
    secret: SecretStr
    # Required when auth_method is key_and_password (SSH login password with key).
    login_password: SecretStr | None = None
    ppk_passphrase: SecretStr | None = None
    country: str | None = Field(default=None, max_length=100)
    location: str | None = Field(default=None, max_length=150)
    provider: str | None = Field(default=None, max_length=150)
    consent_monitoring: bool = True

    @field_validator('host')
    @classmethod
    def clean_host(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or any(ch.isspace() for ch in cleaned):
            raise ValueError('Invalid host')
        return cleaned


def _default_suggestion(discovery: dict) -> dict:
    suggestions = discovery.get('suggestions') or []
    if suggestions:
        return suggestions[0]
    return {
        'protocol': 'openvpn',
        'vpn_service': 'openvpn-server@server',
        'vpn_interface': 'tun0',
        'label': 'Default OpenVPN',
    }


def _run_discovery(profile: ServerAdminProfile) -> dict:
    config = SSHConnectionConfig(
        host=profile.approved_host,
        port=profile.approved_port,
        username=profile.approved_username,
        private_key_path=profile.private_key_path,
        known_hosts_path=profile.known_hosts_path,
    )
    client = _connect_verified(config)
    try:
        cmd = (
            "python3 - <<'SENTINEL_VPN_FLEET_DISCOVERY_V1'\n"
            + _DISCOVERY_SCRIPT
            + "\nSENTINEL_VPN_FLEET_DISCOVERY_V1\n"
        )
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=20)
        raw = stdout.read(120_001)
        stderr.read(4096)
        if stdout.channel.recv_exit_status() != 0 or len(raw) > 120_000:
            return {'protocols': [], 'suggestions': [], 'network_interface': None}
        return validate_fleet_discovery(json.loads(raw.decode('utf-8')))
    finally:
        client.close()


@router.post('/quick-onboard')
def quick_onboard(data: QuickOnboardRequest, request: Request, actor=Depends(_require_admin)):
    """Operator flow: paste SSH key or root password → full monitoring enrollment."""
    _local_only(request)
    if data.consent_monitoring is not True:
        raise HTTPException(422, detail='Monitoring consent required')

    with SessionLocal.begin() as db:
        if db.get(Client, data.client_id) is None:
            raise HTTPException(404, detail='Client not found')
        clash = db.scalar(select(Server.id).where(
            Server.host == data.host, Server.archived_at.is_(None)).limit(1))
        if clash:
            raise HTTPException(409, detail='An active server with this host already exists')
        server = Server(
            client_id=data.client_id,
            name=data.name.strip(),
            host=data.host,
            ssh_port=data.ssh_port,
            ssh_username=data.ssh_username.strip(),
            country=data.country,
            location=data.location,
            provider=data.provider,
            monitoring_status='pending_onboard',
        )
        db.add(server)
        db.flush()
        server_id = server.id

    if data.auth_method == 'key_and_password' and data.login_password is None:
        raise HTTPException(422, detail='login_password required with SSH key for dual-auth hosts')
    enroll_credential(
        server_id,
        CredentialEnrollment(
            auth_method=data.auth_method,
            secret=data.secret,
            login_password=data.login_password,
            ppk_passphrase=data.ppk_passphrase,
        ),
        request,
        actor,
    )

    # Raises HTTPException on SSH failure — that aborts onboard intentionally.
    verify = verify_server_administration(server_id, actor)

    discovery: dict = {'protocols': [], 'suggestions': [], 'network_interface': None}
    with SessionLocal() as db:
        profile = db.get(ServerAdminProfile, server_id)
        if profile is None:
            raise HTTPException(500, detail='Admin profile missing after enrollment')
        try:
            discovery = _run_discovery(profile)
        except Exception:
            discovery = {'protocols': [], 'suggestions': [], 'network_interface': None}

    suggestion = _default_suggestion(discovery)
    network = discovery.get('network_interface') or 'eth0'
    if not isinstance(network, str) or not _SAFE_NAME.match(network):
        network = 'eth0'

    with SessionLocal.begin() as db:
        server = db.get(Server, server_id)
        profile = db.get(ServerAdminProfile, server_id)
        if not server or not profile:
            raise HTTPException(500, detail='Onboard state incomplete')
        row = db.get(ServerMonitoringConfig, server_id)
        if row is None:
            row = ServerMonitoringConfig(server_id=server_id)
            db.add(row)
        row.enabled = True
        row.approved_host = server.host
        row.approved_ssh_username = server.ssh_username
        row.approved_ssh_port = server.ssh_port or 22
        row.ssh_key_path = profile.private_key_path
        row.known_hosts_path = profile.known_hosts_path
        row.vpn_service = suggestion['vpn_service']
        row.vpn_interface = suggestion['vpn_interface']
        row.network_interface = network
        row.approved_at = datetime.now(timezone.utc)
        server.monitoring_status = 'enrolled'
        db.add(ServerAdminAudit(
            server_id=server_id, actor_id=actor.id,
            operation='quick_onboard', result='enrolled',
        ))

    from backend.monitoring_engine import kick_first_collection
    kick_first_collection(server_id)

    return {
        'server_id': server_id,
        'name': data.name.strip(),
        'host': data.host,
        'ssh_verified': True,
        'monitoring_enabled': True,
        'protocol': suggestion.get('protocol'),
        'vpn_service': suggestion['vpn_service'],
        'vpn_interface': suggestion['vpn_interface'],
        'discovery': discovery,
        'verify': {
            'administration_ready': verify.get('administration_ready'),
            'privilege_state': verify.get('privilege_state'),
        },
        'next': 'First health + sessions collection started. Keep START_ALL running for continuous updates.',
    }
