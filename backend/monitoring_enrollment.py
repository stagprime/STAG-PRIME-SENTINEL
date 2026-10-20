"""Step 42A: explicit, scoped, audited *read-only* monitoring enrollment.

Administrator opts in after host-key-pinned SSH verification. When vpn_* fields
are "auto", enrollment discovers the active OpenVPN unit/interface over SSH once,
then the background worker keeps live health + sessions without further operator steps.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import inspect

from backend.admin_access import (
    ServerAdminAudit, ServerAdminProfile,
    _require_admin, public_admin_verification, _safe_profile,
)
from backend.credential_vault import _local_only, credential_ready
from backend.database import Server, ServerMonitoringConfig, SessionLocal, engine
from backend.ssh_monitor import SSHConnectionConfig

router = APIRouter(prefix='/api/server-operations', tags=['Monitoring enrollment'])

_SAFE_TOKEN = r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}'
_SAFE_OR_AUTO = rf'^(?:auto|{_SAFE_TOKEN})$'


class MonitoringEnrollment(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    consent: bool
    vpn_service: str = Field(default='auto', pattern=_SAFE_OR_AUTO)
    vpn_interface: str = Field(default='auto', pattern=_SAFE_OR_AUTO)
    network_interface: str = Field(default='auto', pattern=_SAFE_OR_AUTO)


def _existing_state(db, server_id: str):
    server = db.get(Server, server_id)
    if not server or server.archived_at is not None:
        raise HTTPException(404, detail='Server not found')
    profile = db.get(ServerAdminProfile, server_id)
    if not profile or not _safe_profile(server, profile)['verification_ready']:
        raise HTTPException(409, detail='Configure an approved, inventory-pinned SSH credential first')
    if profile.private_key_path != 'sentinel-vault:' + server_id or not credential_ready(server_id):
        raise HTTPException(409, detail='Enroll an encrypted SSH credential in Server Inventory first')
    recent = public_admin_verification(server, profile)
    if not recent or recent.get('state') != 'success' or not recent.get('ssh_verified'):
        raise HTTPException(409, detail='Recent host-key-verified SSH confirmation required')
    return server, profile, recent


def _resolve_vpn_targets(
    *,
    host: str,
    port: int,
    username: str,
    private_key_path: str,
    known_hosts_path: str | None,
    data: MonitoringEnrollment,
) -> tuple[str, str, str]:
    need = data.vpn_service == 'auto' or data.vpn_interface == 'auto' or data.network_interface == 'auto'
    if not need:
        return data.vpn_service, data.vpn_interface, data.network_interface
    # Prefer multi-protocol fleet discovery (OpenVPN / WireGuard / IKEv2).
    from types import SimpleNamespace
    from backend.quick_onboard import _default_suggestion, _run_discovery
    pinned = SimpleNamespace(
        approved_host=host,
        approved_username=username,
        approved_port=port,
        private_key_path=private_key_path,
        known_hosts_path=known_hosts_path,
    )
    try:
        discovered = _run_discovery(pinned)
    except Exception as exc:
        raise HTTPException(
            502,
            detail=f'Auto-discovery failed; set vpn service/interface explicitly. ({type(exc).__name__})',
        ) from None
    suggestion = _default_suggestion(discovered)
    service = data.vpn_service if data.vpn_service != 'auto' else (
        suggestion.get('vpn_service') or 'openvpn-server@server'
    )
    iface = data.vpn_interface if data.vpn_interface != 'auto' else (
        suggestion.get('vpn_interface') or 'tun0'
    )
    network = data.network_interface if data.network_interface != 'auto' else (
        discovered.get('network_interface') or 'eth0'
    )
    if not re.fullmatch(_SAFE_TOKEN, service) or not re.fullmatch(_SAFE_TOKEN, iface) or not re.fullmatch(_SAFE_TOKEN, network):
        raise HTTPException(422, detail='Discovered VPN identifiers were not safe to enroll')
    return service, iface, network


@router.post('/servers/{server_id}/monitoring/enroll')
def enroll_monitoring(server_id: str, data: MonitoringEnrollment, request: Request,
                      actor=Depends(_require_admin)):
    _local_only(request)
    if data.consent is not True:
        raise HTTPException(422, detail='Administrator must explicitly approve continuous read-only polling')
    with SessionLocal() as db:
        if not inspect(engine).has_table('server_admin_verifications'):
            raise HTTPException(409, detail='Verify SSH first')
        _server, profile, _recent = _existing_state(db, server_id)
        host = profile.approved_host
        port = profile.approved_port
        username = profile.approved_username
        private_key_path = profile.private_key_path
        known_hosts_path = profile.known_hosts_path

    vpn_service, vpn_interface, network_interface = _resolve_vpn_targets(
        host=host,
        port=port,
        username=username,
        private_key_path=private_key_path,
        known_hosts_path=known_hosts_path,
        data=data,
    )

    with SessionLocal.begin() as db:
        server, profile, _recent = _existing_state(db, server_id)
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
        row.vpn_service = vpn_service
        row.vpn_interface = vpn_interface
        row.network_interface = network_interface
        row.approved_at = datetime.now(timezone.utc)
        db.add(ServerAdminAudit(server_id=server_id, actor_id=actor.id,
            operation='monitoring_enroll', result='approved_read_only'))

    from backend.monitoring_engine import kick_first_collection
    kick_first_collection(server_id)

    return {
        'server_id': server_id,
        'monitoring_enabled': True,
        'ssh_verified': True,
        'vpn_service': vpn_service,
        'vpn_interface': vpn_interface,
        'network_interface': network_interface,
        'vpn_sessions_status': 'pending_first_collection',
        'health_status': 'pending_first_collection',
        'note': 'Enrollment approved; first health + sessions collection started immediately.',
    }


@router.post('/servers/{server_id}/monitoring/disable')
def disable_monitoring(server_id: str, request: Request, actor=Depends(_require_admin)):
    _local_only(request)
    with SessionLocal.begin() as db:
        server = db.get(Server, server_id)
        if not server or server.archived_at is not None:
            raise HTTPException(404, detail='Server not found')
        target = db.get(ServerMonitoringConfig, server_id)
        if target is None:
            raise HTTPException(409, detail='Monitoring was not enrolled')
        target.enabled = False
        db.add(ServerAdminAudit(server_id=server_id, actor_id=actor.id,
            operation='monitoring_disable', result='disabled'))
    return {'server_id': server_id, 'monitoring_enabled': False}
