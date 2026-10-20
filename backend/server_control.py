"""Server control: preview catalog + allowlisted VPN service execution.

Remote execution is limited to systemd start/stop/restart of the *enrolled*
VPN unit (OpenVPN / wg-quick / strongSwan). No arbitrary shell. No reboot.
"""
from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import inspect

from backend.admin_access import ServerAdminAudit, ServerAdminProfile, _require_admin, _safe_profile
import threading

from backend.credential_vault import _local_only
from backend.database import Server, ServerMonitoringConfig, SessionLocal, engine
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified

_control_guard = threading.Lock()
_control_running: set[str] = set()


def _control_acquire(server_id: str) -> bool:
    with _control_guard:
        if server_id in _control_running:
            return False
        _control_running.add(server_id)
        return True


def _control_release(server_id: str) -> None:
    with _control_guard:
        _control_running.discard(server_id)


ActionName = Literal[
    'restart', 'memory', 'housekeeping',
    'vpn-start', 'vpn-stop', 'vpn-restart',
]

# Only fixed, human-readable metadata; no command strings or user-supplied shell.
_ACTIONS = (
    ('restart', 'Restart server', 'high', 'Host reboot remains disabled in this build — use your cloud console.'),
    ('memory', 'Memory health & safe reclaim', 'low', 'Inspect pressure; never force-drop Linux filesystem caches.'),
    ('housekeeping', 'Safe cache & log housekeeping', 'medium', 'Review bounded targets and retention; preserve credentials and audit logs.'),
    ('vpn-start', 'Start VPN service', 'medium', 'Starts the enrolled OpenVPN / WireGuard / IKEv2 systemd unit.'),
    ('vpn-stop', 'Stop VPN service', 'high', 'Stops the enrolled VPN unit and disconnects active clients.'),
    ('vpn-restart', 'Restart VPN service', 'high', 'Restarts the enrolled VPN unit; sessions will drop briefly.'),
)

_ACTION_BY_NAME = {item[0]: item for item in _ACTIONS}
_EXECUTABLE = {'vpn-start', 'vpn-stop', 'vpn-restart'}
_SAFE_UNIT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$')
router = APIRouter(prefix='/api/server-operations', tags=['Server Control'])


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    action: ActionName


def _audit_registry_ready() -> bool:
    # Avoid touching existing data, silently creating tables or migrating schema.
    return {'server_admin_profiles', 'server_admin_audit'} <= set(inspect(engine).get_table_names())


def _readiness(server: Server, profile: ServerAdminProfile | None) -> dict:
    status = _safe_profile(server, profile)
    return {
        'server_id': server.id,
        'server_name': server.name,
        'archived': server.archived_at is not None,
        'profile_configured': status['profile_configured'],
        'profile_enabled': status['profile_enabled'],
        'inventory_pinned': status['inventory_pinned'],
        'local_profile_ready': status['verification_ready'],
        'remote_privilege_confirmed_now': False,
        'execution_enabled': True,
        'executable_actions': sorted(_EXECUTABLE),
        'scheduling_enabled': False,
    }


@router.get('/control/actions')
def list_control_actions(admin=Depends(_require_admin)):
    """Authenticated admin-only catalog."""
    return {
        'preview_only': False,
        'execution_enabled': True,
        'executable_actions': sorted(_EXECUTABLE),
        'scheduling_enabled': False,
        'actions': [
            {
                'key': key, 'name': label, 'risk': risk, 'prerequisite': prerequisite,
                'executable': key in _EXECUTABLE,
            }
            for key, label, risk, prerequisite in _ACTIONS
        ],
    }


@router.get('/servers/{server_id}/control/readiness')
def get_control_readiness(server_id: str, admin=Depends(_require_admin)):
    """Local inventory/profile state; cannot claim a live privilege verification."""
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise HTTPException(status_code=404, detail='Server not found')
        if not _audit_registry_ready():
            return {
                'server_id': server.id, 'server_name': server.name,
                'archived': server.archived_at is not None,
                'profile_configured': False, 'profile_enabled': False,
                'inventory_pinned': False, 'local_profile_ready': False,
                'remote_privilege_confirmed_now': False,
                'execution_enabled': True, 'executable_actions': sorted(_EXECUTABLE),
                'scheduling_enabled': False,
                'registry_initialized': False,
            }
        result = _readiness(server, db.get(ServerAdminProfile, server_id))
    return {**result, 'registry_initialized': True}


@router.post('/servers/{server_id}/control/preview')
def preview_control_action(server_id: str, request: PreviewRequest, admin=Depends(_require_admin)):
    """Refuse unapproved/archived servers; record only sanitized preview metadata.

    NEVER add SSH or subprocess calls to this route. Approval for future remote
    execution requires a new endpoint, limited command catalog and job lifecycle.
    """
    if not _audit_registry_ready():
        raise HTTPException(status_code=503, detail='Administrative registry not initialized')
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise HTTPException(status_code=404, detail='Server not found')
        if server.archived_at is not None:
            raise HTTPException(status_code=409, detail='Archived server: action preview not available')
        profile = db.get(ServerAdminProfile, server_id)
        readiness = _readiness(server, profile)
        if not readiness['profile_enabled']:
            raise HTTPException(status_code=409, detail='Administrative profile not approved')
        if not readiness['inventory_pinned']:
            raise HTTPException(status_code=409, detail='Inventory changed; profile reapproval required')
        if not readiness['local_profile_ready']:
            raise HTTPException(status_code=503, detail='Administrative profile local files unavailable')

        # Existing additive audit table; never records key path, host or commands.
        entry = ServerAdminAudit(
            server_id=server.id, actor_id=admin.id,
            operation=f'control_preview:{request.action}', result='preview_only',
        )
        db.add(entry)
        db.commit()
        action = _ACTION_BY_NAME[request.action]
        return {
            'server_id': server.id,
            'server_name': server.name,
            'action': action[0], 'label': action[1],
            'risk': action[2], 'prerequisite': action[3],
            'preview_only': request.action not in _EXECUTABLE,
            'execution_enabled': request.action in _EXECUTABLE,
            'scheduling_enabled': False,
            'remote_connection_attempted': False,
            'message': (
                'Preview logged. Use /control/execute to run allowlisted VPN service actions.'
                if request.action in _EXECUTABLE else
                'Preview logged. This action is not remotely executable in this build.'
            ),
        }


def _unit_for_vpn_service(vpn_service: str) -> str:
    """Map enrolled vpn_service identifiers to a systemd unit name."""
    if not _SAFE_UNIT.match(vpn_service):
        raise ValueError('Unsafe VPN service id')
    if vpn_service.startswith('wg@'):
        iface = vpn_service.split('@', 1)[1]
        if not _SAFE_UNIT.match(iface):
            raise ValueError('Unsafe WireGuard interface')
        return f'wg-quick@{iface}'
    if vpn_service.startswith('ikev2@'):
        raw = vpn_service.split('@', 1)[1]
        # Normalize to common strongSwan unit names
        if raw in {'strongswan', 'strongswan-starter', 'ipsec', 'charon'}:
            return raw
        return 'strongswan'
    return vpn_service.removesuffix('.service')


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    action: ActionName
    confirm: bool = False


@router.post('/servers/{server_id}/control/execute')
def execute_control_action(server_id: str, body: ExecuteRequest, request: Request,
                           admin=Depends(_require_admin)):
    """Allowlisted VPN systemd control only. Requires confirm=true."""
    _local_only(request)
    if body.action not in _EXECUTABLE:
        raise HTTPException(422, detail='Action is not executable remotely')
    if body.confirm is not True:
        raise HTTPException(422, detail='confirm=true required')
    if not _audit_registry_ready():
        raise HTTPException(503, detail='Administrative registry not initialized')
    if not _control_acquire(server_id):
        raise HTTPException(409, detail='Another operation is already running on this server')
    try:
        with SessionLocal() as db:
            server = db.get(Server, server_id)
            if server is None or server.archived_at is not None:
                raise HTTPException(404, detail='Server not found')
            profile = db.get(ServerAdminProfile, server_id)
            readiness = _readiness(server, profile)
            if not readiness['local_profile_ready']:
                raise HTTPException(503, detail='Administrative profile not ready')
            mon = db.get(ServerMonitoringConfig, server_id)
            if mon is None or not mon.enabled:
                raise HTTPException(409, detail='Enroll monitoring (VPN service) first')
            unit = _unit_for_vpn_service(mon.vpn_service)
            config = SSHConnectionConfig(
                host=profile.approved_host, port=profile.approved_port,
                username=profile.approved_username,
                private_key_path=profile.private_key_path,
                known_hosts_path=profile.known_hosts_path,
            )
            server_name = server.name
            vpn_service = mon.vpn_service

        verb = {'vpn-start': 'start', 'vpn-stop': 'stop', 'vpn-restart': 'restart'}[body.action]
        # Fixed argv only — unit validated against allowlist pattern above.
        remote = f'sudo -n systemctl {verb} {unit} && systemctl is-active {unit}'
        client = _connect_verified(config)
        try:
            _stdin, stdout, stderr = client.exec_command(remote, timeout=45)
            out = stdout.read(4096).decode('utf-8', errors='replace').strip()
            err = stderr.read(2048).decode('utf-8', errors='replace').strip()
            code = stdout.channel.recv_exit_status()
        finally:
            client.close()

        ok = code == 0
        with SessionLocal() as db:
            db.add(ServerAdminAudit(
                server_id=server_id, actor_id=admin.id,
                operation=f'control_execute:{body.action}',
                result='success' if ok else 'failed',
            ))
            db.commit()
        if not ok:
            raise HTTPException(502, detail={
                'code': 'VPN_CONTROL_FAILED',
                'message': 'systemctl action failed (passwordless sudo may be required).',
                'unit': unit,
                'stderr_tail': err[-180:] if err else None,
            })
        return {
            'server_id': server_id,
            'server_name': server_name,
            'action': body.action,
            'vpn_service': vpn_service,
            'unit': unit,
            'active_state': out.splitlines()[-1] if out else 'unknown',
            'execution_enabled': True,
            'message': f'VPN unit {unit} {verb} completed.',
        }
    finally:
        _control_release(server_id)
