"""Step 40.7: bounded, allowlisted READ-ONLY SSH diagnostics.

This deliberately is NOT a generic shell, power/VPN controller or scheduler.
Only two constant /proc commands are available; no command, path, argument,
service identifier, or privilege flag can be supplied by the API caller.
Existing pinned administrator profiles and strict host-key trust are reused.
"""
from __future__ import annotations

import math
import socket
import threading
import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException
from pydantic import BaseModel, ConfigDict

from backend.admin_access import (
    ServerAdminAudit, ServerAdminProfile, _require_admin, _safe_profile,
)
from backend.database import Server, SessionLocal
from backend.server_control import _audit_registry_ready
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified


DiagnosticName = Literal['load_average', 'memory_snapshot']

# Commands MUST remain fixed constants. Never interpolate any client input.
_CATALOG = {
    'load_average': ('CPU load averages', 'cat /proc/loadavg'),
    'memory_snapshot': ('Memory and swap summary', 'cat /proc/meminfo'),
}
_MAX_STDOUT = 8192
_MAX_STDERR = 256
_REMOTE_DEADLINE_SECONDS = 9.0

router = APIRouter(prefix='/api/server-operations', tags=['Read-only SSH diagnostics'])


class DiagnosticRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    check: DiagnosticName


# In-process guard, not a substitute for a distributed production job lock.
_guard = threading.Lock()
_running: set[str] = set()


def _acquire(server_id: str) -> bool:
    with _guard:
        if server_id in _running:
            return False
        _running.add(server_id)
        return True


def _release(server_id: str) -> None:
    with _guard:
        _running.discard(server_id)


def _bounded_output(client: Any, command: str) -> str:
    """Hard-deadline, bounded stdout/stderr over a channel; no unbounded read().

    Called ONLY with module-defined read-only commands; nothing is logged.
    SSH channel is closed on success, timeout and error.
    """
    transport = client.get_transport()
    if transport is None or not transport.is_active():
        raise RuntimeError('Remote transport unavailable')
    channel = transport.open_session(timeout=5)
    try:
        channel.settimeout(2)
        channel.exec_command(command)
        end = time.monotonic() + _REMOTE_DEADLINE_SECONDS
        out = bytearray()
        err_size = 0
        while time.monotonic() < end:
            progressed = False
            while channel.recv_ready():
                chunk = channel.recv(2048)
                if not chunk:
                    break
                out.extend(chunk)
                progressed = True
                if len(out) > _MAX_STDOUT:
                    raise RuntimeError('Diagnostic output exceeded limit')
            while channel.recv_stderr_ready():
                chunk = channel.recv_stderr(512)
                if not chunk:
                    break
                err_size += len(chunk)
                progressed = True
                if err_size > _MAX_STDERR:
                    raise RuntimeError('Diagnostic error output exceeded limit')
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                code = channel.recv_exit_status()
                if code != 0:
                    raise RuntimeError('Diagnostic check returned nonzero status')
                return bytes(out).decode('ascii', 'strict')
            if not progressed:
                time.sleep(0.025)
        raise TimeoutError('Diagnostic deadline exceeded')
    finally:
        channel.close()


def _parse(check: DiagnosticName, output: str) -> dict[str, Any]:
    """Parse only known, bounded numeric fields; never return raw SSH output."""
    if check == 'load_average':
        parts = output.split()
        if len(parts) < 3:
            raise ValueError('Malformed load averages')
        values = [float(x) for x in parts[:3]]
        if any(not math.isfinite(v) or v < 0 or v > 100000 for v in values):
            raise ValueError('Unexpected load averages')
        return {'load_1m': values[0], 'load_5m': values[1], 'load_15m': values[2]}
    if check == 'memory_snapshot':
        needed = {'MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'}
        found: dict[str, int] = {}
        for line in output.splitlines():
            name, _, value = line.partition(':')
            if name not in needed:
                continue
            parts = value.strip().split()
            if len(parts) != 2 or parts[1] != 'kB' or not parts[0].isdecimal():
                raise ValueError('Invalid memory statistic')
            kb = int(parts[0])
            if kb > 1_000_000_000_000:
                raise ValueError('Memory statistic out of range')
            found[name] = kb
        if found.keys() != needed:
            raise ValueError('Missing memory statistics')
        if found['MemAvailable'] > found['MemTotal'] or found['SwapFree'] > found['SwapTotal']:
            raise ValueError('Inconsistent memory statistics')
        return {key + '_mib': found[source] // 1024 for key, source in (
            ('total', 'MemTotal'), ('available', 'MemAvailable'),
            ('swap_total', 'SwapTotal'), ('swap_free', 'SwapFree'),
        )}
    raise ValueError('Unsupported diagnostic')


def _run_pinned_diagnostic(config: SSHConnectionConfig, check: DiagnosticName) -> dict[str, Any]:
    client = _connect_verified(config)  # RejectPolicy: no new/changed host key accepted.
    try:
        return _parse(check, _bounded_output(client, _CATALOG[check][1]))
    finally:
        client.close()


def _finish_audit(audit_id: int, result: str) -> None:
    with SessionLocal() as db:
        row = db.get(ServerAdminAudit, audit_id)
        if row:
            row.result = result
            db.commit()


@router.get('/diagnostics/catalog')
def diagnostic_catalog(admin=Depends(_require_admin)):
    return {
        'read_only_execution_enabled': True,
        'arbitrary_commands_enabled': False,
        'power_control_enabled': False,
        'openvpn_control_enabled': False,
        'scheduling_enabled': False,
        'checks': [{'key': name, 'label': label} for name, (label, _command) in _CATALOG.items()],
    }


@router.post('/servers/{server_id}/diagnostics/run')
def run_read_only_diagnostic(server_id: str, request: DiagnosticRequest, admin=Depends(_require_admin)):
    """One audited, bounded, user-initiated read-only probe. Never use sudo."""
    if not _audit_registry_ready():
        raise HTTPException(status_code=503, detail='Administrative profile registry not initialized')
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None or server.archived_at is not None:
            raise HTTPException(status_code=404, detail='Server not found')
        profile = db.get(ServerAdminProfile, server_id)
        status = _safe_profile(server, profile)
        if not status['inventory_pinned']:
            raise HTTPException(status_code=409, detail='Administrative profile missing or inventory approval changed')
        if not status['verification_ready']:
            raise HTTPException(status_code=503, detail='Approved administrative profile files unavailable')
        config = SSHConnectionConfig(
            host=profile.approved_host, port=profile.approved_port,
            username=profile.approved_username, private_key_path=profile.private_key_path,
            known_hosts_path=profile.known_hosts_path,
        )
        server_name = server.name

        if not _acquire(server_id):
            raise HTTPException(status_code=409, detail='Another diagnostic is running for this server')
        try:
            audit = ServerAdminAudit(server_id=server.id, actor_id=admin.id,
                operation='diagnostic:' + request.check, result='attempted')
            db.add(audit)
            db.commit()
            db.refresh(audit)
            audit_id = audit.id
        except Exception:
            _release(server_id)
            raise

    try:
        try:
            metrics = _run_pinned_diagnostic(config, request.check)
        except (BadHostKeyException, AuthenticationException, SSHException,
                OSError, socket.timeout, TimeoutError, RuntimeError, ValueError, UnicodeError):
            _finish_audit(audit_id, 'failed')
            raise HTTPException(status_code=502, detail='Read-only diagnostic failed; inspect trusted SSH access') from None
        _finish_audit(audit_id, 'passed')
        return {
            'server_id': server_id, 'server_name': server_name,
            'check': request.check, 'metrics': metrics,
            'ssh_verified': True, 'host_key_verified': True,
            'audit_recorded': True, 'read_only': True,
            'power_or_vpn_changed': False,
        }
    finally:
        _release(server_id)
