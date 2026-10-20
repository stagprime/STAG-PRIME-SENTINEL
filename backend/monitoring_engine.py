"""Step 41A: approved SSH fallback collector, durable read-only telemetry and incidents.

Runs only in the separately started worker (NOT in API requests or on import).
This is not a privileged administration or OpenVPN installation service.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import os
import threading
import time
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, Server, ServerMonitoringConfig, SessionLocal, engine
from backend.ssh_monitor import SSHConnectionConfig, collect_ssh_health
from backend.vpn_sessions import collect_live_vpn_sessions


def collect_sessions_for_monitor(config: SSHConnectionConfig, *, vpn_service: str) -> dict:
    """OpenVPN CE, WireGuard or IKEv2 session snapshot for the worker."""
    from backend.vpn_fleet import collect_multi_protocol_sessions, protocol_from_service
    proto = protocol_from_service(vpn_service)
    if proto == 'openvpn' and vpn_service.startswith('openvpn-server@'):
        payload = collect_live_vpn_sessions(config, vpn_service=vpn_service)
        payload['protocol'] = 'openvpn'
        if 'auth_failures' not in payload:
            payload['auth_failures'] = None
        return payload
    payload = collect_multi_protocol_sessions(config, vpn_service, proto)
    state = payload.get('state')
    if state not in {'available', 'vpn_not_active', 'permission_required', 'stale_status', 'status_unavailable'}:
        raise RuntimeError('Invalid multi-protocol session state')
    sessions = payload.get('sessions') if state == 'available' else []
    if state == 'available' and (not isinstance(sessions, list) or payload.get('total') != len(sessions)):
        raise RuntimeError('Invalid multi-protocol session rows')
    return {
        'state': state,
        'total': payload.get('total') if state == 'available' else None,
        'sessions': sessions if state == 'available' else [],
        'status_age_seconds': payload.get('status_age_seconds'),
        'protocol': payload.get('protocol') or proto,
        'auth_failures': payload.get('auth_failures'),
        'collected_at_utc': payload.get('collected_at_utc'),
    }

log = logging.getLogger('sentinel.monitor')
SESSION_INTERVAL = 30
HEALTH_INTERVAL = 60
WORKER_HEARTBEAT_INTERVAL = 30
MAX_FAILURE_BACKOFF = 300
RETAIN_SAMPLES = 2880  # bounded history per server+kind, approx 1 day for 30s series


def utcnow():
    return datetime.now(timezone.utc)


def as_utc(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class TelemetrySample(Base):
    __tablename__ = 'sentinel_telemetry_samples'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(12), nullable=False)  # health|sessions
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    data_json: Mapped[str] = mapped_column(Text, nullable=False)


class MonitorState(Base):
    __tablename__ = 'sentinel_monitor_states'
    server_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_health_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sessions_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    health_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    session_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default='pending')
    error_code: Mapped[str | None] = mapped_column(String(40))
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class MonitorIncident(Base):
    __tablename__ = 'sentinel_monitor_incidents'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    code: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(12), nullable=False)  # open|resolved
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionTransition(Base):
    """Diff inferred from 30-second snapshots; does not claim actual logout reason."""
    __tablename__ = 'sentinel_session_transitions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    event: Mapped[str] = mapped_column(String(12), nullable=False)  # appeared|disappeared
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    identity: Mapped[str] = mapped_column(String(160), nullable=False)
    client_public_ip: Mapped[str | None] = mapped_column(String(45))
    vpn_ip: Mapped[str | None] = mapped_column(String(64))


class MonitorWorkerPulse(Base):
    __tablename__ = 'sentinel_monitor_worker_pulse'
    worker_name: Mapped[str] = mapped_column(String(32), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


TABLES = [obj.__table__ for obj in (TelemetrySample, MonitorState, MonitorIncident, SessionTransition, MonitorWorkerPulse)]


def initialize_monitor_tables():
    Base.metadata.create_all(bind=engine, tables=[ServerMonitoringConfig.__table__, *TABLES], checkfirst=True)


def incident_change(db, server_id, code, opened, now):
    existing = db.scalars(select(MonitorIncident).where(MonitorIncident.server_id == server_id,
                     MonitorIncident.code == code, MonitorIncident.state == 'open')).first()
    if opened:
        if existing is None:
            db.add(MonitorIncident(server_id=server_id, code=code, state='open', opened_at=now, last_seen_at=now))
            try:
                from backend.alert_notify import emit_alert
                server = db.get(Server, server_id)
                emit_alert(
                    server_id=server_id,
                    server_name=(server.name if server else server_id),
                    code=code,
                    state='open',
                    detail='Monitoring incident opened',
                )
            except Exception:
                pass
        else:
            existing.last_seen_at = now
    elif existing is not None:
        existing.state = 'resolved'
        existing.last_seen_at = now
        existing.resolved_at = now
        try:
            from backend.alert_notify import emit_alert
            server = db.get(Server, server_id)
            emit_alert(
                server_id=server_id,
                server_name=(server.name if server else server_id),
                code=code,
                state='resolved',
            )
        except Exception:
            pass


def session_key(row):
    # Avoid grouping users sharing CN. No database synthetic ID or secret data.
    return (str(row.get('client_id')), str(row.get('common_name')), str(row.get('public_ip')),
            str(row.get('vpn_ip')), str(row.get('connected_since_unix')))


def record_sample(db, server_id, kind: str, payload: dict, now=None):
    """Validated snapshots only. Inferred session transitions require two good snapshots."""
    if kind not in ('health', 'sessions'):
        raise ValueError('Unexpected telemetry kind')
    now = now or utcnow()
    if not isinstance(payload, dict):
        raise ValueError('Invalid telemetry payload')
    if kind == 'sessions':
        if payload.get('state') not in ('available', 'vpn_not_active', 'permission_required', 'stale_status', 'status_unavailable'):
            raise ValueError('Unrecognized VPN state')
        if payload['state'] == 'available' and (not isinstance(payload.get('sessions'), list)
            or payload.get('total') != len(payload['sessions']) or len(payload['sessions']) > 1000):
            raise ValueError('Invalid session count')
        if payload['state'] != 'available':
            payload = {**payload, 'total': None, 'sessions': []}
        last = db.scalars(select(TelemetrySample).where(TelemetrySample.server_id == server_id,
            TelemetrySample.kind == 'sessions').order_by(TelemetrySample.id.desc()).limit(1)).first()
        if (payload['state'] == 'available' and last and last.state == 'available'):
            old = json.loads(last.data_json).get('sessions', [])
            before = {session_key(s): s for s in old}
            after = {session_key(s): s for s in payload['sessions']}
            for event, items in (('appeared', after.keys() - before.keys()), ('disappeared', before.keys() - after.keys())):
                for key in items:
                    r = (after if event == 'appeared' else before)[key]
                    db.add(SessionTransition(server_id=server_id, event=event, observed_at=now,
                        identity=(r.get('username') or r.get('common_name') or 'unknown')[:160],
                        client_public_ip=r.get('public_ip'), vpn_ip=r.get('vpn_ip')))
        state = payload['state']
    else:
        state = 'connected' if payload.get('status') == 'connected' and payload.get('host_key_verified') is True else 'unverified'
        if state != 'connected':
            raise ValueError('Unverified SSH health sample')
    data = json.dumps(payload, separators=(',', ':'), allow_nan=False)
    if kind == 'sessions':
        # Bound event history independently of sample retention.
        recent = list(db.scalars(select(SessionTransition.id).where(SessionTransition.server_id == server_id)
             .order_by(SessionTransition.id.desc()).offset(10000)).all())
        if recent:
            from sqlalchemy import delete
            for index in range(0, len(recent), 500):
                db.execute(delete(SessionTransition).where(SessionTransition.id.in_(recent[index:index+500])))
    if len(data) > 500_000:
        raise ValueError('Telemetry exceeds storage bounds')
    db.add(TelemetrySample(server_id=server_id, kind=kind, collected_at=now, state=state, data_json=data))
    db.flush()
    # Keep bounded history; small SQLite queries with indexed server_id. Limit is per kind.
    obsolete = list(db.scalars(select(TelemetrySample.id).where(TelemetrySample.server_id == server_id,
        TelemetrySample.kind == kind).order_by(TelemetrySample.id.desc()).offset(RETAIN_SAMPLES)).all())
    if obsolete:
        from sqlalchemy import delete
        for i in range(0, len(obsolete), 500):
            db.execute(delete(TelemetrySample).where(TelemetrySample.id.in_(obsolete[i:i + 500])))
    return state


def sanitized_failure(exc):
    from paramiko.ssh_exception import AuthenticationException, BadHostKeyException
    if isinstance(exc, BadHostKeyException): return 'host_key_mismatch'
    if isinstance(exc, AuthenticationException): return 'authentication_failed'
    if isinstance(exc, (TimeoutError, ConnectionError)): return 'connection_timeout'
    if isinstance(exc, FileNotFoundError): return 'credential_unavailable'
    if 'error reading ssh protocol banner' in str(exc).lower(): return 'ssh_banner_unavailable'
    if isinstance(exc, (OSError,)): return 'transport_unavailable'
    return 'collector_failed'


def get_config(server_id):
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        target = db.get(ServerMonitoringConfig, server_id)
        if not server or not target or server.archived_at is not None or not target.enabled:
            return None
        if (server.host != target.approved_host or (server.ssh_username or '') != target.approved_ssh_username
                or server.ssh_port != target.approved_ssh_port):
            return None
        return (SSHConnectionConfig(host=target.approved_host, username=target.approved_ssh_username,
                   port=target.approved_ssh_port, private_key_path=target.ssh_key_path,
                   known_hosts_path=target.known_hosts_path), target.vpn_service,
                   target.vpn_interface, target.network_interface)


def _poll_one_under_slot(server_id, kind, *, collector_health=collect_ssh_health,
             collector_sessions=collect_sessions_for_monitor, now=None):
    """No SSH until target is both enabled and inventory-pinned. One bounded job."""
    now = now or utcnow()
    config = get_config(server_id)
    if config is None:
        return 'not_enrolled'
    ssh, service, vpn_interface, wan = config
    try:
        if kind == 'health':
            result = collector_health(ssh, vpn_service=service, vpn_interface=vpn_interface,
                                      network_interface=wan)
        elif kind == 'sessions':
            result = collector_sessions(ssh, vpn_service=service)
        else:
            raise ValueError('Invalid collector type')
        with SessionLocal() as db:
            # If enrollment changed while SSH was running, do not save stale data.
            if get_config(server_id) != config:
                return 'enrollment_changed'
            state = db.get(MonitorState, server_id) or MonitorState(server_id=server_id)
            db.add(state)
            result_state = record_sample(db, server_id, kind, result, now)
            state.checked_at = now
            if kind == 'health': state.last_health_at = now
            else: state.last_sessions_at = now
            # Health and VPN session observations are independent. A missing
            # OpenVPN service or unreadable status file is not an SSH outage.
            if kind == 'health':
                state.health_failures = 0
                state.status = 'healthy'
                state.error_code = None
                state.next_attempt_at = None
            else:
                state.session_failures = 0
            state.failures = max(state.health_failures or 0, state.session_failures or 0)
            incident_change(db, server_id, kind + '_collection_failed', False, now)
            incident_change(db, server_id, 'health_degraded', False, now)
            incident_change(db, server_id, 'vpn_observation_unavailable', kind == 'sessions' and result_state not in ('available', 'vpn_not_active'), now)
            incident_change(db, server_id, 'vpn_service_inactive', kind == 'sessions' and result_state == 'vpn_not_active', now)
            if kind == 'health' and isinstance(result, dict):
                cpu = result.get('cpu_percent')
                ram = result.get('memory_used_percent')
                disk = result.get('disk_used_percent')
                incident_change(db, server_id, 'high_cpu', isinstance(cpu, (int, float)) and cpu >= 90, now)
                incident_change(db, server_id, 'high_ram', isinstance(ram, (int, float)) and ram >= 90, now)
                incident_change(db, server_id, 'high_disk', isinstance(disk, (int, float)) and disk >= 90, now)
            if kind == 'sessions' and isinstance(result, dict):
                from backend.issue_engine import SESSION_OVERLOAD_THRESHOLD
                total = result.get('total')
                incident_change(
                    db, server_id, 'session_overload',
                    result_state == 'available' and isinstance(total, int) and total >= SESSION_OVERLOAD_THRESHOLD,
                    now,
                )
            db.commit()
        return result_state
    except Exception as exc:
        error = sanitized_failure(exc)
        log.warning('Monitoring failure server=%s kind=%s code=%s', server_id, kind, error)
        with SessionLocal() as db:
            state = db.get(MonitorState, server_id) or MonitorState(server_id=server_id)
            db.add(state)
            state.checked_at = now
            if kind == 'health':
                state.health_failures = min(1000, (state.health_failures or 0) + 1)
                failures_for_kind = state.health_failures
                state.status = 'degraded' if failures_for_kind < 3 else 'unreachable'
                state.error_code = error
                state.next_attempt_at = now + timedelta(seconds=min(
                    MAX_FAILURE_BACKOFF, 30 * (2 ** min(failures_for_kind - 1, 4))))
                incident_change(db, server_id, 'health_degraded', failures_for_kind >= 1, now)
            else:
                state.session_failures = min(1000, (state.session_failures or 0) + 1)
                failures_for_kind = state.session_failures
            state.failures = max(state.health_failures or 0, state.session_failures or 0)
            incident_change(db, server_id, kind + '_collection_failed', failures_for_kind >= 3, now)
            db.commit()
        return error


def poll_one(server_id, kind, *, collector_health=collect_ssh_health,
             collector_sessions=collect_sessions_for_monitor, now=None):
    """Monitoring-only polling; multi-protocol session collectors supported."""
    return _poll_one_under_slot(server_id, kind, collector_health=collector_health,
                                collector_sessions=collector_sessions, now=now)


def prepare_fresh_enrollment(server_id: str) -> None:
    """Clear prior backoff so a newly enrolled host is not stuck behind old failures."""
    with SessionLocal() as db:
        state = db.get(MonitorState, server_id)
        if state is None:
            state = MonitorState(server_id=server_id)
            db.add(state)
        state.failures = 0
        state.health_failures = 0
        state.session_failures = 0
        state.status = 'pending'
        state.error_code = None
        state.next_attempt_at = None
        db.commit()


def kick_first_collection(server_id: str) -> None:
    """After enroll/onboard: reset backoff and collect health+sessions without waiting for the worker loop.

    Runs in a daemon thread so the HTTP response returns immediately. The
    background worker continues periodic collection afterward. Network/auth
    failures are recorded as error_code for the operator UI — no manual poll needed.
    """
    prepare_fresh_enrollment(server_id)

    def _run():
        try:
            poll_one(server_id, 'health')
            poll_one(server_id, 'sessions')
        except Exception:
            log.exception('Immediate first collection failed server=%s', server_id)

    threading.Thread(target=_run, name=f'sentinel-first-collect-{server_id[:8]}', daemon=True).start()


def active_targets():
    from sqlalchemy import select
    with SessionLocal() as db:
        ids = db.scalars(select(Server.id).join(ServerMonitoringConfig, ServerMonitoringConfig.server_id == Server.id)
                .where(Server.archived_at.is_(None), ServerMonitoringConfig.enabled.is_(True),
                       Server.host == ServerMonitoringConfig.approved_host,
                       Server.ssh_port == ServerMonitoringConfig.approved_ssh_port,
                       Server.ssh_username == ServerMonitoringConfig.approved_ssh_username)).all()
        return list(ids)


def pulse(now=None):
    now = now or utcnow()
    with SessionLocal() as db:
        item = db.get(MonitorWorkerPulse, 'ssh-fallback')
        if item is None:
            item = MonitorWorkerPulse(worker_name='ssh-fallback', seen_at=now)
            db.add(item)
        else:
            item.seen_at = now
        db.commit()


def overview_for_user(user, db):
    from backend.auth_security import can_access_client
    now = utcnow()
    servers = db.scalars(select(Server).where(Server.archived_at.is_(None)).order_by(Server.name)).all()
    rows = []
    for server in servers:
        if not can_access_client(db, user, server.client_id):
            continue
        target = db.get(ServerMonitoringConfig, server.id)
        enabled = bool(target and target.enabled and target.approved_host == server.host
                   and target.approved_ssh_port == server.ssh_port
                   and target.approved_ssh_username == server.ssh_username)
        state = db.get(MonitorState, server.id)
        latest = {}
        raw_payloads = {'health': {}, 'sessions': {}}
        for kind in ('health', 'sessions'):
            sample = db.scalars(select(TelemetrySample).where(TelemetrySample.server_id == server.id,
                TelemetrySample.kind == kind).order_by(TelemetrySample.id.desc()).limit(1)).first()
            if sample:
                age = (now - as_utc(sample.collected_at)).total_seconds()
                # An explicitly inactive VPN is intentionally checked at 300s,
                # unlike a live session feed. Neither old data nor a failed
                # follow-up attempt may be advertised as a fresh observation.
                max_age = (HEALTH_INTERVAL * 2 + 30 if kind == 'health' else
                           MAX_FAILURE_BACKOFF + 60 if sample.state == 'vpn_not_active' else
                           SESSION_INTERVAL * 2 + 30)
                failure_count = ((state.health_failures or 0) if kind == 'health' else
                                 (state.session_failures or 0)) if state else 0
                fresh = enabled and 0 <= age <= max_age and failure_count == 0
                try:
                    payload = json.loads(sample.data_json)
                except (TypeError, ValueError):
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                raw_payloads[kind] = payload
                latest[kind] = {'state': sample.state, 'at_utc': as_utc(sample.collected_at).isoformat(),
                    'age_seconds': max(0, int(age)), 'fresh': fresh,
                    'data': payload if fresh else None}
            else:
                latest[kind] = {'state': 'not_collected', 'at_utc': None, 'age_seconds': None,
                                'fresh': False, 'data': None}
        failures = state.failures if state else 0
        health_failures = state.health_failures if state else 0
        status = ('not_enrolled' if not enabled else 'unreachable' if health_failures >= 3 else
                  'degraded' if health_failures else 'healthy' if latest['health']['fresh'] else 'stale')
        health_payload = raw_payloads['health']
        sessions_payload = raw_payloads['sessions']
        openvpn = health_payload.get('openvpn') if isinstance(health_payload.get('openvpn'), dict) else {}
        auth = sessions_payload.get('auth_failures') if isinstance(sessions_payload.get('auth_failures'), dict) else {}
        def _num(value, lo=0.0, hi=100.0):
            return value if isinstance(value, (int, float)) and lo <= value <= hi else None
        vpn_observation = {
            'configured_service': target.vpn_service if target else None,
            'configured_interface': target.vpn_interface if target else None,
            'service': openvpn.get('service') if isinstance(openvpn.get('service'), str) else (target.vpn_service if target else None),
            'service_status': openvpn.get('service_status') if isinstance(openvpn.get('service_status'), str) else None,
            'tunnel_interface': openvpn.get('interface') if isinstance(openvpn.get('interface'), str) else (target.vpn_interface if target else None),
            'tunnel_ipv4': openvpn.get('tunnel_ipv4') if isinstance(openvpn.get('tunnel_ipv4'), str) else None,
            'health_fresh': bool(latest['health']['fresh']),
            'sessions_state': sessions_payload.get('state') if isinstance(sessions_payload.get('state'), str) else latest['sessions']['state'],
            'sessions_total': sessions_payload.get('total') if isinstance(sessions_payload.get('total'), int) and 0 <= sessions_payload.get('total') <= 10000 else None,
            'sessions_fresh': bool(latest['sessions']['fresh']),
            'status_age_seconds': sessions_payload.get('status_age_seconds') if isinstance(sessions_payload.get('status_age_seconds'), int) else None,
            'protocol': sessions_payload.get('protocol') if isinstance(sessions_payload.get('protocol'), str) else None,
            'auth_failures_observed': auth.get('failed_attempts_observed') if isinstance(auth.get('failed_attempts_observed'), int) else None,
            'cpu_percent': _num(health_payload.get('cpu_percent')),
            'memory_used_percent': _num(health_payload.get('memory_used_percent')),
            'disk_used_percent': _num(health_payload.get('disk_used_percent')),
            'uptime_seconds': _num(health_payload.get('uptime_seconds'), 0, 10**12),
            'observed_at_utc': latest['health']['at_utc'] or latest['sessions']['at_utc'],
        }
        rows.append({'server_id': server.id, 'server_name': server.name, 'client_id': server.client_id,
            'monitoring_enabled': enabled, 'status': status, 'error_code': state.error_code if state and enabled else None,
            'last_checked_utc': as_utc(state.checked_at).isoformat() if state and enabled and state.checked_at else None,
            'health': latest['health'], 'sessions': latest['sessions'],
            'vpn_observation': vpn_observation})
    worker = db.get(MonitorWorkerPulse, 'ssh-fallback')
    worker_age = (now - as_utc(worker.seen_at)).total_seconds() if worker else None
    worker_status = 'running' if worker_age is not None and 0 <= worker_age <= 90 else 'not_running'
    if worker_status != 'running':
        for row in rows:
            if row['monitoring_enabled']:
                row['status'] = 'worker_offline'
                row['health']['fresh'] = False
                row['health']['data'] = None
                row['sessions']['fresh'] = False
                row['sessions']['data'] = None
    return {'worker': {'status': worker_status, 'last_seen_utc': as_utc(worker.seen_at).isoformat() if worker else None},
            'config': {'sessions_interval_seconds': 30, 'health_interval_seconds': 60,
                       'worker_heartbeat_seconds': 30, 'events': 'snapshot_inferred_only'},
            'servers': rows}
