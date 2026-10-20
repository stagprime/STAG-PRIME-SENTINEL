"""Authenticated cache-only telemetry APIs; browsing NEVER launches SSH."""
from datetime import datetime, timedelta
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from backend.auth_api import require_current_session
from backend.auth_security import can_access_client
from backend.database import SessionLocal, Server
from backend.monitoring_engine import (initialize_monitor_tables, overview_for_user, MonitorIncident,
                                       SessionTransition, TelemetrySample, as_utc, utcnow)

router = APIRouter(prefix='/api/monitoring', tags=['Background monitoring'])


def visible_ids(db, user):
    return list(server.id for server in db.scalars(select(Server).where(Server.archived_at.is_(None)))
                if can_access_client(db, user, server.client_id))


@router.get('/overview')
def monitoring_overview(current=Depends(require_current_session)):
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        return overview_for_user(user, db)


@router.get('/fleet-ops')
def monitoring_fleet_ops(current=Depends(require_current_session)):
    """Connected users, auth-failure signals, and per-server issue→solution list."""
    from backend.issue_engine import analyze_server, fleet_connection_summary
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        overview = overview_for_user(user, db)
        name_by_id = {
            s.id: s.name
            for s in db.scalars(select(Server).where(Server.archived_at.is_(None))).all()
            if can_access_client(db, user, s.client_id)
        }
    worker_running = overview.get('worker', {}).get('status') == 'running'
    servers_out = []
    for row in overview.get('servers') or []:
        health = row.get('health', {}).get('data') if isinstance(row.get('health'), dict) else None
        sessions = row.get('sessions', {}).get('data') if isinstance(row.get('sessions'), dict) else None
        issues = analyze_server(
            status=row.get('status'),
            monitoring_enabled=bool(row.get('monitoring_enabled')),
            worker_running=worker_running,
            health=health if isinstance(health, dict) else None,
            sessions=sessions if isinstance(sessions, dict) else None,
        )
        connected = None
        protocol = None
        failed = 0
        active_sessions: list[dict] = []
        if isinstance(sessions, dict) and sessions.get('state') == 'available' and isinstance(sessions.get('total'), int):
            connected = sessions['total']
            protocol = sessions.get('protocol')
            failures = sessions.get('auth_failures') or {}
            if isinstance(failures.get('failed_attempts_observed'), int):
                failed = failures['failed_attempts_observed']
            raw_sessions = sessions.get('sessions')
            if isinstance(raw_sessions, list):
                for item in raw_sessions[:200]:
                    if not isinstance(item, dict):
                        continue
                    active_sessions.append({
                        'common_name': item.get('common_name') or item.get('username') or item.get('peer') or '',
                        'username': item.get('username') or '',
                        'public_ip': item.get('public_ip') or item.get('endpoint') or '',
                        'vpn_ip': item.get('vpn_ip') or '',
                        'connected_since': item.get('connected_since') or item.get('connected_since_unix'),
                        'bytes_received': item.get('bytes_received'),
                        'bytes_sent': item.get('bytes_sent'),
                    })
        sid = row.get('server_id')
        servers_out.append({
            'server_id': sid,
            'server_name': row.get('server_name') or row.get('name') or name_by_id.get(sid),
            'status': row.get('status'),
            'monitoring_enabled': row.get('monitoring_enabled'),
            'protocol': protocol,
            'connected_users': connected,
            'failed_auth_observations': failed,
            'active_sessions': active_sessions,
            'issues': issues,
        })
    summary = fleet_connection_summary([
        {
            'monitoring_enabled': s['monitoring_enabled'],
            'status': s['status'],
            'health': {'data': None},
            'sessions': {
                'data': (
                    {
                        'state': 'available',
                        'total': s['connected_users'],
                        'protocol': s['protocol'],
                        'auth_failures': {'failed_attempts_observed': s['failed_auth_observations']},
                    } if s['connected_users'] is not None else None
                ),
            },
        }
        for s in servers_out
    ])
    summary['open_issue_signals'] = sum(len(s['issues']) for s in servers_out)
    from backend.alert_notify import recent_alerts
    return {
        'worker': overview.get('worker'),
        'summary': summary,
        'servers': servers_out,
        'recent_alerts': recent_alerts(40),
    }


@router.get('/incidents')
def monitoring_incidents(current=Depends(require_current_session)):
    from backend.issue_engine import describe_incident
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        ids = visible_ids(db, user)
        empty = {
            'incidents': [], 'total': 0,
            'summary': {
                'open': 0, 'resolved': 0, 'critical_open': 0, 'high_open': 0,
                'medium_open': 0, 'low_open': 0, 'affected_servers': 0,
                'by_code': [],
            },
        }
        if not ids:
            return empty
        query = select(MonitorIncident).where(MonitorIncident.server_id.in_(ids)).order_by(
            MonitorIncident.id.desc()).limit(500)
        records = {s.id: s for s in db.scalars(select(Server).where(Server.id.in_(ids))).all()}
        entries = []
        for incident in db.scalars(query):
            server = records.get(incident.server_id)
            if server is None:
                continue
            guide = describe_incident(incident.code)
            entries.append({
                'id': incident.id,
                'server_id': server.id,
                'server_name': server.name,
                'code': incident.code,
                'state': incident.state,
                'opened_at_utc': as_utc(incident.opened_at).isoformat(),
                'last_seen_at_utc': as_utc(incident.last_seen_at).isoformat(),
                'resolved_at_utc': as_utc(incident.resolved_at).isoformat() if incident.resolved_at else None,
                'title': guide['title'],
                'severity': guide['severity'],
                'summary': guide['summary'],
                'solution': guide['solution'],
            })
        open_rows = [e for e in entries if e['state'] == 'open']
        by_code_map: dict[str, int] = {}
        for e in open_rows:
            by_code_map[e['code']] = by_code_map.get(e['code'], 0) + 1
        by_code = []
        for code_key, count in sorted(by_code_map.items(), key=lambda kv: -kv[1])[:20]:
            guide = describe_incident(code_key)
            by_code.append({
                'code': code_key,
                'count': count,
                'title': guide['title'],
                'severity': guide['severity'],
            })
        sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for e in open_rows:
            bucket = e['severity'] if e['severity'] in sev else 'medium'
            sev[bucket] += 1
        return {
            'incidents': entries,
            'total': len(entries),
            'summary': {
                'open': len(open_rows),
                'resolved': len(entries) - len(open_rows),
                'critical_open': sev['critical'],
                'high_open': sev['high'],
                'medium_open': sev['medium'],
                'low_open': sev['low'],
                'affected_servers': len({e['server_id'] for e in open_rows}),
                'by_code': by_code,
            },
        }


@router.get('/session-events')
def monitoring_session_events(current=Depends(require_current_session)):
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        ids=visible_ids(db,user)
        empty_summary = {
            'appeared': 0, 'disappeared': 0, 'unique_identities': 0,
            'by_server': [], 'window_note': 'Last 200 snapshot-inferred transitions',
        }
        if not ids:
            return {'events': [], 'total': 0, 'summary': empty_summary}
        records={s.id:s for s in db.scalars(select(Server).where(Server.id.in_(ids))).all()}
        entries=[]
        for item in db.scalars(select(SessionTransition).where(SessionTransition.server_id.in_(ids)).order_by(SessionTransition.id.desc()).limit(200)):
            server = records[item.server_id]
            entries.append({'id': item.id, 'server_id': item.server_id, 'server_name': server.name,
                'event': item.event, 'observed_at_utc': as_utc(item.observed_at).isoformat(),
                'username_or_common_name': item.identity, 'public_ip': item.client_public_ip,
                'vpn_ip': item.vpn_ip, 'source': 'snapshot_inferred', 'disconnect_reason': None})
        by_server_map: dict[str, dict] = {}
        for row in entries:
            bucket = by_server_map.setdefault(row['server_id'], {
                'server_id': row['server_id'], 'server_name': row['server_name'],
                'appeared': 0, 'disappeared': 0,
            })
            if row['event'] == 'appeared':
                bucket['appeared'] += 1
            elif row['event'] == 'disappeared':
                bucket['disappeared'] += 1
        by_server = sorted(by_server_map.values(), key=lambda x: -(x['appeared'] + x['disappeared']))
        summary = {
            'appeared': sum(1 for e in entries if e['event'] == 'appeared'),
            'disappeared': sum(1 for e in entries if e['event'] == 'disappeared'),
            'unique_identities': len({e['username_or_common_name'] for e in entries if e['username_or_common_name']}),
            'by_server': by_server[:40],
            'window_note': 'Last 200 snapshot-inferred transitions',
        }
        return {'events': entries, 'total': len(entries), 'summary': summary}


@router.get('/servers/{server_id}/history')
def monitoring_history(server_id: str, kind: str = Query('health',pattern='^(health|sessions)$'),
                       limit: int = Query(60, ge=1, le=240), current=Depends(require_current_session)):
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None or server.archived_at is not None or not can_access_client(db,user,server.client_id):
            raise HTTPException(status_code=404,detail='Server not found')
        records=db.scalars(select(TelemetrySample).where(TelemetrySample.server_id==server_id,
            TelemetrySample.kind==kind).order_by(TelemetrySample.id.desc()).limit(limit)).all()
        # No old status is represented as live. History is explicitly time-stamped.
        return {'server_id':server_id,'kind':kind,'samples':[
            {'at_utc':as_utc(item.collected_at).isoformat(), 'state':item.state,
             'data': json.loads(item.data_json) if kind=='health' else
                  {'total':json.loads(item.data_json).get('total'), 'state':item.state}}
            for item in records]}


def _safe_int(value, *, lo=0, hi=10**15):
    return value if isinstance(value, int) and lo <= value <= hi else (
        int(value) if isinstance(value, float) and value.is_integer() and lo <= value <= hi else None
    )


def _throughput_from_counters(points: list[dict], *, rx_key: str, tx_key: str, label: str) -> dict:
    """Derive Mbps from consecutive cumulative byte counters (read-only evidence)."""
    usable = [
        p for p in points
        if isinstance(p.get(rx_key), int) and isinstance(p.get(tx_key), int) and p.get('at_utc')
    ]
    if len(usable) < 2:
        return {
            'state': 'insufficient_samples',
            'rx_mbps': None, 'tx_mbps': None, 'window_seconds': None,
            'note': f'Need at least two stored health samples with {label} counters (auto-filled by worker)',
        }
    a, b = usable[-2], usable[-1]
    try:
        t0 = datetime.fromisoformat(a['at_utc'].replace('Z', '+00:00'))
        t1 = datetime.fromisoformat(b['at_utc'].replace('Z', '+00:00'))
    except (TypeError, ValueError):
        return {
            'state': 'unavailable', 'rx_mbps': None, 'tx_mbps': None, 'window_seconds': None,
            'note': 'Sample timestamps were not parseable',
        }
    window = (t1 - t0).total_seconds()
    if window < 5:
        return {
            'state': 'insufficient_samples', 'rx_mbps': None, 'tx_mbps': None, 'window_seconds': window,
            'note': 'Sample window too short for a stable Mbps estimate',
        }
    rx_delta = b[rx_key] - a[rx_key]
    tx_delta = b[tx_key] - a[tx_key]
    if rx_delta < 0 or tx_delta < 0:
        return {
            'state': 'unavailable', 'rx_mbps': None, 'tx_mbps': None, 'window_seconds': int(window),
            'note': f'{label} counters reset between samples',
        }
    return {
        'state': 'available',
        'rx_mbps': round((rx_delta * 8) / window / 1_000_000, 3),
        'tx_mbps': round((tx_delta * 8) / window / 1_000_000, 3),
        'window_seconds': int(window),
        'note': f'Average bits/sec over last two health samples ({label}) · not instantaneous peak',
    }


def _throughput_from_health_history(points: list[dict]) -> dict:
    return _throughput_from_counters(
        points, rx_key='rx_bytes_total', tx_key='tx_bytes_total', label='NIC',
    )


def _network_points_from_samples(samples) -> list[dict]:
    """Oldest→newest counter points from stored health TelemetrySample rows."""
    points = []
    for sample in reversed(list(samples)):
        try:
            payload = json.loads(sample.data_json)
        except (TypeError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        network = payload.get('network') if isinstance(payload.get('network'), dict) else {}
        openvpn = payload.get('openvpn') if isinstance(payload.get('openvpn'), dict) else {}
        points.append({
            'at_utc': as_utc(sample.collected_at).isoformat(),
            'state': sample.state,
            'rx_bytes_total': _safe_int(network.get('rx_bytes_total')),
            'tx_bytes_total': _safe_int(network.get('tx_bytes_total')),
            'rx_errors_total': _safe_int(network.get('rx_errors_total')),
            'tx_errors_total': _safe_int(network.get('tx_errors_total')),
            'rx_dropped_total': _safe_int(network.get('rx_dropped_total')),
            'tx_dropped_total': _safe_int(network.get('tx_dropped_total')),
            'network_interface': network.get('interface') if isinstance(network.get('interface'), str) else None,
            'tunnel_interface': openvpn.get('interface') if isinstance(openvpn.get('interface'), str) else None,
            'tunnel_rx_bytes_total': _safe_int(openvpn.get('rx_bytes_total')),
            'tunnel_tx_bytes_total': _safe_int(openvpn.get('tx_bytes_total')),
        })
    return points


@router.get('/network')
def monitoring_network(current=Depends(require_current_session)):
    """Fleet WAN + tunnel bandwidth board from stored health counter deltas."""
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        overview = overview_for_user(user, db)
        ids = visible_ids(db, user)
        name_by_id = {
            s.id: s.name
            for s in db.scalars(select(Server).where(Server.archived_at.is_(None))).all()
            if can_access_client(db, user, s.client_id)
        }
        servers_out = []
        for row in overview.get('servers') or []:
            sid = row.get('server_id')
            if sid not in ids:
                continue
            health = row.get('health') if isinstance(row.get('health'), dict) else {}
            data = health.get('data') if isinstance(health.get('data'), dict) else None
            network = data.get('network') if isinstance(data, dict) and isinstance(data.get('network'), dict) else {}
            openvpn = data.get('openvpn') if isinstance(data, dict) and isinstance(data.get('openvpn'), dict) else {}
            samples = db.scalars(select(TelemetrySample).where(
                TelemetrySample.server_id == sid, TelemetrySample.kind == 'health'
            ).order_by(TelemetrySample.id.desc()).limit(8)).all()
            points = _network_points_from_samples(samples)
            wan_tp = _throughput_from_counters(
                points, rx_key='rx_bytes_total', tx_key='tx_bytes_total', label='WAN NIC',
            )
            tun_tp = _throughput_from_counters(
                points, rx_key='tunnel_rx_bytes_total', tx_key='tunnel_tx_bytes_total', label='VPN tunnel',
            )
            rx_err = _safe_int(network.get('rx_errors_total'))
            tx_err = _safe_int(network.get('tx_errors_total'))
            rx_drop = _safe_int(network.get('rx_dropped_total'))
            tx_drop = _safe_int(network.get('tx_dropped_total'))
            integrity = 'ok'
            if any(isinstance(v, int) and v > 0 for v in (rx_err, tx_err, rx_drop, tx_drop)):
                integrity = 'attention'
            if not health.get('fresh') or not network:
                integrity = 'unknown'
            servers_out.append({
                'server_id': sid,
                'server_name': name_by_id.get(sid) or row.get('server_name') or sid,
                'monitoring_enabled': bool(row.get('monitoring_enabled')),
                'status': row.get('status'),
                'health_fresh': bool(health.get('fresh')),
                'observed_at_utc': health.get('at_utc'),
                'wan': {
                    'interface': network.get('interface') if isinstance(network.get('interface'), str) else None,
                    'rx_bytes_total': _safe_int(network.get('rx_bytes_total')),
                    'tx_bytes_total': _safe_int(network.get('tx_bytes_total')),
                    'rx_errors_total': rx_err,
                    'tx_errors_total': tx_err,
                    'rx_dropped_total': rx_drop,
                    'tx_dropped_total': tx_drop,
                    'throughput': wan_tp,
                },
                'tunnel': {
                    'interface': openvpn.get('interface') if isinstance(openvpn.get('interface'), str) else None,
                    'tunnel_ipv4': openvpn.get('tunnel_ipv4') if isinstance(openvpn.get('tunnel_ipv4'), str) else None,
                    'service_status': openvpn.get('service_status') if isinstance(openvpn.get('service_status'), str) else None,
                    'rx_bytes_total': _safe_int(openvpn.get('rx_bytes_total')),
                    'tx_bytes_total': _safe_int(openvpn.get('tx_bytes_total')),
                    'throughput': tun_tp,
                },
                'link_integrity': integrity,
                'sample_count': len(points),
            })

        wan_ok = [s for s in servers_out if s['wan']['throughput']['state'] == 'available']
        tun_ok = [s for s in servers_out if s['tunnel']['throughput']['state'] == 'available']
        sources = sum(1 for s in servers_out if s['health_fresh'] and s['wan']['rx_bytes_total'] is not None)
        attention = sum(1 for s in servers_out if s['link_integrity'] == 'attention')
        fleet_rx = round(sum(s['wan']['throughput']['rx_mbps'] or 0 for s in wan_ok), 3) if wan_ok else None
        fleet_tx = round(sum(s['wan']['throughput']['tx_mbps'] or 0 for s in wan_ok), 3) if wan_ok else None
        tun_rx = round(sum(s['tunnel']['throughput']['rx_mbps'] or 0 for s in tun_ok), 3) if tun_ok else None
        tun_tx = round(sum(s['tunnel']['throughput']['tx_mbps'] or 0 for s in tun_ok), 3) if tun_ok else None
        return {
            'worker': overview.get('worker'),
            'summary': {
                'enrolled': len([s for s in servers_out if s['monitoring_enabled']]),
                'counter_sources': sources,
                'wan_throughput_servers': len(wan_ok),
                'tunnel_throughput_servers': len(tun_ok),
                'fleet_wan_rx_mbps': fleet_rx,
                'fleet_wan_tx_mbps': fleet_tx,
                'fleet_tunnel_rx_mbps': tun_rx,
                'fleet_tunnel_tx_mbps': tun_tx,
                'link_attention': attention,
                'note': 'Mbps from consecutive health samples · WAN NIC and tunnel counters are separate · not latency probes',
            },
            'servers': servers_out,
        }


_SECURITY_INCIDENT_CODES = frozenset({
    'high_auth_failures', 'health_collection_failed', 'sessions_collection_failed',
    'health_degraded', 'vpn_service_inactive', 'vpn_observation_unavailable',
    'unreachable', 'high_cpu', 'high_ram', 'high_disk', 'session_overload',
})


def _cert_attention(cert: dict) -> str:
    state = cert.get('state')
    days = cert.get('days_remaining')
    if state == 'permission_needed':
        return 'permission'
    if state != 'available' or not isinstance(days, int):
        return 'unknown'
    if days < 0:
        return 'expired'
    if days <= 14:
        return 'critical'
    if days <= 30:
        return 'expiring'
    return 'ok'


@router.get('/security')
def monitoring_security(current=Depends(require_current_session)):
    """Fleet security evidence: certs, auth fails, journal peek, related incidents."""
    from backend.issue_engine import describe_incident
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        overview = overview_for_user(user, db)
        ids = visible_ids(db, user)
        name_by_id = {
            s.id: s.name
            for s in db.scalars(select(Server).where(Server.archived_at.is_(None))).all()
            if can_access_client(db, user, s.client_id)
        }
        open_incidents = []
        if ids:
            for incident in db.scalars(select(MonitorIncident).where(
                MonitorIncident.server_id.in_(ids),
                MonitorIncident.state == 'open',
            ).order_by(MonitorIncident.id.desc()).limit(300)):
                if incident.code not in _SECURITY_INCIDENT_CODES and not str(incident.code).endswith('_collection_failed'):
                    continue
                guide = describe_incident(incident.code)
                open_incidents.append({
                    'id': incident.id,
                    'server_id': incident.server_id,
                    'server_name': name_by_id.get(incident.server_id, incident.server_id),
                    'code': incident.code,
                    'title': guide['title'],
                    'severity': guide['severity'],
                    'summary': guide['summary'],
                    'solution': guide['solution'],
                    'opened_at_utc': as_utc(incident.opened_at).isoformat(),
                    'last_seen_at_utc': as_utc(incident.last_seen_at).isoformat(),
                })

        servers_out = []
        for row in overview.get('servers') or []:
            sid = row.get('server_id')
            if sid not in ids:
                continue
            health = row.get('health') if isinstance(row.get('health'), dict) else {}
            sessions = row.get('sessions') if isinstance(row.get('sessions'), dict) else {}
            hdata = health.get('data') if isinstance(health.get('data'), dict) else {}
            sdata = sessions.get('data') if isinstance(sessions.get('data'), dict) else {}
            # Prefer latest stored sample for observability (may be richer than overview cache).
            latest_health = db.scalars(select(TelemetrySample).where(
                TelemetrySample.server_id == sid, TelemetrySample.kind == 'health'
            ).order_by(TelemetrySample.id.desc()).limit(1)).first()
            latest_sessions = db.scalars(select(TelemetrySample).where(
                TelemetrySample.server_id == sid, TelemetrySample.kind == 'sessions'
            ).order_by(TelemetrySample.id.desc()).limit(1)).first()
            health_payload = hdata
            sessions_payload = sdata if isinstance(sdata, dict) else {}
            if latest_health is not None:
                try:
                    parsed = json.loads(latest_health.data_json)
                    if isinstance(parsed, dict):
                        health_payload = parsed
                except (TypeError, ValueError):
                    pass
            if latest_sessions is not None:
                try:
                    parsed = json.loads(latest_sessions.data_json)
                    if isinstance(parsed, dict):
                        sessions_payload = parsed
                except (TypeError, ValueError):
                    pass

            obs = _sanitize_observability(health_payload if isinstance(health_payload, dict) else {})
            cert = obs['certificate']
            journal = obs['journal']
            failures = sessions_payload.get('auth_failures') if isinstance(
                sessions_payload.get('auth_failures'), dict) else {}
            failed_n = failures.get('failed_attempts_observed')
            auth = {
                'state': 'available' if isinstance(failed_n, int) and 0 <= failed_n <= 100000 else 'unavailable',
                'failed_attempts_observed': failed_n if isinstance(failed_n, int) and 0 <= failed_n <= 100000 else None,
                'window_seconds': failures.get('window_seconds') if isinstance(failures.get('window_seconds'), int) else None,
                'note': (
                    'From readable local auth/VPN logs collected by the worker'
                    if isinstance(failed_n, int) else
                    'Auth-failure log source not readable yet'
                ),
            }
            cert_attn = _cert_attention(cert)
            auth_attn = 'elevated' if isinstance(failed_n, int) and failed_n >= 10 else (
                'ok' if isinstance(failed_n, int) else 'unknown'
            )
            server_incs = [i for i in open_incidents if i['server_id'] == sid]
            attention = 'ok'
            if cert_attn in ('expired', 'critical') or auth_attn == 'elevated' or any(
                i['severity'] == 'high' for i in server_incs
            ):
                attention = 'high'
            elif cert_attn in ('expiring', 'permission') or server_incs or journal.get('state') == 'permission_needed':
                attention = 'medium'
            elif not health.get('fresh'):
                attention = 'unknown'

            vpn = row.get('vpn_observation') if isinstance(row.get('vpn_observation'), dict) else {}
            servers_out.append({
                'server_id': sid,
                'server_name': name_by_id.get(sid) or row.get('server_name') or sid,
                'monitoring_enabled': bool(row.get('monitoring_enabled')),
                'status': row.get('status'),
                'health_fresh': bool(health.get('fresh')),
                'sessions_fresh': bool(sessions.get('fresh')),
                'observed_at_utc': health.get('at_utc') or sessions.get('at_utc'),
                'certificate': cert,
                'certificate_attention': cert_attn,
                'auth_failures': auth,
                'auth_attention': auth_attn,
                'journal': {
                    'state': journal.get('state'),
                    'unit': journal.get('unit'),
                    'line_count': len(journal.get('lines') or []),
                    'lines': (journal.get('lines') or [])[:5],
                    'note': journal.get('note'),
                },
                'protocol': vpn.get('protocol') or sessions_payload.get('protocol'),
                'open_security_incidents': len(server_incs),
                'attention': attention,
            })

        cert_ok = sum(1 for s in servers_out if s['certificate_attention'] == 'ok')
        cert_risk = sum(1 for s in servers_out if s['certificate_attention'] in ('expired', 'critical', 'expiring'))
        auth_sources = sum(1 for s in servers_out if s['auth_failures']['state'] == 'available')
        auth_elevated = sum(1 for s in servers_out if s['auth_attention'] == 'elevated')
        journal_ok = sum(1 for s in servers_out if s['journal']['state'] == 'available')
        high_attn = sum(1 for s in servers_out if s['attention'] == 'high')
        return {
            'worker': overview.get('worker'),
            'generated_at_utc': as_utc(utcnow()).isoformat(),
            'summary': {
                'enrolled': len([s for s in servers_out if s['monitoring_enabled']]),
                'cert_observed': cert_ok + cert_risk,
                'cert_attention': cert_risk,
                'auth_sources': auth_sources,
                'auth_elevated': auth_elevated,
                'journal_sources': journal_ok,
                'open_security_incidents': len(open_incidents),
                'servers_high_attention': high_attn,
                'note': 'Evidence from stored SSH health/session samples · not a compromise score or threat feed',
            },
            'servers': servers_out,
            'incidents': open_incidents[:80],
        }


def _sanitize_observability(payload: dict) -> dict:
    obs = payload.get('observability') if isinstance(payload.get('observability'), dict) else {}
    journal = obs.get('journal') if isinstance(obs.get('journal'), dict) else {}
    cert = obs.get('certificate') if isinstance(obs.get('certificate'), dict) else {}
    lines = journal.get('lines') if isinstance(journal.get('lines'), list) else []
    safe_lines = [str(x)[:240] for x in lines if isinstance(x, str)][:15]
    j_state = journal.get('state') if journal.get('state') in (
        'available', 'permission_needed', 'unavailable') else 'unavailable'
    c_state = cert.get('state') if cert.get('state') in (
        'available', 'permission_needed', 'unavailable') else 'unavailable'
    days = cert.get('days_remaining')
    return {
        'journal': {
            'state': j_state,
            'unit': journal.get('unit') if isinstance(journal.get('unit'), str) else None,
            'lines': safe_lines if j_state == 'available' else [],
            'note': journal.get('note') if isinstance(journal.get('note'), str) else None,
        },
        'certificate': {
            'state': c_state,
            'path': cert.get('path') if isinstance(cert.get('path'), str) and not str(cert.get('path')).endswith('.key') else None,
            'not_after': cert.get('not_after') if isinstance(cert.get('not_after'), str) else None,
            'not_after_utc': cert.get('not_after_utc') if isinstance(cert.get('not_after_utc'), str) else None,
            'days_remaining': days if isinstance(days, int) and -3650 <= days <= 36500 else None,
            'note': cert.get('note') if isinstance(cert.get('note'), str) else None,
        },
    }


def _safe_pct(value):
    return value if isinstance(value, (int, float)) and 0 <= float(value) <= 100 else None


def _pressure_level(cpu, ram, disk) -> str:
    vals = [v for v in (cpu, ram, disk) if isinstance(v, (int, float))]
    if not vals:
        return 'unknown'
    hot = max(vals)
    if hot >= 90:
        return 'critical'
    if hot >= 75:
        return 'elevated'
    return 'ok'


@router.get('/performance')
def monitoring_performance(hours: int = Query(24, ge=1, le=24),
                           current=Depends(require_current_session)):
    """Fleet CPU/RAM/disk pressure + recent sample series (cache-only, no SSH)."""
    if hours not in (1, 6, 24):
        raise HTTPException(422, detail='Available windows: 1, 6 or 24 hours')
    user, _ = current
    initialize_monitor_tables()
    now = utcnow()
    cutoff = now - timedelta(hours=hours)
    with SessionLocal() as db:
        overview = overview_for_user(user, db)
        ids = visible_ids(db, user)
        name_by_id = {
            s.id: s.name
            for s in db.scalars(select(Server).where(Server.archived_at.is_(None))).all()
            if can_access_client(db, user, s.client_id)
        }
        servers_out = []
        for row in overview.get('servers') or []:
            sid = row.get('server_id')
            if sid not in ids:
                continue
            health = row.get('health') if isinstance(row.get('health'), dict) else {}
            data = health.get('data') if isinstance(health.get('data'), dict) else {}
            live_cpu = _safe_pct(data.get('cpu_percent')) if health.get('fresh') else None
            live_ram = _safe_pct(data.get('memory_used_percent')) if health.get('fresh') else None
            live_disk = _safe_pct(data.get('disk_used_percent')) if health.get('fresh') else None
            uptime = data.get('uptime_seconds') if isinstance(
                data.get('uptime_seconds'), (int, float)) and data.get('uptime_seconds') >= 0 else None
            samples = db.scalars(select(TelemetrySample).where(
                TelemetrySample.server_id == sid,
                TelemetrySample.kind == 'health',
                TelemetrySample.collected_at >= cutoff,
            ).order_by(TelemetrySample.id.desc()).limit(48)).all()
            series = []
            cpu_vals, ram_vals, disk_vals = [], [], []
            for sample in reversed(list(samples)):
                try:
                    payload = json.loads(sample.data_json)
                except (TypeError, ValueError):
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                cpu = _safe_pct(payload.get('cpu_percent'))
                ram = _safe_pct(payload.get('memory_used_percent'))
                disk = _safe_pct(payload.get('disk_used_percent'))
                if cpu is not None:
                    cpu_vals.append(float(cpu))
                if ram is not None:
                    ram_vals.append(float(ram))
                if disk is not None:
                    disk_vals.append(float(disk))
                series.append({
                    'at_utc': as_utc(sample.collected_at).isoformat(),
                    'cpu_percent': cpu,
                    'memory_used_percent': ram,
                    'disk_used_percent': disk,
                })

            def _avg(vals):
                return round(sum(vals) / len(vals), 2) if vals else None

            def _peak(vals):
                return round(max(vals), 2) if vals else None

            pressure = _pressure_level(live_cpu, live_ram, live_disk)
            live_vals = [v for v in (live_cpu, live_ram, live_disk) if isinstance(v, (int, float))]
            headroom = round(100 - max(live_vals), 1) if live_vals else None
            hottest = None
            if live_vals:
                ranked = [(k, v) for k, v in (
                    ('cpu', live_cpu), ('memory', live_ram), ('disk', live_disk)
                ) if isinstance(v, (int, float))]
                hottest = max(ranked, key=lambda x: x[1])[0] if ranked else None
            servers_out.append({
                'server_id': sid,
                'server_name': name_by_id.get(sid) or row.get('server_name') or sid,
                'monitoring_enabled': bool(row.get('monitoring_enabled')),
                'status': row.get('status'),
                'health_fresh': bool(health.get('fresh')),
                'observed_at_utc': health.get('at_utc'),
                'live': {
                    'cpu_percent': live_cpu,
                    'memory_used_percent': live_ram,
                    'disk_used_percent': live_disk,
                    'uptime_seconds': int(uptime) if isinstance(uptime, (int, float)) else None,
                },
                'window': {
                    'hours': hours,
                    'sample_count': len(series),
                    'avg_cpu_percent': _avg(cpu_vals),
                    'avg_memory_percent': _avg(ram_vals),
                    'avg_disk_percent': _avg(disk_vals),
                    'peak_cpu_percent': _peak(cpu_vals),
                    'peak_memory_percent': _peak(ram_vals),
                    'peak_disk_percent': _peak(disk_vals),
                },
                'pressure': pressure,
                'hottest_resource': hottest,
                'headroom_percent': headroom,
                'series': series[-24:],
            })

        observed = [s for s in servers_out if s['health_fresh'] and any(
            isinstance(s['live'][k], (int, float))
            for k in ('cpu_percent', 'memory_used_percent', 'disk_used_percent')
        )]
        pressure_counts = {
            'critical': sum(1 for s in servers_out if s['pressure'] == 'critical'),
            'elevated': sum(1 for s in servers_out if s['pressure'] == 'elevated'),
            'ok': sum(1 for s in servers_out if s['pressure'] == 'ok'),
            'unknown': sum(1 for s in servers_out if s['pressure'] == 'unknown'),
        }
        hist_samples = sum(s['window']['sample_count'] for s in servers_out)
        heads = [s['headroom_percent'] for s in observed if isinstance(s['headroom_percent'], (int, float))]
        avg_headroom = round(sum(heads) / len(heads), 1) if heads else None
        return {
            'worker': overview.get('worker'),
            'period_hours': hours,
            'generated_at_utc': as_utc(now).isoformat(),
            'summary': {
                'enrolled': len([s for s in servers_out if s['monitoring_enabled']]),
                'observed': len(observed),
                'history_samples': hist_samples,
                'pressure': pressure_counts,
                'avg_headroom_percent': avg_headroom,
                'note': 'Live values from fresh health · window averages from stored samples · not capacity forecasts or ISP SLAs',
            },
            'servers': servers_out,
        }


@router.get('/servers/{server_id}/360')
def server_360_snapshot(server_id: str, limit: int = Query(48, ge=1, le=96),
                        current=Depends(require_current_session)):
    """Server-scoped, cache-only evidence. NEVER starts an SSH request or returns credentials.

    Historical samples are intentionally distinct from fresh readings, with bounded
    counts. The existing worker determines freshness and collection errors. A stale
    or offline worker must never make an old sample look current.
    """
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None or server.archived_at is not None or not can_access_client(db, user, server.client_id):
            raise HTTPException(status_code=404, detail='Server not found')

        # Reuse the same freshness, worker-heartbeat and authorization semantics
        # as /overview; do not implement a contradictory status classifier.
        overview = overview_for_user(user, db)
        monitor = next((row for row in overview['servers'] if row['server_id'] == server_id), None)
        if monitor is None:
            raise HTTPException(status_code=404, detail='Server not found')

        history = {'health': [], 'sessions': []}
        latest_health_payload: dict = {}
        latest_sessions_payload: dict = {}
        for kind in ('health', 'sessions'):
            samples = db.scalars(select(TelemetrySample).where(
                TelemetrySample.server_id == server_id, TelemetrySample.kind == kind
            ).order_by(TelemetrySample.id.desc()).limit(limit)).all()
            for sample in reversed(samples):
                # Explicit allowlist avoids returning keys, paths or other unknown
                # future collector fields stored in the JSON document.
                try:
                    payload = json.loads(sample.data_json)
                except (TypeError, ValueError):
                    payload = {}
                if not isinstance(payload, dict):
                    payload = {}
                if kind == 'health':
                    latest_health_payload = payload
                else:
                    latest_sessions_payload = payload
                point = {'at_utc': as_utc(sample.collected_at).isoformat(),
                         'state': sample.state}
                if kind == 'health':
                    for field in ('cpu_percent', 'memory_used_percent', 'disk_used_percent', 'uptime_seconds'):
                        value = payload.get(field)
                        point[field] = (value if type(value) in (int, float) and
                                        0 <= value <= (100 if field != 'uptime_seconds' else 10**12) else None)
                    network = payload.get('network')
                    if isinstance(network, dict):
                        point['network_interface'] = network.get('interface') if isinstance(network.get('interface'), str) else None
                        point['rx_bytes_total'] = _safe_int(network.get('rx_bytes_total'))
                        point['tx_bytes_total'] = _safe_int(network.get('tx_bytes_total'))
                    else:
                        point['network_interface'] = None
                        point['rx_bytes_total'] = None
                        point['tx_bytes_total'] = None
                else:
                    value = payload.get('total')
                    point['connections'] = value if sample.state == 'available' and type(value) is int and 0 <= value <= 1000 else None
                history[kind].append(point)

        obs = _sanitize_observability(latest_health_payload)
        failures = latest_sessions_payload.get('auth_failures') if isinstance(
            latest_sessions_payload.get('auth_failures'), dict) else {}
        failed_n = failures.get('failed_attempts_observed')
        auth_events = {
            'state': 'available' if isinstance(failed_n, int) and failed_n >= 0 else 'unavailable',
            'failed_attempts_observed': failed_n if isinstance(failed_n, int) and 0 <= failed_n <= 100000 else None,
            'window_seconds': failures.get('window_seconds') if isinstance(failures.get('window_seconds'), int) else None,
            'note': (
                'From readable local auth/VPN logs collected by the worker'
                if isinstance(failed_n, int) else
                'Auth-failure log source not readable yet (permission or no log path)'
            ),
        }
        evidence = {
            'throughput': _throughput_from_health_history(history['health']),
            'journal': obs['journal'],
            'certificate': obs['certificate'],
            'tls_auth_events': auth_events,
            'collection': {
                'mode': 'auto_after_enroll',
                'note': 'Worker runs read-only SSH collectors after enroll; this API never starts SSH',
            },
        }

        incidents = db.scalars(select(MonitorIncident).where(
            MonitorIncident.server_id == server_id
        ).order_by(MonitorIncident.id.desc()).limit(20)).all()
        return {
            'server_id': server_id,
            'source': 'stored_ssh_snapshots',
            'worker': overview['worker'],
            'monitor': {
                'server_id': server_id,
                'status': monitor['status'],
                'monitoring_enabled': monitor['monitoring_enabled'],
                'error_code': monitor['error_code'],
                'last_checked_utc': monitor['last_checked_utc'],
                'health': {key: monitor['health'][key] for key in ('state', 'at_utc', 'age_seconds', 'fresh')},
                'sessions': {key: monitor['sessions'][key] for key in ('state', 'at_utc', 'age_seconds', 'fresh')},
            },
            'history': history,
            'evidence': evidence,
            'incidents': [{
                'id': incident.id, 'code': incident.code, 'state': incident.state,
                'opened_at_utc': as_utc(incident.opened_at).isoformat(),
                'last_seen_at_utc': as_utc(incident.last_seen_at).isoformat(),
                'resolved_at_utc': as_utc(incident.resolved_at).isoformat() if incident.resolved_at else None,
            } for incident in incidents],
            'limits': {'history_max_points_per_kind': 96, 'incidents_max_records': 20,
                       'history_is_live': False},
        }
