"""Issue detection + operator solutions for Stag Prime Sentinel fleet ops.

Derives actionable issues from monitoring cache / live session payloads.
Never invents connection counts; unknowns stay unknown.
"""
from __future__ import annotations

import os
from typing import Any

# Concurrent VPN sessions at/above this count raise a high alert (operator can override).
SESSION_OVERLOAD_THRESHOLD = max(5, int(os.environ.get('SENTINEL_SESSION_ALERT_THRESHOLD', '40') or '40'))


SOLUTIONS: dict[str, dict[str, str]] = {
    'worker_offline': {
        'title': 'Monitoring worker not running',
        'severity': 'high',
        'summary': 'No fresh samples are arriving from the background collector.',
        'solution': 'Run START_ALL.bat (or Sentinel_Start_Local_All.py) and confirm Worker: Running on the dashboard.',
    },
    'not_enrolled': {
        'title': 'Server not enrolled for monitoring',
        'severity': 'medium',
        'summary': 'Inventory exists but continuous SSH polling is not approved.',
        'solution': 'Open Server Inventory → enroll SSH key/password → Verify SSH → Enroll monitoring (or use Quick Onboard).',
    },
    'unreachable': {
        'title': 'SSH collector unreachable',
        'severity': 'high',
        'summary': 'Sentinel cannot open a verified SSH session to this host.',
        'solution': 'Confirm VPS power, security-list/firewall allows your Sentinel IP on the SSH port, and vault credentials still work. Re-run Admin SSH Verify.',
    },
    'vpn_service_down': {
        'title': 'VPN service not active',
        'severity': 'high',
        'summary': 'The selected VPN protocol service is not running, so clients cannot connect.',
        'solution': 'Use Server Control → Start/Restart VPN for the enrolled protocol, then recheck sessions. Verify systemd unit name matches discovery.',
    },
    'vpn_service_inactive': {
        'title': 'VPN service inactive',
        'severity': 'high',
        'summary': 'Collector observed the enrolled VPN unit as inactive or failed.',
        'solution': 'Use Server Control → Start/Restart VPN, confirm the systemd unit name, then wait for the next session poll.',
    },
    'sessions_unavailable': {
        'title': 'Session status unavailable',
        'severity': 'medium',
        'summary': 'Host is reachable but live session evidence could not be read.',
        'solution': 'For OpenVPN enable a readable status file; for WireGuard ensure `wg` is installed; for IKEv2 ensure swanctl/ipsec status is readable by the SSH user.',
    },
    'vpn_observation_unavailable': {
        'title': 'VPN observation unavailable',
        'severity': 'medium',
        'summary': 'A readable VPN session/status source was not available on the last poll.',
        'solution': 'Verify status-file permissions or protocol tooling (`wg` / swanctl), then confirm sessions on VPN Sessions after the next poll.',
    },
    'health_collection_failed': {
        'title': 'Health collection failed',
        'severity': 'high',
        'summary': 'Repeated SSH health polls failed for this server.',
        'solution': 'Verify SSH reachability and vault credentials, check collector errors on Server 360, then wait for auto-retry or Refresh.',
    },
    'sessions_collection_failed': {
        'title': 'Session collection failed',
        'severity': 'medium',
        'summary': 'Repeated VPN session polls failed while health may still be fine.',
        'solution': 'Confirm the VPN status source is readable by the SSH user; health can succeed while sessions stay unavailable.',
    },
    'high_auth_failures': {
        'title': 'Elevated authentication failures',
        'severity': 'medium',
        'summary': 'Recent VPN auth logs show many failed attempts (wrong password, TLS, or proposal mismatch).',
        'solution': 'Check client profiles (protocol/cipher/PSK), reset compromised credentials, and rate-limit/firewall abusive source IPs.',
    },
    'high_cpu': {
        'title': 'High CPU pressure',
        'severity': 'high',
        'summary': 'CPU utilization is elevated on the VPS.',
        'solution': 'Inspect top processes via Issue Diagnosis diagnostics, scale the VPS, or reduce crypto load (cipher choice / concurrent users).',
    },
    'high_ram': {
        'title': 'High memory pressure',
        'severity': 'high',
        'summary': 'RAM usage is elevated.',
        'solution': 'Review memory diagnostic, avoid blind cache drops, consider upgrade or limit concurrent sessions.',
    },
    'high_disk': {
        'title': 'Disk nearly full',
        'severity': 'high',
        'summary': 'Root filesystem usage is critical.',
        'solution': 'Clear old VPN/system logs safely, expand disk, and ensure logrotate is active before service disruption.',
    },
    'session_overload': {
        'title': 'Too many VPN users connected',
        'severity': 'high',
        'summary': 'Concurrent VPN sessions exceeded the operator high-alert threshold.',
        'solution': 'Review connected users in Fleet Ops / Server card, kick abusive sessions, or scale the VPS / add capacity.',
    },
    'health_degraded': {
        'title': 'Server health degraded',
        'severity': 'high',
        'summary': 'SSH collector reported degraded or failed host health.',
        'solution': 'Confirm VPS reachability and credentials, then wait for auto-recovery or Refresh monitored servers.',
    },
    'stale': {
        'title': 'Stale monitoring data',
        'severity': 'low',
        'summary': 'Last sample is older than the freshness window.',
        'solution': 'Confirm worker heartbeat and SSH reachability; force a refresh after connectivity is restored.',
    },
    'zero_sessions_service_up': {
        'title': 'VPN up but no connected users',
        'severity': 'low',
        'summary': 'Service is active while zero sessions are observed.',
        'solution': 'Normal if idle. If users report outages, verify client configs, DNS/routing, and firewall ports for the protocol (UDP 1194 / 51820 / 500+4500).',
    },
}


def _num(data: dict | None, key: str) -> float | None:
    if not data:
        return None
    value = data.get(key)
    return float(value) if isinstance(value, (int, float)) and value == value else None


def describe_incident(code: str | None) -> dict[str, str]:
    """Map a stored MonitorIncident.code to operator-facing guidance (no SSH)."""
    key = (code or '').strip().lower().replace(' ', '_')
    aliases = {
        'vpn_service_down': 'vpn_service_inactive',
        'sessions_unavailable': 'vpn_observation_unavailable',
    }
    # Prefer exact catalog entries; allow alias either direction.
    meta = SOLUTIONS.get(key)
    if meta is None and key in aliases:
        meta = SOLUTIONS.get(aliases[key])
    if meta is None:
        for alias_from, alias_to in aliases.items():
            if key == alias_to:
                meta = SOLUTIONS.get(alias_from)
                break
    if meta:
        return {
            'code': key or 'unknown',
            'title': meta['title'],
            'severity': meta['severity'],
            'summary': meta['summary'],
            'solution': meta['solution'],
        }
    title = (key or 'unknown').replace('_', ' ').strip() or 'Unknown incident'
    return {
        'code': key or 'unknown',
        'title': title[:80].title(),
        'severity': 'medium',
        'summary': 'Recorded by the monitoring worker from collector evidence.',
        'solution': 'Open Server 360 for this host, confirm worker status, and review the latest health/session samples.',
    }


def analyze_server(
    *,
    status: str | None,
    monitoring_enabled: bool,
    worker_running: bool,
    health: dict[str, Any] | None,
    sessions: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Return issue dicts with code/title/severity/summary/solution."""
    found: list[str] = []
    if not worker_running:
        found.append('worker_offline')
    if not monitoring_enabled:
        found.append('not_enrolled')
    if status == 'unreachable':
        found.append('unreachable')
    if status in ('degraded',):
        found.append('health_degraded')
    if status == 'stale':
        found.append('stale')

    if isinstance(health, dict):
        openvpn = health.get('openvpn')
        if isinstance(openvpn, dict):
            svc = openvpn.get('service_status')
            if svc and svc != 'active':
                found.append('vpn_service_down')
        # Multi-protocol hints from health payload when present
        for key in ('wireguard', 'ikev2', 'vpn'):
            block = health.get(key)
            if isinstance(block, dict):
                svc = block.get('service_status') or block.get('status')
                if svc and svc not in ('active', 'up', 'running'):
                    found.append('vpn_service_down')
        if health.get('vpn_sessions_state') == 'vpn_not_active':
            found.append('vpn_service_down')

    cpu = _num(health if isinstance(health, dict) else None, 'cpu_percent')
    ram = _num(health if isinstance(health, dict) else None, 'memory_used_percent')
    disk = _num(health if isinstance(health, dict) else None, 'disk_used_percent')
    if cpu is not None and cpu >= 90:
        found.append('high_cpu')
    if ram is not None and ram >= 90:
        found.append('high_ram')
    if disk is not None and disk >= 90:
        found.append('high_disk')

    if isinstance(sessions, dict):
        state = sessions.get('state')
        if state not in (None, 'available', 'vpn_not_active'):
            found.append('sessions_unavailable')
        if state == 'vpn_not_active':
            found.append('vpn_service_down')
        if state == 'available' and sessions.get('total') == 0:
            found.append('zero_sessions_service_up')
        total = sessions.get('total')
        if state == 'available' and isinstance(total, int) and total >= SESSION_OVERLOAD_THRESHOLD:
            found.append('session_overload')
        failures = sessions.get('auth_failures')
        if isinstance(failures, dict):
            n = failures.get('failed_attempts_observed')
            if isinstance(n, int) and n >= 25:
                found.append('high_auth_failures')

    # de-dupe preserving order
    codes = list(dict.fromkeys(found))
    issues = []
    for code in codes:
        meta = SOLUTIONS[code]
        issues.append({'code': code, **meta})
    return issues


def fleet_connection_summary(servers: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate connected users + issue counts across cached overview rows."""
    connected = 0
    connected_coverage = 0
    enrolled = 0
    issue_total = 0
    failed_auth = 0
    by_protocol: dict[str, int] = {'openvpn': 0, 'wireguard': 0, 'ikev2': 0, 'unknown': 0}
    for row in servers:
        if not row.get('monitoring_enabled'):
            continue
        enrolled += 1
        sessions = (row.get('sessions') or {}).get('data') if isinstance(row.get('sessions'), dict) else None
        if isinstance(sessions, dict) and sessions.get('state') == 'available' and isinstance(sessions.get('total'), int):
            connected += sessions['total']
            connected_coverage += 1
            proto = sessions.get('protocol') or 'unknown'
            if proto not in by_protocol:
                proto = 'unknown'
            by_protocol[proto] += sessions['total']
            failures = sessions.get('auth_failures') or {}
            if isinstance(failures.get('failed_attempts_observed'), int):
                failed_auth += failures['failed_attempts_observed']
        health = (row.get('health') or {}).get('data') if isinstance(row.get('health'), dict) else None
        issue_total += len(analyze_server(
            status=row.get('status'),
            monitoring_enabled=True,
            worker_running=True,
            health=health if isinstance(health, dict) else None,
            sessions=sessions if isinstance(sessions, dict) else None,
        ))
    return {
        'enrolled_servers': enrolled,
        'connected_users': connected if connected_coverage else None,
        'connected_source_servers': connected_coverage,
        'failed_auth_observations': failed_auth,
        'open_issue_signals': issue_total,
        'connected_by_protocol': by_protocol,
        'note': 'Connected users only count servers with fresh available session evidence.',
    }
