"""Step 39.1: on-demand, read-only OpenVPN session details for approved VPS.

No sudo, configuration writes, management socket, client disconnects, or key reads.
Connection fields may contain personal data; callers MUST enforce server-side RBAC.
"""
from __future__ import annotations

import json
import shlex
from typing import Any

from backend.ssh_monitor import SSHConnectionConfig, _connect_verified, _validate_remote_identifier


# Remote Python script runs using the already-approved SSH monitoring identity.
# It parses ONLY the selected OpenVPN service's fresh, readable status file.
# No extra permissions are requested or changed.
_REMOTE_VPN_SESSIONS_SCRIPT = r'''
import csv
import ipaddress
import json
import os
import shlex
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
MAX_AGE_SECONDS = 120
MAX_SESSIONS = 1000


def candidates_for_service(service):
    if not service.startswith('openvpn-server@'):
        return []
    instance = service.split('@', 1)[1].removesuffix('.service')
    if not instance or not all(ch.isalnum() or ch in '_-' for ch in instance):
        return []
    names = [
        '/run/openvpn-server/status-' + instance + '.log',
        '/run/openvpn/status-' + instance + '.log',
        '/var/log/openvpn/status-' + instance + '.log',
        '/var/log/openvpn/' + instance + '-status.log',
        '/var/log/openvpn/status-' + instance + '.txt',
        '/var/log/openvpn/' + instance + '-status.txt',
        '/var/log/openvpn-status-' + instance + '.log',
        '/etc/openvpn/server/status-' + instance + '.log',
    ]
    # Explicit per-instance status directive, only when config is readable.
    config = Path('/etc/openvpn/server') / (instance + '.conf')
    try:
        if config.is_file() and config.stat().st_size <= 65536:
            for line in config.read_text(encoding='utf-8', errors='replace').splitlines():
                if not line.strip() or line.lstrip().startswith(('#', ';')):
                    continue
                try:
                    parts = shlex.split(line, comments=True)
                except ValueError:
                    continue
                if len(parts) >= 2 and parts[0] == 'status' and parts[1].startswith('/'):
                    # Use only paths within vetted OpenVPN log/runtime folders.
                    from pathlib import PurePosixPath
                    p = str(PurePosixPath(parts[1]))
                    allowed = ('/run/openvpn-server/', '/run/openvpn/', '/var/log/openvpn/', '/etc/openvpn/server/')
                    if p.startswith(allowed) and '..' not in PurePosixPath(parts[1]).parts:
                        names.insert(0, p)
                    break
    except (OSError, UnicodeError):
        pass
    return list(dict.fromkeys(names))


def public_ip(value):
    """Normalize OpenVPN's Real Address to a verified IP, never a hostname.

    OpenVPN can emit bare IPs, IPv4:port, bracketed IPv6:port, or transport-
    tagged endpoints such as udp4:IP:port / tcp4-server:IP:port. Keep the
    parser strict: reject junk, invalid ports and unsupported prefixes.
    """
    import re

    if not isinstance(value, str):
        return None
    address = value.strip()
    if not address:
        return None

    # OpenVPN 2.7 transport-qualified Real Address (2.6 uses plain IP:port).
    tagged = re.match(r'^(?:udp|tcp)[46](?:-(?:server|client))?:', address, re.I)
    if tagged:
        address = address[tagged.end():]

    # Some OpenVPN endpoint renderings use an address-family marker.
    family = re.match(r'^\[AF_INET6?\]', address)
    if family:
        address = address[family.end():]

    def normalized(host):
        if not host or '%' in host:
            return None
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            return None

    def valid_port(port):
        return port.isascii() and port.isdecimal() and 0 < int(port) <= 65535

    if address.startswith('['):
        # Bracketed IPv6, optionally followed by :port.
        match = re.fullmatch(r'\[([^\]\r\n]+)\](?::([0-9]+))?', address)
        if not match or (match[2] is not None and not valid_port(match[2])):
            return None
        return normalized(match[1])

    direct = normalized(address)
    if direct is not None:
        return direct

    if ':' in address:
        host, port = address.rsplit(':', 1)
        if valid_port(port):
            return normalized(host)
    return None


def safe_text(value, max_length=160):
    if not isinstance(value, str):
        return None
    value = ''.join(ch for ch in value if ch.isprintable()).strip()
    return value[:max_length] if value else None


def nonnegative_int(value):
    try:
        number = int(str(value).strip())
        return number if number >= 0 else None
    except (TypeError, ValueError):
        return None


def parse_status(text):
    """Return list of connections, or None for malformed/unrecognized format."""
    lines = text.splitlines()
    if not lines:
        return None
    delimiter = next((d for d in ('\t', ',') if any(
        line.startswith('HEADER' + d + 'CLIENT_LIST' + d) for line in lines)), None)
    records = []
    if delimiter:
        try:
            rows = list(csv.reader(lines, delimiter=delimiter, strict=True))
        except csv.Error:
            return None
        headers = [row[2:] for row in rows if len(row) >= 3 and row[:2] == ['HEADER', 'CLIENT_LIST']]
        if not headers or not any(row and row[0] in ('TIME', 'TITLE') for row in rows) or not any(row and row[0] == 'END' for row in rows):
            return None
        columns = headers[0]
        for required in ('Common Name', 'Real Address', 'Bytes Received', 'Bytes Sent'):
            if required not in columns:
                return None
        for row in rows:
            if not row or row[0] != 'CLIENT_LIST':
                continue
            values = row[1:]
            if len(values) != len(columns) or len(records) >= MAX_SESSIONS:
                return None
            records.append(dict(zip(columns, values)))
    else:
        if not lines[0].startswith('OpenVPN CLIENT LIST'):
            return None
        try:
            first = next(i for i, line in enumerate(lines) if line.startswith('Common Name,Real Address,'))
            end = next(i for i in range(first + 1, len(lines)) if lines[i].strip() == 'ROUTING TABLE')
            content = list(csv.reader(lines[first:end], strict=True))
        except (StopIteration, csv.Error):
            return None
        if not content:
            return None
        columns = content[0]
        if not all(col in columns for col in ('Common Name', 'Real Address', 'Bytes Received', 'Bytes Sent')):
            return None
        for row in content[1:]:
            if not row:
                continue
            if len(row) != len(columns) or len(records) >= MAX_SESSIONS:
                return None
            records.append(dict(zip(columns, row)))
        if not any(line.strip() == 'END' for line in lines):
            return None

    sessions = []
    for index, record in enumerate(records):
        # One CLIENT_LIST row = one CONNECTION. Never deduplicate usernames/CNs.
        started = nonnegative_int(record.get('Connected Since (time_t)'))
        sessions.append({
            'connection_number': index + 1,
            'common_name': safe_text(record.get('Common Name')),
            'username': safe_text(record.get('Username')),
            'public_ip': public_ip(record.get('Real Address')),
            'vpn_ip': safe_text(record.get('Virtual Address'), 64),
            'vpn_ipv6': safe_text(record.get('Virtual IPv6 Address'), 64),
            'bytes_received': nonnegative_int(record.get('Bytes Received')),
            'bytes_sent': nonnegative_int(record.get('Bytes Sent')),
            'connected_since_unix': started,
            'client_id': nonnegative_int(record.get('Client ID')),
        })
    return sessions


def collect_for_service(service):
    """State is not 'available' unless a fresh parseable file was read."""
    try:
        result = subprocess.run(['systemctl', 'is-active', service], capture_output=True,
                                text=True, timeout=5, check=False)
        active = result.stdout.strip() == 'active'
    except (OSError, subprocess.TimeoutExpired):
        active = False
    if not active:
        return {'state': 'vpn_not_active', 'total': None, 'sessions': [], 'status_age_seconds': None}
    saw_permission_error = False
    saw_stale = False
    for candidate in candidates_for_service(service):
        path = Path(candidate)
        try:
            meta = path.stat()
            if not path.is_file() or meta.st_size <= 0 or meta.st_size > MAX_BYTES:
                continue
            age = max(0, int(time.time() - meta.st_mtime))
            if age > MAX_AGE_SECONDS:
                saw_stale = True
                continue
            sessions = parse_status(path.read_text(encoding='utf-8', errors='replace'))
            if sessions is not None:
                return {'state': 'available', 'total': len(sessions),
                        'sessions': sessions, 'status_age_seconds': age}
        except PermissionError:
            saw_permission_error = True
        except (OSError, UnicodeError):
            continue
    state = 'permission_required' if saw_permission_error else 'stale_status' if saw_stale else 'status_unavailable'
    return {'state': state, 'total': None, 'sessions': [], 'status_age_seconds': None}

def auth_failures_openvpn():
    """Best-effort failed-auth count from world-readable logs (no sudo)."""
    import pathlib
    failed = 0
    paths = list(pathlib.Path('/var/log').glob('openvpn*.log'))[:6]
    ovpn_dir = pathlib.Path('/var/log/openvpn')
    if ovpn_dir.is_dir():
        paths += list(ovpn_dir.glob('*.log'))[:6]
    patterns = ('AUTH_FAILED', 'TLS Error', 'authentication failed')
    for path in paths[:8]:
        try:
            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                continue
            data = path.read_bytes()[-262144:].decode('utf-8', errors='replace')
            for line in data.splitlines()[-2000:]:
                low = line.lower()
                if any(p.lower() in low for p in patterns):
                    failed += 1
        except OSError:
            continue
    return {'window_seconds': 3600, 'failed_attempts_observed': failed, 'source': 'local_readable_logs'}


service = os.environ['SENTINEL_VPN_SERVICE']
result = collect_for_service(service)
result['collected_at_utc'] = datetime.now(timezone.utc).isoformat()
result['auth_failures'] = auth_failures_openvpn()
print(json.dumps(result, separators=(',', ':')))
'''.strip()


def collect_live_vpn_sessions(config: SSHConnectionConfig, *, vpn_service: str) -> dict[str, Any]:
    """On-demand SSH read; never trigger remote writes or installation."""
    service = _validate_remote_identifier(vpn_service, 'VPN service')
    # Narrow scope: only OpenVPN systemd instances, not arbitrary services.
    if not service.startswith('openvpn-server@') or service.endswith('@'):
        raise ValueError('Unsupported OpenVPN service')
    command = (
        f'SENTINEL_VPN_SERVICE={shlex.quote(service)} python3 - <<\'SENTINEL_READ_ONLY_SESSIONS\'\n'
        f'{_REMOTE_VPN_SESSIONS_SCRIPT}\n'
        'SENTINEL_READ_ONLY_SESSIONS\n'
    )
    client = _connect_verified(config)
    try:
        _, stdout, stderr = client.exec_command(command, timeout=25)
        raw = stdout.read(2_500_001)
        # Never expose stderr (possibly host/environment details) to frontend.
        stderr.read(2048)
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0 or len(raw) >= 2_500_001:
            raise RuntimeError('Read-only VPN session collection failed')
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise RuntimeError('VPN session collector returned invalid data') from exc
        if not isinstance(payload, dict) or payload.get('state') not in {
            'available', 'vpn_not_active', 'permission_required', 'stale_status', 'status_unavailable'
        }:
            raise RuntimeError('VPN session collector returned an invalid state')
        if payload['state'] == 'available':
            sessions = payload.get('sessions')
            if not isinstance(sessions, list) or len(sessions) > 1000 or payload.get('total') != len(sessions):
                raise RuntimeError('VPN session collector returned invalid rows')
        else:
            payload['total'] = None
            payload['sessions'] = []
        # Expose only expected normalized keys, not unknown SSH/remote metadata.
        failures = payload.get('auth_failures')
        if not isinstance(failures, dict):
            failures = None
        return {
            'state': payload['state'],
            'total': payload['total'],
            'sessions': payload['sessions'],
            'status_age_seconds': payload.get('status_age_seconds'),
            'collected_at_utc': payload.get('collected_at_utc'),
            'auth_failures': failures,
        }
    finally:
        client.close()
