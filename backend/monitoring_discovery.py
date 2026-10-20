"""Stag Prime Sentinel: read-only, host-key-verified OpenVPN discovery.

Discovery never approves hosts, changes VPN configuration, reads VPN user
credentials, runs sudo, or changes remote filesystem contents. The local-only
monitoring_setup CLI has a separate explicit approval step.
"""
from __future__ import annotations

import json
import re
import shlex
from typing import Any

# This script is fixed source code, never constructed from user input.
# It executes over an already host-key-verified SSH connection without sudo.
_REMOTE_DISCOVERY_SCRIPT = r'''
import json
import os
import re
import shlex
import socket
import subprocess
from pathlib import Path


def run(*args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, check=False, timeout=8)
        return result.stdout if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def get_ipv4_interfaces():
    try:
        result = json.loads(run('ip', '-j', '-4', 'addr', 'show'))
        if isinstance(result, list):
            return result
    except (ValueError, TypeError):
        pass
    return []


def default_wan_devices():
    try:
        routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))
        return sorted({entry['dev'] for entry in routes if isinstance(entry, dict) and entry.get('dev')})
    except (ValueError, KeyError, TypeError):
        return []


def first_ipv4(entry):
    for addr in entry.get('addr_info', []):
        if addr.get('family') == 'inet' and addr.get('local'):
            return addr['local'] + '/' + str(addr.get('prefixlen', 32))
    return None


def get_active_vpn_services():
    data = run('systemctl', 'list-units', '--type=service', '--all', '--plain', '--no-legend', '--no-pager')
    results = []
    for line in data.splitlines():
        fields = line.strip().lstrip('● ').split()
        if len(fields) >= 4 and re.fullmatch(r'openvpn-server@[A-Za-z0-9_.-]+\.service', fields[0]):
            if fields[2] == 'active' and fields[3] == 'running':
                results.append(fields[0][:-8])  # Drop .service suffix.
    return sorted(set(results))


def parse_conf(service):
    instance = service.split('@', 1)[1]
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', instance):
        return None, None
    file = Path('/etc/openvpn/server') / (instance + '.conf')
    try:
        if not file.is_file() or file.stat().st_size > 65536:
            return None, None
        data = file.read_text(encoding='utf-8', errors='replace')
    except (OSError, UnicodeError):
        return None, None
    dev, status = None, None
    for line in data.splitlines():
        try:
            fields = shlex.split(line, comments=True)
        except ValueError:
            continue
        if len(fields) >= 2 and fields[0] == 'dev':
            dev = fields[1]
        elif len(fields) >= 2 and fields[0] == 'status':
            status = fields[1]
    return dev, status


def status_file_metadata(service, configured):
    instance = service.split('@', 1)[1]
    possibilities = []
    if configured and configured.startswith(('/run/', '/var/run/', '/var/log/openvpn/', '/etc/openvpn/server/')):
        possibilities.append(configured)
    possibilities.extend([
        '/run/openvpn-server/status-' + instance + '.log',
        '/run/openvpn/status-' + instance + '.log',
        '/var/log/openvpn/' + instance + '-status.log',
        '/var/log/openvpn/status-' + instance + '.log',
        '/var/log/openvpn/status-' + instance + '.txt',
        '/var/log/openvpn-status-' + instance + '.log',
        '/etc/openvpn/server/status-' + instance + '.log',
    ])
    for candidate in dict.fromkeys(possibilities):
        path = Path(candidate)
        try:
            if path.is_file():
                # No status file contents are ever read or sent back.
                readable = bool(os.access(path, os.R_OK))
                return {'status_file': candidate,
                        'status_access': 'readable' if readable else 'permission_required'}
        except OSError:
            continue
    return {'status_file': configured if configured and configured.startswith('/') else None,
            'status_access': 'not_found'}


services = get_active_vpn_services()
interfaces = get_ipv4_interfaces()
tunnels = {i['ifname']: first_ipv4(i) for i in interfaces
           if isinstance(i, dict) and re.fullmatch(r'(tun|tap|ovpn)[A-Za-z0-9_.-]*', i.get('ifname', ''))
           and first_ipv4(i)}
wan_devices = default_wan_devices()
errors = []
service = None
if len(services) != 1:
    errors.append('Expected exactly one running openvpn-server@ instance; found ' + str(len(services)))
else:
    service = services[0]

vpn_interface = None
vpn_ip = None
status_file = None
status_access = 'unknown'
if service:
    preferred, configured_status = parse_conf(service)
    if preferred and preferred in tunnels:
        vpn_interface = preferred
    elif preferred and preferred.startswith(('tun', 'tap')) and preferred not in ('tun', 'tap'):
        errors.append('Configured VPN interface was not found with an IPv4 address')
    elif len(tunnels) == 1:
        vpn_interface = next(iter(tunnels))
    else:
        errors.append('Could not unambiguously identify the VPN tunnel')
    if vpn_interface:
        vpn_ip = tunnels[vpn_interface]
    metadata = status_file_metadata(service, configured_status)
    status_file = metadata['status_file']
    status_access = metadata['status_access']

wan = None
if len(wan_devices) == 1:
    wan = wan_devices[0]
else:
    errors.append('Could not unambiguously determine default IPv4 WAN interface')

print(json.dumps({
    'hostname': socket.gethostname(),
    'active_openvpn_services': services,
    'vpn_service': service,
    'vpn_interface': vpn_interface,
    'vpn_ipv4': vpn_ip,
    'network_interface': wan,
    'status_file': status_file,
    'status_access': status_access,
    'ready_for_approval': not errors,
    'warnings': errors,
}, separators=(',', ':')))
'''.strip()


class DiscoveryError(RuntimeError):
    """Remote read-only discovery was unsuccessful or ambiguous."""


def validate_discovery(payload: Any) -> dict[str, Any]:
    """Validate untrusted remote metadata before using it to approve SSH monitoring."""
    if not isinstance(payload, dict):
        raise DiscoveryError('Discovery returned an invalid data structure')
    cleaned: dict[str, Any] = {}
    patterns = {
        'vpn_service': r'openvpn-server@[A-Za-z0-9_.-]{1,65}',
        'vpn_interface': r'[A-Za-z0-9_.-]{1,80}',
        'network_interface': r'[A-Za-z0-9_.-]{1,80}',
    }
    for name, pattern in patterns.items():
        value = payload.get(name)
        if value is not None and (not isinstance(value, str) or not re.fullmatch(pattern, value)):
            raise DiscoveryError('Discovery returned an invalid ' + name)
        cleaned[name] = value
    if not isinstance(payload.get('ready_for_approval'), bool):
        raise DiscoveryError('Discovery readiness flag is invalid')
    cleaned['ready_for_approval'] = payload['ready_for_approval'] and all(cleaned[k] for k in patterns)
    services = payload.get('active_openvpn_services')
    if not isinstance(services, list) or len(services) > 20 or any(
        not isinstance(s, str) or not re.fullmatch(patterns['vpn_service'], s) for s in services
    ):
        raise DiscoveryError('Invalid OpenVPN service list')
    cleaned['active_openvpn_services'] = services
    if cleaned['ready_for_approval'] and services != [cleaned['vpn_service']]:
        raise DiscoveryError('Discovery selected an ambiguous OpenVPN service')
    warnings = payload.get('warnings', [])
    if not isinstance(warnings, list) or len(warnings) > 12 or any(not isinstance(w, str) or len(w) > 250 for w in warnings):
        raise DiscoveryError('Invalid remote discovery warnings')
    cleaned['warnings'] = warnings
    state = payload.get('status_access')
    cleaned['status_access'] = state if state in ('readable','permission_required','not_found','unknown') else 'unknown'
    # Status path is displayed only in the trusted local CLI, never returned via HTTP.
    sp = payload.get('status_file')
    cleaned['status_file'] = sp if isinstance(sp, str) and len(sp) < 300 and sp.startswith('/') else None
    ipv4 = payload.get('vpn_ipv4')
    cleaned['vpn_ipv4'] = ipv4 if isinstance(ipv4, str) and len(ipv4) <= 48 else None
    hostname = payload.get('hostname')
    cleaned['hostname'] = hostname[:100] if isinstance(hostname, str) else '(unknown)'
    return cleaned


def discover_ssh_server(*, host: str, username: str, port: int,
                        private_key_path: str, known_hosts_path: str | None = None) -> dict[str, Any]:
    """Run a single read-only probe over strictly host-key-verified SSH."""
    # Defer SSH dependency until actually contacting a remote host (offline tests stay offline).
    from backend.ssh_monitor import SSHConnectionConfig, _connect_verified

    config = SSHConnectionConfig(host=host, username=username, port=port,
                                 private_key_path=private_key_path,
                                 known_hosts_path=known_hosts_path)
    command = "python3 - <<'SENTINEL_DISCOVERY_ONLY'\n" + _REMOTE_DISCOVERY_SCRIPT + "\nSENTINEL_DISCOVERY_ONLY\n"
    client = _connect_verified(config)
    try:
        _, stdout, stderr = client.exec_command(command, timeout=25)
        # Bound the amount read, even if SSH server returns unexpected data.
        result = stdout.read(65537)
        diagnostics = stderr.read(2049)
        code = stdout.channel.recv_exit_status()
        if len(result) > 65536 or len(diagnostics) > 2048:
            raise DiscoveryError('Unexpectedly large discovery response')
        if code != 0:
            raise DiscoveryError('Read-only discovery command failed (exit ' + str(code) + ')')
        try:
            payload = json.loads(result.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as exc:
            raise DiscoveryError('SSH server did not return valid discovery JSON') from exc
        return validate_discovery(payload)
    finally:
        client.close()
