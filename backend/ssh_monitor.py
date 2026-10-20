"""Strictly verified, read-only SSH monitoring for Stag Prime Sentinel.

This module does not change remote configuration or use remote sudo.
SSH credentials remain local to the Sentinel backend and are never returned.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paramiko
import logging
import time

_LOG = logging.getLogger(__name__)



@dataclass(frozen=True)
class SSHConnectionConfig:
    host: str
    username: str
    private_key_path: str
    port: int = 22
    known_hosts_path: str | None = None


def _connect_verified(config: SSHConnectionConfig, key_passphrase: str | None = None) -> paramiko.SSHClient:
    """Open SSH connection; reject new or mismatched server host keys."""
    vault_secret = None
    key_path = None
    if config.private_key_path.startswith('sentinel-vault:'):
        from backend.credential_vault import load_ssh_secret
        server_id = config.private_key_path.removeprefix('sentinel-vault:')
        vault_secret = load_ssh_secret(server_id, host=config.host, port=config.port,
                                       username=config.username)
    else:
        key_path = Path(config.private_key_path).expanduser()
        if not key_path.is_file():
            raise FileNotFoundError("SSH private key file not found")

    # Transient pre-authentication SSH banner timeouts are common on busy VPS
    # hosts, especially if an earlier SSH connection was just closed.
    # Retry ONLY this specific transport-stage condition; never retry bad
    # host keys, failed authentication, or arbitrary remote-command errors.
    for attempt in range(2):
        client = paramiko.SSHClient()
        try:
            client.load_system_host_keys()
            if config.known_hosts_path:
                known_hosts = Path(config.known_hosts_path).expanduser()
                if not known_hosts.is_file():
                    raise FileNotFoundError("SSH known_hosts file not found")
                client.load_host_keys(str(known_hosts))
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            connection = dict(
                hostname=config.host, port=config.port, username=config.username,
                look_for_keys=False, allow_agent=False,
                timeout=10, auth_timeout=20, banner_timeout=20,
            )
            if vault_secret is not None:
                mode, secret = vault_secret
                if mode == 'password':
                    connection.update(password=secret, allow_agent=False,
                                      look_for_keys=False)
                elif mode == 'key_and_password':
                    # Hosts that require publickey AND password (or password after key).
                    from backend.credential_vault import unpack_key_and_password
                    import io
                    key_text, login_password = unpack_key_and_password(secret)
                    parsed = None
                    for key_type in (k for k in (getattr(paramiko, "Ed25519Key", None),
                                     getattr(paramiko, "RSAKey", None),
                                     getattr(paramiko, "ECDSAKey", None),
                                     getattr(paramiko, "DSSKey", None)) if k is not None):
                        try:
                            parsed = key_type.from_private_key(io.StringIO(key_text),
                                                               password=key_passphrase)
                            break
                        except (paramiko.SSHException, ValueError, TypeError):
                            continue
                    if parsed is None:
                        raise ValueError('Unsupported or encrypted SSH private key')
                    connection.update(
                        pkey=parsed,
                        password=login_password,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                else:
                    # Parse entirely in memory. Never create a key file.
                    import io
                    parsed = None
                    for key_type in (k for k in (getattr(paramiko, "Ed25519Key", None),
                                     getattr(paramiko, "RSAKey", None),
                                     getattr(paramiko, "ECDSAKey", None),
                                     getattr(paramiko, "DSSKey", None)) if k is not None):
                        try:
                            parsed = key_type.from_private_key(io.StringIO(secret),
                                                               password=key_passphrase)
                            break
                        except (paramiko.SSHException, ValueError, TypeError):
                            continue
                    if parsed is None:
                        raise ValueError('Unsupported or encrypted SSH private key')
                    connection.update(pkey=parsed)
            else:
                connection.update(key_filename=str(key_path), passphrase=key_passphrase)
            client.connect(**connection)
            return client
        except (paramiko.AuthenticationException, paramiko.BadHostKeyException):
            client.close()
            raise
        except paramiko.SSHException as exc:
            client.close()
            # SSHException also includes authentication/host-key failures in
            # some Paramiko releases; only the literal banner error is retried.
            is_banner_failure = 'error reading ssh protocol banner' in str(exc).lower()
            if not is_banner_failure or attempt == 1:
                raise
            _LOG.warning('Transient SSH banner failure; retrying once with a new connection')
            time.sleep(1.0)
        except Exception:
            client.close()
            raise


def test_ssh_connection(config: SSHConnectionConfig, key_passphrase: str | None = None) -> dict:
    """Test SSH authentication with strict host-key verification (original API)."""
    client = _connect_verified(config, key_passphrase=key_passphrase)
    try:
        return {
            "status": "connected",
            "host": config.host,
            "username": config.username,
            "ssh_port": config.port,
            "host_key_verified": True,
        }
    finally:
        client.close()


# This script runs once on the Ubuntu VPS as the SSH monitoring user.
# It only reads /proc, /sys, disk statistics, systemd status and interface addresses.
# No sudo, firewall writes, restarts, file modifications or secrets are involved.
_REMOTE_HEALTH_SCRIPT = r'''
import csv
import json
import os
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def cpu_snapshot():
    fields = [int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:]]
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return sum(fields), idle


def read_meminfo():
    data = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, _, tail = line.partition(':')
        if tail:
            data[key] = int(tail.strip().split()[0]) * 1024
    return data


def network_counter(interface, counter):
    path = Path('/sys/class/net') / interface / 'statistics' / counter
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError, PermissionError):
        return None


def command_output(arguments):
    try:
        proc = subprocess.run(arguments, capture_output=True, text=True, timeout=5, check=False)
        return proc.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ''


# Step 36.23: read-only OpenVPN status-file monitoring.
# No remote sudo, no enabling management port, and no server changes.
# Reads ONLY the active OpenVPN instance's status file when accessible to
# the approved SSH account. Does not transmit client names or public IPs.
MAX_STATUS_BYTES = 1024 * 1024
STATUS_MAX_AGE_SECONDS = 120


def parse_openvpn_status(text):
    """Return (active_connection_count, recognized) for OpenVPN status v1/v2/v3.

    v1 is a legacy human-readable CSV. v2 is a comma-separated machine format;
    v3 is the same machine format with TAB delimiters. One CLIENT_LIST record
    means one active connection, even when usernames/CNs are shared. A valid
    header-only snapshot means 0; unknown/malformed content means unavailable.
    """
    lines = text.splitlines()
    if not lines:
        return None, False

    # Versions 2 and 3 have TITLE/TIME, HEADER, CLIENT_LIST and END markers.
    # OpenVPN --status-version 3 is TAB-separated (not comma-separated).
    # Choose the format only from an explicit format marker, never from a
    # client-supplied username/IP address or a text-content heuristic.
    for delimiter in ('\t', ','):
        if not any(line.startswith('HEADER' + delimiter + 'CLIENT_LIST' + delimiter)
                   for line in lines):
            continue
        try:
            rows = list(csv.reader(lines, delimiter=delimiter, strict=True))
        except csv.Error:
            return None, False
        has_title = any(row and row[0] == 'TITLE' for row in rows)
        has_time = any(row and row[0] == 'TIME' for row in rows)
        header = [row for row in rows if len(row) >= 4 and row[:2] == ['HEADER', 'CLIENT_LIST']]
        has_end = any(row and row[0] == 'END' for row in rows)
        if not (has_title or has_time) or not header or not has_end:
            return None, False
        count = 0
        for row in rows:
            if row and row[0] == 'CLIENT_LIST':
                if len(row) < 4:
                    return None, False
                count += 1
        return count, True

    # Legacy OpenVPN status-version 1.
    if not lines[0].strip().startswith('OpenVPN CLIENT LIST'):
        return None, False
    try:
        first = next(i for i, line in enumerate(lines)
                     if line.startswith('Common Name,Real Address,'))
        last = next(i for i in range(first + 1, len(lines))
                    if lines[i].strip() == 'ROUTING TABLE')
    except StopIteration:
        return None, False
    try:
        rows = list(csv.reader(lines[first + 1:last], strict=True))
    except csv.Error:
        return None, False
    if any(len(row) < 2 for row in rows if row):
        return None, False
    return len([row for row in rows if row]), True


def _status_candidates(service):
    """Never scan other instances' status files."""
    if '@' not in service:
        return []
    instance = service.split('@', 1)[1].removesuffix('.service')
    if not instance or not all(c.isalnum() or c in '_-' for c in instance):
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
    # The service's own configuration is read only when world-readable.
    # If the status directive uses an absolute path under approved log/runtime
    # trees, that path can take precedence over the common instance defaults.
    config_path = Path('/etc/openvpn/server') / (instance + '.conf')
    try:
        if config_path.is_file() and config_path.stat().st_size <= 65536:
            for line in config_path.read_text(errors='replace').splitlines():
                if not line.strip() or line.lstrip().startswith(('#', ';')):
                    continue
                try:
                    parts = shlex.split(line, comments=True)
                except ValueError:
                    continue
                if len(parts) >= 2 and parts[0] == 'status' and parts[1].startswith('/'):
                    approved_roots = ('/run/', '/var/run/', '/var/log/openvpn', '/etc/openvpn/server/')
                    if parts[1].startswith(approved_roots):
                        names.insert(0, parts[1])
                    break
    except (OSError, UnicodeError):
        pass
    return list(dict.fromkeys(names))


def collect_openvpn_sessions(service, service_status):
    """Return only count, availability and age — never client-identifying rows."""
    if service_status != 'active':
        return None, 'vpn_not_active', None
    for candidate in _status_candidates(service):
        file = Path(candidate)
        try:
            if not file.is_file():
                continue
            meta = file.stat()
            if meta.st_size > MAX_STATUS_BYTES or meta.st_size <= 0:
                continue
            # Do not assume a status file left behind from earlier running
            # OpenVPN is representative of current connections.
            age = max(0, int(time.time() - meta.st_mtime))
            if age > STATUS_MAX_AGE_SECONDS:
                continue
            text = file.read_text(encoding='utf-8', errors='replace')
            count, recognized = parse_openvpn_status(text)
            if recognized:
                return count, 'available', age
        except (OSError, ValueError, UnicodeError):
            # Permissions, missing file, transient replacement: remain unknown.
            continue
    return None, 'status_unavailable', None


def collect_journal_peek(service):
    """Read-only last journal lines for the VPN unit. Never uses sudo."""
    try:
        proc = subprocess.run(
            ['journalctl', '-u', service, '-n', '15', '--no-pager', '-o', 'cat'],
            capture_output=True, text=True, timeout=6, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {'state': 'unavailable', 'unit': service, 'lines': [], 'note': 'journalctl not available'}
    err = (proc.stderr or '').lower()
    if proc.returncode != 0 or 'permission' in err or 'denied' in err:
        return {
            'state': 'permission_needed',
            'unit': service,
            'lines': [],
            'note': 'SSH user cannot read this systemd journal unit (grant journal ACL or use a monitoring group)',
        }
    lines = [ln[:240] for ln in (proc.stdout or '').splitlines() if ln.strip()][:15]
    if not lines:
        return {'state': 'unavailable', 'unit': service, 'lines': [], 'note': 'No recent journal lines'}
    return {'state': 'available', 'unit': service, 'lines': lines, 'note': 'Last 15 lines · read-only'}


def _public_cert_candidates(service):
    names = []
    if '@' in service:
        instance = service.split('@', 1)[1].removesuffix('.service')
        if instance and all(c.isalnum() or c in '_-' for c in instance):
            conf = Path('/etc/openvpn/server') / (instance + '.conf')
            try:
                if conf.is_file() and conf.stat().st_size <= 65536:
                    for line in conf.read_text(errors='replace').splitlines():
                        if not line.strip() or line.lstrip().startswith(('#', ';')):
                            continue
                        try:
                            parts = shlex.split(line, comments=True)
                        except ValueError:
                            continue
                        if len(parts) >= 2 and parts[0] in ('cert', 'ca') and parts[1].startswith('/'):
                            if 'private' in parts[1].lower() or parts[1].endswith('.key'):
                                continue
                            names.append(parts[1])
            except (OSError, UnicodeError):
                pass
            names.extend([
                '/etc/openvpn/server/' + instance + '.crt',
                '/etc/openvpn/server/ca.crt',
            ])
    return list(dict.fromkeys(names))


def collect_public_certificate(service):
    """Read public certificate metadata only. Never opens private keys."""
    for path in _public_cert_candidates(service):
        file = Path(path)
        try:
            if not file.is_file() or file.stat().st_size > 65536:
                continue
            text = file.read_text(errors='replace')
            if 'PRIVATE KEY' in text or 'BEGIN RSA PRIVATE' in text:
                continue
            if 'BEGIN CERTIFICATE' not in text:
                continue
            not_after = None
            openssl = command_output(['openssl', 'x509', '-enddate', '-noout', '-in', path])
            if openssl.startswith('notAfter='):
                not_after = openssl.split('=', 1)[1].strip()
            days = None
            iso = None
            if not_after:
                try:
                    from datetime import datetime as _dt
                    end = _dt.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    iso = end.isoformat()
                    days = int((end - datetime.now(timezone.utc)).total_seconds() // 86400)
                except (ValueError, TypeError, OverflowError):
                    iso = None
                    days = None
            return {
                'state': 'available',
                'path': path,
                'not_after': not_after,
                'not_after_utc': iso,
                'days_remaining': days,
                'note': 'Public certificate only · private keys are never read',
            }
        except PermissionError:
            return {
                'state': 'permission_needed',
                'path': path,
                'not_after': None,
                'not_after_utc': None,
                'days_remaining': None,
                'note': 'Certificate file exists but SSH user cannot read it',
            }
        except (OSError, UnicodeError, ValueError):
            continue
    return {
        'state': 'unavailable',
        'path': None,
        'not_after': None,
        'not_after_utc': None,
        'days_remaining': None,
        'note': 'No world-readable public cert found under approved OpenVPN paths',
    }


start_total, start_idle = cpu_snapshot()
time.sleep(0.25)
end_total, end_idle = cpu_snapshot()
delta = end_total - start_total
cpu_percent = round(100.0 * (1.0 - (end_idle - start_idle) / delta), 1) if delta > 0 else None

mem = read_meminfo()
mem_total = mem.get('MemTotal', 0)
mem_available = mem.get('MemAvailable', mem.get('MemFree', 0))
mem_used = max(0, mem_total - mem_available)

storage = shutil.disk_usage('/')
service = os.environ['SENTINEL_VPN_SERVICE']
tunnel = os.environ['SENTINEL_VPN_INTERFACE']
network = os.environ['SENTINEL_WAN_INTERFACE']
if network == 'auto':
    # Linux default-route NIC discovery, not an SSH or network configuration
    # change. Works with ens3/enp*/eth0 names without guessing the interface.
    route_tokens = command_output(['ip', '-4', 'route', 'show', 'default']).split()
    network = route_tokens[route_tokens.index('dev') + 1] if 'dev' in route_tokens and route_tokens.index('dev') + 1 < len(route_tokens) else 'unavailable'

vpn_status = command_output(['systemctl', 'is-active', service]) or 'unknown'
session_count, session_state, session_age = collect_openvpn_sessions(service, vpn_status)
address_raw = command_output(['ip', '-4', '-o', 'addr', 'show', 'dev', tunnel])
tunnel_ipv4 = None
parts = address_raw.split()
if 'inet' in parts:
    i = parts.index('inet')
    if i + 1 < len(parts):
        tunnel_ipv4 = parts[i + 1]

journal = collect_journal_peek(service)
certificate = collect_public_certificate(service)

payload = {
    'collected_at_utc': datetime.now(timezone.utc).isoformat(),
    'hostname': os.uname().nodename,
    'uptime_seconds': int(float(Path('/proc/uptime').read_text().split()[0])),
    'cpu_percent': cpu_percent,
    'memory_total_bytes': mem_total,
    'memory_used_bytes': mem_used,
    'memory_available_bytes': mem_available,
    'memory_used_percent': round(mem_used * 100.0 / mem_total, 1) if mem_total else None,
    'disk_total_bytes': storage.total,
    'disk_used_bytes': storage.used,
    'disk_free_bytes': storage.free,
    'disk_used_percent': round(storage.used * 100.0 / storage.total, 1) if storage.total else None,
    'network': {
        'interface': network,
        'rx_bytes_total': network_counter(network, 'rx_bytes'),
        'tx_bytes_total': network_counter(network, 'tx_bytes'),
        'rx_errors_total': network_counter(network, 'rx_errors'),
        'tx_errors_total': network_counter(network, 'tx_errors'),
        'rx_dropped_total': network_counter(network, 'rx_dropped'),
        'tx_dropped_total': network_counter(network, 'tx_dropped'),
    },
    'openvpn': {
        'service': service,
        'service_status': vpn_status,
        'interface': tunnel,
        'tunnel_ipv4': tunnel_ipv4,
        # Tunnel iface counters — separate from WAN NIC; never add them together.
        'rx_bytes_total': network_counter(tunnel, 'rx_bytes'),
        'tx_bytes_total': network_counter(tunnel, 'tx_bytes'),
    },
    # Auto-collected after enroll by the monitoring worker (read-only).
    'observability': {
        'journal': journal,
        'certificate': certificate,
    },
    # No client usernames/public IPs in the unauthenticated health API.
    'vpn_connected_sessions': session_count,
    'vpn_sessions_state': session_state,
    'vpn_sessions_status_age_seconds': session_age,
}
print(json.dumps(payload, separators=(',', ':')))
'''.strip()


def _validate_remote_identifier(value: str, label: str) -> str:
    # Allowed systemd unit and Linux interface characters, without shell metacharacters.
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,80}", value):
        raise ValueError(f"Invalid {label}")
    return value


def collect_ssh_health(
    config: SSHConnectionConfig,
    *,
    vpn_service: str = "openvpn-server@eu01",
    vpn_interface: str = "tun-eu01",
    network_interface: str = "eth0",
    key_passphrase: str | None = None,
) -> dict[str, Any]:
    """Collect read-only Linux/OpenVPN health over one verified SSH session.

    CPU is a short sample. Network byte counts are cumulative since interface
    initialization, not instantaneous speeds. Active VPN session counts are
    obtained read-only from this instance's readable, recent OpenVPN status
    file if available. Otherwise the count remains None (never fake zero).
    Session count measures connections, not distinct people. No IPs exposed.

    EU-02 and MENA-01 should supply their own vpn_service/interface values.
    """
    vpn_service = _validate_remote_identifier(vpn_service, "VPN service")
    vpn_interface = _validate_remote_identifier(vpn_interface, "VPN interface")
    network_interface = _validate_remote_identifier(network_interface, "network interface")

    environment = " ".join(
        f"{name}={shlex.quote(value)}"
        for name, value in (
            ("SENTINEL_VPN_SERVICE", vpn_service),
            ("SENTINEL_VPN_INTERFACE", vpn_interface),
            ("SENTINEL_WAN_INTERFACE", network_interface),
        )
    )
    command = (
        f"{environment} python3 - <<'SENTINEL_READ_ONLY_HEALTH'\n"
        f"{_REMOTE_HEALTH_SCRIPT}\n"
        "SENTINEL_READ_ONLY_HEALTH\n"
    )

    client = _connect_verified(config, key_passphrase=key_passphrase)
    try:
        _, stdout, stderr = client.exec_command(command, timeout=20)
        stdout_text = stdout.read().decode("utf-8", errors="replace").strip()
        stderr_text = stderr.read().decode("utf-8", errors="replace").strip()
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            raise RuntimeError(
                f"Read-only SSH health collection failed (exit {exit_code}): "
                f"{stderr_text[-350:] or 'No diagnostic output'}"
            )
        try:
            collected = json.loads(stdout_text)
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError("Remote health check returned invalid JSON") from exc
        if not isinstance(collected, dict):
            raise RuntimeError("Remote health check did not return a JSON object")
        return {
            "status": "connected",
            "host": config.host,
            "username": config.username,
            "ssh_port": config.port,
            "host_key_verified": True,
            **collected,
        }
    finally:
        client.close()
