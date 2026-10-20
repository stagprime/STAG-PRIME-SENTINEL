"""Stag Prime Sentinel — read-only Linux VPS health collector.

Step 35.1: Parsing and local self-test only. No SSH login is attempted when
this module is imported or run with --self-test.

Later, an independently authenticated and host-key-verified Paramiko SSHClient
can be passed to collect_linux_health(client) to read standard Linux counters.
Never place SSH keys, passwords, or VPN profiles in this file.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from typing import Any


MAX_COMMAND_OUTPUT = 65536  # Linux /proc and df responses should be small.


def _read_only_command(client: Any, command: str) -> str:
    """Run one predefined, read-only Linux command on an authenticated SSH client."""
    _stdin, stdout, stderr = client.exec_command(command, timeout=10)
    output = stdout.read(MAX_COMMAND_OUTPUT + 1)
    error = stderr.read(4097)
    if len(output) > MAX_COMMAND_OUTPUT or len(error) > 4096:
        raise RuntimeError('Unexpectedly large response from Linux collector')
    exit_code = stdout.channel.recv_exit_status()
    if exit_code != 0:
        detail = error.decode('utf-8', errors='replace').strip()[:180]
        raise RuntimeError(f'Linux health command failed ({exit_code}): {detail}')
    return output.decode('utf-8', errors='replace')


def _cpu_ticks(stat_text: str) -> tuple[int, int]:
    """Return (all CPU ticks, idle ticks) from the aggregate /proc/stat line."""
    first = stat_text.splitlines()[0].split() if stat_text.strip() else []
    if len(first) < 5 or first[0] != 'cpu':
        raise ValueError('Linux CPU statistics are missing')
    ticks = [int(item) for item in first[1:]]
    total = sum(ticks)
    idle = ticks[3] + (ticks[4] if len(ticks) > 4 else 0)
    return total, idle


def _cpu_percent(before: str, after: str) -> float:
    total_a, idle_a = _cpu_ticks(before)
    total_b, idle_b = _cpu_ticks(after)
    interval = total_b - total_a
    if interval <= 0:
        raise ValueError('CPU counter interval was not positive')
    busy = interval - (idle_b - idle_a)
    return round(max(0.0, min(100.0, 100.0 * busy / interval)), 1)


def _memory_stats(meminfo_text: str) -> dict[str, int | float]:
    values: dict[str, int] = {}
    for line in meminfo_text.splitlines():
        if ':' not in line:
            continue
        name, data = line.split(':', 1)
        parts = data.split()
        if parts and parts[0].isdigit():
            values[name] = int(parts[0]) * 1024  # /proc/meminfo values are in KiB.
    total = values.get('MemTotal', 0)
    available = values.get('MemAvailable', -1)
    if total <= 0 or available < 0:
        raise ValueError('Required Linux RAM statistics are missing')
    used = max(0, total - min(total, available))
    return {
        'memory_total_bytes': total,
        'memory_used_bytes': used,
        'memory_used_percent': round(100.0 * used / total, 1),
    }


def _disk_stats(df_text: str) -> dict[str, int | float]:
    lines = [line for line in df_text.splitlines() if line.strip()]
    if len(lines) < 2:
        raise ValueError('Root filesystem disk statistics are missing')
    fields = lines[-1].split()
    if len(fields) < 6 or not fields[4].endswith('%'):
        raise ValueError('Unexpected df output for root filesystem')
    # df -P -k reports 1024-byte blocks.
    total_bytes = int(fields[1]) * 1024
    used_bytes = int(fields[2]) * 1024
    return {
        'disk_root_total_bytes': total_bytes,
        'disk_root_used_bytes': used_bytes,
        'disk_root_used_percent': float(fields[4][:-1]),
    }


def _uptime_seconds(uptime_text: str) -> int:
    fields = uptime_text.split()
    if not fields:
        raise ValueError('Linux uptime statistics are missing')
    return max(0, int(float(fields[0])))


def _network_interfaces(netdev_text: str) -> list[dict[str, int | str]]:
    """Return per-interface byte totals, not bandwidth rate (yet)."""
    interfaces: list[dict[str, int | str]] = []
    for line in netdev_text.splitlines():
        if ':' not in line:
            continue
        iface, counters_text = line.split(':', 1)
        name = iface.strip()
        parts = counters_text.split()
        if name == 'lo' or len(parts) < 16:
            continue
        interfaces.append({
            'interface': name,
            'rx_bytes_since_boot': int(parts[0]),
            'tx_bytes_since_boot': int(parts[8]),
        })
    return interfaces


def collect_linux_health(verified_ssh_client: Any) -> dict[str, Any]:
    """Collect Linux metrics using an ALREADY verified SSH connection.

    This function deliberately does not open SSH connections, look up private
    keys, or select host-key policies. Those belong in the secure SSH layer.
    CPU percentage samples two /proc/stat snapshots approximately 0.8s apart.
    """
    cpu_before = _read_only_command(verified_ssh_client, 'cat /proc/stat')
    time.sleep(0.8)
    cpu_after = _read_only_command(verified_ssh_client, 'cat /proc/stat')
    meminfo = _read_only_command(verified_ssh_client, 'cat /proc/meminfo')
    disk = _read_only_command(verified_ssh_client, 'LC_ALL=C df -P -k /')
    uptime = _read_only_command(verified_ssh_client, 'cat /proc/uptime')
    network = _read_only_command(verified_ssh_client, 'cat /proc/net/dev')

    return {
        'collected_at_utc': datetime.now(timezone.utc).isoformat(),
        'cpu_used_percent': _cpu_percent(cpu_before, cpu_after),
        **_memory_stats(meminfo),
        **_disk_stats(disk),
        'uptime_seconds': _uptime_seconds(uptime),
        'network_interfaces': _network_interfaces(network),
        'vpn_active_sessions': None,  # OpenVPN session collector is a later step.
        'monitoring_source': 'linux_proc_over_verified_ssh',
    }


def _self_test() -> None:
    """Offline parser checks using dummy values. NO VPS network access."""
    cpu_a = 'cpu  100 0 100 800 0 0 0 0 0 0\n'
    cpu_b = 'cpu  120 0 130 850 0 0 0 0 0 0\n'
    assert _cpu_percent(cpu_a, cpu_b) == 50.0
    memory = _memory_stats('MemTotal: 2048000 kB\nMemAvailable: 1024000 kB\n')
    assert memory['memory_used_percent'] == 50.0
    disk = _disk_stats('Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda1 1024000 409600 614400 40% /\n')
    assert disk['disk_root_used_percent'] == 40.0
    assert _uptime_seconds('86400.23 1000.02') == 86400
    net = _network_interfaces('Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n lo: 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\n eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n')
    assert net == [{'interface': 'eth0', 'rx_bytes_since_boot': 1000, 'tx_bytes_since_boot': 2000}]
    print('Health collector offline self-test: PASSED')
    print('CPU, RAM, disk, uptime, network parsers: OK')
    print('Remote VPS connection: NOT ATTEMPTED')
    print('VPN live sessions: NOT YET CONFIGURED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Sentinel Linux health collector')
    parser.add_argument('--self-test', action='store_true', help='Verify parsers locally without any SSH connection')
    args = parser.parse_args()
    if not args.self_test:
        parser.error('Step 35.1 only supports --self-test (no remote connections)')
    _self_test()
