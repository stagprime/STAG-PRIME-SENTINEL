"""Stag Prime Sentinel — strictly verified SSH health collection.

Step 35.2: Add the secure connection layer for the Step 35.1 Linux
collector. Running --self-test uses a mocked SSHClient: no VPS is contacted.

Keep private keys OUTSIDE the project and synced/cloud folders. Only use
this module with VPSs you are authorized to monitor. SSH host fingerprints
must be verified independently before adding them to known_hosts.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import paramiko

from backend.health_collector import collect_linux_health
from backend.ssh_monitor import SSHConnectionConfig


def collect_vps_health(
    config: SSHConnectionConfig,
    *,
    key_passphrase: str | None = None,
) -> dict[str, Any]:
    """Collect read-only Linux metrics with strict SSH host-key checking.

    This does not change the remote server. It never accepts unknown SSH
    host keys automatically, and it does not use SSH agent/password fallback.
    The specified private key must be OpenSSH/PEM, not PuTTY .ppk.
    """
    if not config.host.strip() or not config.username.strip():
        raise ValueError("SSH host and username must be provided")
    if not 1 <= config.port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")

    key_path = Path(config.private_key_path).expanduser()
    if key_path.suffix.lower() == ".ppk":
        raise ValueError(
            "PuTTY .ppk keys are not supported here. Export an OpenSSH "
            "private-key COPY using PuTTYgen; keep the original .ppk safe."
        )
    if not key_path.is_file():
        raise FileNotFoundError("SSH private key file was not found")

    hosts_path = (
        Path(config.known_hosts_path).expanduser()
        if config.known_hosts_path
        else Path.home() / ".ssh" / "known_hosts"
    )
    if not hosts_path.is_file():
        raise FileNotFoundError(
            "known_hosts file was not found; verify the VPS SSH host "
            "fingerprint through a trusted channel first"
        )

    client = paramiko.SSHClient()
    try:
        client.load_host_keys(str(hosts_path))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        client.connect(
            hostname=config.host,
            port=config.port,
            username=config.username,
            key_filename=str(key_path),
            passphrase=key_passphrase,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
        )
        metrics = collect_linux_health(client)
        return {
            "host": config.host,
            "ssh_host_key_verified": True,
            **metrics,
        }
    finally:
        client.close()


def _self_test() -> None:
    """Test complete SSH-to-collector wiring using a fake SSH client."""
    from tempfile import TemporaryDirectory
    from unittest.mock import Mock, patch

    fixture_outputs = {
        "cat /proc/stat": [
            "cpu  100 0 100 800 0 0 0 0 0 0\n",
            "cpu  120 0 130 850 0 0 0 0 0 0\n",
        ],
        "cat /proc/meminfo": [
            "MemTotal: 2048000 kB\nMemAvailable: 1024000 kB\n"
        ],
        "LC_ALL=C df -P -k /": [
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/vda1 1024000 409600 614400 40% /\n"
        ],
        "cat /proc/uptime": ["86400.23 1000.02\n"],
        "cat /proc/net/dev": [
            "Inter-| Receive | Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|"
            "bytes packets errs drop fifo colls carrier compressed\n"
            " lo: 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\n"
            " eth0: 1000 0 0 0 0 0 0 0 2000 0 0 0 0 0 0 0\n"
        ],
    }

    fake_ssh = Mock()
    observed_commands: list[str] = []

    def mock_exec(command: str, *, timeout: int) -> tuple[Mock, Mock, Mock]:
        assert timeout == 10
        observed_commands.append(command)
        payload = fixture_outputs[command].pop(0).encode("utf-8")
        stdout = Mock()
        stdout.read.return_value = payload
        stdout.channel.recv_exit_status.return_value = 0
        stderr = Mock()
        stderr.read.return_value = b""
        return Mock(), stdout, stderr

    fake_ssh.exec_command.side_effect = mock_exec

    with TemporaryDirectory() as directory:
        key = Path(directory) / "fixture-openssh-key"
        known_hosts = Path(directory) / "known_hosts"
        key.write_text("OFFLINE TEST PLACEHOLDER; NOT A PRIVATE KEY\n")
        known_hosts.write_text("OFFLINE TEST PLACEHOLDER; NOT A HOST KEY\n")
        config = SSHConnectionConfig(
            host="192.0.2.10",  # Reserved documentation IP; not contacted.
            username="monitor",
            private_key_path=str(key),
            known_hosts_path=str(known_hosts),
        )
        with (
            patch("backend.ssh_health.paramiko.SSHClient", return_value=fake_ssh),
            patch("backend.health_collector.time.sleep", return_value=None),
        ):
            result = collect_vps_health(config)

        fake_ssh.load_host_keys.assert_called_once_with(str(known_hosts))
        policy = fake_ssh.set_missing_host_key_policy.call_args.args[0]
        assert isinstance(policy, paramiko.RejectPolicy)
        kwargs = fake_ssh.connect.call_args.kwargs
        assert kwargs["hostname"] == "192.0.2.10"
        assert kwargs["look_for_keys"] is False
        assert kwargs["allow_agent"] is False
        assert kwargs["key_filename"] == str(key)
        assert len(observed_commands) == 6
        assert result["cpu_used_percent"] == 50.0
        assert result["memory_used_percent"] == 50.0
        assert result["disk_root_used_percent"] == 40.0
        assert result["uptime_seconds"] == 86400
        assert result["ssh_host_key_verified"] is True
        fake_ssh.close.assert_called_once()

    print("SSH health integration offline self-test: PASSED")
    print("Strict host-key policy and SSH key selection: OK (mocked)")
    print("CPU, RAM, disk, uptime, network collector integration: OK (mocked)")
    print("Remote VPS connection: NOT ATTEMPTED")
    print("OpenVPN live sessions: NOT YET CONFIGURED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel verified SSH health collector")
    parser.add_argument(
        "--self-test", action="store_true",
        help="Run fully offline integration tests; never connects to a VPS",
    )
    args = parser.parse_args()
    if not args.self_test:
        parser.error("Step 35.2 supports --self-test only; remote test comes later")
    _self_test()
