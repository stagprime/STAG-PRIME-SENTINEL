"""Step 40.10-E.5: bounded transport retry without relaxing SSH trust.

Entirely offline; no network, private keys, SSH credentials, or VPS touched.
"""
from __future__ import annotations

import tempfile
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko
from backend import ssh_monitor


class SSHBannerRetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        key = Path(self.tmp.name) / 'dummy-key'
        key.write_text('offline fixture; not a key', encoding='utf-8')
        self.config = ssh_monitor.SSHConnectionConfig(
            host='198.51.100.7', username='opc', private_key_path=str(key))

    def _connect(self, clients):
        with patch.object(ssh_monitor.paramiko, 'SSHClient', side_effect=clients), \
             patch.object(ssh_monitor.time, 'sleep') as pause:
            result = ssh_monitor._connect_verified(self.config)
        return result, pause

    def test_normal_connection_has_no_retry(self):
        client = MagicMock()
        result, pause = self._connect([client])
        self.assertIs(result, client)
        self.assertEqual(client.connect.call_count, 1)
        self.assertEqual(client.connect.call_args.kwargs['banner_timeout'], 20)
        self.assertEqual(client.connect.call_args.kwargs['auth_timeout'], 20)
        self.assertFalse(client.connect.call_args.kwargs['allow_agent'])
        self.assertFalse(client.connect.call_args.kwargs['look_for_keys'])
        client.set_missing_host_key_policy.assert_called_once()
        self.assertIsInstance(client.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
        pause.assert_not_called()

    def test_banner_failure_retries_once_with_fresh_client(self):
        first = MagicMock()
        second = MagicMock()
        first.connect.side_effect = paramiko.SSHException('Error reading SSH protocol banner')
        result, pause = self._connect([first, second])
        self.assertIs(result, second)
        first.close.assert_called_once()
        second.close.assert_not_called()
        pause.assert_called_once_with(1.0)
        second.load_system_host_keys.assert_called_once()
        second.set_missing_host_key_policy.assert_called_once()

    def test_second_banner_failure_stops(self):
        first, second = MagicMock(), MagicMock()
        for c in (first, second):
            c.connect.side_effect = paramiko.SSHException('Error reading SSH protocol banner')
        with patch.object(ssh_monitor.paramiko, 'SSHClient', side_effect=[first, second]), \
             patch.object(ssh_monitor.time, 'sleep') as pause:
            with self.assertRaises(paramiko.SSHException):
                ssh_monitor._connect_verified(self.config)
        first.close.assert_called_once()
        second.close.assert_called_once()
        pause.assert_called_once_with(1.0)

    def test_authentication_failure_never_retries(self):
        first = MagicMock()
        first.connect.side_effect = paramiko.AuthenticationException('No authentication')
        with patch.object(ssh_monitor.paramiko, 'SSHClient', return_value=first) as factory, \
             patch.object(ssh_monitor.time, 'sleep') as pause:
            with self.assertRaises(paramiko.AuthenticationException):
                ssh_monitor._connect_verified(self.config)
        factory.assert_called_once()
        pause.assert_not_called()
        first.close.assert_called_once()

    def test_bad_host_key_never_retries(self):
        client = MagicMock()
        client.connect.side_effect = paramiko.BadHostKeyException(
            '198.51.100.7', MagicMock(), MagicMock())
        with patch.object(ssh_monitor.paramiko, 'SSHClient', return_value=client) as factory, \
             patch.object(ssh_monitor.time, 'sleep') as pause:
            with self.assertRaises(paramiko.BadHostKeyException):
                ssh_monitor._connect_verified(self.config)
        factory.assert_called_once()
        client.close.assert_called_once()
        pause.assert_not_called()

    def test_non_banner_transport_failure_never_retries(self):
        first = MagicMock()
        first.connect.side_effect = paramiko.SSHException('Host key verification failed')
        with patch.object(ssh_monitor.paramiko, 'SSHClient', return_value=first) as factory, \
             patch.object(ssh_monitor.time, 'sleep') as pause:
            with self.assertRaises(paramiko.SSHException):
                ssh_monitor._connect_verified(self.config)
        factory.assert_called_once()
        pause.assert_not_called()

    def test_socket_error_never_retries_blindly(self):
        first = MagicMock()
        first.connect.side_effect = OSError('Simulated socket error')
        with patch.object(ssh_monitor.paramiko, 'SSHClient', return_value=first) as factory, \
             patch.object(ssh_monitor.time, 'sleep') as pause:
            with self.assertRaises(OSError):
                ssh_monitor._connect_verified(self.config)
        factory.assert_called_once()
        pause.assert_not_called()

    def test_vault_password_stays_out_of_retry_logs(self):
        secret = 'MOCK-SECRET-DO-NOT-LOG'
        config = ssh_monitor.SSHConnectionConfig(
            host='198.51.100.7', username='sentineladmin',
            private_key_path='sentinel-vault:00000000-0000-0000-0000-000000000001')
        first, second = MagicMock(), MagicMock()
        first.connect.side_effect = paramiko.SSHException('Error reading SSH protocol banner')
        fake_vault = types.ModuleType('backend.credential_vault')
        fake_vault.load_ssh_secret = MagicMock(return_value=('password', secret))
        with patch.dict(sys.modules, {'backend.credential_vault': fake_vault}), \
             patch.object(ssh_monitor.paramiko, 'SSHClient', side_effect=[first, second]), \
             patch.object(ssh_monitor.time, 'sleep'), \
             self.assertLogs(ssh_monitor._LOG.name, level='WARNING') as logs:
            self.assertIs(ssh_monitor._connect_verified(config), second)
        self.assertEqual(first.connect.call_args.kwargs['password'], secret)
        self.assertEqual(second.connect.call_args.kwargs['password'], secret)
        self.assertNotIn(secret, '\n'.join(logs.output))


if __name__ == '__main__':
    unittest.main()
