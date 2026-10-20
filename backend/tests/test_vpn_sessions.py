"""Step 39.1 offline tests: no network or VPS connection."""
import ast
import csv
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'vpn_sessions.py'
module = ast.parse(SOURCE.read_text(encoding='utf-8'))
assign = next(node for node in module.body if isinstance(node, ast.Assign) and any(
    isinstance(t, ast.Name) and t.id == '_REMOTE_VPN_SESSIONS_SCRIPT' for t in node.targets))
remote_text = ast.literal_eval(assign.value.func.value).strip() if isinstance(assign.value, ast.Call) else ast.literal_eval(assign.value)
remote_ast = ast.parse(remote_text)
functions = [n for n in remote_ast.body if isinstance(n, ast.FunctionDef)]
import ipaddress, subprocess, shlex
from datetime import datetime, timezone
namespace = {
    'csv': csv, 'ipaddress': ipaddress, 'os': os, 'time': time, 'Path': Path,
    'shlex': shlex, 'subprocess': subprocess,
    'MAX_BYTES': 2 * 1024 * 1024, 'MAX_AGE_SECONDS': 120, 'MAX_SESSIONS': 1000,
}
exec(compile(ast.Module(body=functions, type_ignores=[]), '<test-remote>', 'exec'), namespace)
parse = namespace['parse_status']

V3 = '''TITLE\tOpenVPN 2.6
TIME\tMon Oct 12 20:00:00 2026\t1791844800
HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher
CLIENT_LIST\tsame-user\t198.51.100.1:55100\t10.8.0.2\t\t200\t340\tMon\t1791844800\tshared\t0\t0\tAES-256-GCM
CLIENT_LIST\tsame-user\t198.51.100.2:55101\t10.8.0.3\t\t650\t240\tMon\t1791844801\tshared\t1\t1\tAES-256-GCM
HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)
END
'''
V1 = '''OpenVPN CLIENT LIST
Updated,Mon Oct 12 20:00:00 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
user1,198.51.100.2:3405,303,600,Mon Oct 12 19:00:00 2026
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
GLOBAL STATS
Max queue,0
END
'''


class VpnSessionParserTests(unittest.TestCase):
    def test_v3_two_connections_with_shared_username(self):
        result = parse(V3)
        self.assertEqual(len(result), 2)
        self.assertEqual([r['public_ip'] for r in result], ['198.51.100.1', '198.51.100.2'])
        self.assertEqual(result[0]['vpn_ip'], '10.8.0.2')
        self.assertEqual(result[1]['bytes_received'], 650)
        self.assertEqual(result[0]['connected_since_unix'], 1791844800)
        self.assertEqual(result[0]['username'], 'shared')

    def test_v2_comma_separated(self):
        self.assertEqual(len(parse(V3.replace('\t', ','))), 2)

    def test_v1_legacy(self):
        rows = parse(V1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['public_ip'], '198.51.100.2')
        self.assertIsNone(rows[0]['vpn_ip'])

    def test_v3_empty_valid_zero(self):
        v3 = '\n'.join(line for line in V3.splitlines() if not line.startswith('CLIENT_LIST\t')) + '\n'
        self.assertEqual(parse(v3), [])

    def test_no_unknown_as_zero(self):
        for text in ('', 'oops', 'HEADER\tCLIENT_LIST\tCommon Name\tReal Address\nEND\n',
                     V3.replace('END\n', ''), V3.replace('Bytes Received', 'Garbage')):
            self.assertIsNone(parse(text))

    def test_tab_preserves_commas(self):
        rows = parse(V3.replace('CLIENT_LIST\tsame-user\t', 'CLIENT_LIST\tshared,common\t'))
        self.assertEqual(rows[0]['common_name'], 'shared,common')

    def test_public_ip_does_not_copy_arbitrary_text(self):
        self.assertIsNone(namespace['public_ip']('password=secret'))
        self.assertEqual(namespace['public_ip']('[2001:db8::1]:1234'), '2001:db8::1')
        self.assertEqual(namespace['public_ip']('2001:db8::1'), '2001:db8::1')

    def test_candidate_service_scope(self):
        paths = namespace['candidates_for_service']('openvpn-server@eu01')
        self.assertTrue(paths)
        self.assertTrue(all('eu01' in p for p in paths))
        self.assertIn('/var/log/openvpn/eu01-status.log', paths)
        self.assertEqual(namespace['candidates_for_service']('ssh.service'), [])

    def test_fresh_status_and_stale(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'vpn.log'
            p.write_text(V3)
            original = namespace['candidates_for_service']
            namespace['candidates_for_service'] = lambda _: [str(p)]
            try:
                with patch.dict(namespace, {'subprocess': _ActiveService}):
                    data = namespace['collect_for_service']('openvpn-server@eu01')
                    self.assertEqual((data['state'], data['total']), ('available', 2))
                    os.utime(p, (time.time() - 300, time.time() - 300))
                    data = namespace['collect_for_service']('openvpn-server@eu01')
                    self.assertEqual(data['state'], 'stale_status')
                    self.assertIsNone(data['total'])
            finally:
                namespace['candidates_for_service'] = original

    def test_inactive_does_not_emit_zero(self):
        with patch.dict(namespace, {'subprocess': _InactiveService}):
            result = namespace['collect_for_service']('openvpn-server@server')
            self.assertEqual(result['state'], 'vpn_not_active')
            self.assertIsNone(result['total'])

    def test_permission_required_not_silent_zero(self):
        class DeniedPath:
            def stat(self): raise PermissionError('denied')
        orig_path, orig_candidates = namespace['Path'], namespace['candidates_for_service']
        namespace['Path'] = lambda _: DeniedPath()
        namespace['candidates_for_service'] = lambda _: ['/denied/status.log']
        try:
            with patch.dict(namespace, {'subprocess': _ActiveService}):
                result = namespace['collect_for_service']('openvpn-server@server')
            self.assertEqual(result['state'], 'permission_required')
            self.assertIsNone(result['total'])
        finally:
            namespace['Path'] = orig_path
            namespace['candidates_for_service'] = orig_candidates

    def test_secret_data_not_in_remote_code(self):
        remote = remote_text
        self.assertNotIn('sudo ', remote)
        self.assertNotIn('tls-crypt', remote)
        self.assertNotIn('private_key', remote)
        self.assertNotIn('systemctl restart', remote)


class _ActiveService:
    @staticmethod
    def run(*args, **kwargs):
        class Result: stdout='active\n'
        return Result()


class _InactiveService:
    @staticmethod
    def run(*args, **kwargs):
        class Result: stdout='inactive\n'
        return Result()


if __name__ == '__main__':
    unittest.main()
