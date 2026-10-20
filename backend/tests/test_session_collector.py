"""Offline tests for the session-count collector embedded in the remote script.

This test never connects to a VPS and requires only Python standard library.
"""
import ast
import csv
import os
import shlex
import time
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Allow installation of this test under backend/tests or project-root tests.
SOURCE = Path(__file__).resolve().parents[1] / 'ssh_monitor.py'
if not SOURCE.is_file():
    SOURCE = Path(__file__).resolve().parents[1] / 'backend' / 'ssh_monitor.py'
MODULE = ast.parse(SOURCE.read_text(encoding='utf-8'))
ASSIGNMENT = next(n for n in MODULE.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == '_REMOTE_HEALTH_SCRIPT' for t in n.targets))
# The file uses a literal .strip(); pull its string argument without executing the module.
assert isinstance(ASSIGNMENT.value, ast.Call) and isinstance(ASSIGNMENT.value.func, ast.Attribute)
remote = ast.literal_eval(ASSIGNMENT.value.func.value).strip()
REMOTE_AST = ast.parse(remote)
FUNCTIONS = ['parse_openvpn_status', '_status_candidates', 'collect_openvpn_sessions']
helper_nodes = [node for node in REMOTE_AST.body if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
assert len(helper_nodes) == len(FUNCTIONS)
namespace = {'csv': csv, 'Path': Path, 'time': time, 'shlex': shlex, 'MAX_STATUS_BYTES': 1024 * 1024, 'STATUS_MAX_AGE_SECONDS': 120}
exec(compile(ast.Module(body=helper_nodes, type_ignores=[]), '<remote-status-functions>', 'exec'), namespace)
parse = namespace['parse_openvpn_status']
collect = namespace['collect_openvpn_sessions']

# OpenVPN's actual --status-version 3 format is TAB-delimited.
V3 = """TITLE\tOpenVPN 2.7 x86_64
TIME\tMon Oct 12 20:00:00 2026\t1791844800
HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher
CLIENT_LIST\tsame-user\t198.51.100.1:44810\t10.8.0.2\t\t200\t340\tMon\t0\tsame-user\t0\t0\tAES-256-GCM
CLIENT_LIST\tsame-user\t198.51.100.2:44551\t10.8.0.3\t\t650\t240\tMon\t0\tsame-user\t1\t1\tAES-256-GCM
HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)
GLOBAL_STATS\tMax bcast/mcast queue length\t0
END
"""
# --status-version 2 uses identical logical rows, but with commas.
V2 = V3.replace('\t', ',')

V1 = '''OpenVPN CLIENT LIST
Updated,Mon Oct 12 20:00:00 2026
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
user1,198.51.100.2:3405,303,600,Mon Oct 12 19:00:00 2026
user2,198.51.100.3:3406,404,700,Mon Oct 12 19:00:00 2026
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
GLOBAL STATS
Max bcast/mcast queue length,0
END
'''

class TestStatusParser(unittest.TestCase):
    def test_version_three_counts_connections_not_unique_usernames(self):
        self.assertEqual(parse(V3), (2, True))

    def test_version_two_and_empty_status(self):
        self.assertEqual(parse(V2), (2, True))
        empty_v2 = '\n'.join(line for line in V2.splitlines()
                              if not line.startswith('CLIENT_LIST,')) + '\n'
        self.assertEqual(parse(empty_v2), (0, True))

    def test_version_three_tab_delimited_empty_status(self):
        empty_v3 = '\n'.join(line for line in V3.splitlines()
                              if not line.startswith('CLIENT_LIST\t')) + '\n'
        self.assertEqual(parse(empty_v3), (0, True))

    def test_version_three_tab_preserves_commas_in_common_name(self):
        payload = V3.replace('CLIENT_LIST\tsame-user\t', 'CLIENT_LIST\tuser,with,commas\t')
        self.assertEqual(parse(payload), (2, True))

    def test_version_one(self):
        self.assertEqual(parse(V1), (2, True))
        self.assertEqual(parse(V1.replace('user1,198.51.100.2:3405,303,600,Mon Oct 12 19:00:00 2026\nuser2,198.51.100.3:3406,404,700,Mon Oct 12 19:00:00 2026\n', '')), (0,True))

    def test_bad_format_is_unknown_not_zero(self):
        self.assertEqual(parse('random file\n'), (None, False))
        self.assertEqual(parse('CLIENT_LIST\nEND\n'), (None, False))
        self.assertEqual(parse('HEADER,CLIENT_LIST,Common Name,Real Address\nEND\n'), (None, False))
        self.assertEqual(parse(''), (None, False))
        self.assertEqual(parse('HEADER\tCLIENT_LIST\tCommon Name\tReal Address\nEND\n'), (None, False))
        self.assertEqual(parse('TITLE\tTest\nTIME\tToday\t1\nHEADER\tCLIENT_LIST\tName\tAddr\n'), (None, False))

    def test_missing_status_or_inactive_vpn_is_unknown(self):
        with patch.dict(namespace, {'_status_candidates': lambda _: []}):
            self.assertEqual(collect('openvpn-server@server', 'active'), (None, 'status_unavailable', None))
            self.assertEqual(collect('openvpn-server@server', 'inactive'), (None, 'vpn_not_active', None))

    def test_fresh_status_and_stale(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'status-server.log'
            path.write_text(V3)
            original = namespace['_status_candidates']
            namespace['_status_candidates'] = lambda _: [str(path)]
            try:
                n, state, age = collect('openvpn-server@server', 'active')
                self.assertEqual((n, state), (2, 'available'))
                self.assertIsInstance(age, int)
                os.utime(path, (time.time() - 400, time.time() - 400))
                self.assertEqual(collect('openvpn-server@server', 'active'), (None, 'status_unavailable', None))
            finally:
                namespace['_status_candidates'] = original

    def test_eu01_instance_status_path_when_config_is_not_readable(self):
        # EU-01 uses 'status /var/log/openvpn/eu01-status.log 10'.
        # Its /etc/openvpn/server/eu01.conf is root-only and not readable
        # by the monitoring SSH account, so the instance-scoped fallback
        # must work without reading the protected config.
        candidate_paths = namespace['_status_candidates']('openvpn-server@eu01')
        self.assertIn('/var/log/openvpn/eu01-status.log', candidate_paths)
        self.assertNotIn('/var/log/openvpn/eu02-status.log', candidate_paths)

    def test_no_broad_status_search_other_instances(self):
        entries = namespace['_status_candidates']('openvpn-server@eu01')
        self.assertTrue(all('eu01' in entry for entry in entries))

if __name__ == '__main__':
    unittest.main(verbosity=2)
