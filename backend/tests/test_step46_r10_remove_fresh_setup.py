"""Step 46-R10: removal guarantees. No network connections or VPS changes."""
import unittest
from unittest.mock import patch
from pathlib import Path

from backend.main import app
from backend import monitoring_engine as monitoring


def _flatten_paths(routes) -> list[str]:
    """FastAPI 0.143+ keeps included routers nested as _IncludedRouter."""
    paths: list[str] = []
    for route in routes:
        path = getattr(route, "path", None)
        if isinstance(path, str):
            paths.append(path)
        nested = getattr(route, "routes", None)
        if nested:
            paths.extend(_flatten_paths(nested))
        original = getattr(route, "original_router", None)
        if original is not None and getattr(original, "routes", None):
            paths.extend(_flatten_paths(original.routes))
    return paths


class RemovalContractTests(unittest.TestCase):
    def test_fresh_provisioning_routes_are_not_registered(self):
        paths = _flatten_paths(app.routes)
        forbidden = ('/fresh-setup/', '/fresh-setup', '/openvpn-setup/',
                     '/openvpn-setup', '/vpn-stages/', '/vpn-stages',
                     '/vpn-clients/create', '/vpn-clients/download')
        for path in paths:
            self.assertFalse(any(fragment in path for fragment in forbidden), path)
        # Essential read-only and controlled monitoring APIs must remain reachable.
        for expected in ('/api/monitoring/overview', '/api/servers',
                         '/api/server-operations/admin-profiles'):
            self.assertIn(expected, paths)

    def test_legacy_provisioning_lock_cannot_pause_monitoring(self):
        server_id = '11111111-1111-1111-1111-111111111111'
        with patch.object(monitoring, '_poll_one_under_slot', return_value='connected') as worker:
            result = monitoring.poll_one(server_id, 'health')
            self.assertEqual(result, 'connected')
            worker.assert_called_once()

    def test_only_retired_source_modules_removed(self):
        root = Path(__file__).resolve().parents[1]
        for module in ('fresh_setup_execution.py', 'fresh_vpn_provisioning.py',
                       'openvpn_setup_preflight.py', 'server_ssh_coordination.py'):
            self.assertFalse((root / module).exists(), module)
        for module in ('monitoring_engine.py','monitoring_worker.py','server_control.py',
                       'controlled_jobs.py','command_preflight.py'):
            self.assertTrue((root / module).is_file(), module)


if __name__ == '__main__':
    unittest.main()
