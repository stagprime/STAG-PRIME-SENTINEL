"""Offline regression tests for the read-only bulk OpenVPN discovery cache."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base, Client, Server, ServerMonitoringConfig
from backend import onboarding_probe as p


class OnboardingProbeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.data = Path(temp.name)
        self.engine = create_engine('sqlite:///' + str(self.data / 'probe-tests.db'))
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, autoflush=False)
        self.report_dir = patch.object(p, 'REPORT_DIR', self.data / 'reports')
        self.report_dir.start()
        self.addCleanup(self.report_dir.stop)
        self.key = self.data / 'fake-ssh-key.pem'
        self.key.write_text('OFFLINE PLACEHOLDER', encoding='utf-8')
        with self.Session.begin() as db:
            client1 = Client(name='Customer One')
            client2 = Client(name='Customer Two')
            db.add_all([client1, client2])
            db.flush()
            self.a = Server(name='EU-01', client_id=client1.id, host='192.0.2.11', ssh_username='monitor', ssh_port=22)
            self.b = Server(name='OTHER', client_id=client2.id, host='192.0.2.20', ssh_username='monitor', ssh_port=22)
            db.add_all([self.a, self.b])
            db.flush()
            self.a_id = self.a.id
            self.b_id = self.b.id
            self.a = None
            self.b = None
            db.add(ServerMonitoringConfig(server_id=self.a_id, enabled=True,
                                           approved_host='192.0.2.11', approved_ssh_username='monitor',
                                           approved_ssh_port=22, ssh_key_path=str(self.key),
                                           vpn_service='openvpn-server@eu01',
                                           vpn_interface='tun0', network_interface='eth0'))
        self.call_count = 0

    def valid_metadata(self):
        return {'hostname': 'vpn-host', 'vpn_service': 'openvpn-server@eu01',
                'active_openvpn_services':['openvpn-server@eu01'],
                'vpn_interface': 'tun0', 'vpn_ipv4': '10.8.0.1/24',
                'network_interface': 'eth0', 'status_file': '/var/log/openvpn/secret-status.log',
                'status_access': 'readable', 'ready_for_approval': True, 'warnings': []}

    def fake_discovery(self, **kwargs):
        self.call_count += 1
        self.assertEqual(kwargs['host'], '192.0.2.11')
        return self.valid_metadata()

    def test_all_approved_never_probes_inventory_only(self):
        output = p.probe_selected(all_approved=True, session_factory=self.Session, discovery=self.fake_discovery)
        self.assertEqual(self.call_count, 1)
        self.assertEqual([x['state'] for x in output], ['success', 'skipped_not_approved'])

    def test_single_unapproved_is_skipped_without_ssh(self):
        output = p.probe_selected(server_id=self.b_id, session_factory=self.Session, discovery=self.fake_discovery)
        self.assertEqual(output[0]['state'], 'skipped_not_approved')
        self.assertEqual(self.call_count, 0)

    def test_cache_exposes_only_public_observations(self):
        p.probe_selected(server_id=self.a_id, session_factory=self.Session, discovery=self.fake_discovery)
        with self.Session() as db:
            server = db.get(Server, self.a_id)
            profile = db.get(ServerMonitoringConfig, self.a_id)
            value = p.public_snapshot(server, profile)
        self.assertEqual(value['state'], 'success')
        self.assertEqual(value['observation']['status_access'], 'readable')
        self.assertNotIn('status_file', value['observation'])
        self.assertNotIn('approved_fingerprint', value)
        self.assertNotIn(str(self.key), str(value))
        self.assertNotIn('/var/log/openvpn/secret-status.log', str(value))

    def test_new_approval_invalidates_cached_report(self):
        p.probe_selected(server_id=self.a_id, session_factory=self.Session, discovery=self.fake_discovery)
        with self.Session.begin() as db:
            db.get(ServerMonitoringConfig, self.a_id).approved_ssh_port = 2222
        with self.Session() as db:
            snapshot = p.public_snapshot(db.get(Server, self.a_id), db.get(ServerMonitoringConfig, self.a_id))
        self.assertIsNone(snapshot)

    def test_changed_inventory_blocks_ssh(self):
        with self.Session.begin() as db:
            db.get(Server, self.a_id).host = '203.0.113.99'
        p.probe_selected(all_approved=True, session_factory=self.Session, discovery=self.fake_discovery)
        self.assertEqual(self.call_count, 0)

    def test_stale_snapshot_is_not_live(self):
        p.probe_selected(server_id=self.a_id, session_factory=self.Session, discovery=self.fake_discovery)
        with self.Session() as db:
            server = db.get(Server, self.a_id)
            profile = db.get(ServerMonitoringConfig, self.a_id)
            snapshot = p.public_snapshot(server, profile, now=datetime.now(timezone.utc) + timedelta(minutes=16))
        self.assertEqual(snapshot['state'], 'stale')
        self.assertNotIn('observation', snapshot)

    def test_ssh_failure_does_not_leak_exception_details(self):
        def fail(**kwargs):
            raise RuntimeError('Private key D:/DO_NOT_LEAK.pem')
        p.probe_selected(server_id=self.a_id, session_factory=self.Session, discovery=fail)
        with self.Session() as db:
            value = p.public_snapshot(db.get(Server, self.a_id), db.get(ServerMonitoringConfig, self.a_id))
        self.assertEqual(value['state'], 'error')
        self.assertNotIn('DO_NOT_LEAK', str(value))

    def test_user_must_confirm_explicitly(self):
        with self.assertRaises(SystemExit) as exc:
            p.main(['--all-approved'])
        self.assertEqual(exc.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
