"""All tests are OFFLINE. No SSH connection, VPN restart or live DB changes."""
import argparse
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.database import Base, Client, Server, ServerMonitoringConfig
from backend import monitoring_discovery as md
from backend import monitoring_setup as ms


class TestRemoteDiscovery(unittest.TestCase):
    def run_remote(self, services=None, interfaces=None, routes=None):
        services = ['openvpn-server@server.service loaded active running OpenVPN'] if services is None else services
        interfaces = [{'ifname': 'eth0', 'addr_info': [{'family': 'inet', 'local': '192.0.2.4', 'prefixlen': 24}]},
                      {'ifname': 'tun0', 'addr_info': [{'family': 'inet', 'local': '10.8.0.1', 'prefixlen': 24}]}] if interfaces is None else interfaces
        routes = [{'dev': 'eth0'}] if routes is None else routes

        def fake_run(cmd, *args, **kwargs):
            cmd = tuple(cmd)
            if cmd[:2] == ('systemctl', 'list-units'):
                return SimpleNamespace(returncode=0, stdout='\n'.join(services))
            if cmd[:4] == ('ip', '-j', '-4', 'addr'):
                return SimpleNamespace(returncode=0, stdout=json.dumps(interfaces))
            if cmd[:4] == ('ip', '-j', '-4', 'route'):
                return SimpleNamespace(returncode=0, stdout=json.dumps(routes))
            return SimpleNamespace(returncode=1, stdout='')

        capture = io.StringIO()
        with patch('subprocess.run', side_effect=fake_run), contextlib.redirect_stdout(capture):
            exec(md._REMOTE_DISCOVERY_SCRIPT, {'__name__': '__main__'})
        return md.validate_discovery(json.loads(capture.getvalue()))

    def test_eu02_single_active_instance(self):
        value = self.run_remote()
        self.assertTrue(value['ready_for_approval'])
        self.assertEqual(value['vpn_service'], 'openvpn-server@server')
        self.assertEqual(value['vpn_interface'], 'tun0')
        self.assertEqual(value['network_interface'], 'eth0')
        self.assertEqual(value['status_access'], 'not_found')

    def test_oracle_wan_enp0s5(self):
        value = self.run_remote(interfaces=[{'ifname':'tun0','addr_info':[{'family':'inet','local':'10.8.0.1','prefixlen':24}]}], routes=[{'dev':'enp0s5'}])
        self.assertEqual(value['network_interface'], 'enp0s5')
        self.assertTrue(value['ready_for_approval'])

    def test_no_active_service_refused(self):
        value = self.run_remote(services=[])
        self.assertFalse(value['ready_for_approval'])

    def test_multiple_openvpn_services_refused(self):
        value = self.run_remote(services=['openvpn-server@one.service loaded active running OpenVPN',
                                          'openvpn-server@two.service loaded active running OpenVPN'])
        self.assertFalse(value['ready_for_approval'])

    def test_multiple_tunnels_refused(self):
        value = self.run_remote(interfaces=[{'ifname':'tun0','addr_info':[{'family':'inet','local':'10.8.0.1','prefixlen':24}]},
                                            {'ifname':'tun1','addr_info':[{'family':'inet','local':'10.9.0.1','prefixlen':24}]}])
        self.assertFalse(value['ready_for_approval'])

    def test_multiple_wan_routes_refused(self):
        value = self.run_remote(routes=[{'dev': 'eth0'}, {'dev': 'eth1'}])
        self.assertFalse(value['ready_for_approval'])

    def test_invalid_remote_value_rejected(self):
        with self.assertRaises(md.DiscoveryError):
            md.validate_discovery({'ready_for_approval':True, 'vpn_service':'openvpn-server@foo;rm',
                                   'vpn_interface':'tun0', 'network_interface':'eth0',
                                   'active_openvpn_services':['openvpn-server@foo;rm']})

    def test_claimed_ready_inconsistent_service_rejected(self):
        with self.assertRaises(md.DiscoveryError):
            md.validate_discovery({'ready_for_approval':True, 'vpn_service':'openvpn-server@server',
                                   'vpn_interface':'tun0', 'network_interface':'eth0',
                                   'active_openvpn_services':['openvpn-server@other']})


class TestLocalApproval(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine = create_engine('sqlite:///' + str(Path(self.temp.name) / 'test.db'))
        self.addCleanup(self.engine.dispose)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        with self.Session.begin() as db:
            client = Client(name='Example Client')
            db.add(client)
            db.flush()
            server = Server(client_id=client.id, name='NEW-SERVER', host='192.0.2.100', ssh_port=22,
                            ssh_username='monitor', monitoring_status='not_connected')
            db.add(server)
            db.flush()
            self.server_id = server.id
        self.key = Path(self.temp.name) / 'fake-key-for-offline-tests'
        self.key.write_text('NOT A REAL PRIVATE KEY', encoding='utf-8')
        self.patchers = [patch.object(ms, 'SessionLocal', self.Session),
                         patch.object(ms, 'engine', self.engine),
                         patch.object(ms, '_create_safe_db_backup', return_value=None)]
        for mocked in self.patchers:
            mocked.start()
            self.addCleanup(mocked.stop)
        self.args = argparse.Namespace(server_id=self.server_id, server_name=None, client_name=None,
                                       key_path=str(self.key), known_hosts_path=None,
                                       approve=True, replace=False)
        self.meta = dict(vpn_service='openvpn-server@server', vpn_interface='tun0', network_interface='eth0',
                         ready_for_approval=True, status_access='not_found', warnings=[])

    def test_explicit_approval_adds_only_profile(self):
        with patch.object(ms, 'discover_ssh_server', return_value=self.meta), contextlib.redirect_stdout(io.StringIO()):
            ms.configure_auto(self.args)
        with self.Session() as db:
            self.assertEqual(len(db.scalars(select(Client)).all()), 1)
            self.assertEqual(len(db.scalars(select(Server)).all()), 1)
            cfg = db.get(ServerMonitoringConfig, self.server_id)
            self.assertTrue(cfg.enabled)
            self.assertEqual(cfg.approved_host, '192.0.2.100')
            self.assertEqual(cfg.vpn_interface, 'tun0')
            self.assertEqual(cfg.ssh_key_path, str(self.key.resolve()))

    def test_discover_does_not_approve_profile(self):
        with patch.object(ms, 'discover_ssh_server', return_value=self.meta), contextlib.redirect_stdout(io.StringIO()):
            ms.discover(self.args)
        with self.Session() as db:
            self.assertIsNone(db.get(ServerMonitoringConfig, self.server_id))

    def test_approval_flag_required_no_remote_connection(self):
        self.args.approve = False
        with patch.object(ms, 'discover_ssh_server') as remote:
            with self.assertRaises(ValueError):
                ms.configure_auto(self.args)
            remote.assert_not_called()

    def test_ambiguous_config_never_saved(self):
        self.meta['ready_for_approval'] = False
        self.meta['warnings'] = ['Multiple active services']
        with patch.object(ms, 'discover_ssh_server', return_value=self.meta):
            with self.assertRaises(md.DiscoveryError):
                with contextlib.redirect_stdout(io.StringIO()):
                    ms.configure_auto(self.args)
        with self.Session() as db:
            self.assertIsNone(db.get(ServerMonitoringConfig, self.server_id))

    def test_existing_profile_not_replaced_implicitly(self):
        with patch.object(ms, 'discover_ssh_server', return_value=self.meta), contextlib.redirect_stdout(io.StringIO()):
            ms.configure_auto(self.args)
        with patch.object(ms, 'discover_ssh_server') as remote:
            with self.assertRaises(ValueError):
                ms.configure_auto(self.args)
            remote.assert_not_called()


if __name__ == '__main__':
    unittest.main()
