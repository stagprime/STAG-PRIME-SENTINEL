"""Step 40.7 security regressions. No real SSH and no production DB."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.read_only_jobs as jobs
from backend.admin_access import ServerAdminAudit, ServerAdminProfile
from backend.auth_api import SESSION_COOKIE, _csrf_for_token, auth_database
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server
from backend.main import app


class ReadOnlyJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = Path(self.tmp.name) / 'test-key-not-real'
        self.key.write_text('TEST', encoding='utf-8')
        self.engine = create_engine('sqlite+pysqlite:///:memory:',
            connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        self.db_patch = patch.object(jobs, 'SessionLocal', self.factory)
        self.db_patch.start()
        # server_control checks whether the profile/audit tables exist.
        self.registry_patch = patch.object(jobs, '_audit_registry_ready', return_value=True)
        self.registry_patch.start()

        def override():
            with self.factory() as db:
                yield db
        app.dependency_overrides[auth_database] = override
        with self.factory() as db:
            client = Client(name='Read Only Test Tenant')
            db.add(client); db.flush()
            s = Server(name='Read Only VPS', client_id=client.id,
                host='198.51.100.55', ssh_port=22, ssh_username='admin')
            db.add(s); db.flush()
            self.sid = s.id
            a = AuthUser(username='a407', display_name='Admin', role='admin', password_hash='dummy')
            staff = AuthUser(username='s407', display_name='Staff', role='staff', password_hash='dummy')
            db.add_all([a, staff]); db.flush()
            self.tokens = {}
            for name, u in [('admin', a), ('staff', staff)]:
                token, _ = create_session(db, u)
                self.tokens[name] = token
            self.admin_id = a.id
            db.add(ServerAdminProfile(server_id=self.sid, enabled=True,
                approved_host=s.host, approved_username=s.ssh_username,
                approved_port=22, private_key_path=str(self.key)))
            db.commit()
        self.web = TestClient(app)
        self.url = f'/api/server-operations/servers/{self.sid}/diagnostics/run'
        self.catalog = '/api/server-operations/diagnostics/catalog'

    def tearDown(self):
        self.web.close()
        app.dependency_overrides.clear()
        self.registry_patch.stop()
        self.db_patch.stop()
        self.engine.dispose()
        jobs._release(self.sid)
        self.tmp.cleanup()

    def headers(self, role='admin'):
        return {'Authorization': 'Bearer ' + self.tokens[role]}

    def run_check(self, check='load_average', headers=None, **extra):
        return self.web.post(self.url, json={'check': check, **extra}, headers=headers or self.headers())

    def audit(self):
        with self.factory() as db:
            return list(db.scalars(select(ServerAdminAudit)).all())

    def test_catalog_admin_and_no_commands_or_secrets(self):
        self.assertEqual(self.web.get(self.catalog).status_code, 401)
        self.assertEqual(self.web.get(self.catalog, headers=self.headers('staff')).status_code, 403)
        r = self.web.get(self.catalog, headers=self.headers())
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['read_only_execution_enabled'])
        self.assertFalse(data['arbitrary_commands_enabled'])
        self.assertFalse(data['power_control_enabled'])
        self.assertFalse(data['openvpn_control_enabled'])
        self.assertEqual([c['key'] for c in data['checks']], ['load_average', 'memory_snapshot'])
        self.assertNotIn('cat /proc', r.text)
        self.assertNotIn(str(self.key), r.text)

    def test_auth_and_csrf_enforced_before_network(self):
        with patch.object(jobs, '_run_pinned_diagnostic', side_effect=AssertionError('SSH forbidden')) as ssh:
            self.assertEqual(self.run_check(headers=self.headers('staff')).status_code, 403)
            self.assertEqual(self.web.post(self.url, json={'check':'load_average'}).status_code, 401)
            c = {'Cookie': f'{SESSION_COOKIE}={self.tokens["admin"]}'}
            self.assertEqual(self.run_check(headers=c).status_code, 403)
            ssh.assert_not_called()
            self.assertEqual(len(self.audit()), 0)
        c['x-sentinel-csrf'] = _csrf_for_token(self.tokens['admin'])
        with patch.object(jobs, '_run_pinned_diagnostic', return_value={'load_1m': 0.2}) as ssh:
            self.assertEqual(self.run_check(headers=c).status_code, 200)
            ssh.assert_called_once()

    def test_allowlist_rejects_extra_shell_and_unknown(self):
        for req in ({'check':'reboot'}, {'check':'load_average', 'command':'sudo shutdown -h now'},
                    {'check':['load_average']}, {'check':'load_average','sudo': True},
                    {'check': 'memory_snapshot;rm -rf /'}, {}):
            r = self.web.post(self.url, json=req, headers=self.headers())
            self.assertEqual(r.status_code,422,r.text)
        self.assertEqual(self.audit(),[])

    def test_approved_execution_audit_and_sanitized_metrics(self):
        with patch.object(jobs, '_run_pinned_diagnostic', return_value={
                'load_1m': 0.1, 'load_5m': 0.2, 'load_15m': 0.3}) as ssh:
            r=self.run_check()
        self.assertEqual(r.status_code,200,r.text)
        self.assertTrue(r.json()['read_only'])
        self.assertTrue(r.json()['audit_recorded'])
        self.assertFalse(r.json()['power_or_vpn_changed'])
        self.assertEqual(r.json()['metrics']['load_1m'],0.1)
        self.assertNotIn(str(self.key),r.text)
        self.assertNotIn('198.51.100',r.text)
        self.assertEqual(ssh.call_args.args[0].host,'198.51.100.55')
        aud=self.audit()
        self.assertEqual(len(aud),1)
        self.assertEqual(aud[0].result,'passed')
        self.assertEqual(aud[0].operation,'diagnostic:load_average')
        self.assertEqual(aud[0].actor_id,self.admin_id)

    def test_archived_disabled_changed_endpoint_unknown_or_missing_key(self):
        with patch.object(jobs,'_run_pinned_diagnostic',side_effect=AssertionError('SSH')) as ssh:
            self.assertEqual(self.web.post('/api/server-operations/servers/unknown/diagnostics/run',
                json={'check':'load_average'},headers=self.headers()).status_code,404)
            with self.factory() as db:
                db.get(Server, self.sid).archived_at = datetime.now(timezone.utc)
                db.commit()
            self.assertEqual(self.run_check().status_code,404)
            with self.factory() as db:
                db.get(Server, self.sid).archived_at=None
                db.get(ServerAdminProfile, self.sid).enabled=False
                db.commit()
            self.assertEqual(self.run_check().status_code,409)
            with self.factory() as db:
                db.get(ServerAdminProfile, self.sid).enabled=True
                db.get(Server, self.sid).ssh_username='unexpected'
                db.commit()
            self.assertEqual(self.run_check().status_code,409)
            with self.factory() as db:
                db.get(Server, self.sid).ssh_username='admin'
                db.get(ServerAdminProfile, self.sid).private_key_path='/missing/test/path'
                db.commit()
            self.assertEqual(self.run_check().status_code,503)
            ssh.assert_not_called()
        self.assertEqual(self.audit(),[])

    def test_connection_failure_sanitized_audited_released(self):
        with patch.object(jobs,'_run_pinned_diagnostic',side_effect=RuntimeError('key secret /tmp/private')):
            r=self.run_check()
        self.assertEqual(r.status_code,502,r.text)
        self.assertNotIn('secret',r.text)
        self.assertEqual(self.audit()[0].result,'failed')
        self.assertNotIn(self.sid,jobs._running)

    def test_concurrent_request_rejected_before_audit(self):
        self.assertTrue(jobs._acquire(self.sid))
        try:
            r=self.run_check()
            self.assertEqual(r.status_code,409)
            self.assertEqual(self.audit(),[])
        finally:
            jobs._release(self.sid)

    def test_parsers_numeric_only_and_reject_bad_fields(self):
        self.assertEqual(jobs._parse('load_average','0.05 0.25 1.00 1/22 5')['load_5m'],.25)
        self.assertEqual(jobs._parse('memory_snapshot', 'MemTotal: 1048576 kB\nMemAvailable: 524288 kB\nSwapTotal: 2048 kB\nSwapFree: 1024 kB\n')['available_mib'],512)
        for check,out in [('load_average','NaN 2.0 1.0'),('load_average','-1 1 2'),
                          ('memory_snapshot','MemTotal: TOKEN kB')]:
            with self.assertRaises(ValueError):jobs._parse(check,out)

    def test_fixed_commands_bounded_channel_and_no_output_leaks(self):
        sent=[]
        channel=MagicMock()
        channel.recv_ready.side_effect=[True, False,False]
        channel.recv.side_effect=[b'0.11 0.22 0.33 1/4 123\n']
        channel.recv_stderr_ready.return_value=False
        channel.exit_status_ready.return_value=True
        channel.recv_exit_status.return_value=0
        channel.exec_command.side_effect=lambda c:sent.append(c)
        transport=MagicMock()
        transport.is_active.return_value=True
        transport.open_session.return_value=channel
        client=MagicMock()
        client.get_transport.return_value=transport
        with patch.object(jobs, '_connect_verified',return_value=client) as connect:
            result=jobs._run_pinned_diagnostic(jobs.SSHConnectionConfig(
                host='198.51.100.55',username='admin',private_key_path=str(self.key)), 'load_average')
        self.assertEqual(sent,['cat /proc/loadavg'])
        self.assertEqual(result['load_15m'],.33)
        self.assertTrue(channel.close.called)
        self.assertTrue(client.close.called)
        self.assertTrue(connect.called)

    def test_oversized_output_is_rejected_and_channel_closed(self):
        ch=MagicMock()
        ch.recv_ready.return_value=True
        ch.recv.return_value=b'X'*2048
        ch.recv_stderr_ready.return_value=False
        transport=MagicMock();transport.is_active.return_value=True;transport.open_session.return_value=ch
        client=MagicMock();client.get_transport.return_value=transport
        with self.assertRaises(RuntimeError):jobs._bounded_output(client,'cat /proc/loadavg')
        self.assertTrue(ch.close.called)


if __name__=='__main__':unittest.main()
