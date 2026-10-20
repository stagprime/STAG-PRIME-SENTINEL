"""Step 40.2.1 — isolated HTTP and SSH preflight regression tests.

Uses an in-memory database and mocked SSH. Does not contact any VPS.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.admin_access as admin_access
from backend.auth_api import auth_database, _csrf_for_token, SESSION_COOKIE
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server
from backend.main import app
from backend.ssh_monitor import SSHConnectionConfig


class AdminSSHAccessTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.key = Path(self.work.name) / 'fake-not-a-real-key'
        self.key.write_text('TEST ONLY')
        self.engine = create_engine('sqlite+pysqlite:///:memory:',
            connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        self.db_patch = patch.object(admin_access, 'SessionLocal', self.factory)
        self.engine_patch = patch.object(admin_access, 'engine', self.engine)
        self.db_patch.start(); self.engine_patch.start()
        def override_db():
            with self.factory() as db:
                yield db
        app.dependency_overrides[auth_database] = override_db
        with self.factory() as db:
            c = Client(name='Tenant A')
            db.add(c); db.flush()
            one = Server(name='Test VPS', client_id=c.id, host='198.51.100.11',
                ssh_port=22, ssh_username='operator')
            db.add(one); db.flush()
            self.sid = one.id
            admin = AuthUser(username='theadmin', display_name='Admin', role='admin', password_hash='dummy')
            staff = AuthUser(username='somestaff', display_name='Staff', role='staff', password_hash='dummy')
            client = AuthUser(username='theclient', display_name='Client', role='client', client_id=c.id, password_hash='dummy')
            db.add_all([admin,staff,client]); db.flush()
            self.tokens = {}
            for label, user in [('admin', admin), ('staff', staff), ('client', client)]:
                token, _ = create_session(db, user)
                self.tokens[label] = token
            self.admin_id=admin.id
            db.add(admin_access.ServerAdminProfile(server_id=self.sid, enabled=True,
                approved_host='198.51.100.11', approved_username='operator',
                approved_port=22, private_key_path=str(self.key)))
            db.commit()
        self.web = TestClient(app)
        self.url = f'/api/server-operations/servers/{self.sid}/admin/verify'
        self.directory = '/api/server-operations/admin-profiles'

    def tearDown(self):
        self.web.close()
        app.dependency_overrides.clear()
        self.engine_patch.stop();self.db_patch.stop()
        self.engine.dispose()
        self.work.cleanup()

    def headers(self, role):
        return {'Authorization': 'Bearer ' + self.tokens[role]}

    def test_unauthenticated_and_nonadmin_never_initiate_ssh(self):
        with patch.object(admin_access, 'verify_administrative_ssh', side_effect=AssertionError('unexpected SSH')) as mock:
            self.assertEqual(self.web.post(self.url).status_code,401)
            self.assertEqual(self.web.get(self.directory).status_code,401)
            for role in ('staff', 'client'):
                self.assertEqual(self.web.post(self.url, headers=self.headers(role)).status_code,403)
                self.assertEqual(self.web.get(self.directory, headers=self.headers(role)).status_code,403)
            mock.assert_not_called()

    def test_directory_no_private_key_paths_or_credential_contents(self):
        r=self.web.get(self.directory,headers=self.headers('admin'))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()['total'],1)
        self.assertTrue(r.json()['profiles'][0]['verification_ready'])
        self.assertNotIn(str(self.key),r.text)
        self.assertNotIn('private_key',r.text)
        self.assertNotIn('password',r.text)

    def test_admin_verify_mocked_ssh_and_persists_audit(self):
        response = {'ssh_verified': True, 'host_key_verified': True,
                    'privilege_state': 'sudo_nopasswd', 'administration_ready': True}
        with patch.object(admin_access, 'verify_administrative_ssh', return_value=response) as mock:
            r=self.web.post(self.url,headers=self.headers('admin'))
            self.assertEqual(r.status_code,200,r.text)
            self.assertEqual(r.json()['privilege_state'],'sudo_nopasswd')
            self.assertNotIn(str(self.key),r.text)
            self.assertEqual(mock.call_count,1)
            self.assertEqual(mock.call_args.args[0].host,'198.51.100.11')
            self.assertEqual(mock.call_args.args[0].username,'operator')
        with self.factory() as db:
            logs=db.scalars(select(admin_access.ServerAdminAudit)).all()
            self.assertEqual(len(logs),1)
            self.assertEqual(logs[0].result,'verified')
            self.assertEqual(logs[0].actor_id,self.admin_id)

    def test_inventory_change_blocks_ssh_no_automatic_redirect(self):
        with self.factory() as db:
            server=db.get(Server,self.sid);server.host='203.0.113.70';db.commit()
        with patch.object(admin_access, 'verify_administrative_ssh',side_effect=AssertionError('SSH called')) as spy:
            r=self.web.post(self.url,headers=self.headers('admin'))
            self.assertEqual(r.status_code,409)
            spy.assert_not_called()

    def test_archived_disabled_missing_and_bad_key_fail_closed(self):
        with patch.object(admin_access, 'verify_administrative_ssh',side_effect=AssertionError('SSH called')) as spy:
            with self.factory() as db:
                profile=db.get(admin_access.ServerAdminProfile,self.sid)
                profile.enabled=False;db.commit()
            self.assertEqual(self.web.post(self.url,headers=self.headers('admin')).status_code,409)
            with self.factory() as db:
                profile=db.get(admin_access.ServerAdminProfile,self.sid)
                profile.enabled=True;profile.private_key_path='Z:/does/not/exist';db.commit()
            self.assertEqual(self.web.post(self.url,headers=self.headers('admin')).status_code,503)
            with self.factory() as db:
                srv=db.get(Server,self.sid)
                from datetime import datetime, timezone
                srv.archived_at=datetime.now(timezone.utc)
                db.commit()
            self.assertEqual(self.web.post(self.url,headers=self.headers('admin')).status_code,404)
            spy.assert_not_called()

    def test_remote_auth_failure_sanitized_and_audited(self):
        with patch.object(admin_access,'verify_administrative_ssh',side_effect=RuntimeError('DO-NOT-LEAK KEY TOKEN')):
            r=self.web.post(self.url,headers=self.headers('admin'))
        self.assertEqual(r.status_code,502)
        self.assertNotIn('DO-NOT-LEAK',r.text)
        with self.factory() as db:
            entries=db.scalars(select(admin_access.ServerAdminAudit)).all()
            self.assertEqual(entries[0].result,'connection_failed')

    def test_cookie_write_requires_csrf(self):
        with self.factory() as db:
            # Seeded session token here is already authenticated and valid.
            token=self.tokens['admin']
        self.web.cookies.set(SESSION_COOKIE,token,domain='testserver.local',path='/api')
        # TestClient can vary cookie domain matching, so use explicit cookie header.
        cookie={'Cookie':f'{SESSION_COOKIE}={token}'}
        with patch.object(admin_access, 'verify_administrative_ssh', side_effect=AssertionError('unexpected SSH')) as spy:
            r=self.web.post(self.url,headers=cookie)
            self.assertIn(r.status_code,(403,401))
            spy.assert_not_called()
        self.web.cookies.clear()

    def test_local_enrollment_creates_additive_tables_and_integrity_backup(self):
        # CLI runs against an entirely separate SQLite file; never real sentinel.db.
        from argparse import Namespace
        from unittest.mock import patch as patched
        from sqlalchemy import create_engine as create_sqlite_engine
        from sqlalchemy.orm import sessionmaker as sqlite_sessionmaker
        import backend.admin_access_cli as cli
        directory = Path(self.work.name) / 'local-project'
        data = directory / 'data'
        data.mkdir(parents=True)
        disk_engine = create_sqlite_engine('sqlite:///' + (data / 'sentinel.db').as_posix())
        # Prior inventory schema; administrative tables do not exist yet.
        Base.metadata.create_all(disk_engine, tables=[Client.__table__, Server.__table__])
        factory = sqlite_sessionmaker(bind=disk_engine, autocommit=False, autoflush=False)
        with factory() as db:
            client = Client(name='Local Tenant')
            db.add(client); db.flush()
            server = Server(client_id=client.id, name='CLI-vps',
                host='192.0.2.41', ssh_port=22, ssh_username='adminops')
            db.add(server); db.commit()
            server_id = server.id
        args = Namespace(server_id=server_id, server_name=None, client_name=None,
            from_monitoring=False, key_path=str(self.key),
            known_hosts_path=None, replace=False, approve=True)
        with (patched.object(cli,'DATA_DIR',data), patched.object(cli,'BASE_DIR',directory),
              patched.object(cli,'SessionLocal',factory), patched.object(cli,'engine',disk_engine)):
            cli.enroll(args)
        with factory() as db:
            self.assertEqual(db.query(Server).count(),1)
            profile=db.get(admin_access.ServerAdminProfile,server_id)
            self.assertEqual(profile.approved_host,'192.0.2.41')
            self.assertTrue(profile.enabled)
        self.assertEqual(len(list((directory/'backups').glob('*.db'))),1)
        disk_engine.dispose()

    def test_sqlite_backup_closes_both_connections_before_cleanup(self):
        """Windows cannot remove a temporary SQLite backup while handles remain open."""
        from contextlib import closing
        import sqlite3
        from unittest.mock import patch as patched
        import backend.admin_access_cli as cli

        data = Path(self.work.name) / 'backup-source'
        data.mkdir()
        source = data / 'sentinel.db'
        with closing(sqlite3.connect(str(source))) as connection:
            connection.execute('CREATE TABLE keep_me (number INTEGER)')
            connection.execute('INSERT INTO keep_me VALUES (42)')
            connection.commit()

        real_connect = sqlite3.connect
        opened = []

        def tracked_connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            opened.append(connection)
            return connection

        with (patched.object(cli, 'DATA_DIR', data),
              patched.object(cli, 'BASE_DIR', Path(self.work.name)),
              patched.object(cli.sqlite3, 'connect', side_effect=tracked_connect)):
            backup_path = cli._backup_db()

        self.assertEqual(len(opened), 2)
        for connection in opened:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute('SELECT 1')
        with closing(real_connect(str(backup_path))) as restored:
            self.assertEqual(restored.execute('SELECT number FROM keep_me').fetchone()[0], 42)
            self.assertEqual(restored.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
        # Must succeed on Windows without forcing Python garbage collection.
        backup_path.unlink()
        self.assertFalse(backup_path.exists())

    def test_password_sudo_detected_but_privileged_execution_not_authorized(self):
        fake = MagicMock()
        conf = SSHConnectionConfig(host='198.51.100.11', username='operator',
                                   private_key_path=str(self.key))
        def reply(_client, cmd, max_output=64):
            return (0, '1001') if cmd == 'id -u' else (1, '')
        with patch.object(admin_access, '_connect_verified', return_value=fake), \
             patch.object(admin_access, '_simple_command', side_effect=reply), \
             patch.object(admin_access, '_sudo_requires_password', return_value=True) as probe:
            result = admin_access.verify_administrative_ssh(conf)
        self.assertEqual(result['privilege_state'], 'sudo_password_required')
        self.assertTrue(result['ssh_verified'])
        self.assertFalse(result['administration_ready'])
        probe.assert_called_once_with(fake)
        fake.close.assert_called_once()

    def test_unavailable_sudo_never_assumed_password_sudo(self):
        fake = MagicMock()
        conf = SSHConnectionConfig(host='198.51.100.11', username='operator',
                                   private_key_path=str(self.key))
        def reply(_client, cmd, max_output=64):
            return (0, '1001') if cmd == 'id -u' else (1, '')
        with patch.object(admin_access, '_connect_verified', return_value=fake), \
             patch.object(admin_access, '_simple_command', side_effect=reply), \
             patch.object(admin_access, '_sudo_requires_password', return_value=False):
            result = admin_access.verify_administrative_ssh(conf)
        self.assertEqual(result['privilege_state'], 'sudo_unavailable')
        self.assertFalse(result['administration_ready'])

    def test_password_required_sudo_is_audited_and_verification_cached(self):
        response = {'ssh_verified': True, 'host_key_verified': True,
                    'privilege_state': 'sudo_password_required', 'administration_ready': False}
        with patch.object(admin_access, 'verify_administrative_ssh', return_value=response):
            r = self.web.post(self.url, headers=self.headers('admin'))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertFalse(r.json()['administration_ready'])
        self.assertNotIn(str(self.key), r.text)
        with self.factory() as db:
            server = db.get(Server, self.sid)
            profile = db.get(admin_access.ServerAdminProfile, self.sid)
            cached = admin_access.public_admin_verification(server, profile)
            self.assertEqual(cached['state'], 'success')
            self.assertEqual(cached['privilege_state'], 'sudo_password_required')
            self.assertFalse(cached['administration_ready'])
            self.assertFalse(cached['password_sudo_supported'])
            entry = db.scalars(select(admin_access.ServerAdminAudit)).first()
            self.assertEqual(entry.result, 'sudo_password_required')
            profile.approved_username = 'newuser'
            db.commit()
            self.assertIsNone(admin_access.public_admin_verification(server, profile))

    def test_failure_cannot_leave_previous_cached_ssh_success(self):
        good = {'ssh_verified': True, 'host_key_verified': True,
                'privilege_state': 'root', 'administration_ready': True}
        with patch.object(admin_access, 'verify_administrative_ssh', return_value=good):
            self.assertEqual(self.web.post(self.url, headers=self.headers('admin')).status_code, 200)
        with patch.object(admin_access, 'verify_administrative_ssh', side_effect=RuntimeError('secret')):
            self.assertEqual(self.web.post(self.url, headers=self.headers('admin')).status_code, 502)
        with self.factory() as db:
            server = db.get(Server, self.sid)
            profile = db.get(admin_access.ServerAdminProfile, self.sid)
            cached = admin_access.public_admin_verification(server, profile)
            self.assertEqual(cached['state'], 'error')
            self.assertFalse(cached['administration_ready'])

    def test_no_arbitrary_command_executor(self):
        r=self.web.post('/api/server-operations/servers/'+self.sid+'/admin/run',
            headers=self.headers('admin'),json={'command':'rm -rf /'})
        self.assertEqual(r.status_code,404)

    def test_allowed_identity_verification_is_bounded(self):
        fake=MagicMock()
        seen=[]
        def reply(_client, cmd, max_output=64):
            seen.append(cmd)
            return (0,'1000') if cmd == 'id -u' else (0,'0')
        conf=SSHConnectionConfig(host='198.51.100.11',username='operator',
            private_key_path=str(self.key))
        with patch.object(admin_access,'_connect_verified',return_value=fake),\
             patch.object(admin_access,'_simple_command',side_effect=reply):
            r=admin_access.verify_administrative_ssh(conf)
        self.assertEqual(seen,['id -u','sudo -n id -u'])
        self.assertEqual(r['privilege_state'],'sudo_nopasswd')
        self.assertTrue(fake.close.called)


if __name__ == '__main__':
    unittest.main()
