"""Step 40.5: isolated server-control preview security tests; NO VPS contact."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.admin_access import ServerAdminAudit, ServerAdminProfile
from backend.auth_api import SESSION_COOKIE, _csrf_for_token, auth_database
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server
from backend.main import app
import backend.server_control as sc


class ServerControlPreviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = Path(self.tmp.name) / 'unit-test.key'
        self.key.write_text('NOT A REAL KEY', encoding='utf-8')
        self.engine = create_engine('sqlite+pysqlite:///:memory:',
            connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.factory = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db_patch = patch.object(sc, 'SessionLocal', self.factory)
        self.engine_patch = patch.object(sc, 'engine', self.engine)
        self.db_patch.start()
        self.engine_patch.start()

        def override_db():
            with self.factory() as db:
                yield db
        app.dependency_overrides[auth_database] = override_db
        with self.factory() as db:
            client = Client(name='Client 40.5')
            db.add(client); db.flush()
            server = Server(name='Test VPS 40.5', client_id=client.id,
                host='192.0.2.44', ssh_port=22, ssh_username='admin')
            db.add(server); db.flush()
            self.sid = server.id
            admin = AuthUser(username='step405admin', display_name='Admin', role='admin', password_hash='test')
            staff = AuthUser(username='step405staff', display_name='Staff', role='staff', password_hash='test')
            db.add_all([admin, staff]); db.flush()
            self.admin_id = admin.id
            self.tokens = {}
            for key, user in [('admin', admin), ('staff', staff)]:
                token, _ = create_session(db, user)
                self.tokens[key] = token
            db.add(ServerAdminProfile(server_id=server.id, enabled=True,
                approved_host=server.host, approved_username=server.ssh_username,
                approved_port=22, private_key_path=str(self.key)))
            db.commit()
        self.web = TestClient(app)
        self.url = f'/api/server-operations/servers/{self.sid}/control/preview'
        self.readiness = f'/api/server-operations/servers/{self.sid}/control/readiness'
        self.catalog = '/api/server-operations/control/actions'

    def tearDown(self):
        self.web.close()
        app.dependency_overrides.clear()
        self.engine_patch.stop(); self.db_patch.stop()
        self.engine.dispose()
        self.tmp.cleanup()

    def auth(self, who):
        return {'Authorization': 'Bearer ' + self.tokens[who]}

    def preview(self, action='restart', **kwargs):
        return self.web.post(self.url, json={'action': action, **kwargs}, headers=self.auth('admin'))

    def audit_entries(self):
        with self.factory() as db:
            return [(a.actor_id, a.server_id, a.operation, a.result)
                    for a in db.scalars(select(ServerAdminAudit)).all()]

    def test_admin_catalog_exactly_six_allowlisted_no_commands(self):
        r = self.web.get(self.catalog, headers=self.auth('admin'))
        self.assertEqual(r.status_code, 200, r.text)
        keys = [a['key'] for a in r.json()['actions']]
        self.assertEqual(keys, ['restart', 'memory', 'housekeeping',
                                'vpn-start', 'vpn-stop', 'vpn-restart'])
        self.assertFalse(r.json()['preview_only'])
        self.assertTrue(r.json()['execution_enabled'])
        self.assertEqual(sorted(r.json()['executable_actions']),
                         ['vpn-restart', 'vpn-start', 'vpn-stop'])
        self.assertNotIn('command', r.text)
        self.assertEqual(self.audit_entries(), [])

    def test_all_endpoints_admin_only(self):
        for url in (self.catalog, self.readiness):
            self.assertEqual(self.web.get(url).status_code, 401)
            self.assertEqual(self.web.get(url, headers=self.auth('staff')).status_code, 403)
        self.assertEqual(self.web.post(self.url, json={'action': 'restart'}).status_code, 401)
        self.assertEqual(self.web.post(self.url, headers=self.auth('staff'),
                                       json={'action': 'restart'}).status_code, 403)
        self.assertEqual(self.audit_entries(), [])

    def test_readiness_is_not_live_ssh_and_no_paths(self):
        r = self.web.get(self.readiness, headers=self.auth('admin'))
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()['inventory_pinned'])
        self.assertTrue(r.json()['local_profile_ready'])
        self.assertFalse(r.json()['remote_privilege_confirmed_now'])
        self.assertTrue(r.json()['execution_enabled'])
        self.assertNotIn(str(self.key), r.text)
        self.assertNotIn('192.0.2.44', r.text)

    def test_approved_preview_audit_only_no_ssh_and_no_secrets(self):
        with patch('backend.ssh_monitor._connect_verified', side_effect=AssertionError('SSH FORBIDDEN')) as ssh:
            for action in ('restart', 'memory', 'housekeeping',
                           'vpn-start', 'vpn-stop', 'vpn-restart'):
                r = self.preview(action)
                self.assertEqual(r.status_code, 200, r.text)
                self.assertEqual(r.json()['action'], action)
                executable = action in ('vpn-start', 'vpn-stop', 'vpn-restart')
                self.assertEqual(r.json()['preview_only'], not executable)
                self.assertEqual(r.json()['execution_enabled'], executable)
                self.assertFalse(r.json()['remote_connection_attempted'])
                self.assertNotIn(str(self.key), r.text)
                self.assertNotIn('password', r.text)
            ssh.assert_not_called()
        audit = self.audit_entries()
        self.assertEqual(len(audit), 6)
        self.assertTrue(all(a[0] == self.admin_id and a[1] == self.sid
                            and a[2].startswith('control_preview:') and a[3] == 'preview_only'
                            for a in audit))

    def test_shutdown_disallowed_with_no_audit_or_execution(self):
        # The product no longer offers VPS power-off, including through API.
        with patch('backend.ssh_monitor._connect_verified', side_effect=AssertionError('SSH FORBIDDEN')) as ssh:
            response = self.preview('shutdown')
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.audit_entries(), [])
        ssh.assert_not_called()

    def test_arbitrary_action_and_extra_payload_blocked_without_audit(self):
        for payload in ({'action': 'sudo reboot'}, {'action': 'restart', 'command': 'rm -rf /'},
                        {'action': 'restart', 'schedule': 'every day'}, {'action': ['restart']}):
            r = self.web.post(self.url, json=payload, headers=self.auth('admin'))
            self.assertEqual(r.status_code, 422, r.text)
        self.assertEqual(self.audit_entries(), [])
        r = self.web.post(f'/api/server-operations/servers/{self.sid}/admin/run',
                          headers=self.auth('admin'), json={'command': 'reboot'})
        self.assertEqual(r.status_code, 404)

    def test_cookie_post_requires_csrf(self):
        token = self.tokens['admin']
        headers = {'Cookie': f'{SESSION_COOKIE}={token}'}
        r = self.web.post(self.url, headers=headers, json={'action': 'memory'})
        self.assertEqual(r.status_code, 403, r.text)
        self.assertEqual(self.audit_entries(), [])
        headers['x-sentinel-csrf'] = _csrf_for_token(token)
        r = self.web.post(self.url, headers=headers, json={'action': 'memory'})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(len(self.audit_entries()), 1)

    def test_archived_disabled_and_identity_mismatch_fail_closed(self):
        with self.factory() as db:
            server = db.get(Server, self.sid)
            server.archived_at = datetime.now(timezone.utc)
            db.commit()
        self.assertEqual(self.preview().status_code, 409)
        with self.factory() as db:
            server = db.get(Server, self.sid)
            server.archived_at = None
            profile = db.get(ServerAdminProfile, self.sid)
            profile.enabled = False
            db.commit()
        self.assertEqual(self.preview().status_code, 409)
        with self.factory() as db:
            db.get(ServerAdminProfile, self.sid).enabled = True
            db.get(Server, self.sid).host = '203.0.113.44'
            db.commit()
        self.assertEqual(self.preview().status_code, 409)
        self.assertEqual(self.audit_entries(), [])

    def test_missing_key_and_unknown_server_refused(self):
        self.assertEqual(self.web.post('/api/server-operations/servers/not-a-uuid/control/preview',
            headers=self.auth('admin'), json={'action': 'memory'}).status_code, 404)
        with self.factory() as db:
            db.get(ServerAdminProfile, self.sid).private_key_path = '/not/a/key'
            db.commit()
        self.assertEqual(self.preview('memory').status_code, 503)
        self.assertEqual(self.audit_entries(), [])


if __name__ == '__main__':
    unittest.main()
