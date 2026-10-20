"""Step 38.4 HTTP-level role, account, client-grant and audit tests; no VPS access.

Run from project root:
  .venv\\Scripts\\python.exe -m unittest discover -s backend\\tests -p "test_user_management.py" -v
Tests use independent in-memory SQLite; never modify data/sentinel.db.
"""
import unittest
from sqlalchemy import create_engine, select, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.auth_api import auth_database, router as auth_router
from backend.auth_models import AuthClientGrant, AuthSession, AuthUser
from backend.auth_security import can_access_client, create_session, hash_password, lookup_session, verify_password
from backend.database import Base, Client, Server
from backend.user_management import (
    AuthAuditEvent, admin_router, account_router, initialize_user_management_db,
)


PASSWORD = 'VerySecureDistinctPassphrase2026!?'
NEW_PASSWORD = 'AnotherStrongUnpredictablePhrase2027#'


class UserManagementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pwhash = hash_password(PASSWORD)

    def setUp(self):
        engine = create_engine('sqlite+pysqlite:///:memory:',
                               connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        # Match SQLite installations that enforce foreign-key references.
        with engine.connect() as conn:
            conn.exec_driver_sql('PRAGMA foreign_keys=ON')
        self.engine = engine
        self.factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        with self.factory() as db:
            a = Client(name='Alpha Company')
            b = Client(name='Beta Company')
            db.add_all([a, b]); db.flush()
            self.cid_a, self.cid_b = a.id, b.id
            srv = Server(name='production-vps', client_id=a.id, host='192.0.2.40')
            db.add(srv); db.flush()
            self.server_id = srv.id
            admin = AuthUser(username='adminowner', display_name='Main Administrator',
                             role='admin', password_hash=self.pwhash)
            staff = AuthUser(username='staffperson', display_name='Support Staff',
                             role='staff', password_hash=self.pwhash)
            client = AuthUser(username='clientperson', display_name='Alpha Client',
                              role='client', client_id=a.id, password_hash=self.pwhash)
            db.add_all([admin, staff, client]); db.flush()
            self.admin_id, self.staff_id, self.client_id = admin.id, staff.id, client.id
            db.add(AuthClientGrant(user_id=staff.id, client_id=a.id))
            db.commit()
            self.tokens = {}
            for label, user in [('admin', admin), ('staff', staff), ('client', client)]:
                tok, _ = create_session(db, user)
                self.tokens[label] = tok
        webapp = FastAPI()
        webapp.include_router(auth_router)
        webapp.include_router(admin_router)
        webapp.include_router(account_router)

        def override_db():
            with self.factory() as db:
                yield db
        webapp.dependency_overrides[auth_database] = override_db
        self.web = TestClient(webapp)

    def tearDown(self):
        self.web.close()
        self.engine.dispose()

    def head(self, who):
        return {'Authorization': 'Bearer ' + self.tokens[who]}

    def create(self, **changes):
        data = dict(username='newstaff', display_name='New Staff Member', password=PASSWORD,
                    role='staff', client_ids=[self.cid_a])
        data.update(changes)
        return self.web.post('/api/admin/users', headers=self.head('admin'), json=data)

    def test_admin_only_all_routes_including_audit(self):
        paths = ['/api/admin/users', f'/api/admin/users/{self.staff_id}', '/api/admin/audit']
        for path in paths:
            self.assertEqual(self.web.get(path).status_code, 401)
            for who in ('staff', 'client'):
                self.assertEqual(self.web.get(path, headers=self.head(who)).status_code, 403)
        for who in ('staff', 'client'):
            self.assertEqual(self.web.post('/api/admin/users', headers=self.head(who), json={}).status_code, 403)
            self.assertEqual(self.web.patch(f'/api/admin/users/{self.staff_id}', headers=self.head(who), json={}).status_code, 403)
            self.assertEqual(self.web.put(f'/api/admin/users/{self.staff_id}/grants', headers=self.head(who), json={}).status_code, 403)
            self.assertEqual(self.web.post(f'/api/admin/users/{self.staff_id}/reset-password', headers=self.head(who), json={}).status_code, 403)

    def test_admin_client_directory_complete_and_protected(self):
        url = '/api/admin/clients'
        self.assertEqual(self.web.get(url).status_code, 401)
        for role in ('staff', 'client'):
            self.assertEqual(self.web.get(url, headers=self.head(role)).status_code, 403)
        response = self.web.get(url, headers=self.head('admin'))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers.get('cache-control'), 'no-store')
        payload = response.json()
        self.assertEqual(payload['total'], 2)
        self.assertEqual({c['id'] for c in payload['clients']}, {self.cid_a, self.cid_b})
        self.assertEqual({c['name'] for c in payload['clients']}, {'Alpha Company', 'Beta Company'})
        self.assertNotIn('password', response.text)
        self.assertNotIn('token', response.text)

    def test_list_and_detail_never_return_secrets(self):
        response = self.web.get('/api/admin/users', headers=self.head('admin'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get('cache-control'), 'no-store')
        self.assertEqual(response.json()['total'], 3)
        self.assertNotIn('password', response.text)
        self.assertNotIn('token', response.text)
        self.assertNotIn('locked_until', response.text)
        self.assertNotIn('password', self.web.get(f'/api/admin/users/{self.admin_id}',headers=self.head('admin')).text)

    def test_create_staff_with_grant_and_tenant_isolation(self):
        response = self.create()
        self.assertEqual(response.status_code, 201, response.text)
        target_id = response.json()['id']
        self.assertEqual(response.json()['client_ids'], [self.cid_a])
        with self.factory() as db:
            target = db.get(AuthUser, target_id)
            self.assertTrue(verify_password(PASSWORD, target.password_hash))
            self.assertTrue(can_access_client(db, target, self.cid_a))
            self.assertFalse(can_access_client(db, target, self.cid_b))
            self.assertIsNotNone(db.scalar(select(AuthAuditEvent).where(AuthAuditEvent.action == 'user_created')))

    def test_create_client_requires_valid_organization(self):
        self.assertEqual(self.create(username='newclient', role='client', client_ids=[], client_id=None).status_code, 422)
        self.assertEqual(self.create(username='newclient', role='client', client_ids=[], client_id='missing').status_code, 422)
        self.assertEqual(self.create(username='newclient', role='client', client_ids=[], client_id=self.cid_b).status_code, 201)

    def test_duplicate_username_and_bad_password_rejected(self):
        self.assertEqual(self.create(username='STAFFPERSON').status_code, 409)
        self.assertEqual(self.create(password='short').status_code, 422)
        self.assertEqual(self.create(password='newstaff-ThisHasAUsernameAndEnoughLength!').status_code, 422)

    def test_no_implicit_admin_escalation(self):
        self.assertEqual(self.create(username='newadmin', role='admin', client_ids=[]).status_code, 422)
        self.assertEqual(self.create(username='newadmin', role='admin', client_ids=[],confirm_admin_access=True).status_code, 201)
        result = self.web.patch(f'/api/admin/users/{self.staff_id}',
                                headers=self.head('admin'), json={'role':'admin'})
        self.assertEqual(result.status_code, 422)

    def test_staff_grants_replace_and_revoke_old_session(self):
        response = self.web.put(f'/api/admin/users/{self.staff_id}/grants', headers=self.head('admin'),json={'client_ids':[self.cid_b]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['client_ids'], [self.cid_b])
        with self.factory() as db:
            staff = db.get(AuthUser, self.staff_id)
            self.assertFalse(can_access_client(db, staff, self.cid_a))
            self.assertTrue(can_access_client(db, staff, self.cid_b))
            self.assertIsNone(lookup_session(db,self.tokens['staff']))

    def test_invalid_and_duplicate_grants_are_atomic(self):
        for grants in ([self.cid_a,'bad-id'], [self.cid_a,self.cid_a]):
            res=self.web.put(f'/api/admin/users/{self.staff_id}/grants',headers=self.head('admin'),json={'client_ids':grants})
            self.assertEqual(res.status_code,422,res.text)
        with self.factory() as db:
            grants=db.scalars(select(AuthClientGrant.client_id).where(AuthClientGrant.user_id==self.staff_id)).all()
            self.assertEqual(grants,[self.cid_a])
            self.assertIsNotNone(lookup_session(db,self.tokens['staff']))

    def test_role_transition_clears_staff_grants_and_sessions(self):
        res = self.web.patch(f'/api/admin/users/{self.staff_id}', headers=self.head('admin'),
                             json={'role':'client','client_id':self.cid_b})
        self.assertEqual(res.status_code,200,res.text)
        self.assertEqual(res.json()['client_ids'], [])
        self.assertEqual(res.json()['client_id'], self.cid_b)
        with self.factory() as db:
            user=db.get(AuthUser,self.staff_id)
            self.assertFalse(can_access_client(db,user,self.cid_a))
            self.assertTrue(can_access_client(db,user,self.cid_b))
            self.assertIsNone(lookup_session(db,self.tokens['staff']))
            self.assertEqual(db.scalars(select(AuthClientGrant).where(AuthClientGrant.user_id==user.id)).all(),[])

    def test_disable_user_revokes_session(self):
        res = self.web.patch(f'/api/admin/users/{self.staff_id}',headers=self.head('admin'),json={'is_active':False})
        self.assertEqual(res.status_code, 200)
        with self.factory() as db:
            self.assertFalse(db.get(AuthUser,self.staff_id).is_active)
            self.assertIsNone(lookup_session(db,self.tokens['staff']))

    def test_admin_self_protection_and_last_admin(self):
        for payload in ({'role':'staff'},{'is_active':False}):
            self.assertEqual(self.web.patch(f'/api/admin/users/{self.admin_id}',headers=self.head('admin'),json=payload).status_code,409)
        with self.factory() as db:
            admin=db.get(AuthUser,self.admin_id)
            self.assertTrue(admin.is_active)
            self.assertEqual(admin.role,'admin')

    def test_password_reset_revokes_session_without_echoing_password(self):
        res=self.web.post(f'/api/admin/users/{self.staff_id}/reset-password',headers=self.head('admin'), json={'new_password':NEW_PASSWORD})
        self.assertEqual(res.status_code,200,res.text)
        self.assertNotIn(NEW_PASSWORD,res.text)
        with self.factory() as db:
            user=db.get(AuthUser,self.staff_id)
            self.assertTrue(verify_password(NEW_PASSWORD,user.password_hash))
            self.assertIsNone(lookup_session(db,self.tokens['staff']))
        self.assertEqual(self.web.post(f'/api/admin/users/{self.admin_id}/reset-password',headers=self.head('admin'),json={'new_password':NEW_PASSWORD}).status_code,409)

    def test_own_password_change_requires_current_password_and_logs_out(self):
        url='/api/auth/change-password'
        wrong=self.web.post(url,headers=self.head('admin'),json={'current_password':'incorrect','new_password':NEW_PASSWORD})
        self.assertEqual(wrong.status_code,403)
        good=self.web.post(url,headers=self.head('admin'),json={'current_password':PASSWORD,'new_password':NEW_PASSWORD})
        self.assertEqual(good.status_code,200,good.text)
        self.assertEqual(self.web.get('/api/auth/me',headers=self.head('admin')).status_code,401)
        with self.factory() as db:
            self.assertTrue(verify_password(NEW_PASSWORD,db.get(AuthUser,self.admin_id).password_hash))
        self.assertNotIn(NEW_PASSWORD,good.text)

    def test_audit_metadata_not_credentials(self):
        self.create()
        res=self.web.get('/api/admin/audit?limit=20', headers=self.head('admin'))
        self.assertEqual(res.status_code,200,res.text)
        self.assertTrue(res.json()['events'])
        self.assertEqual(res.json()['events'][0]['action'],'user_created')
        self.assertNotIn(PASSWORD,res.text)
        self.assertNotIn('password_hash',res.text)
        self.assertEqual(self.web.get('/api/admin/audit?limit=201',headers=self.head('admin')).status_code,422)

    def test_existing_server_data_not_changed_and_schema_idempotent(self):
        initialize_user_management_db(self.engine)
        initialize_user_management_db(self.engine)
        self.create()
        with self.factory() as db:
            srv=db.get(Server,self.server_id)
            self.assertEqual(srv.host,'192.0.2.40')
            self.assertEqual(db.scalar(select(Client.name).where(Client.id==self.cid_a)),'Alpha Company')

    def test_invalid_fields_fail_closed(self):
        self.assertEqual(self.create(username='newstaff',is_superuser=True).status_code,422)
        self.assertEqual(self.web.patch(f'/api/admin/users/{self.staff_id}',headers=self.head('admin'),json={'role':None}).status_code,422)
        self.assertEqual(self.web.patch(f'/api/admin/users/{self.staff_id}',headers=self.head('admin'),json={'client_id':self.cid_b}).status_code,422)
        self.assertEqual(self.web.put(f'/api/admin/users/{self.client_id}/grants',headers=self.head('admin'),json={'client_ids':[self.cid_a]}).status_code,409)


    def deletion(self, user_id, **changes):
        data = dict(confirm_username='staffperson', admin_password=PASSWORD,
                    confirm_permanent_delete=True)
        data.update(changes)
        return self.web.request('DELETE', f'/api/admin/users/{user_id}',
                                headers=self.head('admin'), json=data)

    def test_delete_requires_admin_and_disabled_account(self):
        for who in ('staff', 'client'):
            self.assertEqual(self.web.request('DELETE', f'/api/admin/users/{self.staff_id}',
                             headers=self.head(who), json={}).status_code, 403)
        self.assertEqual(self.web.request('DELETE', f'/api/admin/users/{self.staff_id}', json={}).status_code, 401)
        self.assertEqual(self.deletion(self.staff_id).status_code, 409)
        with self.factory() as db:
            self.assertIsNotNone(db.get(AuthUser,self.staff_id))

    def test_delete_rejects_own_admin_account(self):
        response = self.deletion(self.admin_id, confirm_username='adminowner')
        self.assertEqual(response.status_code,409)
        with self.factory() as db:
            self.assertIsNotNone(db.get(AuthUser,self.admin_id))

    def test_delete_requires_exact_username_checkbox_and_admin_password(self):
        self.web.patch(f'/api/admin/users/{self.staff_id}',headers=self.head('admin'),json={'is_active':False})
        self.assertEqual(self.deletion(self.staff_id, confirm_username='StaffPerson').status_code,422)
        self.assertEqual(self.deletion(self.staff_id, confirm_permanent_delete=False).status_code,422)
        self.assertEqual(self.deletion(self.staff_id, admin_password='wrong').status_code,403)
        self.assertEqual(self.deletion(self.staff_id, secret_debug='ignored').status_code,422)
        with self.factory() as db:
            self.assertIsNotNone(db.get(AuthUser,self.staff_id))

    def test_delete_removes_account_sessions_grants_and_user_audit_without_inventory_changes(self):
        self.web.patch(f'/api/admin/users/{self.staff_id}',headers=self.head('admin'),json={'is_active':False})
        response = self.deletion(self.staff_id)
        self.assertEqual(response.status_code,200,response.text)
        self.assertNotIn(PASSWORD,response.text)
        self.assertNotIn('staffperson',response.text)
        with self.factory() as db:
            self.assertIsNone(db.get(AuthUser,self.staff_id))
            self.assertEqual(db.scalars(select(AuthSession).where(AuthSession.user_id==self.staff_id)).all(),[])
            self.assertEqual(db.scalars(select(AuthClientGrant).where(AuthClientGrant.user_id==self.staff_id)).all(),[])
            self.assertEqual(db.scalars(select(AuthAuditEvent).where(AuthAuditEvent.target_user_id==self.staff_id)).all(),[])
            self.assertEqual(db.scalars(select(AuthAuditEvent).where(AuthAuditEvent.actor_user_id==self.staff_id)).all(),[])
            self.assertEqual(db.get(Server,self.server_id).host,'192.0.2.40')
            self.assertEqual(db.get(Client,self.cid_a).name,'Alpha Company')
        self.assertEqual(self.web.get('/api/auth/me',headers=self.head('staff')).status_code,401)
        audit=self.web.get('/api/admin/audit',headers=self.head('admin'))
        self.assertEqual(audit.status_code,200)
        deleted=[v for v in audit.json()['events'] if v['action']=='user_permanently_deleted']
        self.assertEqual(len(deleted),1)
        self.assertIsNone(deleted[0]['target_user_id'])
        self.assertEqual(deleted[0]['details']['deleted_role'],'staff')
        self.assertNotIn('staffperson',audit.text)
        self.assertNotIn(PASSWORD,audit.text)

    def test_delete_missing_account_fails_without_changing_another_user(self):
        self.assertEqual(self.deletion('00000000-0000-0000-0000-000000000000').status_code,404)
        with self.factory() as db:
            self.assertIsNotNone(db.get(AuthUser,self.staff_id))


if __name__=='__main__':
    unittest.main()
