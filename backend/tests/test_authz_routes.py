"""Step 38.3: HTTP-level tenant isolation and authorization tests; never contacts SSH."""
import unittest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.database import Base, Client, Server
from backend.auth_models import AuthUser, AuthClientGrant
from backend.auth_security import create_session
from backend.auth_api import auth_database
from backend.main import app
import backend.main as main


class ProtectedRoutesTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine('sqlite+pysqlite:///:memory:',
                               connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(engine)
        self.engine=engine
        self.factory=sessionmaker(bind=engine, autocommit=False, autoflush=False)
        def auth_override():
            with self.factory() as db: yield db
        app.dependency_overrides[auth_database]=auth_override
        self.mock_db=patch.object(main,'SessionLocal',self.factory)
        self.mock_registry=patch.object(main,'_monitoring_registry_exists',return_value=True)
        self.mock_db.start();self.mock_registry.start()
        with self.factory() as db:
            a=Client(name='Tenant A');b=Client(name='Tenant B')
            db.add_all([a,b]);db.flush()
            self.a_id=a.id;self.b_id=b.id
            one=Server(client_id=a.id,name='A-vps',host='192.0.2.5',ssh_username='monitor')
            two=Server(client_id=b.id,name='B-vps',host='198.51.100.5',ssh_username='monitor')
            db.add_all([one,two]);db.flush()
            self.a_server=one.id;self.b_server=two.id
            admin=AuthUser(username='admin111',display_name='Administrator',role='admin',password_hash='irrelevant')
            staff=AuthUser(username='staff111',display_name='Staff',role='staff',password_hash='irrelevant')
            client=AuthUser(username='client111',display_name='Client',role='client',client_id=a.id,password_hash='irrelevant')
            ungranted=AuthUser(username='ungranted',display_name='Staff2',role='staff',password_hash='irrelevant')
            db.add_all([admin,staff,client,ungranted]);db.flush()
            db.add(AuthClientGrant(user_id=staff.id,client_id=a.id))
            db.commit()
            self.headers={}
            for key,user in [('admin',admin),('staff',staff),('client',client),('ungranted',ungranted)]:
                token,_=create_session(db,user)
                self.headers[key]={'Authorization':f'Bearer {token}'}
        self.web=TestClient(app)

    def tearDown(self):
        self.web.close()
        app.dependency_overrides.clear()
        self.mock_db.stop(); self.mock_registry.stop()
        self.engine.dispose()

    def test_unauthenticated_endpoints_are_denied(self):
        for url in ['/api/servers','/api/servers/archived','/api/monitoring/targets',
                    '/api/onboarding/preflight',f'/api/servers/{self.a_server}/health']:
            with self.subTest(url=url):self.assertEqual(self.web.get(url).status_code,401)
        self.assertEqual(self.web.post('/api/servers',json={}).status_code,401)
        self.assertEqual(self.web.get('/api/health').status_code,200)

    def test_admin_inventory_sees_both_tenants(self):
        r=self.web.get('/api/servers',headers=self.headers['admin'])
        self.assertEqual(r.status_code,200)
        self.assertEqual({x['name'] for x in r.json()['servers']},{'A-vps','B-vps'})

    def test_staff_client_and_ungranted_scope(self):
        for role,names in [('staff',{'A-vps'}),('client',{'A-vps'}),('ungranted',set())]:
            with self.subTest(role=role):
                h=self.headers[role]
                self.assertEqual({x['name'] for x in self.web.get('/api/servers',headers=h).json()['servers']},names)
                self.assertEqual({x['server_name'] for x in self.web.get('/api/monitoring/targets',headers=h).json()['targets']},names)
                self.assertEqual({x['server_name'] for x in self.web.get('/api/onboarding/preflight',headers=h).json()['entries']},names)
                self.assertEqual(self.web.get('/api/servers/archived',headers=h).status_code,200)

    def test_cross_client_health_never_reaches_ssh(self):
        with patch.object(main,'collect_ssh_health',side_effect=AssertionError('remote SSH called')) as spy:
            r=self.web.get(f'/api/servers/{self.b_server}/health',headers=self.headers['client'])
            self.assertEqual(r.status_code,404)
            spy.assert_not_called()

    def test_staff_client_cannot_write_even_with_valid_login(self):
        for role in ['staff','client','ungranted']:
            with self.subTest(role=role):
                h=self.headers[role]
                self.assertEqual(self.web.post('/api/servers',headers=h,json={'client_name':'Tenant B','name':'hack','host':'203.0.113.5'}).status_code,403)
                self.assertEqual(self.web.patch(f'/api/servers/{self.a_server}',headers=h,json={'name':'alter'}).status_code,403)
                self.assertEqual(self.web.post(f'/api/servers/{self.a_server}/archive',headers=h).status_code,403)
                self.assertEqual(self.web.post(f'/api/servers/{self.a_server}/restore',headers=h).status_code,403)

    def test_admin_write_preserves_inventory(self):
        r=self.web.post('/api/servers',headers=self.headers['admin'],json={'client_name':'Tenant A','name':'Test 3','host':'203.0.113.5'})
        self.assertEqual(r.status_code,201)
        self.assertEqual(self.web.post(f"/api/servers/{r.json()['id']}/archive",headers=self.headers['admin']).status_code,200)
        self.assertEqual(self.web.post(f"/api/servers/{r.json()['id']}/restore",headers=self.headers['admin']).status_code,200)


if __name__ == '__main__':unittest.main()
