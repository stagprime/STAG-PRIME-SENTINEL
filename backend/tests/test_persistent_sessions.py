"""Step 38.4.6: isolated HTTP cookie/CSRF tests. Does not access sentinel.db or SSH."""
import hashlib
import unittest
from datetime import timedelta
from unittest.mock import patch

from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth_api import auth_database, router, require_current_session
from backend.auth_models import AuthSession, AuthUser, create_auth_tables, utcnow
from backend.auth_security import hash_password
from backend.database import Base
from backend.user_management import admin_router, initialize_user_management_db

ORIGIN = {'Origin': 'http://localhost:5173'}
PASSWORD = 'Testing-very-long-secret-passphrase-2026!'


class PersistentSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = hash_password(PASSWORD)

    def setUp(self):
        self.engine = create_engine('sqlite+pysqlite:///:memory:',
                                    connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        initialize_user_management_db(self.engine)
        self.factory = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        with self.factory() as db:
            u = AuthUser(username='cookieadmin', display_name='Cookie Admin',
                         role='admin', password_hash=self.password_hash)
            db.add(u)
            db.commit()
            self.uid = u.id
        app = FastAPI()
        app.include_router(router)
        app.include_router(admin_router)
        @app.post('/api/dummy-change')
        def dummy_change(current=Depends(require_current_session)):
            return {'ok': True, 'username': current[0].username}
        def override_db():
            with self.factory() as db:
                yield db
        app.dependency_overrides[auth_database] = override_db
        self.client = TestClient(app, base_url='http://localhost:5173')

    def tearDown(self):
        self.client.close()
        self.engine.dispose()

    def login(self):
        return self.client.post('/api/auth/login-cookie', headers=ORIGIN,
                                json={'username': 'cookieadmin', 'password': PASSWORD})

    def test_cookie_is_httponly_samesite_strict_and_not_returned(self):
        res = self.login()
        self.assertEqual(res.status_code, 200)
        self.assertNotIn('access_token', res.json())
        self.assertNotIn('token_type', res.json())
        header = res.headers['set-cookie'].lower()
        for part in ('sentinel_session=', 'httponly', 'samesite=strict', 'path=/api', 'max-age=28800'):
            self.assertIn(part, header)
        self.assertEqual(res.headers['cache-control'], 'no-store')

    def test_secure_cookie_switch_for_https_deployment(self):
        with patch.dict('os.environ', {'SENTINEL_COOKIE_SECURE': '1'}):
            response = self.login()
        self.assertEqual(response.status_code, 200)
        self.assertIn('secure', response.headers['set-cookie'].lower())

    def test_refresh_restores_user_and_csrf(self):
        data = self.login().json()
        res = self.client.get('/api/auth/session')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['user']['username'], 'cookieadmin')
        self.assertEqual(res.json()['csrf_token'], data['csrf_token'])
        self.assertNotIn('access_token', res.json())
        self.assertEqual(self.client.get('/api/auth/me').status_code, 200)

    def test_login_requires_origin_and_rejects_cross_origin(self):
        self.assertEqual(self.client.post('/api/auth/login-cookie', json={
            'username': 'cookieadmin', 'password': PASSWORD}).status_code, 403)
        self.assertEqual(self.client.post('/api/auth/login-cookie',
            headers={'Origin': 'https://bad.example'}, json={
                'username': 'cookieadmin', 'password': PASSWORD}).status_code, 403)
        self.assertIsNone(self.client.cookies.get('sentinel_session'))

    def test_cookie_write_without_csrf_is_denied(self):
        self.login()
        self.assertEqual(self.client.post('/api/dummy-change').status_code, 403)
        self.assertEqual(self.client.post('/api/auth/logout-cookie').status_code, 403)
        self.assertEqual(self.client.get('/api/auth/session').status_code, 200)

    def test_cookie_wrong_csrf_denied_correct_allowed(self):
        data = self.login().json()
        self.assertEqual(self.client.post('/api/dummy-change',
                         headers={'X-Sentinel-CSRF': 'incorrect'}).status_code, 403)
        self.assertEqual(self.client.post('/api/dummy-change',
                         headers={'X-Sentinel-CSRF': data['csrf_token']}).status_code, 200)

    def test_admin_mutation_requires_csrf(self):
        data = self.login().json()
        self.assertEqual(self.client.get('/api/admin/users').status_code, 200)
        request = {'username': 'teststaff', 'display_name': 'Test Staff',
                   'password': PASSWORD, 'role': 'staff', 'client_ids': []}
        self.assertEqual(self.client.post('/api/admin/users', json=request).status_code, 403)
        self.assertEqual(self.client.post('/api/admin/users', json=request,
            headers={'X-Sentinel-CSRF': data['csrf_token']}).status_code, 201)

    def test_logout_invalidates_session_and_removes_cookie(self):
        data = self.login().json()
        cookie = self.client.cookies.get('sentinel_session')
        res = self.client.post('/api/auth/logout-cookie',
                               headers={'X-Sentinel-CSRF': data['csrf_token']})
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(self.client.cookies.get('sentinel_session'))
        self.assertEqual(self.client.get('/api/auth/session').status_code, 401)
        with self.factory() as db:
            session = db.get(AuthSession, hashlib.sha256(cookie.encode()).hexdigest())
            self.assertIsNotNone(session.revoked_at_utc)

    def test_disabled_account_invalidates_cookie_session(self):
        self.login()
        with self.factory() as db:
            user = db.get(AuthUser, self.uid)
            user.is_active = False
            db.commit()
        self.assertEqual(self.client.get('/api/auth/session').status_code, 401)

    def test_expired_cookie_session_denied(self):
        self.login()
        token = self.client.cookies.get('sentinel_session')
        with self.factory() as db:
            session = db.get(AuthSession, hashlib.sha256(token.encode()).hexdigest())
            session.expires_at_utc = utcnow() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.get('/api/auth/session').status_code, 401)

    def test_cookie_and_bearer_compatibility(self):
        self.login()
        old = self.client.post('/api/auth/login', json={
            'username': 'cookieadmin', 'password': PASSWORD})
        token = old.json()['access_token']
        self.assertEqual(self.client.post('/api/dummy-change',
                         headers={'Authorization': 'Bearer ' + token}).status_code, 200)
        self.assertEqual(self.client.get('/api/auth/me', headers={
            'Authorization': 'Bearer ' + token}).status_code, 200)

    def test_logout_clears_expired_cookie(self):
        self.login()
        token = self.client.cookies.get('sentinel_session')
        with self.factory() as db:
            session = db.get(AuthSession, hashlib.sha256(token.encode()).hexdigest())
            session.revoked_at_utc = utcnow()
            db.commit()
        self.assertEqual(self.client.post('/api/auth/logout-cookie').status_code, 200)
        self.assertIsNone(self.client.cookies.get('sentinel_session'))


if __name__ == '__main__':
    unittest.main()
