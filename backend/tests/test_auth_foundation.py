"""Step 38.1 isolated HTTP/security checks. Never touches data/sentinel.db."""
import hashlib
import os
import unittest
from datetime import timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth_api import auth_database, router
from backend.auth_models import AuthClientGrant, AuthSession, AuthUser, create_auth_tables, utcnow
from backend.auth_security import (
    authenticate, can_access_client, create_session, hash_password,
    lookup_session, normalize_username, require_client_access, validate_password,
    verify_password,
)
from backend.database import Base, Client


class TestAuthenticationFoundation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "This-is-a-unique-long-phrase-438!"
        cls.pwhash = hash_password(cls.password)

    def setUp(self):
        self.engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False}, poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        create_auth_tables(self.engine)
        self.factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        with self.factory() as db:
            a = Client(name="Tenant A")
            b = Client(name="Tenant B")
            db.add_all([a, b]); db.flush()
            self.cid_a, self.cid_b = a.id, b.id
            admin = AuthUser(username="adminuser", display_name="Admin", role="admin", password_hash=self.pwhash)
            staff = AuthUser(username="staffuser", display_name="Staff", role="staff", password_hash=self.pwhash)
            client = AuthUser(username="clientuser", display_name="Client", role="client", client_id=a.id, password_hash=self.pwhash)
            db.add_all([admin, staff, client]); db.flush()
            self.admin_id, self.staff_id, self.client_id = admin.id, staff.id, client.id
            db.add(AuthClientGrant(user_id=staff.id, client_id=a.id))
            db.commit()

        app = FastAPI()
        app.include_router(router)
        def override_database():
            with self.factory() as db:
                yield db
        app.dependency_overrides[auth_database] = override_database
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        self.engine.dispose()

    def login(self, username="adminuser", password=None):
        return self.client.post("/api/auth/login", json={"username": username, "password": password if password is not None else self.password})

    def test_login_token_random_and_hash_only_at_rest(self):
        a = self.login()
        b = self.login()
        self.assertEqual(a.status_code, 200)
        self.assertEqual(a.json()["user"]["role"], "admin")
        self.assertEqual(a.headers["cache-control"], "no-store")
        self.assertNotEqual(a.json()["access_token"], b.json()["access_token"])
        token = a.json()["access_token"]
        with self.factory() as db:
            rows = db.scalars(select(AuthSession)).all()
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0].token_hash, hashlib.sha256(token.encode()).hexdigest())
            self.assertNotEqual(rows[0].token_hash, token)

    def test_password_is_salted_hash_not_plaintext(self):
        self.assertTrue(verify_password(self.password, self.pwhash))
        self.assertFalse(verify_password("wrong", self.pwhash))
        self.assertNotIn(self.password, self.pwhash)
        self.assertNotEqual(hash_password(self.password), self.pwhash)

    def test_password_rules_and_username_rules(self):
        self.assertEqual(normalize_username("  Client.User  "), "client.user")
        with self.assertRaises(ValueError):
            normalize_username("a")
        with self.assertRaises(ValueError):
            validate_password("short", "alice")
        with self.assertRaises(ValueError):
            validate_password("alice-My-Really-Long-Passphrase-559!", "alice")

    def test_invalid_login_generic_failure(self):
        self.assertEqual(self.login("adminuser", "wrong").status_code, 401)
        self.assertEqual(self.login("absentuser", "wrong").status_code, 401)
        self.assertEqual(self.login("adminuser", "wrong").json()["detail"], "Invalid credentials")
        self.assertEqual(self.login("absentuser", "wrong").json()["detail"], "Invalid credentials")

    def test_me_requires_auth_and_logout_revokes(self):
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        token = self.login().json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}
        self.assertEqual(self.client.get("/api/auth/me", headers=h).json()["username"], "adminuser")
        self.assertEqual(self.client.post("/api/auth/logout", headers=h).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=h).status_code, 401)

    def test_expired_session_denied(self):
        token = self.login().json()["access_token"]
        with self.factory() as db:
            session = db.get(AuthSession, hashlib.sha256(token.encode()).hexdigest())
            session.expires_at_utc = utcnow() - timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code, 401)

    def test_disabled_user_denied_even_with_live_token(self):
        token = self.login().json()["access_token"]
        with self.factory() as db:
            user = db.get(AuthUser, self.admin_id)
            user.is_active = False
            db.commit()
        self.assertEqual(self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code, 401)

    def test_account_lockout_five_failures(self):
        for _ in range(5):
            self.assertEqual(self.login(password="bad-passphrase").status_code, 401)
        self.assertEqual(self.login().status_code, 401)
        with self.factory() as db:
            admin = db.get(AuthUser, self.admin_id)
            self.assertGreater(admin.locked_until_utc, utcnow())

    def test_admin_scopes_all_clients(self):
        token = self.login().json()["access_token"]
        response = self.client.get("/api/auth/clients", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual({x["name"] for x in response.json()["clients"]}, {"Tenant A", "Tenant B"})

    def test_staff_scopes_only_explicit_grants(self):
        token = self.login(username="staffuser").json()["access_token"]
        res = self.client.get("/api/auth/clients", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual([x["name"] for x in res.json()["clients"]], ["Tenant A"])
        with self.factory() as db:
            user = db.get(AuthUser, self.staff_id)
            self.assertTrue(can_access_client(db, user, self.cid_a))
            self.assertFalse(can_access_client(db, user, self.cid_b))

    def test_client_scopes_only_own_tenant(self):
        token = self.login(username="clientuser").json()["access_token"]
        res = self.client.get("/api/auth/clients", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual([x["name"] for x in res.json()["clients"]], ["Tenant A"])
        with self.factory() as db:
            user = db.get(AuthUser, self.client_id)
            self.assertTrue(can_access_client(db, user, self.cid_a))
            self.assertFalse(can_access_client(db, user, self.cid_b))

    def test_staff_without_grant_denied_by_default(self):
        with self.factory() as db:
            db.query(AuthClientGrant).delete()
            db.commit()
        token = self.login(username="staffuser").json()["access_token"]
        self.assertEqual(self.client.get("/api/auth/clients", headers={"Authorization": f"Bearer {token}"}).json()["clients"], [])

    def test_create_table_does_not_modify_existing_inventory(self):
        with self.factory() as db:
            before = db.scalar(select(Client).where(Client.id == self.cid_a)).name
        create_auth_tables(self.engine)
        with self.factory() as db:
            after = db.scalar(select(Client).where(Client.id == self.cid_a)).name
        self.assertEqual(before, after)

    def test_wrong_scheme_denied(self):
        self.assertEqual(self.client.get("/api/auth/me", headers={"Authorization": "Basic abc"}).status_code, 401)


if __name__ == "__main__":
    unittest.main()
