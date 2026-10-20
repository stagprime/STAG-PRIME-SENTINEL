"""Step 40.10B offline tests: encrypted credential enrollment; NO LIVE VPS."""
import os
import tempfile
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.main as main
import backend.credential_vault as vault
import backend.admin_access as access
from backend.auth_api import auth_database, SESSION_COOKIE, _csrf_for_token
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server

class CredentialVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread':False},poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine,autoflush=False,autocommit=False)
        self.key = Fernet.generate_key().decode()
        self.patches = [patch.object(vault, 'engine',self.engine),patch.object(vault,'SessionLocal',self.sessions),
                        patch.object(access,'engine',self.engine),patch.object(access,'SessionLocal',self.sessions),
                        patch.dict(os.environ, {'SENTINEL_VAULT_MASTER_KEY':self.key,
                                                'SENTINEL_CREDENTIAL_DEV_ALLOW_LOCAL':'1'})]
        for p in self.patches: p.start()
        def auth_db():
            with self.sessions() as db: yield db
        main.app.dependency_overrides[auth_database]=auth_db
        with self.sessions() as db:
            owner=Client(name='Local Credential Test')
            db.add(owner);db.flush()
            srv=Server(client_id=owner.id,name='Local Test VPS',host='192.0.2.11',ssh_port=22,ssh_username='opc')
            db.add(srv);db.flush();self.server_id=srv.id
            admin=AuthUser(username='credential_admin',display_name='Admin',role='admin',password_hash='not-real')
            user=AuthUser(username='credential_user',display_name='Staff',role='staff',password_hash='not-real')
            db.add_all([admin,user]);db.flush()
            self.tokens={}
            for role,who in [('admin',admin),('staff',user)]:
                self.tokens[role]=create_session(db,who)[0]
            db.commit()
        self.client=TestClient(main.app)
        self.url=f'/api/server-operations/servers/{self.server_id}/credentials'
    def tearDown(self):
        self.client.close();main.app.dependency_overrides.clear()
        for p in reversed(self.patches):p.stop()
        self.engine.dispose();self.temp.cleanup()
    def headers(self,role='admin'):
        return {'Authorization':'Bearer '+self.tokens[role]}
    def enroll(self,method='password',secret='Test-Password-12345!'):
        return self.client.post(self.url,headers=self.headers(),json={'auth_method':method,'secret':secret})

    def test_password_encrypted_never_responded_and_pinned(self):
        secret='Unique-Test-Secret-XYZ12!'
        r=self.enroll(secret=secret)
        self.assertEqual(r.status_code,200,r.text)
        self.assertNotIn(secret,r.text)
        self.assertFalse(r.json()['host_key_verified'])
        with self.sessions() as db:
            item=db.get(vault.EncryptedSSHCredential,self.server_id)
            self.assertNotIn(secret.encode(),item.encrypted_secret)
            profile=db.get(access.ServerAdminProfile,self.server_id)
            self.assertEqual(profile.private_key_path,'sentinel-vault:'+self.server_id)
            self.assertEqual(db.query(access.ServerAdminAudit).count(),1)
        mode,value=vault.load_ssh_secret(self.server_id,host='192.0.2.11',port=22,username='opc')
        self.assertEqual((mode,value),('password',secret))
        r=self.client.get(self.url+'/status',headers=self.headers())
        self.assertEqual(r.status_code,200)
        self.assertNotIn(secret,r.text)
        self.assertTrue(r.json()['host_pinned'])
        self.assertTrue(access._safe_profile(self._get_server(), self._get_profile())['verification_ready'])
    def _get_server(self):
        with self.sessions() as db:
            s=db.get(Server,self.server_id)
            db.expunge(s)
            return s
    def _get_profile(self):
        with self.sessions() as db:
            s=db.get(access.ServerAdminProfile,self.server_id)
            db.expunge(s)
            return s
    def test_saved_password_status_survives_readback_without_exposing_secret(self):
        secret='PersistedCredentialTest123!'
        self.assertEqual(self.enroll(secret=secret).status_code,200)
        response=self.client.get(self.url+'/status',headers=self.headers())
        self.assertEqual(response.status_code,200,response.text)
        data=response.json()
        self.assertTrue(data['configured'])
        self.assertEqual(data['auth_method'],'password')
        self.assertTrue(data['host_pinned'])
        self.assertTrue(data['vault_accessible'])
        self.assertTrue(data['last_updated_at_utc'])
        self.assertNotIn(secret,response.text)
        self.assertNotIn('encrypted_secret',response.text)
        self.assertNotIn('private_key_path',response.text)

    def test_saved_status_fails_closed_if_encrypted_data_is_corrupt(self):
        self.assertEqual(self.enroll().status_code,200)
        with self.sessions.begin() as db:
            db.get(vault.EncryptedSSHCredential,self.server_id).encrypted_secret=b'corrupt-token'
        response=self.client.get(self.url+'/status',headers=self.headers())
        self.assertEqual(response.status_code,200,response.text)
        self.assertTrue(response.json()['configured'])
        self.assertFalse(response.json()['vault_accessible'])
        self.assertNotIn('corrupt-token',response.text)

    def test_admin_only_and_csrf(self):
        body={'auth_method':'password','secret':'Test-Password-12345!'}
        self.assertEqual(self.client.post(self.url,json=body).status_code,401)
        self.assertEqual(self.client.post(self.url,headers=self.headers('staff'),json=body).status_code,403)
        cookie={'Cookie':f'{SESSION_COOKIE}={self.tokens["admin"]}'}
        self.assertEqual(self.client.post(self.url,headers=cookie,json=body).status_code,403)
        cookie['x-sentinel-csrf']=_csrf_for_token(self.tokens['admin'])
        self.assertEqual(self.client.post(self.url,headers=cookie,json=body).status_code,200)
    def test_bad_types_forbidden_and_no_raw_secret_in_errors(self):
        for body in ({'auth_method':'root','secret':'Test-Password-12345!'},
                     {'auth_method':'password','secret':'short'},
                     {'auth_method':'password','secret':'Test-Password-12345!','command':'sudo reboot'},
                     {'auth_method':'private_key','secret':'ssh-ed25519 AAAA...'},
                     {'auth_method':'password','secret':['Test-Password-12345!']}):
            r=self.client.post(self.url,headers=self.headers(),json=body)
            self.assertEqual(r.status_code,422,r.text)
            self.assertNotIn('Test-Password-12345!',r.text)
    def test_change_endpoint_breaks_pinned_vault_access(self):
        self.enroll()
        with self.sessions() as db:
            db.get(Server,self.server_id).host='192.0.2.44';db.commit()
        with self.assertRaises(RuntimeError):
            vault.load_ssh_secret(self.server_id,host='192.0.2.11',port=22,username='opc')
        self.assertFalse(vault.credential_ready(self.server_id))
    def test_archived_server_rejects_enrollment(self):
        from datetime import datetime, timezone
        with self.sessions() as db:
            db.get(Server,self.server_id).archived_at=datetime.now(timezone.utc);db.commit()
        self.assertEqual(self.enroll().status_code,404)
    def test_without_master_key_fails_closed(self):
        # On Windows an empty env var still permits the external LOCALAPPDATA
        # master-key fallback. Isolate BOTH key sources during this test so
        # it validates genuine key unavailability, not a live development key.
        absent_vault_root = os.path.join(self.temp.name, 'vault-not-initialized')
        with patch.dict(os.environ, {
            'SENTINEL_VAULT_MASTER_KEY': '',
            'LOCALAPPDATA': absent_vault_root,
        }):
            self.assertFalse(vault.credential_ready(self.server_id))
            response = self.enroll()
            self.assertEqual(response.status_code, 503, response.text)
            self.assertNotIn('Test-Password-12345!', response.text)
    def test_unknown_server_rejected(self):
        self.assertEqual(self.client.post('/api/server-operations/servers/no-such-server/credentials',headers=self.headers(),json={'auth_method':'password','secret':'Test-Password-12345!'}).status_code,404)
    def test_status_does_not_expose_secret_or_path(self):
        self.enroll()
        r=self.client.get(self.url+'/status',headers=self.headers())
        self.assertNotIn('encrypted_secret',r.text)
        self.assertNotIn('credential_version',r.text)
        self.assertNotIn('private_key_path',r.text)

if __name__=='__main__':unittest.main()
