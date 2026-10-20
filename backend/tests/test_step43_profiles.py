"""Step 43: offline, private-key-safe API and parser regressions."""
import os
import unittest
from unittest.mock import patch
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

from backend.database import Base, Client, Server
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.auth_api import auth_database
from backend.admin_access import ServerAdminAudit
from backend.main import app
import backend.openvpn_profiles as profiles
import backend.admin_access as admin

SAMPLE = '''client\ndev tun\nproto udp\nremote 198.51.100.8 1194\nremote-cert-tls server\n<ca>\nCA_DATA\n</ca>\n<cert>\nCERT_DATA\n</cert>\n<key>\nPRIVATE_SECRET_NOT_FOR_BROWSER\n</key>\n'''

class ProfilesTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite+pysqlite:///:memory:',poolclass=StaticPool,connect_args={'check_same_thread':False})
        self.Session=sessionmaker(bind=self.engine,autoflush=False,autocommit=False)
        Base.metadata.create_all(self.engine)
        self.fernet=Fernet(Fernet.generate_key())
        self.patchers=[patch.object(profiles,'SessionLocal',self.Session),patch.object(profiles,'engine',self.engine),
                       patch.object(profiles,'_master_key',return_value=self.fernet),
                       patch.object(admin,'SessionLocal',self.Session),patch.object(admin,'engine',self.engine),
                       patch.dict(os.environ,{'SENTINEL_CREDENTIAL_DEV_ALLOW_LOCAL':'1'})]
        for p in self.patchers:p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patchers)])
        self.addCleanup(self.engine.dispose)
        with self.Session() as db:
            client1=Client(name='Tenant One');client2=Client(name='Tenant Two')
            db.add_all([client1,client2]);db.flush()
            one=Server(client_id=client1.id,name='vpn-one',host='192.0.2.11',ssh_port=22)
            two=Server(client_id=client2.id,name='vpn-two',host='192.0.2.12',ssh_port=22)
            db.add_all([one,two]);db.flush()
            self.sid=one.id;self.foreign=two.id
            root=AuthUser(username='profiles-root',display_name='Admin',role='admin',password_hash='unused')
            viewer=AuthUser(username='profiles-client',display_name='Client',role='client',client_id=client1.id,password_hash='unused')
            db.add_all([root,viewer]);db.flush()
            self.root_token,_=create_session(db,root)
            self.viewer_token,_=create_session(db,viewer)
        def override():
            with self.Session() as db:yield db
        app.dependency_overrides[auth_database]=override
        self.addCleanup(app.dependency_overrides.clear)
        self.web=TestClient(app)
        self.addCleanup(self.web.close)
        self.url=f'/api/server-operations/servers/{self.sid}/openvpn-profiles'
        self.root_headers={'Authorization':'Bearer '+self.root_token}
        self.viewer_headers={'Authorization':'Bearer '+self.viewer_token}

    def payload(self,**kw):
        return {'name':'admin-client','ovpn_content':SAMPLE,**kw}

    def test_auth_guard_and_role_guard(self):
        self.assertEqual(self.web.get(self.url).status_code,401)
        self.assertEqual(self.web.get(self.url,headers=self.viewer_headers).status_code,403)
        self.assertEqual(self.web.post(self.url,json=self.payload(),headers=self.viewer_headers).status_code,403)

    def test_encrypted_import_metadata_no_secret_leak(self):
        response=self.web.post(self.url,json=self.payload(vpn_username='alice',vpn_password='verysecret'),headers=self.root_headers)
        self.assertEqual(response.status_code,201,response.text)
        self.assertNotIn('PRIVATE_SECRET',response.text)
        self.assertNotIn('verysecret',response.text)
        self.assertTrue(response.json()['has_inline_private_key'])
        with self.Session() as db:
            row=db.scalars(select(profiles.EncryptedOpenVPNProfile)).one()
            self.assertNotIn(b'PRIVATE_SECRET',row.encrypted_payload)
            decrypted=self.fernet.decrypt(row.encrypted_payload)
            self.assertIn(b'PRIVATE_SECRET',decrypted)
        listed=self.web.get(self.url,headers=self.root_headers)
        self.assertEqual(listed.status_code,200,listed.text)
        self.assertEqual(len(listed.json()['profiles']),1)
        self.assertNotIn('PRIVATE_SECRET',listed.text)
        self.assertFalse(listed.json()['monitoring_requires_profile'])

    def test_duplicate_names_and_remove(self):
        one=self.web.post(self.url,json=self.payload(),headers=self.root_headers)
        self.assertEqual(one.status_code,201,one.text)
        self.assertEqual(self.web.post(self.url,json=self.payload(),headers=self.root_headers).status_code,409)
        url=self.url+'/'+one.json()['id']
        self.assertEqual(self.web.delete(url,headers=self.root_headers).status_code,200)
        self.assertEqual(self.web.delete(url,headers=self.root_headers).status_code,404)
        with self.Session() as db:
            actions=[x.operation for x in db.scalars(select(ServerAdminAudit)).all()]
            self.assertIn('openvpn_profile_import',actions)
            self.assertIn('openvpn_profile_remove',actions)

    def test_cross_server_delete_rejected(self):
        one=self.web.post(self.url,json=self.payload(),headers=self.root_headers)
        bad=f'/api/server-operations/servers/{self.foreign}/openvpn-profiles/{one.json()["id"]}'
        self.assertEqual(self.web.delete(bad,headers=self.root_headers).status_code,404)

    def test_unsafe_directives_rejected(self):
        for directive in ('script-security 2','up /tmp/evil','plugin /tmp/lib.so',
                          'management 0.0.0.0 9999','auth-user-pass /home/user/secret','config /tmp/a'):
            with self.subTest(directive=directive):
                content=SAMPLE+directive+'\n'
                r=self.web.post(self.url,json=self.payload(ovpn_content=content),headers=self.root_headers)
                self.assertEqual(r.status_code,422,(directive,r.text))
        with self.Session() as db:self.assertEqual(db.query(profiles.EncryptedOpenVPNProfile).count(),0)

    def test_invalid_profile_and_payload_rejected(self):
        for content in ('server\nremote foo','client\n',SAMPLE+'</key>\n',SAMPLE+'\x00',SAMPLE+'x'*140000):
            with self.subTest(value=content[:12]):
                self.assertEqual(self.web.post(self.url,json=self.payload(ovpn_content=content),headers=self.root_headers).status_code,422)

    def test_request_validation_does_not_echo_secret(self):
        response=self.web.post(self.url,json={'name':123,'ovpn_content':SAMPLE},headers=self.root_headers)
        self.assertEqual(response.status_code,422)
        self.assertNotIn('PRIVATE_SECRET',response.text)
        self.assertNotIn(SAMPLE,response.text)

    def test_vpn_password_requires_username(self):
        self.assertEqual(self.web.post(self.url,json=self.payload(vpn_password='abc'),headers=self.root_headers).status_code,422)

    def test_profile_vault_unavailable_fails_closed(self):
        with patch.object(profiles,'_master_key',side_effect=RuntimeError('vault secret path')):
            result=self.web.post(self.url,json=self.payload(),headers=self.root_headers)
        self.assertEqual(result.status_code,503)
        self.assertNotIn('vault secret path',result.text)

    def test_windows_crlf_client_profile_imports(self):
        profile = SAMPLE.replace('\n', '\r\n')
        result=self.web.post(self.url,json=self.payload(ovpn_content=profile),headers=self.root_headers)
        self.assertEqual(result.status_code,201,result.text)

    def test_no_ssh_connect_or_external_requests_on_upload(self):
        with patch('backend.ssh_monitor._connect_verified',side_effect=AssertionError('Unexpected SSH')) as ssh:
            self.assertEqual(self.web.post(self.url,json=self.payload(),headers=self.root_headers).status_code,201)
            ssh.assert_not_called()

if __name__=='__main__':unittest.main()
