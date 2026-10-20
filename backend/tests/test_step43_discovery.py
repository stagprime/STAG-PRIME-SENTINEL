"""Step 43: OpenVPN discovery fail-closed API, parser and mock scanner."""
import os
import json
import unittest
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from backend.database import Base, Client, Server
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.auth_api import auth_database
from backend.admin_access import ServerAdminProfile
from backend.main import app
import backend.openvpn_discovery as d
import backend.admin_access as admin

VALID={
 'services':[{'name':'openvpn-server@server','active':True}],
 'tunnel_interfaces':['tun0'],'network_interface':'ens3',
 'suggested_vpn_service':'openvpn-server@server','suggested_vpn_interface':'tun0',
 'status_file':{'found':True,'readable':True}
}

class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite+pysqlite:///:memory:',poolclass=StaticPool,connect_args={'check_same_thread':False})
        self.Session=sessionmaker(bind=self.engine,autoflush=False,autocommit=False)
        Base.metadata.create_all(self.engine)
        self.patchers=[patch.object(d,'SessionLocal',self.Session),patch.object(admin,'SessionLocal',self.Session),
                       patch.object(admin,'engine',self.engine),patch.dict(os.environ,{'SENTINEL_CREDENTIAL_DEV_ALLOW_LOCAL':'1'})]
        for p in self.patchers:p.start()
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patchers)])
        self.addCleanup(self.engine.dispose)
        with self.Session() as db:
            org=Client(name='Demo test');db.add(org);db.flush()
            server=Server(client_id=org.id,name='dev',host='192.0.2.35',ssh_username='opc',ssh_port=22)
            db.add(server);db.flush();self.sid=server.id
            root=AuthUser(username='discover-admin',role='admin',display_name='Admin',password_hash='none')
            other=AuthUser(username='discover-client',role='client',display_name='Client',client_id=org.id,password_hash='none')
            db.add_all([root,other]);db.flush();db.commit()
            self.token,_=create_session(db,root);self.other_token,_=create_session(db,other)
        def override():
            with self.Session() as db:yield db
        app.dependency_overrides[auth_database]=override
        self.addCleanup(app.dependency_overrides.clear)
        self.web=TestClient(app)
        self.addCleanup(self.web.close)
        self.url=f'/api/server-operations/servers/{self.sid}/openvpn/discover'
        self.auth={'Authorization':'Bearer '+self.token}
    def test_validator_accepts_minimal_safe_result(self):
        x=d.validate_discovery(VALID)
        self.assertTrue(x['read_only'])
        self.assertFalse(x['installation_authorized'])
    def test_validator_rejects_injected_and_inconsistent_data(self):
        for altered in [dict(VALID,network_interface='eth0;curl'),dict(VALID,suggested_vpn_service='unrelated'),dict(VALID,tunnel_interfaces=['tun0;id']),dict(VALID,status_file={'found':1,'readable':1})]:
            with self.subTest(altered=altered):
                with self.assertRaises(ValueError):d.validate_discovery(altered)
    def test_roles_and_no_profile_fail_closed(self):
        self.assertEqual(self.web.post(self.url).status_code,401)
        self.assertEqual(self.web.post(self.url,headers={'Authorization':'Bearer '+self.other_token}).status_code,403)
        with patch.object(d,'execute',side_effect=AssertionError('Should not SSH')) as ssh:
            self.assertEqual(self.web.post(self.url,headers=self.auth).status_code,409)
            ssh.assert_not_called()
    def test_verified_scan_returns_only_bounded_readonly_values(self):
        with self.Session.begin() as db:
            db.add(ServerAdminProfile(server_id=self.sid,enabled=True,
                approved_host='192.0.2.35',approved_username='opc',approved_port=22,
                private_key_path='sentinel-vault:'+self.sid))
        with patch.object(d,'_safe_profile',return_value={'verification_ready':True}),\
             patch.object(d,'public_admin_verification',return_value={'state':'success','ssh_verified':True}),\
             patch.object(d,'execute',return_value=d.validate_discovery(VALID)) as ssh:
            r=self.web.post(self.url,headers=self.auth)
        self.assertEqual(r.status_code,200,r.text)
        self.assertTrue(r.json()['read_only'])
        self.assertFalse(r.json()['installation_authorized'])
        ssh.assert_called_once()
    def test_scan_exception_is_sanitized(self):
        with self.Session.begin() as db:
            db.add(ServerAdminProfile(server_id=self.sid,enabled=True,
                approved_host='192.0.2.35',approved_username='opc',approved_port=22,
                private_key_path='sentinel-vault:'+self.sid))
        with patch.object(d,'_safe_profile',return_value={'verification_ready':True}),\
             patch.object(d,'public_admin_verification',return_value={'state':'success','ssh_verified':True}),\
             patch.object(d,'execute',side_effect=RuntimeError('private ssh path /secrets/here')):
            r=self.web.post(self.url,headers=self.auth)
        self.assertEqual(r.status_code,502,r.text)
        self.assertNotIn('/secrets/here',r.text)

if __name__=='__main__':unittest.main()
