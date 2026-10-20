"""Step 42A: isolated, no-network enrollment/security tests."""
import os
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.auth_api import auth_database, SESSION_COOKIE, _csrf_for_token
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server, ServerMonitoringConfig
from backend.main import app, _approved_monitor_settings
import backend.admin_access as admin
import backend.monitoring_enrollment as enrollment
import backend.credential_vault as vault


class Step42EnrollmentSafety(unittest.TestCase):
    def setUp(self):
        self.eng = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread':False},poolclass=StaticPool)
        self.Session=sessionmaker(bind=self.eng, autoflush=False, autocommit=False)
        Base.metadata.create_all(self.eng)
        self.patchers=[patch.object(enrollment,'SessionLocal',self.Session),patch.object(enrollment,'engine',self.eng),
                       patch.object(admin,'SessionLocal',self.Session),patch.object(admin,'engine',self.eng),
                       patch.object(enrollment,'credential_ready',return_value=True),
                       patch.object(vault,'credential_ready',return_value=True),
                       patch.dict(os.environ,{'SENTINEL_CREDENTIAL_DEV_ALLOW_LOCAL':'1'})]
        for p in self.patchers:p.start()
        def reset():
            for p in reversed(self.patchers):p.stop()
        self.addCleanup(reset)
        self.addCleanup(self.eng.dispose)
        with self.Session() as db:
            tenant=Client(name='Tenant Test');db.add(tenant);db.flush()
            server=Server(client_id=tenant.id,name='Test VPS',host='192.0.2.20',ssh_port=22,ssh_username='opc')
            db.add(server);db.flush();self.sid=server.id
            admin_user=AuthUser(username='admin42',display_name='Admin',role='admin',password_hash='unused')
            client=AuthUser(username='tenant42',display_name='Client',role='client',client_id=tenant.id,password_hash='unused')
            db.add_all([admin_user,client]);db.flush()
            db.commit()
            self.admin_token,_=create_session(db,admin_user)
            self.client_token,_=create_session(db,client)
            db.add(admin.ServerAdminProfile(server_id=server.id,enabled=True,approved_host=server.host,
                approved_username='opc',approved_port=22,private_key_path='sentinel-vault:'+server.id))
            db.commit()
        # Create verified evidence using a bound identity pin, not a fabricated SSH command.
        with self.Session.begin() as db:
            srv=db.get(Server,self.sid);profile=db.get(admin.ServerAdminProfile,self.sid)
            db.add(admin.AdminSSHVerification(server_id=self.sid,identity_pin=admin._identity_pin(srv,profile),
                result='success',privilege_state='sudo_nopasswd',checked_at=datetime.now(timezone.utc)))
        def override():
            with self.Session() as db:yield db
        app.dependency_overrides[auth_database]=override
        self.addCleanup(app.dependency_overrides.clear)
        self.web=TestClient(app)
        self.addCleanup(self.web.close)
        self.endpoint=f'/api/server-operations/servers/{self.sid}/monitoring/enroll'

    def h(self,role='admin'):
        return {'Authorization':'Bearer '+(self.admin_token if role=='admin' else self.client_token)}
    def body(self,**kw):
        return {'consent':True,'vpn_service':'openvpn-server@server','vpn_interface':'tun0','network_interface':'ens3',**kw}

    def test_anonymous_and_nonadmin_cannot_enroll(self):
        self.assertEqual(self.web.post(self.endpoint,json=self.body()).status_code,401)
        self.assertEqual(self.web.post(self.endpoint,json=self.body(),headers=self.h('client')).status_code,403)
        with self.Session() as db:self.assertIsNone(db.get(ServerMonitoringConfig,self.sid))

    def test_explicit_optin_and_successful_monitor_enrollment_without_ssh(self):
        self.assertEqual(self.web.post(self.endpoint,json=self.body(consent=False),headers=self.h()).status_code,422)
        with patch('backend.admin_access.verify_administrative_ssh',side_effect=AssertionError('Unexpected SSH')) as ssh:
            r=self.web.post(self.endpoint,json=self.body(),headers=self.h())
            self.assertEqual(r.status_code,200,r.text)
            ssh.assert_not_called()
        self.assertTrue(r.json()['monitoring_enabled'])
        self.assertEqual(r.json()['health_status'],'pending_first_collection')
        with self.Session() as db:
            target=db.get(ServerMonitoringConfig,self.sid)
            self.assertTrue(target.enabled)
            self.assertEqual(target.approved_host,'192.0.2.20')
            self.assertEqual(target.ssh_key_path,'sentinel-vault:'+self.sid)
            self.assertEqual(target.network_interface,'ens3')
            self.assertTrue(any(a.operation=='monitoring_enroll' for a in db.scalars(select(admin.ServerAdminAudit)).all()))

    def test_verify_evidence_expires_no_auto_ssh(self):
        with self.Session.begin() as db:
            db.get(admin.AdminSSHVerification,self.sid).checked_at=datetime.now(timezone.utc)-timedelta(hours=1)
        self.assertEqual(self.web.post(self.endpoint,json=self.body(),headers=self.h()).status_code,409)
        with self.Session() as db:self.assertIsNone(db.get(ServerMonitoringConfig,self.sid))

    def test_inventory_and_credential_changes_invalidate_authority(self):
        with self.Session.begin() as db:db.get(Server,self.sid).host='192.0.2.21'
        self.assertEqual(self.web.post(self.endpoint,json=self.body(),headers=self.h()).status_code,409)

    def test_names_are_strictly_validated(self):
        for value in ['$(touch /tmp/malice)','eth0;id','../../root','weird space']:
            r=self.web.post(self.endpoint,json=self.body(network_interface=value),headers=self.h())
            self.assertEqual(r.status_code,422,(value,r.text))

    def test_browser_cookie_must_supply_csrf(self):
        r=self.web.post(self.endpoint,json=self.body(),headers={'Cookie':f'{SESSION_COOKIE}={self.admin_token}'})
        self.assertIn(r.status_code,(401,403))

    def test_enrollment_can_be_disabled_no_remote_write(self):
        self.assertEqual(self.web.post(self.endpoint,json=self.body(),headers=self.h()).status_code,200)
        result=self.web.post(f'/api/server-operations/servers/{self.sid}/monitoring/disable',headers=self.h())
        self.assertEqual(result.status_code,200,result.text)
        with self.Session() as db:self.assertFalse(db.get(ServerMonitoringConfig,self.sid).enabled)

    def test_vault_ready_status_matches_backend_poller(self):
        class Target:
            enabled=True
            approved_host='192.0.2.20'
            approved_ssh_username='opc'
            approved_ssh_port=22
            ssh_key_path='sentinel-vault:'+self.sid
            known_hosts_path=None
            vpn_service='openvpn-server@server'
            vpn_interface='tun0'
            network_interface='ens3'
        with self.Session() as db:srv=db.get(Server,self.sid)
        self.assertEqual(_approved_monitor_settings(srv,Target()),[])

if __name__=='__main__':unittest.main()
