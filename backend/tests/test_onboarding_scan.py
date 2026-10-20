"""Step 40.10 offline audit, tenant-RBAC and classification tests. NO LIVE SSH."""
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.admin_access as admin_access
import backend.onboarding_scan as scan
import backend.main as main
from backend.auth_api import auth_database
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server


class OnboardingClassificationTests(unittest.TestCase):
    def sample(self, **updates):
        value = {'os_id':'ol','os_major':'9','package_state':'absent',
                 'systemd_checked':True,'service_units_found':0,'active_services_found':0}
        value.update(updates)
        return value

    def test_fresh_candidate_never_authorizes_install(self):
        result = scan.classify(self.sample())
        self.assertEqual(result['classification'],'fresh_candidate')
        self.assertFalse(result['installation_authorized'])

    def test_installed_package_without_service_is_not_fresh(self):
        self.assertEqual(scan.classify(self.sample(package_state='installed'))['classification'],'openvpn_detected')

    def test_stopped_service_unit_is_not_fresh(self):
        self.assertEqual(scan.classify(self.sample(service_units_found=1))['classification'],'openvpn_detected')

    def test_running_service_is_provisionally_detected(self):
        r=scan.classify(self.sample(package_state='installed',service_units_found=2,active_services_found=1))
        self.assertEqual(r['classification'],'openvpn_service_active')
        self.assertNotIn('sessions',r)

    def test_unknown_or_unsupported_os_fail_closed(self):
        self.assertEqual(scan.classify(self.sample(os_id='custom'))['classification'],'needs_review')
        self.assertEqual(scan.classify(self.sample(systemd_checked=False))['classification'],'needs_review')
        self.assertEqual(scan.classify(self.sample(package_state='unknown'))['classification'],'needs_review')

    def test_untrusted_malformed_remote_data_rejected(self):
        for change in ({'service_units_found':-1},{'active_services_found':2},
                       {'service_units_found':True},{'os_id':'ol;rm -rf /'},
                       {'os_major':'very large'},{'package_state':'broken'},
                       {'systemd_checked':'true'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                scan.classify(self.sample(**change))


class OnboardingScanRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.fake_key=Path(self.tmp.name)/'dummy.key'
        self.fake_key.write_text('NOT A REAL PRIVATE KEY')
        self.engine=create_engine('sqlite+pysqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.factory=sessionmaker(bind=self.engine,autoflush=False,autocommit=False)
        self.patches=[
            patch.object(scan,'SessionLocal',self.factory),patch.object(scan,'engine',self.engine),
            patch.object(admin_access,'SessionLocal',self.factory),patch.object(admin_access,'engine',self.engine),
            patch.object(main,'SessionLocal',self.factory),patch.object(main,'engine',self.engine),
        ]
        for p in self.patches:p.start()
        def session_db():
            with self.factory() as db:yield db
        main.app.dependency_overrides[auth_database]=session_db
        with self.factory() as db:
            tenant=Client(name='Testing Tenant');other=Client(name='Other Tenant')
            db.add_all([tenant,other]);db.flush()
            one=Server(name='Test Key',client_id=tenant.id,host='192.0.2.10',ssh_port=22,ssh_username='opc')
            two=Server(name='Other Customer',client_id=other.id,host='192.0.2.90',ssh_port=22,ssh_username='root')
            db.add_all([one,two]);db.flush()
            self.sid=one.id;self.other_sid=two.id
            admin=AuthUser(username='boss',display_name='Boss',role='admin',password_hash='TEST')
            client=AuthUser(username='client',display_name='Client',role='client',client_id=tenant.id,password_hash='TEST')
            db.add_all([admin,client]);db.flush()
            self.tokens={}
            for key,user in [('admin',admin),('client',client)]:
                self.tokens[key]=create_session(db,user)[0]
            db.add(admin_access.ServerAdminProfile(server_id=self.sid,enabled=True,approved_host='192.0.2.10',
                   approved_port=22,approved_username='opc',private_key_path=str(self.fake_key)))
            db.commit()
        self.web=TestClient(main.app)
        self.url=f'/api/server-operations/servers/{self.sid}/onboarding/scan'

    def tearDown(self):
        self.web.close();main.app.dependency_overrides.clear()
        for p in reversed(self.patches):p.stop()
        self.engine.dispose();self.tmp.cleanup()

    def auth(self, role):
        return {'Authorization':'Bearer '+self.tokens[role]}

    def mock_remote(self, **updates):
        result={'classification':'fresh_candidate','os_family':'ol','os_major':'9',
            'openvpn_package':'absent','systemd_checked':True,'service_units_found':0,
            'active_services_found':0,'next_step':'Review before installation',
            'read_only':True,'installation_authorized':False}
        result.update(updates)
        return result

    def test_admin_only_no_connection_without_auth(self):
        with patch.object(scan,'scan_host',side_effect=AssertionError('unexpected SSH')) as spy:
            self.assertEqual(self.web.post(self.url).status_code,401)
            self.assertEqual(self.web.post(self.url,headers=self.auth('client')).status_code,403)
            spy.assert_not_called()

    def test_success_audits_and_only_returns_safe_fields(self):
        with patch.object(scan,'scan_host',return_value=self.mock_remote()) as spy:
            reply=self.web.post(self.url,headers=self.auth('admin'))
        self.assertEqual(reply.status_code,200,reply.text)
        self.assertEqual(reply.json()['classification'],'fresh_candidate')
        self.assertEqual(spy.call_args.args[0].host,'192.0.2.10')
        self.assertNotIn(str(self.fake_key),reply.text)
        with self.factory() as db:
            entries=db.scalars(select(admin_access.ServerAdminAudit)).all()
            self.assertEqual(len(entries),1)
            self.assertEqual(entries[0].result,'verified')
            self.assertEqual(db.query(scan.OnboardingScan).count(),1)
        # Admin preflight contains cached classification. Clients see only their tenant.
        r=self.web.get('/api/onboarding/preflight',headers=self.auth('client'))
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(len(r.json()['entries']),1)
        self.assertFalse(r.json()['entries'][0]['scan_ready'])
        self.assertEqual(r.json()['entries'][0]['onboarding_scan']['classification'],'fresh_candidate')
        self.assertNotIn(str(self.fake_key),r.text)

    def test_edited_inventory_denies_retargeting(self):
        with self.factory() as db:
            one=db.get(Server,self.sid);one.host='192.0.2.200';db.commit()
        with patch.object(scan,'scan_host',side_effect=AssertionError('unexpected SSH')) as spy:
            self.assertEqual(self.web.post(self.url,headers=self.auth('admin')).status_code,409)
            spy.assert_not_called()
        r=self.web.get('/api/onboarding/preflight',headers=self.auth('admin'))
        self.assertEqual(r.json()['entries'][0]['scan_ready'],False)

    def test_archived_and_other_client_denied(self):
        with patch.object(scan,'scan_host',side_effect=AssertionError('unexpected SSH')) as spy:
            self.assertEqual(self.web.post('/api/server-operations/servers/'+self.other_sid+'/onboarding/scan',headers=self.auth('client')).status_code,403)
            with self.factory() as db:
                one=db.get(Server,self.sid);one.archived_at=datetime.now(timezone.utc);db.commit()
            self.assertEqual(self.web.post(self.url,headers=self.auth('admin')).status_code,404)
            spy.assert_not_called()

    def test_failed_scan_is_sanitized_and_logged(self):
        with patch.object(scan,'scan_host',side_effect=RuntimeError('SECRET-KNOWN-HOST-AND-PATH')):
            r=self.web.post(self.url,headers=self.auth('admin'))
        self.assertEqual(r.status_code,502,r.text)
        self.assertNotIn('SECRET-',r.text)
        with self.factory() as db:
            entry=db.scalars(select(admin_access.ServerAdminAudit)).first()
            self.assertEqual(entry.result,'scan_failed')

    def test_cached_result_stales_and_invalidates_on_reapproval(self):
        with patch.object(scan,'scan_host',return_value=self.mock_remote()):
            self.assertEqual(self.web.post(self.url,headers=self.auth('admin')).status_code,200)
        with self.factory() as db:
            one=db.get(Server,self.sid);profile=db.get(admin_access.ServerAdminProfile,self.sid)
            self.assertEqual(scan.public_scan(one,profile)['state'],'success')
            later=datetime.now(timezone.utc)+timedelta(hours=1)
            self.assertEqual(scan.public_scan(one,profile,now=later)['state'],'stale')
            profile.approved_at=datetime.now(timezone.utc)+timedelta(seconds=1)
            db.commit()
        with self.factory() as db:
            one=db.get(Server,self.sid);profile=db.get(admin_access.ServerAdminProfile,self.sid)
            self.assertIsNone(scan.public_scan(one,profile))

    def test_no_dangerous_ssh_executor(self):
        r=self.web.post(f'/api/server-operations/servers/{self.sid}/onboarding/install',
            headers=self.auth('admin'),json={'command':'sudo rm -rf /'})
        self.assertEqual(r.status_code,404)


if __name__=='__main__':
    unittest.main()
