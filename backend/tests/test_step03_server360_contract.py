"""Step 03 - authenticated, tenant-isolated, cache-only Server 360 coverage."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base, Client, Server, ServerMonitoringConfig
from backend.auth_api import auth_database
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.main import app
from backend import monitoring_api as api
from backend import monitoring_engine as me


class Server360ContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='server360_')
        self.addCleanup(temp.cleanup)
        engine = create_engine('sqlite:///' + str(Path(temp.name) / 'test.db'))
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        patchers = [patch.object(me, 'engine', engine), patch.object(me, 'SessionLocal', self.Session),
                    patch.object(api, 'SessionLocal', self.Session)]
        for p in patchers:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(patchers)])

        def auth_override():
            with self.Session() as db:
                yield db
        app.dependency_overrides[auth_database] = auth_override
        self.addCleanup(app.dependency_overrides.clear)
        now = datetime.now(timezone.utc)
        with self.Session.begin() as db:
            alpha = Client(name='A'); beta = Client(name='B')
            db.add_all([alpha, beta]); db.flush()
            a = Server(client_id=alpha.id, name='A server', host='192.0.2.4', ssh_port=22, ssh_username='monitor')
            b = Server(client_id=beta.id, name='B server', host='192.0.2.5', ssh_port=22, ssh_username='monitor')
            db.add_all([a,b]);db.flush()
            self.a,self.b = a.id,b.id
            db.add(ServerMonitoringConfig(server_id=a.id, enabled=True, approved_host=a.host,
                approved_ssh_port=22, approved_ssh_username='monitor', ssh_key_path='SECRET_KEY_PATH',
                vpn_service='openvpn', vpn_interface='tun0', network_interface='ens3'))
            db.add(me.MonitorWorkerPulse(worker_name='ssh-fallback', seen_at=now))
            db.add(me.TelemetrySample(server_id=a.id,kind='health',collected_at=now-timedelta(seconds=20),
                state='connected',data_json=json.dumps({'status':'connected','host_key_verified':True,
                    'cpu_percent':12.5,'memory_used_percent':25,'disk_used_percent':33,
                    'private_key':'SHOULD_NOT_LEAK','password':'SHOULD_NOT_LEAK',
                    'network':{'interface':'ens3','private_key':'SHOULD_NOT_LEAK'}})))
            db.add(me.TelemetrySample(server_id=a.id,kind='sessions',collected_at=now-timedelta(seconds=20),
                state='available',data_json=json.dumps({'state':'available','total':3,'sessions':[],
                'password':'SHOULD_NOT_LEAK'})))
            db.add(me.MonitorIncident(server_id=a.id,code='SSH_UNREACHABLE',state='resolved',opened_at=now,
                last_seen_at=now,resolved_at=now))
            user=AuthUser(username='client_example',display_name='Example',role='client',client_id=alpha.id,
                password_hash='not-for-use')
            db.add(user);db.flush()
            self.token,_=create_session(db,user)
        self.web=TestClient(app)
        self.addCleanup(self.web.close)
        self.headers={'Authorization':'Bearer '+self.token}

    def endpoint(self, sid=None):
        return f'/api/monitoring/servers/{sid or self.a}/360'

    def test_auth_and_tenant_scope(self):
        self.assertEqual(self.web.get(self.endpoint()).status_code,401)
        self.assertEqual(self.web.get(self.endpoint(self.b),headers=self.headers).status_code,404)
        self.assertEqual(self.web.get(self.endpoint('nonexistent'),headers=self.headers).status_code,404)

    def test_cached_result_redacts_unknown_fields(self):
        with patch.object(me,'collect_ssh_health', side_effect=AssertionError('SSH must not run')):
            response=self.web.get(self.endpoint(),headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        payload=response.json()
        self.assertEqual(payload['source'],'stored_ssh_snapshots')
        self.assertEqual(payload['server_id'],self.a)
        self.assertEqual(payload['history']['health'][0]['cpu_percent'],12.5)
        self.assertEqual(payload['history']['sessions'][0]['connections'],3)
        self.assertEqual(payload['incidents'][0]['code'],'SSH_UNREACHABLE')
        self.assertFalse(payload['limits']['history_is_live'])
        for secret in ('SECRET_KEY_PATH','SHOULD_NOT_LEAK'):
            self.assertNotIn(secret,response.text)

    def test_bound_checks_and_no_fabricated_samples(self):
        self.assertEqual(self.web.get(self.endpoint()+'?limit=9999',headers=self.headers).status_code,422)
        self.assertEqual(self.web.get(self.endpoint()+'?limit=0',headers=self.headers).status_code,422)
        with self.Session.begin() as db:
            db.query(me.TelemetrySample).filter(me.TelemetrySample.kind=='sessions').delete()
        response=self.web.get(self.endpoint(),headers=self.headers)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['history']['sessions'],[])
        self.assertIsNone(response.json()['monitor']['sessions'].get('data'))

    def test_archived_is_hidden(self):
        with self.Session.begin() as db:
            db.get(Server,self.a).archived_at=datetime.now(timezone.utc)
        self.assertEqual(self.web.get(self.endpoint(),headers=self.headers).status_code,404)

    def test_worker_offline_does_not_claim_fresh(self):
        with self.Session.begin() as db:
            db.get(me.MonitorWorkerPulse,'ssh-fallback').seen_at=datetime.now(timezone.utc)-timedelta(hours=1)
        response=self.web.get(self.endpoint(),headers=self.headers)
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['worker']['status'],'not_running')
        self.assertFalse(response.json()['monitor']['health']['fresh'])
        self.assertEqual(response.json()['history']['health'][0]['cpu_percent'],12.5)


if __name__=='__main__': unittest.main()
