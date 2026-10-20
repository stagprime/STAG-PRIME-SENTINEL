"""HTTP-level Step 41A regression; fully isolated DB and no remote SSH."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from backend.database import Base, Client, Server, ServerMonitoringConfig
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.auth_api import auth_database
from backend.main import app
from backend import monitoring_engine as me
from backend import monitoring_api as api

class MonitorRoutesStep41(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory(prefix='step41api_')
        self.addCleanup(directory.cleanup)
        engine=create_engine('sqlite:///' + str(Path(directory.name)/'unit.db'))
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)
        self.Session=sessionmaker(bind=engine,autoflush=False,autocommit=False)
        self.patchers=[patch.object(me,'engine',engine),patch.object(me,'SessionLocal',self.Session),
                       patch.object(api,'SessionLocal',self.Session)]
        for p in self.patchers:p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self.patchers)])
        def auth_override():
            with self.Session() as db:yield db
        app.dependency_overrides[auth_database]=auth_override
        self.addCleanup(app.dependency_overrides.clear)
        with self.Session.begin() as db:
            alpha=Client(name='Tenant Alpha');beta=Client(name='Tenant Beta')
            db.add_all([alpha,beta]);db.flush()
            a=Server(client_id=alpha.id,name='A',host='192.0.2.3',ssh_port=22,ssh_username='monitor')
            b=Server(client_id=beta.id,name='B',host='198.51.100.3',ssh_port=22,ssh_username='monitor')
            db.add_all([a,b]);db.flush()
            self.a,self.b=a.id,b.id
            db.add(ServerMonitoringConfig(server_id=a.id,enabled=True,approved_host=a.host,
                approved_ssh_username='monitor',approved_ssh_port=22,ssh_key_path='FAKE',
                vpn_service='openvpn-server@server',vpn_interface='tun0',network_interface='eth0'))
            u=AuthUser(username='client_a',display_name='Client A',role='client',client_id=alpha.id,password_hash='fake')
            db.add(u);db.flush()
            self.token,_=create_session(db,u)
        self.web=TestClient(app)
        self.addCleanup(self.web.close)

    def test_auth_required_all_monitoring_routes(self):
        for path in ['/api/monitoring/overview','/api/monitoring/incidents',
                     '/api/monitoring/session-events',f'/api/monitoring/servers/{self.a}/history']:
            self.assertEqual(self.web.get(path).status_code,401)

    def test_approvals_and_tenant_visibility(self):
        headers={'Authorization':'Bearer '+self.token}
        data=self.web.get('/api/monitoring/overview',headers=headers)
        self.assertEqual(data.status_code,200,data.text)
        self.assertEqual([x['server_id'] for x in data.json()['servers']],[self.a])
        self.assertEqual(data.json()['worker']['status'],'not_running')
        self.assertEqual(self.web.get(f'/api/monitoring/servers/{self.b}/history',headers=headers).status_code,404)
        self.assertEqual(self.web.get(f'/api/monitoring/servers/{self.a}/history',headers=headers).status_code,200)

    def test_no_remote_ssh_from_get(self):
        headers={'Authorization':'Bearer '+self.token}
        with patch.object(me,'collect_ssh_health',side_effect=AssertionError('Unexpected SSH')):
            for endpoint in ['/api/monitoring/overview','/api/monitoring/incidents',
                             '/api/monitoring/session-events',f'/api/monitoring/servers/{self.a}/history?kind=sessions']:
                response=self.web.get(endpoint,headers=headers)
                self.assertEqual(response.status_code,200,response.text)

    def test_invalid_history_kind_is_rejected(self):
        response=self.web.get(f'/api/monitoring/servers/{self.a}/history?kind=../../private',headers={'Authorization':'Bearer '+self.token})
        self.assertEqual(response.status_code,422)


if __name__=='__main__':unittest.main()
