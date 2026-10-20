"""Step 40.9: isolated job-history/API authorization and safety tests; no VPS contact."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.controlled_jobs as jobs
from backend.admin_access import ServerAdminAudit, ServerAdminProfile
from backend.auth_api import SESSION_COOKIE, _csrf_for_token, auth_database
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server
from backend.main import app


class ControlledJobSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = Path(self.tmp.name) / 'dummy-key-not-real'
        self.key.write_text('NOT A REAL KEY', encoding='utf-8')
        self.engine = create_engine('sqlite+pysqlite:///:memory:',
            connect_args={'check_same_thread': False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        self.patches = [
            patch.object(jobs, 'SessionLocal', self.factory),
            patch.object(jobs, 'engine', self.engine),
            patch.object(jobs, '_audit_registry_ready', return_value=True),
        ]
        for p in self.patches: p.start()
        def auth_db():
            with self.factory() as db:
                yield db
        app.dependency_overrides[auth_database] = auth_db
        with self.factory() as db:
            tenant = Client(name='Job Test Tenant')
            db.add(tenant); db.flush()
            server = Server(client_id=tenant.id, name='Not A VPS',
                host='198.51.100.50', ssh_username='readonly', ssh_port=22)
            db.add(server); db.flush(); self.sid = server.id
            admin = AuthUser(username='admin409',display_name='A',role='admin',password_hash='dummy')
            staff = AuthUser(username='staff409',display_name='S',role='staff',password_hash='dummy')
            db.add_all([admin,staff]); db.flush()
            self.tokens={}
            for label,user in [('admin',admin),('staff',staff)]:
                token,_ = create_session(db,user); self.tokens[label]=token
            self.admin_id=admin.id
            db.add(ServerAdminProfile(server_id=self.sid,enabled=True,
                approved_host=server.host,approved_port=22,approved_username='readonly',
                private_key_path=str(self.key)))
            db.commit()
        self.web=TestClient(app)
        self.run_url=f'/api/server-operations/servers/{self.sid}/jobs/read-only'
        self.catalog='/api/server-operations/jobs/catalog'

    def tearDown(self):
        self.web.close()
        app.dependency_overrides.clear()
        for p in reversed(self.patches): p.stop()
        jobs._release(self.sid)
        self.engine.dispose()
        self.tmp.cleanup()

    def headers(self, role='admin'):
        return {'Authorization':'Bearer '+self.tokens[role]}

    def create(self,payload=None,headers=None):
        return self.web.post(self.run_url,json=payload or {'check':'load_average'},
                             headers=headers if headers is not None else self.headers())

    def test_catalog_admin_only_and_no_shell_or_shutdown(self):
        self.assertEqual(self.web.get(self.catalog).status_code,401)
        self.assertEqual(self.web.get(self.catalog,headers=self.headers('staff')).status_code,403)
        r=self.web.get(self.catalog,headers=self.headers())
        self.assertEqual(r.status_code,200)
        body=r.json()
        self.assertTrue(body['persisted_job_history'])
        self.assertFalse(body['background_worker_enabled'])
        self.assertFalse(body['power_control_enabled'])
        self.assertFalse(body['arbitrary_commands_enabled'])
        self.assertEqual([x['key'] for x in body['checks']],['load_average','memory_snapshot'])
        self.assertNotIn(str(self.key),r.text)
        self.assertNotIn('shutdown',r.text.lower())

    def test_reject_wrong_role_and_csrf_before_ssh_or_writes(self):
        with patch.object(jobs,'_run_pinned_diagnostic',side_effect=AssertionError('SSH forbidden')) as runner:
            self.assertEqual(self.create(headers={}).status_code,401)
            self.assertEqual(self.create(headers=self.headers('staff')).status_code,403)
            self.assertEqual(self.create(headers={'Cookie':f'{SESSION_COOKIE}={self.tokens["admin"]}'}).status_code,403)
            runner.assert_not_called()
        with self.factory() as db:
            self.assertEqual(db.query(jobs.ControlledDiagnosticJob).count(),0)
        headers={'Cookie':f'{SESSION_COOKIE}={self.tokens["admin"]}',
                 'x-sentinel-csrf':_csrf_for_token(self.tokens['admin'])}
        with patch.object(jobs,'_run_pinned_diagnostic',return_value={'load_1m':0.0,'load_5m':0.2,'load_15m':0.4}):
            self.assertEqual(self.create(headers=headers).status_code,200)

    def test_reject_nonallowlisted_requests_and_shell_injection(self):
        for data in [{'check':'shutdown'},{'check':'reboot'},{'check':'load_average','command':'sudo reboot'},
                     {'check':'memory_snapshot','sudo':True},{'check':['load_average']},
                     {'check':'load_average; rm -rf /'}, {'check':{'name':'load_average'}}]:
            self.assertEqual(self.create(data).status_code,422,str(data))
        with self.factory() as db:
            self.assertEqual(db.query(jobs.ControlledDiagnosticJob).count(),0)

    def test_success_job_is_sanitized_persisted_audited_and_retrievable(self):
        metrics={'load_1m':0.12,'load_5m':0.2,'load_15m':0.3}
        with patch.object(jobs,'_run_pinned_diagnostic',return_value=metrics) as runner:
            r=self.create()
        self.assertEqual(r.status_code,200,r.text)
        result=r.json()
        self.assertEqual(result['status'],'succeeded')
        self.assertEqual(result['metrics'],metrics)
        self.assertTrue(result['audit_recorded'])
        self.assertFalse(result['background_worker_enabled'])
        self.assertFalse(result['remote_write_performed'])
        self.assertEqual(result['server_id'],self.sid)
        self.assertNotIn(str(self.key),r.text)
        self.assertNotIn('198.51.100.50',r.text)
        runner.assert_called_once()
        self.assertEqual(runner.call_args.args[1], 'load_average')
        get=self.web.get('/api/server-operations/jobs/'+result['job_id'],headers=self.headers())
        self.assertEqual(get.status_code,200,get.text)
        self.assertEqual(get.json()['metrics'],metrics)
        with self.factory() as db:
            job=db.get(jobs.ControlledDiagnosticJob,result['job_id'])
            self.assertEqual(job.actor_id,self.admin_id)
            self.assertEqual(job.status,'succeeded')
            audit=db.scalars(select(ServerAdminAudit)).all()
            self.assertEqual(len(audit),1)
            self.assertEqual(audit[0].operation,'controlled_job:load_average')
            self.assertEqual(audit[0].result,'job_succeeded')

    def test_failed_ssh_job_has_safe_status_no_raw_error_and_audit(self):
        with patch.object(jobs,'_run_pinned_diagnostic',side_effect=RuntimeError('SECRET AND PRIVATE KEY')):
            r=self.create({'check':'memory_snapshot'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['status'],'failed')
        self.assertIsNone(r.json()['metrics'])
        self.assertNotIn('SECRET',r.text)
        with self.factory() as db:
            audit=db.scalars(select(ServerAdminAudit)).all()
            self.assertEqual(audit[0].result,'job_failed')

    def test_archived_or_unapproved_server_fails_closed(self):
        with self.factory() as db:
            db.get(Server,self.sid).archived_at=datetime.now(timezone.utc); db.commit()
        self.assertEqual(self.create().status_code,404)
        with self.factory() as db:
            db.get(Server,self.sid).archived_at=None
            db.get(ServerAdminProfile,self.sid).enabled=False; db.commit()
        self.assertEqual(self.create().status_code,409)
        with self.factory() as db:
            db.get(ServerAdminProfile,self.sid).enabled=True
            db.get(Server,self.sid).host='203.0.113.99'; db.commit()
        self.assertEqual(self.create().status_code,409)

    def test_missing_key_and_missing_registry_and_server(self):
        self.key.unlink()
        self.assertEqual(self.create().status_code,503)
        self.assertEqual(self.web.post('/api/server-operations/servers/not-found/jobs/read-only',
            json={'check':'load_average'},headers=self.headers()).status_code,404)
        with patch.object(jobs,'_audit_registry_ready',return_value=False):
            self.assertEqual(self.create().status_code,503)

    def test_busy_server_rejected_and_no_leaked_lock(self):
        self.assertTrue(jobs._acquire(self.sid))
        try:
            self.assertEqual(self.create().status_code,409)
        finally:
            jobs._release(self.sid)
        with patch.object(jobs,'_run_pinned_diagnostic',return_value={'load_1m':1,'load_5m':1,'load_15m':1}):
            self.assertEqual(self.create().status_code,200)

    def test_job_lookup_secure_and_bad_identifiers(self):
        self.assertEqual(self.web.get('/api/server-operations/jobs/not-a-uuid',headers=self.headers()).status_code,404)
        self.assertEqual(self.web.get('/api/server-operations/jobs/aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',headers=self.headers()).status_code,404)
        self.assertEqual(self.web.get('/api/server-operations/jobs/aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',headers=self.headers('staff')).status_code,403)
        self.assertEqual(self.web.get('/api/server-operations/jobs/catalog').status_code,401)

    def test_second_check_snapshot_only(self):
        with patch.object(jobs,'_run_pinned_diagnostic',return_value={'total_mib':4096,'available_mib':3500,'swap_total_mib':0,'swap_free_mib':0}):
            r=self.create({'check':'memory_snapshot'})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['check'],'memory_snapshot')
        self.assertEqual(r.json()['metrics']['total_mib'],4096)

if __name__=='__main__':
    unittest.main()
