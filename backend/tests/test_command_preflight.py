"""Step 40.10-E.1 offline permission, approval, audit and read-only boundary tests."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import backend.command_preflight as runner
from backend.admin_access import ServerAdminProfile, ServerAdminAudit
from backend.auth_api import auth_database, SESSION_COOKIE, _csrf_for_token
from backend.auth_models import AuthUser
from backend.auth_security import create_session
from backend.database import Base, Client, Server
from backend.main import app


class ReviewedRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.key = Path(self.temp.name)/'fake-key'
        self.key.write_text('FAKE PUBLIC TEST DATA', encoding='utf8')
        self.eng = create_engine('sqlite+pysqlite:///:memory:',
            connect_args={'check_same_thread':False}, poolclass=StaticPool)
        Base.metadata.create_all(self.eng)
        self.session = sessionmaker(bind=self.eng)
        self.patches=[patch.object(runner,'engine',self.eng),
                      patch.object(runner,'SessionLocal',self.session),
                      patch.object(runner,'public_admin_verification',return_value={
                          'state':'success','ssh_verified':True,'privilege_state':'sudo_nopasswd'})]
        for p in self.patches:p.start()
        def auth_db():
            with self.session() as db:yield db
        app.dependency_overrides[auth_database]=auth_db
        with self.session() as db:
            org=Client(name='Security sandbox');db.add(org);db.flush()
            srv=Server(client_id=org.id,name='Mock VPS',host='198.51.100.10',ssh_username='opc',ssh_port=22)
            db.add(srv);db.flush();self.sid=srv.id
            db.add(ServerAdminProfile(server_id=srv.id,enabled=True,
                approved_host=srv.host,approved_port=22,approved_username='opc',private_key_path=str(self.key)))
            self.tokens={}
            for role in ('admin','staff'):
                user=AuthUser(username='runner'+role, display_name=role,role=role,password_hash='dummy')
                db.add(user);db.flush()
                token,_=create_session(db,user);self.tokens[role]=token
            db.commit()
        self.web=TestClient(app)
        self.base=f'/api/server-operations/servers/{self.sid}/command-runner'

    def tearDown(self):
        self.web.close();app.dependency_overrides.clear()
        for p in reversed(self.patches):p.stop()
        runner._release(self.sid)
        self.eng.dispose();self.temp.cleanup()

    def auth(self,role='admin'):
        return {'Authorization':'Bearer '+self.tokens[role]}

    def preview(self,body=None,headers=None):
        return self.web.post(self.base+'/preview',json=body if body is not None else {'check_id':'identity_uid'},
            headers=headers if headers is not None else self.auth())

    def execute(self,pid,approved=True):
        return self.web.post(self.base+'/execute',json={'preview_id':pid,'approve':approved},headers=self.auth())

    def test_catalog_admin_only_scoped_sudo_without_arbitrary(self):
        path='/api/server-operations/command-runner/catalog'
        self.assertEqual(self.web.get(path).status_code,401)
        self.assertEqual(self.web.get(path,headers=self.auth('staff')).status_code,403)
        r=self.web.get(path,headers=self.auth())
        self.assertEqual(r.status_code,200)
        data=r.json()
        self.assertTrue(data['sudo_enabled']);self.assertEqual(data['sudo_scope'],'fixed_root_identity_proof_only');self.assertFalse(data['install_enabled'])
        self.assertFalse(data['arbitrary_shell_enabled'])
        self.assertEqual({x['check_id'] for x in data['checks']},set(runner._COMMANDS))
        self.assertTrue(next(x['privileged'] for x in data['checks'] if x['check_id']=='sudo_root_identity'))
        self.assertNotIn(str(self.key),r.text)

    def test_no_anonymous_staff_csrf_or_shell_injection(self):
        self.assertEqual(self.preview(headers={}).status_code,401)
        self.assertEqual(self.preview(headers=self.auth('staff')).status_code,403)
        self.assertEqual(self.preview(headers={'Cookie':f'{SESSION_COOKIE}={self.tokens["admin"]}'}).status_code,403)
        for data in ({'check_id':'sudo reboot'}, {'check_id':'identity_uid; id'},
                     {'check_id':'identity_uid','command':'id -u'}, {'check_id':None},
                     {'check_id':['identity_uid']}, {'check_id':'openvpn_binary','sudo':True}):
            self.assertEqual(self.preview(data).status_code,422,str(data))
        self.assertEqual(self.preview(headers={'Cookie':f'{SESSION_COOKIE}={self.tokens["admin"]}',
            'x-sentinel-csrf':_csrf_for_token(self.tokens['admin'])}).status_code,200)

    def test_preview_requires_recent_verified_ssh(self):
        with patch.object(runner,'public_admin_verification',return_value=None):
            self.assertEqual(self.preview().status_code,409)

    def test_preview_one_shot_persisted_audited_and_sanitized(self):
        preview=self.preview().json()
        self.assertEqual(preview['exact_command'],'id -u')
        self.assertTrue(preview['read_only'])
        with patch.object(runner,'_run_ssh',return_value={'uid':1000}) as ssh:
            r=self.execute(preview['preview_id'])
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['result'],{'uid':1000})
        self.assertTrue(r.json()['audit_recorded'])
        ssh.assert_called_once()
        self.assertEqual(self.execute(preview['preview_id']).status_code,409)
        logs=self.web.get(self.base+'/runs',headers=self.auth())
        self.assertEqual(logs.status_code,200)
        self.assertEqual(logs.json()['runs'][0]['result'],{'uid':1000})
        self.assertNotIn(str(self.key),logs.text)
        with self.session() as db:
            operations={x.operation for x in db.query(ServerAdminAudit).all()}
        self.assertTrue({'command_preview','command_execute','command_result'}<=operations)

    def test_reject_approval_false_and_identity_change(self):
        pid=self.preview().json()['preview_id']
        self.assertEqual(self.execute(pid,False).status_code,422)
        with self.session() as db:
            srv=db.get(Server,self.sid);srv.host='198.51.100.11';db.commit()
        with patch.object(runner,'_run_ssh',side_effect=AssertionError('must not SSH')) as remote:
            self.assertEqual(self.execute(pid).status_code,409)
            remote.assert_not_called()

    def test_generic_remote_exception_is_redacted_and_audited(self):
        pid=self.preview().json()['preview_id']
        with patch.object(runner,'_run_ssh',side_effect=RuntimeError('SECRET TOKEN private key path')):
            r=self.execute(pid)
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['status'],'failed')
        self.assertEqual(r.json()['failure_category'],'COMMAND_RESULT_UNAVAILABLE')
        self.assertNotIn('SECRET',r.text)
        self.assertEqual(self.execute(pid).status_code,409)

    def test_bounded_parser_rejects_unexpected_output(self):
        self.assertEqual(runner._parse('identity_uid','0\n'),{'uid':0})
        self.assertEqual(runner._parse('openvpn_binary','NOT_FOUND'),{'openvpn_binary':'absent'})
        self.assertEqual(runner._parse('root_disk','Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/vda 102400 10240 92160 10% /'),{'total_mib':100,'used_mib':10,'available_mib':90})
        for text in ('server user@example.com','abc','123; echo bad','0\nSECRET'):
            with self.assertRaises(ValueError): runner._parse('identity_uid',text)

    def test_preview_expiration_rejected_without_remote_execution(self):
        pid=self.preview().json()['preview_id']
        with self.session() as db:
            from datetime import timedelta
            item=db.get(runner.ReviewedCommandPreview,pid)
            item.created_at-=timedelta(minutes=3);db.commit()
        with patch.object(runner,'_run_ssh',side_effect=AssertionError('expired')):
            self.assertEqual(self.execute(pid).status_code,409)

    def test_sudo_requires_fresh_verified_privilege(self):
        with patch.object(runner,'public_admin_verification',return_value={
                'state':'success','ssh_verified':True,'privilege_state':'sudo_unavailable'}):
            self.assertEqual(self.preview({'check_id':'sudo_root_identity'}).status_code,409)
        r=self.preview({'check_id':'sudo_root_identity'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertTrue(r.json()['privileged'])
        self.assertEqual(r.json()['required_confirmation'],'APPROVE SUDO READ ONLY')

    def test_sudo_requires_separate_confirmation_no_unreviewed_remote_execution(self):
        pid=self.preview({'check_id':'sudo_root_identity'}).json()['preview_id']
        with patch.object(runner,'_run_sudo_proof',return_value={
                'effective_uid':0,'sudo_verified':True}) as ssh:
            self.assertEqual(self.execute(pid).status_code,422)
            self.assertEqual(self.web.post(self.base+'/execute',headers=self.auth(),json={
                'preview_id':pid,'approve':True,'privileged_confirmation':'no'}).status_code,422)
            ssh.assert_not_called()
            r=self.web.post(self.base+'/execute',headers=self.auth(),json={
                'preview_id':pid,'approve':True,
                'privileged_confirmation':'APPROVE SUDO READ ONLY'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['result'],{'effective_uid':0,'sudo_verified':True})
        self.assertTrue(r.json()['sudo_used'])
        self.assertEqual(self.web.post(self.base+'/execute',headers=self.auth(),json={
                'preview_id':pid,'approve':True,'privileged_confirmation':'APPROVE SUDO READ ONLY'}).status_code,409)
        with self.session() as db:
            audits=[x.operation for x in db.query(ServerAdminAudit).all()]
        self.assertTrue({'privileged_preview','privileged_execute','privileged_result'}<=set(audits))

    def test_sudo_failure_is_redacted_no_password_or_raw_stderr(self):
        pid=self.preview({'check_id':'sudo_root_identity'}).json()['preview_id']
        with patch.object(runner,'_run_sudo_proof',side_effect=runner.SudoProofFailure('SUDO_AUTHORIZATION_FAILED')):
            r=self.web.post(self.base+'/execute',headers=self.auth(),json={
                'preview_id':pid,'approve':True,'privileged_confirmation':'APPROVE SUDO READ ONLY'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['status'],'failed')
        self.assertEqual(r.json()['failure_category'],'SUDO_AUTHORIZATION_FAILED')
        self.assertNotIn('password',r.text.lower())

    def test_sudo_parsing_exact_root_uid(self):
        self.assertEqual(runner._parse('sudo_root_identity','0\n'),{'effective_uid':0,'sudo_verified':True})
        for output in ('1000','not root','0\nSECRET',''):
            with self.assertRaises(ValueError):runner._parse('sudo_root_identity',output)

    def test_sudo_pinned_to_server_identity_and_time(self):
        pid=self.preview({'check_id':'sudo_root_identity'}).json()['preview_id']
        with self.session() as db:
            db.get(Server,self.sid).ssh_username='changed';db.commit()
        with patch.object(runner,'_run_sudo_proof',side_effect=AssertionError('must not reach VPS')) as ssh:
            r=self.web.post(self.base+'/execute',headers=self.auth(),json={
                'preview_id':pid,'approve':True,'privileged_confirmation':'APPROVE SUDO READ ONLY'})
        self.assertEqual(r.status_code,409)
        ssh.assert_not_called()

    def test_sudo_channel_password_from_vault_not_logged_or_returned(self):
        class FakeChannel:
            def __init__(self):self.command=None;self.password=None;self.closed=False
            def settimeout(self,t):pass
            def exec_command(self,c):self.command=c
            def sendall(self,b):self.password=b
            def shutdown_write(self):pass
            def recv_ready(self):return not self.closed and self.command is not None and not hasattr(self,'sent')
            def recv(self,n):self.sent=True;return b'0\n'
            def recv_stderr_ready(self):return False
            def exit_status_ready(self):return hasattr(self,'sent')
            def recv_exit_status(self):return 0
            def close(self):self.closed=True
        class FakeTransport:
            def __init__(self):self.channel=FakeChannel()
            def is_active(self):return True
            def open_session(self,timeout):return self.channel
        class FakeSSH:
            def __init__(self):self.t=FakeTransport();self.closed=False
            def get_transport(self):return self.t
            def close(self):self.closed=True
        from backend.ssh_monitor import SSHConnectionConfig
        c=SSHConnectionConfig(host='example.invalid',port=22,username='opc',private_key_path='sentinel-vault:'+self.sid)
        fake=FakeSSH()
        with patch.object(runner,'_connect_verified',return_value=fake),patch('backend.credential_vault.load_ssh_secret',return_value=('password','FAKE_TEST_SECRET')) as load:
            result=runner._run_sudo_proof(c)
        self.assertEqual(result,{'effective_uid':0,'sudo_verified':True})
        self.assertEqual(fake.t.channel.command,runner._COMMANDS['sudo_root_identity'][1])
        self.assertEqual(fake.t.channel.password,b'FAKE_TEST_SECRET\n')
        self.assertTrue(fake.closed)
        load.assert_called_once()
        self.assertNotIn('FAKE_TEST_SECRET',str(result))

    def test_sudo_private_key_never_invents_password(self):
        class FakeChannel:
            def settimeout(self,t):pass
            def exec_command(self,c):pass
            def shutdown_write(self):pass
            def recv_ready(self):return not hasattr(self,'read')
            def recv(self,n):self.read=True;return b'0\n'
            def recv_stderr_ready(self):return False
            def exit_status_ready(self):return hasattr(self,'read')
            def recv_exit_status(self):return 0
            def close(self):pass
        class FakeSSH:
            def __init__(self):self.c=FakeChannel()
            def get_transport(self):return self
            def is_active(self):return True
            def open_session(self,timeout):return self.c
            def close(self):pass
        from backend.ssh_monitor import SSHConnectionConfig
        c=SSHConnectionConfig(host='example.invalid',username='opc',private_key_path=str(self.key))
        with patch.object(runner,'_connect_verified',return_value=FakeSSH()):
            self.assertEqual(runner._run_sudo_proof(c)['effective_uid'],0)

if __name__=='__main__':unittest.main()
