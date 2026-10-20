"""Tenant-scoped client registry and safe organization edits, no remote actions."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, Client, Server
from backend.auth_api import require_current_session
from backend.user_management import require_admin_session
from backend.client_directory import router


class ClientDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
        Base.metadata.create_all(self.engine,tables=[Client.__table__,Server.__table__])
        self.factory=sessionmaker(bind=self.engine)
        with self.factory.begin() as db:
            db.add_all([Client(id='c1',name='Client One'),Client(id='c2',name='Client Two'),
                        Server(id='s1',client_id='c1',name='Server One',host='192.0.2.10')])
        app=FastAPI()
        app.include_router(router)
        self.user=SimpleNamespace(id='u1',role='admin',is_active=True,client_id=None)
        app.dependency_overrides[require_current_session]=lambda:(self.user,None)
        app.dependency_overrides[require_admin_session]=self._admin
        self.patch=patch('backend.client_directory.SessionLocal',self.factory)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.client=TestClient(app)
        self.addCleanup(self.client.close)
        self.addCleanup(self.engine.dispose)

    def _admin(self):
        from fastapi import HTTPException
        if self.user.role!='admin':raise HTTPException(403,detail='Administrator role required')
        return self.user

    def test_list_client_scope_and_active_server_counts(self):
        r=self.client.get('/api/clients')
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['total'],2)
        self.assertEqual(next(x['active_servers'] for x in r.json()['clients'] if x['id']=='c1'),1)
        self.user.role='client';self.user.client_id='c1'
        res=self.client.get('/api/clients')
        self.assertEqual([x['id'] for x in res.json()['clients']],['c1'])

    def test_create_patch_preserves_client_uuid_and_server_ownership(self):
        r=self.client.post('/api/clients',json={'name':' New Corp ','contact_email':'hello@example.com'})
        self.assertEqual(r.status_code,201,r.text)
        cid=r.json()['id']
        updated=self.client.patch('/api/clients/'+cid,json={'name':'Renamed Corp','contact_email':None})
        self.assertEqual(updated.status_code,200)
        self.assertEqual(updated.json()['id'],cid)
        with self.factory() as db:
            self.assertEqual(db.get(Server,'s1').client_id,'c1')

    def test_duplicate_and_invalid_email_fail_closed(self):
        self.assertEqual(self.client.post('/api/clients',json={'name':'CLIENT ONE'}).status_code,409)
        self.assertEqual(self.client.post('/api/clients',json={'name':'New','contact_email':'not email'}).status_code,422)
        self.assertEqual(self.client.patch('/api/clients/c1',json={'name':'Client Two'}).status_code,409)
        self.assertEqual(self.client.patch('/api/clients/c1',json={'name':None}).status_code,422)

    def test_mutations_admin_only(self):
        self.user.role='client'; self.user.client_id='c1'
        self.assertEqual(self.client.post('/api/clients',json={'name':'Denied'}).status_code,403)
        self.assertEqual(self.client.patch('/api/clients/c1',json={'name':'Denied'}).status_code,403)

    def test_extra_fields_rejected(self):
        self.assertEqual(self.client.post('/api/clients',json={'name':'New Tenant','is_admin':True}).status_code,422)

if __name__=='__main__':unittest.main()
