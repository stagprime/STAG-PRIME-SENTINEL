"""Step45 API contract: authorization and no network access for bulk actions."""
import unittest
from types import SimpleNamespace
from uuid import uuid4
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.database import Base, Client, Server
from backend.admin_access import _require_admin
from backend.inventory_bulk import router


class InventoryBulkAPITests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite:///:memory:',connect_args={'check_same_thread':False},poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session=sessionmaker(self.engine)
        self.server_id=str(uuid4())
        with self.Session.begin() as db:
            c=Client(id=str(uuid4()),name='Tenant')
            db.add(c)
            db.add(Server(id=self.server_id,client_id=c.id,name='VM',host='192.0.2.10'))
        self.admin=SimpleNamespace(id=str(uuid4()),role='admin')
        app=FastAPI();app.include_router(router)
        def role_check():
            if self.admin.role!='admin':raise HTTPException(403,'Administrator role required')
            return self.admin
        app.dependency_overrides[_require_admin]=role_check
        p=patch('backend.inventory_bulk.SessionLocal',self.Session)
        p.start();self.addCleanup(p.stop)
        self.web=TestClient(app);self.addCleanup(self.web.close)
        self.addCleanup(self.engine.dispose)

    def test_role_is_checked_on_archive_and_delete(self):
        self.admin.role='client'
        body={'server_ids':[self.server_id]}
        self.assertEqual(self.web.post('/api/inventory/bulk/archive',json=body).status_code,403)
        self.assertEqual(self.web.post('/api/inventory/bulk/permanent-delete',json={**body,'confirmation':'DELETE 1 SERVERS'}).status_code,403)

    def test_archive_is_database_only_and_can_be_restored(self):
        r=self.web.post('/api/inventory/bulk/archive',json={'server_ids':[self.server_id]})
        self.assertEqual(r.status_code,200,r.text)
        self.assertFalse(r.json()['remote_changes'])
        with self.Session() as db:self.assertIsNotNone(db.get(Server,self.server_id).archived_at)

    def test_valid_confirmed_permanent_delete(self):
        with patch('backend.ssh_monitor._connect_verified',side_effect=AssertionError('SSH forbidden')) as ssh:
            r=self.web.post('/api/inventory/bulk/permanent-delete',json={'server_ids':[self.server_id],'confirmation':'DELETE 1 SERVERS'})
        self.assertEqual(r.status_code,200,r.text)
        self.assertTrue(r.json()['audit_retained'])
        self.assertEqual(r.json()['deleted'],1)
        ssh.assert_not_called()
        with self.Session() as db:self.assertIsNone(db.get(Server,self.server_id))

    def test_wrong_confirmation_keeps_server(self):
        r=self.web.post('/api/inventory/bulk/permanent-delete',json={'server_ids':[self.server_id],'confirmation':'DELETE ALL'})
        self.assertEqual(r.status_code,422)
        with self.Session() as db:self.assertIsNotNone(db.get(Server,self.server_id))

if __name__=='__main__':unittest.main()
