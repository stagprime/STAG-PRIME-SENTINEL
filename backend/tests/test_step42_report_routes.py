"""Offline FastAPI route tests for read-only, permission-scoped monitoring exports."""
import unittest
from types import SimpleNamespace
from datetime import datetime,timezone
import json
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from backend.database import Base, Client, Server
from backend.monitoring_engine import TelemetrySample, MonitorIncident
from backend.auth_api import require_current_session
from backend.monitoring_reports import router


class ReportRouteTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:', connect_args={'check_same_thread':False}, poolclass=StaticPool)
        Base.metadata.create_all(self.engine, tables=[Client.__table__, Server.__table__,
                                  TelemetrySample.__table__, MonitorIncident.__table__])
        self.session_factory=sessionmaker(bind=self.engine)
        with self.session_factory.begin() as db:
            db.add_all([Client(id='tenantA',name='Tenant A'),Client(id='tenantB',name='Tenant B'),
                        Server(id='A',client_id='tenantA',name='Safe',host='192.0.2.10'),
                        Server(id='B',client_id='tenantB',name='=DANGEROUS',host='192.0.2.11'),
                        TelemetrySample(server_id='B',kind='sessions',state='available',
                          collected_at=datetime.now(timezone.utc),data_json=json.dumps({'total':23}))])
        app=FastAPI()
        app.include_router(router)
        self.user=SimpleNamespace(role='client',id='userA',client_id='tenantA',is_active=True)
        app.dependency_overrides[require_current_session] = lambda:(self.user,None)
        self.patch_session=patch('backend.monitoring_reports.SessionLocal',self.session_factory)
        self.patch_init=patch('backend.monitoring_reports.initialize_monitor_tables',lambda:None)
        self.patch_session.start();self.patch_init.start()
        self.addCleanup(self.patch_session.stop)
        self.addCleanup(self.patch_init.stop)
        self.client=TestClient(app)
        self.addCleanup(self.client.close)
        self.addCleanup(self.engine.dispose)

    def test_summary_is_tenant_scoped(self):
        r=self.client.get('/api/monitoring/reports/summary')
        self.assertEqual(r.status_code,200)
        payload=r.json()
        self.assertEqual([s['server_id'] for s in payload['servers']],['A'])
        self.assertIsNone(payload['servers'][0]['peak_observed_connections'])
        # Avoid matching digits in the response timestamp; check tenant data instead.
        self.assertNotIn('tenantB',r.text)
        self.assertNotIn('=DANGEROUS',r.text)

    def test_export_is_scoped_and_excel_safe(self):
        self.user.role='admin'
        r=self.client.get('/api/monitoring/reports/summary.csv')
        self.assertEqual(r.status_code,200)
        self.assertIn("'=DANGEROUS",r.text)
        self.assertIn('attachment;',r.headers['content-disposition'])
        self.user.role='client'
        r=self.client.get('/api/monitoring/reports/summary.csv')
        self.assertEqual(r.status_code,200)
        self.assertNotIn('DANGEROUS',r.text)

    def test_invalid_window_is_rejected(self):
        for hours in [0,2,100]:
            self.assertEqual(self.client.get('/api/monitoring/reports/summary',params={'hours':hours}).status_code,422)

if __name__=='__main__':unittest.main()
