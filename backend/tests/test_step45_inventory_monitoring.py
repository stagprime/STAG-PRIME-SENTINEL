"""Step 45 offline tests: destructive actions and SSH monitoring pacing.

Never opens a socket or modifies a user's actual database.
"""
import tempfile
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import sessionmaker

import backend.main  # registers route/model tables
from backend.database import Base, Client, Server, ServerMonitoringConfig
from backend.admin_access import ServerAdminAudit
from backend.monitoring_engine import TelemetrySample, sanitized_failure
from backend.monitoring_worker import session_delay
from backend.inventory_bulk import (_ids, BulkDelete, bulk_permanent_delete,
                                    permanent_delete_records, InventoryRemovalAudit)


class Step45InventorySafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = create_engine('sqlite:///' + self.tmp.name + '/isolation.db')
        @event.listens_for(self.engine, 'connect')
        def foreign_keys(conn, record):
            conn.execute('PRAGMA foreign_keys=ON')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        self.id1 = str(uuid4()); self.id2 = str(uuid4())
        self.actor = str(uuid4())
        with self.Session.begin() as db:
            c = Client(id=str(uuid4()), name='Test tenant')
            db.add(c)
            for sid,name in ((self.id1,'alpha'),(self.id2,'beta')):
                db.add(Server(id=sid,client_id=c.id,name=name,host='192.0.2.5',
                              ssh_username='opc',ssh_port=22))
        with self.Session.begin() as db:
            db.add(ServerMonitoringConfig(server_id=self.id1,enabled=True,
                 approved_host='192.0.2.5',approved_ssh_username='opc',approved_ssh_port=22,
                 ssh_key_path='sentinel-vault:'+self.id1,known_hosts_path=None,
                 vpn_service='openvpn-server@server',vpn_interface='tun0',network_interface='eth0'))
            db.add(TelemetrySample(server_id=self.id1,kind='health',
                     collected_at=datetime.now(timezone.utc),state='connected',data_json='{}'))
            db.add(ServerAdminAudit(server_id=self.id1,actor_id=self.actor,
                     operation='credential_enroll',result='enrolled_unverified'))

    def tearDown(self):
        self.engine.dispose()

    def test_delete_removes_active_monitoring_and_keeps_other_tenant_row(self):
        with self.Session.begin() as db:
            count = permanent_delete_records(db,[self.id1],self.actor)
        self.assertEqual(count,1)
        with self.Session() as db:
            self.assertIsNone(db.get(Server,self.id1))
            self.assertIsNotNone(db.get(Server,self.id2))
            self.assertIsNone(db.get(ServerMonitoringConfig,self.id1))
            self.assertFalse(db.scalars(select(TelemetrySample).where(TelemetrySample.server_id==self.id1)).all())
            history=list(db.scalars(select(ServerAdminAudit).where(ServerAdminAudit.server_id==self.id1)))
            self.assertEqual(len(history),1)
            receipt=list(db.scalars(select(InventoryRemovalAudit).where(InventoryRemovalAudit.server_id==self.id1)))
            self.assertEqual(len(receipt),1)
            self.assertEqual(receipt[0].actor_id,self.actor)

    def test_unreviewed_extension_fails_closed_without_mutation(self):
        with self.engine.begin() as conn:
            conn.execute(text('CREATE TABLE unknown_plugin (server_id TEXT)'))
        with self.assertRaises(HTTPException) as ctx:
            with self.Session.begin() as db:
                permanent_delete_records(db,[self.id1],self.actor)
        self.assertEqual(ctx.exception.status_code,409)
        with self.Session() as db:
            self.assertIsNotNone(db.get(Server,self.id1))
            self.assertIsNotNone(db.get(ServerMonitoringConfig,self.id1))

    def test_all_or_nothing_if_id_missing(self):
        with self.assertRaises(HTTPException):
            with self.Session.begin() as db:
                permanent_delete_records(db,[self.id1,str(uuid4())],self.actor)
        with self.Session() as db:
            self.assertIsNotNone(db.get(Server,self.id1))

    def test_reject_duplicate_or_invalid_identifiers(self):
        for ids in ([self.id1,self.id1],['bad-id'],[],[self.id1]*51):
            with self.assertRaises(HTTPException):_ids(ids)

    def test_confirmed_phrase_required_before_db(self):
        with self.assertRaises(HTTPException) as ctx:
            bulk_permanent_delete(BulkDelete(server_ids=[self.id1],confirmation='DELETE 2 SERVERS'),
                                  SimpleNamespace(id=self.actor))
        self.assertEqual(ctx.exception.status_code,422)

    def test_no_remote_vps_invoked_during_delete(self):
        from unittest.mock import patch
        with patch('backend.ssh_monitor._connect_verified',side_effect=AssertionError('remote SSH forbidden')) as ssh:
            with self.Session.begin() as db:
                self.assertEqual(permanent_delete_records(db,[self.id1],self.actor),1)
        ssh.assert_not_called()


class Step45MonitorPacingTests(unittest.TestCase):
    def test_inactive_vpn_uses_slow_refresh(self):
        self.assertEqual(session_delay('vpn_not_active'),300)
    def test_available_vpn_keeps_30_second_sessions(self):
        self.assertEqual(session_delay('available'),30)
        self.assertEqual(session_delay('permission_required'),30)
    def test_banner_transport_failure_sanitized(self):
        self.assertEqual(sanitized_failure(Exception('Error reading SSH protocol banner [WinError 10038]')),
                         'ssh_banner_unavailable')
    def test_transport_details_not_exposed(self):
        self.assertEqual(sanitized_failure(OSError('private log /somepath')), 'transport_unavailable')


if __name__=='__main__': unittest.main()
