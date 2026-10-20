"""Step 41A offline monitoring unit tests. No real SSH, sudo, or VPN activity."""
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from backend.database import Base, Client, Server, ServerMonitoringConfig
from backend import monitoring_engine as me


class MonitoringStep41Tests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='sentinel41_')
        self.addCleanup(tmp.cleanup)
        engine = create_engine('sqlite:///' + str(Path(tmp.name) / 'isolated.db'))
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(bind=engine)
        self.Session = sessionmaker(bind=engine)
        patches=[patch.object(me,'SessionLocal',self.Session),patch.object(me,'engine',engine)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        with self.Session.begin() as db:
            c1=Client(name='Alpha'); c2=Client(name='Beta'); db.add_all([c1,c2]);db.flush()
            a=Server(client_id=c1.id,name='Test One',host='192.0.2.20',ssh_port=22,ssh_username='monitor')
            b=Server(client_id=c2.id,name='Test Two',host='192.0.2.21',ssh_port=22,ssh_username='monitor')
            db.add_all([a,b]);db.flush()
            self.one,self.two = a.id,b.id
            db.add(ServerMonitoringConfig(server_id=a.id, enabled=True, approved_host=a.host,
                approved_ssh_username=a.ssh_username,approved_ssh_port=22,ssh_key_path='fake',
                vpn_service='openvpn-server@server',vpn_interface='tun0',network_interface='eth0'))
        self.now=me.utcnow()

    def _vpn(self, rows):
        return {'state':'available', 'total':len(rows), 'sessions':rows, 'status_age_seconds':1}

    def _row(self, client_id, ip):
        return {'client_id':client_id, 'common_name':'shared', 'username':'shared',
                'public_ip':ip, 'vpn_ip':'10.8.0.2', 'connected_since_unix':10,
                'bytes_received':15, 'bytes_sent':20}

    def test_inventory_only_is_not_polled(self):
        self.assertEqual(me.poll_one(self.two, 'health', collector_health=lambda *_args,**_kwargs: self.fail('SSH performed')), 'not_enrolled')
        self.assertEqual(me.active_targets(), [self.one])

    def test_pinned_identity_mismatch_prevents_ssh(self):
        with self.Session.begin() as db:
            server=db.get(Server,self.one)
            server.host='192.0.2.80'
        self.assertEqual(me.poll_one(self.one,'sessions',collector_sessions=lambda *_args,**_kwargs: self.fail('SSH performed')), 'not_enrolled')

    def test_available_zero_is_distinct_from_unknown(self):
        with self.Session.begin() as db:
            me.record_sample(db,self.one,'sessions',self._vpn([]),self.now)
            me.record_sample(db,self.one,'sessions',{'state':'stale_status','total':0,'sessions':[]},self.now+timedelta(seconds=30))
        with self.Session() as db:
            rows=db.scalars(select(me.TelemetrySample).where(me.TelemetrySample.server_id==self.one).order_by(me.TelemetrySample.id)).all()
            self.assertEqual(json.loads(rows[0].data_json)['total'],0)
            self.assertIsNone(json.loads(rows[1].data_json)['total'])

    def test_snapshot_events_per_connection_not_cn(self):
        with self.Session.begin() as db:
            me.record_sample(db,self.one,'sessions',self._vpn([self._row(1,'198.51.100.1')]),self.now)
            me.record_sample(db,self.one,'sessions',self._vpn([self._row(1,'198.51.100.1'),self._row(2,'198.51.100.2')]),self.now+timedelta(seconds=30))
            me.record_sample(db,self.one,'sessions',self._vpn([self._row(2,'198.51.100.2')]),self.now+timedelta(seconds=60))
        with self.Session() as db:
            events=db.scalars(select(me.SessionTransition)).all()
            self.assertEqual([(e.event,e.client_public_ip) for e in events], [('appeared','198.51.100.2'),('disappeared','198.51.100.1')])

    def test_no_events_across_stale_gap(self):
        with self.Session.begin() as db:
            me.record_sample(db,self.one,'sessions',self._vpn([self._row(1,'198.51.100.1')]),self.now)
            me.record_sample(db,self.one,'sessions',{'state':'permission_required','total':None,'sessions':[]},self.now+timedelta(seconds=30))
            me.record_sample(db,self.one,'sessions',self._vpn([]),self.now+timedelta(seconds=60))
        with self.Session() as db:
            self.assertEqual(len(db.scalars(select(me.SessionTransition)).all()),0)

    def test_read_only_monitor_collectors_do_not_use_sudo(self):
        health = {'status':'connected','host':'192.0.2.20','host_key_verified':True,
                  'cpu_percent':1,'memory_used_percent':1,'disk_used_percent':1}
        self.assertEqual(me.poll_one(self.one,'health',collector_health=lambda *args,**kw:health,now=self.now),'connected')
        with self.Session() as db:
            item=db.get(me.MonitorState,self.one)
            self.assertEqual(item.status,'healthy')
            self.assertEqual(item.failures,0)

    def test_three_failures_one_incident_and_recovery(self):
        def fail(*args,**kwargs):raise TimeoutError('secret/path or network')
        for i in range(3):
            self.assertEqual(me.poll_one(self.one,'sessions',collector_sessions=fail,now=self.now+timedelta(seconds=i*30)), 'connection_timeout')
        with self.Session() as db:
            incidents=db.scalars(select(me.MonitorIncident)).all()
            self.assertEqual(len(incidents),1)
            self.assertEqual(incidents[0].state,'open')
            self.assertEqual(db.get(me.MonitorState,self.one).status,'pending')
            self.assertEqual(db.get(me.MonitorState,self.one).session_failures,3)
            self.assertEqual(db.get(me.MonitorState,self.one).health_failures,0)
        self.assertEqual(me.poll_one(self.one,'sessions',collector_sessions=lambda *args,**kw:self._vpn([]),now=self.now+timedelta(seconds=120)), 'available')
        with self.Session() as db:
            incidents=db.scalars(select(me.MonitorIncident)).all()
            self.assertEqual(len(incidents),1)
            self.assertEqual(incidents[0].state,'resolved')

    def test_sessions_failure_cannot_mark_good_ssh_as_unreachable(self):
        health = {'status': 'connected', 'host_key_verified': True, 'cpu_percent': 12}
        me.poll_one(self.one, 'health', collector_health=lambda *_a, **_k: health, now=self.now)
        def broken_vpn(*_a, **_k): raise TimeoutError('simulated sessions only')
        for n in range(3):
            me.poll_one(self.one, 'sessions', collector_sessions=broken_vpn,
                        now=self.now + timedelta(seconds=n * 10))
        me.pulse(self.now)
        with self.Session() as db:
            state = db.get(me.MonitorState, self.one)
            self.assertEqual(state.status, 'healthy')
            self.assertEqual(state.health_failures, 0)
            self.assertEqual(state.session_failures, 3)
            self.assertIsNone(state.error_code)
            overview = me.overview_for_user(SimpleNamespace(role='admin', is_active=True), db)
            row = next(row for row in overview['servers'] if row['server_id'] == self.one)
            self.assertEqual(row['status'], 'healthy')
            self.assertTrue(row['health']['fresh'])
            self.assertFalse(row['sessions']['fresh'])

    def test_failed_health_does_not_show_old_health_as_live(self):
        health = {'status': 'connected', 'host_key_verified': True, 'cpu_percent': 12}
        me.poll_one(self.one, 'health', collector_health=lambda *_a, **_k: health, now=self.now)
        def broken_ssh(*_a, **_k): raise TimeoutError('simulated health only')
        me.poll_one(self.one, 'health', collector_health=broken_ssh,
                    now=self.now + timedelta(seconds=1))
        me.pulse(self.now)
        with self.Session() as db:
            state = db.get(me.MonitorState, self.one)
            self.assertEqual(state.status, 'degraded')
            overview = me.overview_for_user(SimpleNamespace(role='admin', is_active=True), db)
            row = next(row for row in overview['servers'] if row['server_id'] == self.one)
            self.assertEqual(row['status'], 'degraded')
            self.assertFalse(row['health']['fresh'])
            self.assertIsNone(row['health']['data'])

    def test_inactive_vpn_observation_uses_300_second_ttl(self):
        with self.Session.begin() as db:
            me.record_sample(db, self.one, 'sessions',
                {'state': 'vpn_not_active', 'total': None, 'sessions': []},
                self.now - timedelta(seconds=240))
        me.pulse(self.now)
        with self.Session() as db:
            overview = me.overview_for_user(SimpleNamespace(role='admin', is_active=True), db)
            row = next(row for row in overview['servers'] if row['server_id'] == self.one)
            self.assertTrue(row['sessions']['fresh'])
            self.assertEqual(row['sessions']['data']['state'], 'vpn_not_active')
            self.assertIsNone(row['sessions']['data']['total'])

    def test_cross_client_rows_hidden(self):
        with self.Session.begin() as db:
            me.record_sample(db,self.one,'sessions',self._vpn([]),self.now)
        me.pulse(self.now)
        with self.Session() as db:
            mine=me.overview_for_user(SimpleNamespace(role='client',client_id=db.get(Server,self.one).client_id,is_active=True),db)
            other=me.overview_for_user(SimpleNamespace(role='client',client_id=db.get(Server,self.two).client_id,is_active=True),db)
            self.assertEqual([x['server_id'] for x in mine['servers']],[self.one])
            self.assertEqual([x['server_id'] for x in other['servers']],[self.two])

    def test_worker_offline_never_displays_old_snapshots_as_live(self):
        old=self.now-timedelta(minutes=20)
        with self.Session.begin() as db:
            me.record_sample(db,self.one,'sessions',self._vpn([self._row(1,'198.51.100.1')]),old)
        with self.Session() as db:
            overview=me.overview_for_user(SimpleNamespace(role='admin',client_id=None,is_active=True),db)
            one=next(x for x in overview['servers'] if x['server_id']==self.one)
            self.assertEqual(one['status'],'worker_offline')
            self.assertIsNone(one['sessions']['data'])
            self.assertFalse(one['sessions']['fresh'])

    def test_prepare_fresh_enrollment_clears_backoff(self):
        with self.Session.begin() as db:
            db.add(me.MonitorState(
                server_id=self.one, status='unreachable', error_code='connection_timeout',
                failures=9, health_failures=9, session_failures=4,
                next_attempt_at=self.now + timedelta(minutes=5),
            ))
        me.prepare_fresh_enrollment(self.one)
        with self.Session() as db:
            state = db.get(me.MonitorState, self.one)
            self.assertEqual(state.status, 'pending')
            self.assertIsNone(state.error_code)
            self.assertEqual(state.health_failures, 0)
            self.assertEqual(state.session_failures, 0)
            self.assertIsNone(state.next_attempt_at)

    def test_kick_first_collection_runs_health_then_sessions(self):
        calls = []
        def fake_poll(server_id, kind, **_kw):
            calls.append((server_id, kind))
            return 'connected' if kind == 'health' else 'available'
        with patch.object(me, 'poll_one', side_effect=fake_poll), \
             patch.object(me.threading.Thread, 'start', lambda self: self.run()):
            me.kick_first_collection(self.one)
        self.assertEqual(calls, [(self.one, 'health'), (self.one, 'sessions')])
        with self.Session() as db:
            state = db.get(me.MonitorState, self.one)
            self.assertEqual(state.status, 'pending')
            self.assertEqual(state.health_failures, 0)


if __name__ == '__main__':
    unittest.main()
