"""Report regression: client isolation, genuine observations, no fake zeros or CSV formula injection."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
import json
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.database import Base, Client, Server
from backend.monitoring_engine import TelemetrySample, MonitorIncident
from backend.monitoring_reports import reporting_rows, _csv_field


class Step42ReportTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(self.engine, tables=[Client.__table__, Server.__table__,
                                 TelemetrySample.__table__, MonitorIncident.__table__])
        self.db = Session(self.engine)
        self.addCleanup(self.engine.dispose)
        self.addCleanup(self.db.close)
        self.now = datetime.now(timezone.utc)
        self.db.add_all([Client(id='c1', name='Client A'), Client(id='c2',name='Client B'),
                         Server(id='s1',client_id='c1',name='Server A',host='192.0.2.1',ssh_port=22),
                         Server(id='s2',client_id='c2',name='=bad',host='192.0.2.2',ssh_port=22)])
        self.db.commit()

    def sample(self, server_id, kind, state, data, *, age=0):
        self.db.add(TelemetrySample(server_id=server_id,kind=kind,state=state,
                    collected_at=self.now-timedelta(minutes=age),data_json=json.dumps(data)))
        self.db.commit()

    @staticmethod
    def who(role, client_id=None):
        return SimpleNamespace(role=role,client_id=client_id,is_active=True,id='fake')

    def test_client_scoping_and_known_peak_only(self):
        self.sample('s1','sessions','available',{'total':3,'sessions':[1,2,3]})
        self.sample('s1','sessions','available',{'total':0,'sessions':[]})
        self.sample('s1','sessions','vpn_not_active',{'total':None,'sessions':[]})
        self.sample('s2','sessions','available',{'total':29,'sessions':[]})
        rows=reporting_rows(self.db,self.who('client','c1'),now=self.now)['servers']
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['server_id'],'s1')
        self.assertEqual(rows[0]['session_samples'],2)
        self.assertEqual(rows[0]['peak_observed_connections'],3)
        self.assertEqual(rows[0]['average_observed_connections'],1.5)
        self.assertNotIn('s2',str(rows))

    def test_unknown_is_null_never_zero(self):
        self.sample('s1','sessions','status_unavailable',{'total':None,'sessions':[]})
        row=reporting_rows(self.db,self.who('client','c1'),now=self.now)['servers'][0]
        self.assertEqual(row['session_samples'],0)
        self.assertIsNone(row['peak_observed_connections'])
        self.assertIsNone(row['average_observed_connections'])

    def test_health_averages_and_old_data_excluded(self):
        self.sample('s1','health','connected',{'cpu_percent':40,'memory_used_percent':30,'disk_used_percent':10})
        self.sample('s1','health','connected',{'cpu_percent':20,'memory_used_percent':50,'disk_used_percent':30})
        self.sample('s1','health','connected',{'cpu_percent':90},age=1500)
        row=next(r for r in reporting_rows(self.db,self.who('admin'),now=self.now)['servers'] if r['server_id']=='s1')
        self.assertEqual(row['health_samples'],2)
        self.assertEqual(row['average_cpu_percent'],30)
        self.assertEqual(row['average_ram_percent'],40)
        self.assertEqual(row['average_disk_percent'],20)

    def test_outside_scope_returns_no_rows(self):
        rows=reporting_rows(self.db,self.who('client','other'),now=self.now)['servers']
        self.assertEqual(rows,[])

    def test_csv_excel_formula_protection(self):
        for payload in ('=SUM(1,2)',' +SUM(1,2)','@something','-7','\t=HYPERLINK(1)'):
            self.assertTrue(_csv_field(payload).startswith("'"),payload)
        self.assertEqual(_csv_field(None),'')
        self.assertEqual(_csv_field('Normal name'),'Normal name')

    def test_invalid_window_fails_closed(self):
        with self.assertRaises(ValueError):
            reporting_rows(self.db,self.who('admin'),hours=720,now=self.now)


if __name__=='__main__': unittest.main()
