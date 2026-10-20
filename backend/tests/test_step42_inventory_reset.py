"""Offline non-networking test inventory cleanup regression."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from backend.test_inventory_reset import run


class Step42InventoryResetTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'sentinel.db'
        self.backups = Path(self.temp.name) / 'backups'
        with closing(sqlite3.connect(self.db)) as c, c:
            c.executescript('''
                PRAGMA foreign_keys=ON;
                CREATE TABLE clients(id TEXT PRIMARY KEY, name TEXT);
                CREATE TABLE servers(id TEXT PRIMARY KEY,client_id TEXT NOT NULL REFERENCES clients(id),name TEXT,host TEXT,ssh_port INTEGER,ssh_username TEXT,archived_at TEXT,monitoring_status TEXT);
                CREATE TABLE auth_users(id TEXT PRIMARY KEY,client_id TEXT REFERENCES clients(id));
                CREATE TABLE auth_client_grants(user_id TEXT,client_id TEXT REFERENCES clients(id));
                CREATE TABLE server_admin_profiles(server_id TEXT PRIMARY KEY REFERENCES servers(id),note TEXT);
                CREATE TABLE encrypted_ssh_credentials(server_id TEXT PRIMARY KEY REFERENCES servers(id),ciphertext TEXT);
                CREATE TABLE server_monitoring_configs(server_id TEXT PRIMARY KEY REFERENCES servers(id),enabled INTEGER);
                CREATE TABLE server_admin_verifications(server_id TEXT PRIMARY KEY REFERENCES servers(id),result TEXT);
                CREATE TABLE sentinel_telemetry_samples(id INTEGER PRIMARY KEY,server_id TEXT,data_json TEXT);
                CREATE TABLE sentinel_monitor_states(server_id TEXT PRIMARY KEY,state TEXT);
                CREATE TABLE sentinel_monitor_incidents(id INTEGER PRIMARY KEY,server_id TEXT);
                CREATE TABLE sentinel_session_transitions(id INTEGER PRIMARY KEY,server_id TEXT);
                CREATE TABLE onboarding_scans(id TEXT PRIMARY KEY,server_id TEXT);
                CREATE TABLE openvpn_setup_preflights(id TEXT PRIMARY KEY,server_id TEXT);
                CREATE TABLE reviewed_command_previews(id TEXT PRIMARY KEY,server_id TEXT REFERENCES servers(id));
                CREATE TABLE reviewed_command_runs(id TEXT PRIMARY KEY,server_id TEXT REFERENCES servers(id));
                CREATE TABLE controlled_diagnostic_jobs(id TEXT PRIMARY KEY,server_id TEXT);
                CREATE TABLE server_admin_audit(id INTEGER PRIMARY KEY,server_id TEXT, result TEXT);
                CREATE TABLE sentinel_monitor_worker_pulse(worker_name TEXT PRIMARY KEY);
            ''')
            c.executemany('INSERT INTO clients VALUES(?,?)', [('c1','Stag Prime LLC'),('c2','Stag VPN'),('c3','Demo Client')])
            servers = [
                ('k','c1','sentinel-test-key','161.118.172.56',22,'opc',None,'healthy'),
                ('p','c1','sentinel-test-password','152.67.0.221',22,'sentineladmin',None,'healthy'),
                ('d1','c2','EU-01','167.233.63.213',22,'tariq',None,'connected'),
                ('d2','c2','EU-02','188.245.181.29',22,'tariq',None,'connected'),
                ('d3','c2','MENA-01','145.241.127.122',22,'tariq',None,'connected'),
                ('d4','c3','SENTINEL-TEST-01','192.0.2.10',22,'opc',None,'not_connected'),
                ('d5','c3','TEST-VPS-02','198.51.100.20',22,'opc','archived','not_connected'),
            ]
            c.executemany('INSERT INTO servers VALUES(?,?,?,?,?,?,?,?)',servers)
            for sid in [s[0] for s in servers]:
                for table,col,value in [
                    ('server_admin_profiles','note','profile'),('encrypted_ssh_credentials','ciphertext','secret'),
                    ('server_monitoring_configs','enabled',1),('server_admin_verifications','result','success'),
                    ('sentinel_monitor_states','state','healthy')]:
                    c.execute(f'INSERT INTO {table}(server_id,{col}) VALUES(?,?)',(sid,value))
                c.execute('INSERT INTO sentinel_telemetry_samples(server_id,data_json) VALUES(?,?)',(sid,'{}'))
                c.execute('INSERT INTO reviewed_command_runs(id,server_id) VALUES(?,?)',(sid,sid))
                c.execute('INSERT INTO server_admin_audit(server_id,result) VALUES(?,?)',(sid,'verified'))
            c.execute('INSERT INTO sentinel_monitor_worker_pulse VALUES(?)',('worker',))

    def q(self, query, args=()):
        with closing(sqlite3.connect(self.db)) as c, c:
            return c.execute(query,args).fetchall()

    def test_dry_run_no_changes_or_backup(self):
        result = run(self.db, apply=False,backup_root=self.backups)
        self.assertEqual(result['remove'],5)
        self.assertEqual(len(self.q('SELECT id FROM servers')),7)
        self.assertFalse(self.backups.exists())

    def test_apply_backup_purge_two_test_preserve_credentials_and_security_audit(self):
        result=run(self.db,apply=True,backup_root=self.backups)
        self.assertEqual(result['removed'],5)
        self.assertEqual(self.q('SELECT id FROM servers ORDER BY id'),[('k',),('p',)])
        self.assertEqual(self.q('SELECT server_id FROM encrypted_ssh_credentials ORDER BY server_id'), [('k',),('p',)])
        self.assertEqual(self.q('SELECT server_id FROM server_admin_profiles ORDER BY server_id'), [('k',),('p',)])
        self.assertEqual(self.q('SELECT * FROM sentinel_telemetry_samples'),[])
        self.assertEqual(self.q('SELECT * FROM sentinel_monitor_worker_pulse'),[])
        self.assertEqual(self.q('SELECT * FROM server_monitoring_configs'),[])
        self.assertEqual(self.q('SELECT COUNT(*) FROM server_admin_audit'),[(7,)])
        self.assertEqual(self.q('SELECT id FROM clients ORDER BY id'), [('c1',)])
        self.assertEqual(self.q('PRAGMA foreign_key_check'),[])
        original=Path(result['backup'])
        self.assertTrue(original.exists())
        with closing(sqlite3.connect(original)) as c, c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM servers').fetchone()[0],7)

    def test_exact_host_guard_fail_closed(self):
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute("UPDATE servers SET host='203.0.113.8' WHERE name='sentinel-test-key'")
        with self.assertRaisesRegex(RuntimeError,'Identity mismatch'):
            run(self.db,apply=True,backup_root=self.backups)
        self.assertEqual(len(self.q('SELECT id FROM servers')),7)
        self.assertFalse(self.backups.exists())

    def test_absent_test_target_guard_fail_closed(self):
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute("DELETE FROM server_monitoring_configs WHERE server_id='p'")
            c.execute("DELETE FROM server_admin_verifications WHERE server_id='p'")
            c.execute("DELETE FROM server_admin_profiles WHERE server_id='p'")
            c.execute("DELETE FROM encrypted_ssh_credentials WHERE server_id='p'")
            c.execute("DELETE FROM sentinel_telemetry_samples WHERE server_id='p'")
            c.execute("DELETE FROM sentinel_monitor_states WHERE server_id='p'")
            c.execute("DELETE FROM reviewed_command_runs WHERE server_id='p'")
            c.execute("DELETE FROM servers WHERE id='p'")
        with self.assertRaisesRegex(RuntimeError,'exactly one'):
            run(self.db,apply=True,backup_root=self.backups)
        self.assertFalse(self.backups.exists())

    def test_unknown_server_scoped_table_prevents_unreviewed_purge(self):
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('CREATE TABLE new_future_data(server_id TEXT, unexpected TEXT)')
        with self.assertRaisesRegex(RuntimeError,'Unknown server-scoped table'):
            run(self.db,apply=True,backup_root=self.backups)
        self.assertEqual(len(self.q('SELECT id FROM servers')),7)

    def test_second_apply_is_idempotent_no_new_backup_or_data_loss(self):
        run(self.db,apply=True,backup_root=self.backups)
        before = list(self.backups.iterdir())
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute("INSERT INTO sentinel_telemetry_samples(server_id,data_json) VALUES('k','\"new_data\"')")
        result=run(self.db,apply=True,backup_root=self.backups)
        self.assertTrue(result['already_clean'])
        self.assertEqual(self.q('SELECT data_json FROM sentinel_telemetry_samples'), [('\"new_data\"',)])
        self.assertEqual(before,list(self.backups.iterdir()))

    def test_auth_linked_client_not_deleted(self):
        with closing(sqlite3.connect(self.db)) as c, c:
            c.execute('INSERT INTO auth_users VALUES(?,?)',('user1','c2'))
        run(self.db,apply=True,backup_root=self.backups)
        self.assertEqual(self.q('SELECT id FROM clients ORDER BY id'), [('c1',),('c2',)])


if __name__=='__main__':
    unittest.main()
