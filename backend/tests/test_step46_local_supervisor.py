"""Local service supervisor regression: no live processes, databases, or SSH."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

SCRIPT = Path(__file__).resolve().parents[2] / 'Sentinel_Start_Local_All.py'
spec = importlib.util.spec_from_file_location('sentinel_local_launcher_46', SCRIPT)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class FakeProcess:
    def __init__(self, returncode=None): self.returncode = returncode; self.pid = 100
    def poll(self): return self.returncode


class StarterTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)
        self.services = {
            'FastAPI': (['python', '-m', 'uvicorn'], self.root),
            'Frontend': (['npm', 'run', 'dev'], self.root),
            'Read-only monitoring worker': (['python','-m','backend.monitoring_worker'], self.root),
        }
        patcher = patch.object(launcher, 'commands', return_value=self.services)
        patcher.start(); self.addCleanup(patcher.stop)

    def test_check_does_not_launch_or_contact_ports(self):
        with patch.object(launcher, 'spawn', side_effect=AssertionError('spawn forbidden')):
            with patch.object(launcher, 'localhost_port_open', side_effect=AssertionError('socket forbidden')):
                launcher.run(self.root, check_only=True)

    def test_reuse_existing_api_and_frontend_start_worker(self):
        with patch.object(launcher,'localhost_port_open',return_value=True), \
             patch.object(launcher,'trusted_existing_api',return_value=True), \
             patch.object(launcher,'trusted_existing_frontend',return_value=True), \
             patch.object(launcher,'worker_lock_held',return_value=False), \
             patch.object(launcher,'spawn',return_value=FakeProcess()) as launch, \
             patch.object(launcher,'stop_owned') as stop:
            launcher.run(self.root, watch=False)
        self.assertEqual(launch.call_count,1)
        self.assertEqual(launch.call_args.args[0],'Read-only monitoring worker')
        self.assertEqual(stop.call_count,1)

    def test_existing_worker_lock_prevents_duplicate(self):
        with patch.object(launcher,'localhost_port_open',return_value=True), \
             patch.object(launcher,'trusted_existing_api',return_value=True), \
             patch.object(launcher,'trusted_existing_frontend',return_value=True), \
             patch.object(launcher,'worker_lock_held',return_value=True), \
             patch.object(launcher,'spawn',side_effect=AssertionError('duplicate worker')):
            launcher.run(self.root, watch=False)

    def test_unknown_backend_fails_closed(self):
        with patch.object(launcher,'localhost_port_open',return_value=True), \
             patch.object(launcher,'trusted_existing_api',return_value=False), \
             patch.object(launcher,'spawn',side_effect=AssertionError('never spawn')):
            with self.assertRaisesRegex(RuntimeError,'unrecognized/unhealthy'):
                launcher.run(self.root, watch=False)

    def test_unknown_frontend_fails_closed(self):
        with patch.object(launcher,'localhost_port_open',side_effect=lambda port:port==5173), \
             patch.object(launcher,'trusted_existing_frontend',return_value=False), \
             patch.object(launcher,'spawn',return_value=FakeProcess()) as create, \
             patch.object(launcher,'stop_owned') as stop:
            with self.assertRaisesRegex(RuntimeError,'unrecognized frontend'):
                launcher.run(self.root, watch=False)
        self.assertEqual(create.call_count,1)
        self.assertEqual(stop.call_count,1)

    def test_free_ports_start_three_services(self):
        with patch.object(launcher,'localhost_port_open',return_value=False), \
             patch.object(launcher,'worker_lock_held',return_value=False), \
             patch.object(launcher,'spawn',return_value=FakeProcess()) as create, \
             patch.object(launcher,'stop_owned') as stop:
            launcher.run(self.root, watch=False)
        self.assertEqual([a.args[0] for a in create.call_args_list],
                         ['FastAPI','Frontend','Read-only monitoring worker'])
        self.assertEqual(stop.call_count,3)

    def test_worker_only_restart_capped(self):
        # The worker has exited. The sleep callback aborts the supervisor after
        # the first bounded retry delay, without launching any real process.
        with patch.object(launcher,'localhost_port_open',return_value=True), \
             patch.object(launcher,'trusted_existing_api',return_value=True), \
             patch.object(launcher,'trusted_existing_frontend',return_value=True), \
             patch.object(launcher,'worker_lock_held',return_value=False), \
             patch.object(launcher,'spawn',return_value=FakeProcess(returncode=1)) as create, \
             patch.object(launcher,'stop_owned') as stop:
            delays=[]
            def stop_after_one(delay):
                delays.append(delay)
                raise KeyboardInterrupt()
            launcher.run(self.root, watch=True, sleep=stop_after_one)
        self.assertEqual(delays, [5])
        self.assertEqual(create.call_count,1)
        self.assertEqual(stop.call_count,1)

    def test_worker_lock_empty_or_unlocked_is_free(self):
        d=self.root/'data';d.mkdir()
        lock=d/'monitoring-worker.lock'
        self.assertFalse(launcher.worker_lock_held(self.root))
        lock.write_bytes(b'0')
        self.assertFalse(launcher.worker_lock_held(self.root))

    def test_existing_backend_health_must_be_exact(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,_):return b'{"service":"other-backend","status":"healthy"}'
        with patch.object(launcher,'urlopen',return_value=Response()):
            self.assertFalse(launcher.trusted_existing_api())


if __name__=='__main__': unittest.main()
