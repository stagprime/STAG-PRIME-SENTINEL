"""Step 45-R2 offline worker pacing tests: no SSH, database or subprocess."""
import unittest
from unittest.mock import MagicMock, patch

from backend import monitoring_worker as worker


class StopSimulation(Exception):
    pass


class WorkerScheduleIsolationTests(unittest.TestCase):
    def test_first_cycle_collects_health_before_sessions(self):
        calls = []
        with patch.object(worker, 'singleton_lock', return_value=MagicMock()), \
             patch.object(worker, 'initialize_monitor_tables'), \
             patch.object(worker, 'active_targets', return_value=['test-server']), \
             patch.object(worker, 'poll_one', side_effect=lambda sid, kind: calls.append(kind) or 'connected'), \
             patch.object(worker.threading, 'Thread', return_value=MagicMock()):
            worker.run(single_cycle=True)
        self.assertEqual(calls, ['health'])

    def test_vpn_failure_does_not_starve_health_recovery(self):
        clock = [0.0]
        calls = []
        def poll(_sid, kind):
            calls.append((round(clock[0]), kind))
            return 'connected' if kind == 'health' else 'connection_timeout'
        def advance(_seconds):
            clock[0] += 9.0
            if clock[0] > 72:
                raise StopSimulation()
        with patch.object(worker, 'singleton_lock', return_value=MagicMock()), \
             patch.object(worker, 'initialize_monitor_tables'), \
             patch.object(worker, 'active_targets', return_value=['test-server']), \
             patch.object(worker, 'poll_one', side_effect=poll), \
             patch.object(worker.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(worker.time, 'sleep', side_effect=advance), \
             patch.object(worker.threading, 'Thread', return_value=MagicMock()):
            with self.assertRaises(StopSimulation):
                worker.run()
        self.assertEqual([kind for _,kind in calls if kind == 'health'], ['health','health'])
        self.assertTrue(any(kind == 'sessions' for _,kind in calls))
        self.assertGreaterEqual(min(t for t,k in calls if k == 'sessions'), worker.MIN_HOST_SSH_GAP)


if __name__ == '__main__':
    unittest.main()
