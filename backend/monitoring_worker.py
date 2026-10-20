"""Explicit, separate long-running worker. No auto-SSH when starting FastAPI.

Run exactly ONE worker alongside FastAPI in production. The worker requires
pre-approved monitoring profiles; it never creates approvals or elevates SSH.
"""
import argparse
import logging
import os
import sys
import threading
import time
from pathlib import Path

from backend.monitoring_engine import (initialize_monitor_tables, active_targets, poll_one,
                                       pulse, utcnow)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('sentinel.monitor.worker')


def singleton_lock():
    path = Path(__file__).resolve().parent.parent / 'data' / 'monitoring-worker.lock'
    path.parent.mkdir(parents=True, exist_ok=True)
    f = path.open('a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            f.seek(0)
            if f.read(1) == b'':
                f.write(b'0')
                f.flush()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        raise RuntimeError('Another Sentinel monitor worker already holds the lock')
    return f


# One host never receives rapid back-to-back SSH handshakes from this worker.
MIN_HOST_SSH_GAP = 8


def session_delay(result: str) -> int:
    # 30-second snapshots only when the VPN is configured/active. An absent
    # OpenVPN service is not polled every 30s over a separate SSH handshake.
    return 300 if result == 'vpn_not_active' else 30


def run(single_cycle=False):
    lock = singleton_lock()
    stop = threading.Event()
    heartbeat_thread = None
    try:
        initialize_monitor_tables()
        def heartbeat_loop():
            while not stop.is_set():
                try:
                    pulse()
                except Exception:
                    log.exception('Worker heartbeat database failure')
                stop.wait(30)
        heartbeat_thread = threading.Thread(target=heartbeat_loop, name='sentinel-heartbeat', daemon=True)
        heartbeat_thread.start()
        schedule = {}
        while True:
            ids = set(active_targets())
            schedule = {key: value for key, value in schedule.items() if key[0] in ids}
            for server_id in sorted(ids):
                # First-ever sample is health, and health retains its own cadence
                # even after an OpenVPN session collection error.
                for kind, period in (('health', 60), ('sessions', 30)):
                    key = (server_id, kind)
                    clock = time.monotonic()
                    if clock < schedule.get(key, 0) or clock < schedule.get((server_id, 'next_ssh'), 0):
                        continue
                    result = poll_one(server_id, kind)
                    done = time.monotonic()
                    schedule[(server_id, 'next_ssh')] = done + MIN_HOST_SSH_GAP
                    if result == 'maintenance_paused':
                        schedule[key] = done + 10
                        continue
                    retry = result in ('connection_timeout', 'transport_unavailable', 'collector_failed',
                        'authentication_failed', 'host_key_mismatch', 'credential_unavailable', 'ssh_banner_unavailable')
                    failures_key = (server_id, 'failures_' + kind)
                    if retry:
                        attempt = schedule.get(failures_key, 0) + 1
                        schedule[failures_key] = attempt
                        schedule[key] = done + min(300, 30 * (2 ** min(attempt - 1, 4)))
                    else:
                        schedule[failures_key] = 0
                        schedule[key] = done + (session_delay(result) if kind == 'sessions' else period)
            if single_cycle:
                break
            time.sleep(2)
    finally:
        stop.set()
        if heartbeat_thread is not None: heartbeat_thread.join(timeout=2)
        lock.close()


if __name__ == '__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--once', action='store_true', help='one approved collection cycle, then exit')
    args=ap.parse_args()
    run(single_cycle=args.once)
