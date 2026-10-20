r"""Stag Prime Sentinel — local development supervisor (no remote deployment).

From project root:
  .\.venv\Scripts\python.exe Sentinel_Start_Local_All.py

Starts (or reuses trusted) FastAPI + Vite and a single read-only monitoring worker.
Does not create credentials, enroll servers, or modify any remote VPS.
Ctrl+C stops only processes this supervisor spawned.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen as stdlib_urlopen

# Patchable for unit tests
urlopen = stdlib_urlopen

API_PORT = 8000
FRONTEND_PORT = 5173
API_HEALTH = f'http://127.0.0.1:{API_PORT}/api/health'
FRONTEND_URL = f'http://127.0.0.1:{FRONTEND_PORT}/'
EXPECTED_SERVICE = 'sentinel-backend'


def commands(root: Path) -> dict[str, tuple[list[str], Path]]:
    venv_python = root / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    if not venv_python.is_file():
        raise RuntimeError('Project virtual environment Python was not found')
    if not (root / 'backend/main.py').is_file() or not (root / 'frontend/package.json').is_file():
        raise RuntimeError('Run from StagPrimeSentinel project root')
    if not (root / 'frontend/node_modules').is_dir():
        raise RuntimeError('Frontend dependencies not installed. Run npm ci in frontend first')
    npm = _which_npm()
    if not npm:
        raise RuntimeError('Node/npm was not found')
    py = str(venv_python)
    return {
        'FastAPI': (
            [py, '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', str(API_PORT)],
            root,
        ),
        'Frontend': (
            [npm, 'run', 'dev', '--', '--host', '127.0.0.1', '--port', str(FRONTEND_PORT)],
            root / 'frontend',
        ),
        'Read-only monitoring worker': (
            [py, '-m', 'backend.monitoring_worker'],
            root,
        ),
    }


def _which_npm() -> str | None:
    import shutil
    return shutil.which('npm.cmd' if os.name == 'nt' else 'npm') or shutil.which('npm')


def localhost_port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        return sock.connect_ex(('127.0.0.1', port)) == 0


def trusted_existing_api() -> bool:
    try:
        req = Request(API_HEALTH, headers={'Accept': 'application/json'})
        with urlopen(req, timeout=2.0) as resp:
            if getattr(resp, 'status', 200) != 200:
                return False
            raw = resp.read(4096)
        data = json.loads(raw.decode('utf-8', errors='replace'))
        return isinstance(data, dict) and data.get('service') == EXPECTED_SERVICE and data.get('status') == 'healthy'
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError, TypeError):
        return False


def trusted_existing_frontend() -> bool:
    try:
        req = Request(FRONTEND_URL, headers={'Accept': 'text/html'})
        with urlopen(req, timeout=2.0) as resp:
            if getattr(resp, 'status', 200) != 200:
                return False
            raw = resp.read(8192).decode('utf-8', errors='replace').lower()
        # Vite index typically includes the app root markup / vite client.
        return '<div id="root"' in raw or '/@vite/client' in raw or 'vite' in raw
    except (URLError, TimeoutError, OSError, ValueError, TypeError):
        return False


def worker_lock_held(root: Path) -> bool:
    """True only when another live process holds the Windows/POSIX exclusive lock."""
    path = root / 'data' / 'monitoring-worker.lock'
    if not path.is_file():
        return False
    try:
        with path.open('a+b') as handle:
            if os.name == 'nt':
                import msvcrt
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    return True
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
                return False
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return True
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            return False
    except OSError:
        return False


def spawn(label: str, argv: list[str], cwd: Path):
    kwargs: dict = {'cwd': str(cwd)}
    if os.name == 'nt':
        kwargs['creationflags'] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True
    proc = subprocess.Popen(argv, **kwargs)
    print(f'STARTED {label} pid={proc.pid}', flush=True)
    return proc


def stop_owned(label: str, proc) -> None:
    if proc is None or proc.poll() is not None:
        return
    print(f'STOPPING {label} pid={proc.pid}', flush=True)
    try:
        if os.name == 'nt':
            subprocess.run(
                ['taskkill', '/PID', str(proc.pid), '/T', '/F'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=12,
            )
        else:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                proc.terminate()
    except (OSError, subprocess.TimeoutExpired):
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=8)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass


def run(root: Path, *, check_only: bool = False, watch: bool = True, sleep=time.sleep) -> None:
    services = commands(root)
    if check_only:
        print('LOCAL STARTER CHECK PASS — 3 services configured; no process or SSH connection started')
        return

    owned: list[tuple[str, object]] = []
    try:
        api_up = localhost_port_open(API_PORT)
        fe_up = localhost_port_open(FRONTEND_PORT)

        if api_up and not trusted_existing_api():
            raise RuntimeError(
                f'Port {API_PORT} is occupied by an unrecognized/unhealthy backend. '
                'Stop it, then re-run this launcher.'
            )

        if not api_up:
            label = 'FastAPI'
            argv, cwd = services[label]
            owned.append((label, spawn(label, argv, cwd)))
            # Brief wait so health can come up for subsequent checks in watch mode.
            sleep(1.2)

        if fe_up and not trusted_existing_frontend():
            # Fail closed: if we already started FastAPI in this run, stop it.
            raise RuntimeError(
                f'Port {FRONTEND_PORT} is occupied by an unrecognized frontend. '
                'Stop it, then re-run this launcher.'
            )

        if not fe_up:
            label = 'Frontend'
            argv, cwd = services[label]
            owned.append((label, spawn(label, argv, cwd)))

        if worker_lock_held(root):
            print('Monitoring worker already locked by another process — not starting a duplicate.', flush=True)
        else:
            label = 'Read-only monitoring worker'
            argv, cwd = services[label]
            owned.append((label, spawn(label, argv, cwd)))

        print(f'Web UI: {FRONTEND_URL}  API docs: http://127.0.0.1:{API_PORT}/docs', flush=True)
        print('Keep this terminal open. Ctrl+C stops owned child processes only.', flush=True)

        if not watch:
            return

        worker_restarts = 0
        while True:
            for label, proc in list(owned):
                code = proc.poll()
                if code is None:
                    continue
                if label == 'Read-only monitoring worker' and worker_restarts < 1 and not worker_lock_held(root):
                    print(f'{label} exited ({code}); bounded restart in 5s…', flush=True)
                    stop_owned(label, proc)
                    owned = [(l, p) for l, p in owned if l != label]
                    sleep(5)
                    argv, cwd = services[label]
                    owned.append((label, spawn(label, argv, cwd)))
                    worker_restarts += 1
                    continue
                raise RuntimeError(f'{label} stopped unexpectedly (exit {code})')
            sleep(2)
    except KeyboardInterrupt:
        print('\nStopping owned Sentinel services…', flush=True)
    finally:
        for label, proc in reversed(owned):
            stop_owned(label, proc)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start Stag Prime Sentinel locally')
    parser.add_argument('--check', action='store_true', help='validate setup without starting processes')
    parser.add_argument('--no-watch', action='store_true', help='start once and exit (owned processes keep running)')
    args = parser.parse_args()
    try:
        run(Path(__file__).resolve().parent, check_only=args.check, watch=not args.no_watch)
    except Exception as exc:
        print('LOCAL STARTER FAILED:', exc, file=sys.stderr)
        sys.exit(1)
