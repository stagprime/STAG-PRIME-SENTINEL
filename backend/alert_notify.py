"""Local operator alerts for 24/7 monitoring (file + optional webhook).

Triggered when monitoring incidents open/close. Never blocks the worker loop.
"""
from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def _alert_dir() -> Path:
    home = os.environ.get('LOCALAPPDATA') or os.environ.get('HOME') or '.'
    path = Path(home) / 'StagPrimeSentinel' / 'alerts'
    path.mkdir(parents=True, exist_ok=True)
    return path


def _webhook_file() -> Path:
    return _alert_dir().parent / 'alert_webhook.url'


def webhook_url() -> str | None:
    env = os.environ.get('SENTINEL_ALERT_WEBHOOK', '').strip()
    if env:
        return env
    file = _webhook_file()
    if file.is_file():
        url = file.read_text(encoding='utf-8', errors='replace').strip()
        return url or None
    return None


def webhook_locked_by_env() -> bool:
    return bool(os.environ.get('SENTINEL_ALERT_WEBHOOK', '').strip())


def validate_webhook_url(url: str) -> str:
    from urllib.parse import urlparse
    cleaned = (url or '').strip()
    if not cleaned or len(cleaned) > 500 or any(ch in cleaned for ch in '\r\n\t '):
        raise ValueError('Webhook URL must be a single https address')
    parsed = urlparse(cleaned)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Webhook URL must be https without embedded credentials')
    return cleaned


def set_webhook_url(url: str | None) -> None:
    """Persist or clear the operator webhook file. Env var always wins at send time."""
    file = _webhook_file()
    if not url:
        try:
            file.unlink(missing_ok=True)
        except OSError:
            pass
        return
    file.write_text(validate_webhook_url(url) + '\n', encoding='utf-8')


def webhook_status() -> dict:
    url = webhook_url()
    if not url:
        return {'configured': False, 'masked': None, 'source': None, 'locked_by_env': webhook_locked_by_env()}
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or 'configured'
    return {
        'configured': True,
        'masked': f'{parsed.scheme}://{host}/…',
        'source': 'environment' if webhook_locked_by_env() else 'file',
        'locked_by_env': webhook_locked_by_env(),
    }


def emit_alert(*, server_id: str, server_name: str, code: str, state: str, detail: str = '') -> None:
    """Append a JSONL alert and best-effort POST to webhook."""
    now = datetime.now(timezone.utc).isoformat()
    record = {
        'at_utc': now,
        'server_id': server_id,
        'server_name': server_name,
        'code': code,
        'state': state,
        'detail': detail[:500],
    }
    try:
        day = datetime.now(timezone.utc).strftime('%Y%m%d')
        path = _alert_dir() / f'alerts-{day}.jsonl'
        with path.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(record, separators=(',', ':')) + '\n')
    except OSError:
        pass
    url = webhook_url()
    if not url or state != 'open':
        return
    try:
        body = json.dumps({
            'text': f'Sentinel alert: {server_name} · {code} · {state}',
            'alert': record,
        }).encode('utf-8')
        req = urllib.request.Request(
            url, data=body, method='POST',
            headers={'Content-Type': 'application/json', 'User-Agent': 'StagPrimeSentinel/1.0'},
        )
        urllib.request.urlopen(req, timeout=4).read(512)
    except Exception:
        pass


def recent_alerts(limit: int = 50) -> list[dict]:
    path = _alert_dir() / f"alerts-{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    out.reverse()
    return out
