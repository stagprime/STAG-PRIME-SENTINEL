"""Local-dev default SSH private key path (Windows operator convenience).

Stores only a filesystem path under LOCALAPPDATA — never the key bytes in the repo.
Used so operators can re-enroll from D:\\….ppk without re-browsing the file each time.
"""
from __future__ import annotations

import os
from pathlib import Path


def _config_dir() -> Path:
    home = os.environ.get('LOCALAPPDATA') or os.environ.get('HOME') or ''
    if not home:
        raise RuntimeError('LOCALAPPDATA/HOME not set')
    path = Path(home) / 'StagPrimeSentinel'
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_key_path_file() -> Path:
    return _config_dir() / 'default_ssh_private_key_path.txt'


def get_default_key_path() -> Path | None:
    file = default_key_path_file()
    if not file.is_file():
        return None
    raw = file.read_text(encoding='utf-8', errors='replace').strip().strip('"')
    if not raw:
        return None
    return Path(raw)


def set_default_key_path(path: str | Path) -> Path:
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise FileNotFoundError(f'Key file not found: {resolved}')
    # Refuse obvious public keys by extension only; content checked at enroll time.
    if resolved.suffix.lower() == '.pub':
        raise ValueError('Refusing to save a .pub public key path as the default private key')
    default_key_path_file().write_text(str(resolved.resolve()), encoding='utf-8')
    return resolved.resolve()


def describe_default_key() -> dict:
    path = get_default_key_path()
    if path is None:
        return {'configured': False, 'path': None, 'exists': False, 'size_bytes': None}
    exists = path.is_file()
    return {
        'configured': True,
        'path': str(path),
        'exists': exists,
        'size_bytes': path.stat().st_size if exists else None,
    }
