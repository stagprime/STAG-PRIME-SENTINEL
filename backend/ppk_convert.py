"""Convert PuTTY .ppk (v2 and v3) private keys to OpenSSH private key text.

Uses puttykeys for classic v2 when possible; implements v3 (incl. ssh-ed25519)
for the common Encryption: none case. Encrypted v3 may use puttygen if installed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


def _is_ppk(text: str) -> bool:
    head = text.lstrip('\ufeff').lstrip()
    return (
        head.startswith('PuTTY-User-Key-File-2:')
        or head.startswith('PuTTY-User-Key-File-3:')
        or ('Private-MAC:' in text and 'Public-Lines:' in text and 'Private-Lines:' in text)
    )


def _parse_ppk_fields(ppkraw: str) -> dict[str, object]:
    lines = [l.strip() for l in ppkraw.strip().replace('\r\n', '\n').replace('\r', '\n').split('\n') if l.strip()]
    if not lines:
        raise ValueError('Empty PPK')
    header = lines[0]
    version = 2 if header.startswith('PuTTY-User-Key-File-2:') else 3 if header.startswith('PuTTY-User-Key-File-3:') else 0
    if version == 0:
        raise ValueError('Missing PuTTY-User-Key-File-2/3 header (re-upload the full .ppk file, not a partial paste)')
    keytype_hdr = header.split(':', 1)[1].strip().encode()
    fields: dict[str, object] = {'version': version, 'header_keytype': keytype_hdr}
    i = 1
    while i < len(lines):
        line = lines[i]
        if line.startswith('Encryption: '):
            fields['encryption'] = line[12:].strip()
        elif line.startswith('Comment: '):
            fields['comment'] = line[9:].encode()
        elif line.startswith('Public-Lines: '):
            n = int(line[14:])
            fields['pubbin'] = base64.b64decode(''.join(lines[i + 1:i + 1 + n]))
            i += n
        elif line.startswith('Private-Lines: '):
            n = int(line[15:])
            fields['privbin'] = base64.b64decode(''.join(lines[i + 1:i + 1 + n]))
            i += n
        elif line.startswith('Private-MAC: '):
            fields['mac'] = line[13:].strip()
        elif line.startswith('Key-Derivation:') or line.startswith('Argon2'):
            fields['encrypted_kdf'] = True
        i += 1
    if 'pubbin' not in fields or 'privbin' not in fields:
        raise ValueError('PPK missing Public-Lines or Private-Lines')
    return fields


def _openssh_ed25519(pubbin: bytes, privbin: bytes, comment: bytes) -> str:
    pubio = _Bin(pubbin)
    keytype = pubio.read_string()
    if keytype != b'ssh-ed25519':
        raise ValueError(f'Unsupported key type in public blob: {keytype!r}')
    pubval = pubio.read_string()
    privio = _Bin(privbin)
    prival = privio.read_string()
    pubopenssh = struct.pack('>I', len(keytype)) + keytype + struct.pack('>I', len(pubval)) + pubval
    lastpart = (
        struct.pack('>II', 1, 1) + pubopenssh
        + struct.pack('>I', len(prival) + len(pubval)) + prival + pubval
        + struct.pack('>I', len(comment)) + comment
    )
    pad = 8 - (len(lastpart) % 8)
    lastpart += bytes(range(1, pad + 1))
    complete = (
        b'openssh-key-v1\x00'
        + b'\x00\x00\x00\x04none'
        + b'\x00\x00\x00\x04none'
        + struct.pack('>III', 0, 1, len(pubopenssh))
        + pubopenssh
        + struct.pack('>I', len(lastpart))
        + lastpart
    )
    b64 = base64.b64encode(complete).decode()
    body = '\n'.join(b64[i:i + 70] for i in range(0, len(b64), 70))
    return f'-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n'


class _Bin:
    def __init__(self, data: bytes):
        self._data = data
        self._i = 0

    def read(self, n: int) -> bytes:
        out = self._data[self._i:self._i + n]
        if len(out) != n:
            raise ValueError('Truncated PPK binary field')
        self._i += n
        return out

    def read_string(self) -> bytes:
        (n,) = struct.unpack('>I', self.read(4))
        return self.read(n)


def _puttygen_convert(ppkraw: str, passphrase: str) -> str | None:
    puttygen = shutil.which('puttygen') or shutil.which('puttygen.exe')
    if not puttygen:
        # Common Windows install path when PATH was not refreshed.
        cand = Path(r'C:\Program Files\PuTTY\puttygen.exe')
        puttygen = str(cand) if cand.is_file() else None
    if not puttygen:
        return None
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / 'key.ppk'
        dst = Path(tmp) / 'key_openssh'
        passfile = Path(tmp) / 'oldpass.txt'
        src.write_text(ppkraw, encoding='utf-8')
        # Always feed passphrase via file so puttygen never blocks on console prompt.
        passfile.write_text(passphrase or '', encoding='utf-8')
        cmd = [
            puttygen, str(src),
            '-O', 'private-openssh',
            '-o', str(dst),
            '--old-passphrase', str(passfile),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0 or not dst.is_file():
            return None
        out = dst.read_text(encoding='utf-8', errors='replace').strip()
        if 'BEGIN' in out and 'PRIVATE KEY' in out:
            return out + '\n'
    return None


def ppk_to_openssh(ppkraw: str, passphrase: str = '') -> str:
    """Return OpenSSH private key text, or raise ValueError with operator-facing reason."""
    text = ppkraw.replace('\r\n', '\n').replace('\r', '\n').strip().lstrip('\ufeff')
    if not _is_ppk(text):
        raise ValueError('Not a PuTTY private key (.ppk)')

    # Classic v2 via puttykeys when header matches (fast, no external binary).
    if text.lstrip().startswith('PuTTY-User-Key-File-2:'):
        try:
            from puttykeys import ppkraw_to_openssh
            out = ppkraw_to_openssh(text, passphrase or '')
            if isinstance(out, bytes):
                out = out.decode('utf-8')
            if out and 'PRIVATE KEY' in out:
                return out if out.endswith('\n') else out + '\n'
        except Exception as exc:
            # Fall through to puttygen / native v3 path.
            v2_err = exc
        else:
            v2_err = None
    else:
        v2_err = None

    # Native unencrypted v3 (incl. ssh-ed25519) — no puttygen required.
    try:
        fields = _parse_ppk_fields(text)
    except ValueError:
        fields = None

    if fields is not None:
        encryption = str(fields.get('encryption') or 'none').lower()
        if encryption in ('none', '') and not fields.get('encrypted_kdf'):
            pubbin = fields['pubbin']
            privbin = fields['privbin']
            comment = fields.get('comment') or b''
            assert isinstance(pubbin, bytes) and isinstance(privbin, bytes) and isinstance(comment, bytes)
            pubio = _Bin(pubbin)
            keytype = pubio.read_string()
            if keytype == b'ssh-ed25519':
                return _openssh_ed25519(pubbin, privbin, comment)
            if keytype == b'ssh-rsa' and text.lstrip().startswith('PuTTY-User-Key-File-3:'):
                rewritten = text.replace('PuTTY-User-Key-File-3:', 'PuTTY-User-Key-File-2:', 1)
                try:
                    from puttykeys import ppkraw_to_openssh
                    out = ppkraw_to_openssh(rewritten, '')
                    if isinstance(out, bytes):
                        out = out.decode('utf-8')
                    if out and 'PRIVATE KEY' in out:
                        return out if out.endswith('\n') else out + '\n'
                except Exception:
                    pass

    # Encrypted / remaining formats: puttygen when installed.
    via_cli = _puttygen_convert(text, passphrase)
    if via_cli:
        return via_cli

    if fields is not None:
        encryption = str(fields.get('encryption') or 'none').lower()
        if encryption not in ('none', '') or fields.get('encrypted_kdf'):
            raise ValueError(
                'This .ppk is encrypted. Enter the PuTTY passphrase, or export '
                'OpenSSH key from PuTTYgen → Conversions → Export OpenSSH key.'
            )
        pubio = _Bin(fields['pubbin'])  # type: ignore[arg-type]
        keytype = pubio.read_string()
        raise ValueError(
            f'Unsupported PPK key type {keytype!r}. Export OpenSSH key with PuTTYgen.'
        )

    if v2_err is not None:
        raise ValueError(f'PPK v2 conversion failed: {type(v2_err).__name__}') from v2_err
    raise ValueError(
        'Could not convert this .ppk. Re-upload the full private key file, or export OpenSSH from PuTTYgen.'
    )
