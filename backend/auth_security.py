"""Standard-library PBKDF2 password hashing and opaque server-side sessions.

No JWT signing secret, static admin credentials, or browser-local auth storage.
PBKDF2-HMAC-SHA256 (600,000 rounds) is a portable fallback; plan Argon2id
and mandatory HTTPS in production before public exposure.
"""
import base64
import hashlib
import hmac
import re
import secrets
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth_models import AuthClientGrant, AuthSession, AuthUser, utcnow

ROLES = {"admin", "staff", "client", "viewer"}
PBKDF2_ITERATIONS = 600_000
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_HOURS = 8
USERNAME_RE = re.compile(r"^[a-z][a-z0-9._-]{2,79}$")
# A fixed dummy hash avoids skipping the expensive hash work for unknown users.
_DUMMY_HASH = None


def normalize_username(username: str) -> str:
    name = username.strip().lower()
    if not USERNAME_RE.fullmatch(name):
        raise ValueError("Username must be 3-80 lower-case letters, numbers, dots, hyphens or underscores; start with a letter")
    return name


def validate_password(password: str, username: str | None = None) -> None:
    if not isinstance(password, str) or not (14 <= len(password) <= 128):
        raise ValueError("Password must be 14-128 characters")
    if username and username.lower() in password.lower():
        raise ValueError("Password must not contain the username")
    if len(set(password)) < 7:
        raise ValueError("Password needs greater character variety")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    s = base64.urlsafe_b64encode(salt).decode("ascii")
    h = base64.urlsafe_b64encode(key).decode("ascii")
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${s}${h}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations_raw, salt_encoded, expected_encoded = encoded.split("$")
        iterations = int(iterations_raw)
        if algorithm != "pbkdf2_sha256" or iterations != PBKDF2_ITERATIONS:
            return False
        salt = base64.urlsafe_b64decode(salt_encoded)
        expected = base64.urlsafe_b64decode(expected_encoded)
        if len(salt) != 16 or len(expected) != 32:
            return False
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(derived, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


def safe_verify_password(password: str, encoded: str | None) -> bool:
    global _DUMMY_HASH
    if encoded:
        return verify_password(password, encoded)
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("not-a-real-sentinel-user-placeholder")
    verify_password(password, _DUMMY_HASH)
    return False


def authenticate(db: Session, username: str, password: str) -> AuthUser | None:
    """Account-level lockout. Do not report whether a username exists."""
    now = utcnow()
    name = username.strip().lower()
    if not USERNAME_RE.fullmatch(name) or not password or len(password) > 1024:
        safe_verify_password("dummy", None)
        return None
    user = db.scalar(select(AuthUser).where(AuthUser.username == name))
    valid = safe_verify_password(password, user.password_hash if user else None)
    if user is None or not user.is_active:
        return None
    if user.locked_until_utc and user.locked_until_utc > now:
        return None
    if not valid:
        user.failed_login_count = (user.failed_login_count or 0) + 1
        if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
            user.locked_until_utc = now + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
        db.commit()
        return None
    user.failed_login_count = 0
    user.locked_until_utc = None
    db.commit()
    return user


def create_session(db: Session, user: AuthUser) -> tuple[str, AuthSession]:
    bearer = secrets.token_urlsafe(48)  # >= 256-bit entropy
    token_hash = hashlib.sha256(bearer.encode("ascii")).hexdigest()
    record = AuthSession(
        token_hash=token_hash, user_id=user.id,
        expires_at_utc=utcnow() + timedelta(hours=SESSION_HOURS),
    )
    db.add(record)
    db.commit()
    return bearer, record


def lookup_session(db: Session, token: str) -> tuple[AuthUser, AuthSession] | None:
    if not isinstance(token, str) or not (32 <= len(token) <= 256):
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    record = db.get(AuthSession, digest)
    if record is None or record.revoked_at_utc is not None or record.expires_at_utc <= utcnow():
        return None
    user = db.get(AuthUser, record.user_id)
    if user is None or not user.is_active or user.role not in ROLES:
        return None
    if user.role == "client" and not user.client_id:
        return None
    return user, record


def revoke_session(db: Session, record: AuthSession) -> None:
    record.revoked_at_utc = utcnow()
    db.commit()


def can_access_client(db: Session, user: AuthUser, client_id: str) -> bool:
    if not client_id or not user.is_active:
        return False
    if user.role in ("admin", "viewer"):
        return True
    if user.role == "client":
        return bool(user.client_id and user.client_id == client_id)
    if user.role == "staff":
        return db.get(AuthClientGrant, (user.id, client_id)) is not None
    return False


def require_client_access(db: Session, user: AuthUser, client_id: str) -> None:
    from fastapi import HTTPException
    if not can_access_client(db, user, client_id):
        raise HTTPException(status_code=403, detail="Client access denied")
