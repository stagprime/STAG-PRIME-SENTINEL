"""Step 38.1 auth-only endpoints. Existing inventory APIs are NOT protected yet.

For now, ONLY loopback development. Never publish this service before the
follow-up integration enforces auth on *every* inventory/health/onboarding API.
"""
from datetime import timezone
import hashlib
import hmac
import os
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Response, Request, Cookie
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth_models import AuthClientGrant, AuthUser
from backend.auth_security import authenticate, create_session, lookup_session, revoke_session, SESSION_HOURS
from backend.database import Client, SessionLocal

router = APIRouter(prefix="/api/auth", tags=["Authentication (development foundation)"])


def auth_database():
    with SessionLocal() as db:
        yield db


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=128)


# Step 38.4.6 — HttpOnly browser sessions. Legacy Bearer endpoints remain
# for existing CLI/integration clients; new browser login never returns a bearer.
SESSION_COOKIE = "sentinel_session"
CSRF_HEADER = "x-sentinel-csrf"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
DEV_ORIGINS = {
    "http://localhost:5173", "http://127.0.0.1:5173",
    "http://localhost:8000", "http://127.0.0.1:8000",
}


def _csrf_for_token(token: str) -> str:
    """Synchronizer token bound to the unguessable bearer; not stored in DB."""
    return hmac.new(token.encode('utf-8'), b'sentinel-browser-csrf-v1', hashlib.sha256).hexdigest()


def origin_matches_request_host(request: Request) -> bool:
    """True when the browser Origin is this same site (production host or local proxy)."""
    origin = request.headers.get('origin', '').rstrip('/')
    if not origin:
        return False
    parsed = urlsplit(origin)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return False
    forwarded = request.headers.get('x-forwarded-host', '')
    host = (forwarded.split(',')[0].strip() or request.headers.get('host', '')).strip()
    return bool(host) and parsed.netloc.lower() == host.lower()


def _allowed_browser_origin(request: Request) -> bool:
    """Prevent login CSRF. Same-site hosts and explicit local/configured origins only."""
    origin = request.headers.get('origin', '').rstrip('/')
    if not origin:
        return False
    parsed = urlsplit(origin)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        return False
    if origin_matches_request_host(request):
        return True
    allowed = DEV_ORIGINS | {x.strip().rstrip('/') for x in os.environ.get('SENTINEL_ALLOWED_ORIGINS', '').split(',') if x.strip()}
    return origin in allowed


def _set_browser_cookie(response: Response, request: Request, token: str) -> None:
    # Localhost uses HTTP. HTTPS deployments, including Vercel's forwarded proto, use Secure.
    forwarded = request.headers.get('x-forwarded-proto', '').split(',')[0].strip().lower()
    secure = (
        request.url.scheme == 'https'
        or forwarded == 'https'
        or os.environ.get('SENTINEL_COOKIE_SECURE') == '1'
    )
    response.set_cookie(
        key=SESSION_COOKIE, value=token, httponly=True,
        secure=secure, samesite='strict', path='/api',
        max_age=SESSION_HOURS * 3600,
    )


def require_current_session(
    request: Request,
    authorization: str | None = Header(default=None),
    browser_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    db: Session = Depends(auth_database),
):
    # Explicit Bearer authorization is supported for existing non-browser API
    # clients; it cannot be sent automatically cross-site like a Cookie.
    if authorization is not None:
        scheme, sep, token = authorization.partition(' ')
        if not sep or scheme.lower() != 'bearer':
            raise HTTPException(status_code=401, detail='Authentication required')
        token = token.strip()
        using_cookie = False
    elif browser_cookie:
        token = browser_cookie
        using_cookie = True
    else:
        raise HTTPException(status_code=401, detail='Authentication required')

    result = lookup_session(db, token)
    if not result:
        raise HTTPException(status_code=401, detail='Session expired or invalid')
    if using_cookie and request.method.upper() in UNSAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, '')
        if not hmac.compare_digest(supplied, _csrf_for_token(token)):
            raise HTTPException(status_code=403, detail='CSRF verification failed')
    return result


def safe_user_data(user: AuthUser) -> dict:
    return {
        "id": user.id, "username": user.username,
        "display_name": user.display_name,
        "role": user.role, "client_id": user.client_id,
    }


@router.post("/login")
def login(data: LoginPayload, response: Response, db: Session = Depends(auth_database)):
    response.headers["Cache-Control"] = "no-store"
    user = authenticate(db, data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
    token, session = create_session(db, user)
    return {
        "token_type": "bearer", "access_token": token,
        "expires_at_utc": session.expires_at_utc.replace(tzinfo=timezone.utc).isoformat(),
        "user": safe_user_data(user),
    }


@router.get("/me")
def me(response: Response, current=Depends(require_current_session)):
    response.headers["Cache-Control"] = "no-store"
    user, _ = current
    return safe_user_data(user)


@router.post("/logout")
def logout(response: Response, current=Depends(require_current_session), db: Session = Depends(auth_database)):
    response.headers["Cache-Control"] = "no-store"
    _, session = current
    revoke_session(db, session)
    return {"message": "Signed out"}


@router.get("/clients")
def permitted_clients(response: Response, current=Depends(require_current_session), db: Session = Depends(auth_database)):
    """Proof of server-side role/client scoping; not a replacement for API guards."""
    response.headers["Cache-Control"] = "no-store"
    user, _ = current
    if user.role in ("admin", "viewer"):
        query = select(Client.id, Client.name).order_by(Client.name)
    elif user.role == "staff":
        query = (select(Client.id, Client.name)
                 .join(AuthClientGrant, AuthClientGrant.client_id == Client.id)
                 .where(AuthClientGrant.user_id == user.id).order_by(Client.name))
    elif user.role == "client":
        query = select(Client.id, Client.name).where(Client.id == user.client_id)
    else:
        raise HTTPException(status_code=403, detail="Client access denied")
    return {"clients": [{"id": cid, "name": name} for cid, name in db.execute(query).all()]}


@router.post('/login-cookie')
def browser_login(data: LoginPayload, response: Response, request: Request,
                  db: Session = Depends(auth_database)):
    """Secure browser-specific login; never exposes opaque session bearer."""
    response.headers['Cache-Control'] = 'no-store'
    if not _allowed_browser_origin(request):
        raise HTTPException(status_code=403, detail='Browser origin not permitted')
    user = authenticate(db, data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token, session = create_session(db, user)
    _set_browser_cookie(response, request, token)
    return {
        'user': safe_user_data(user),
        'csrf_token': _csrf_for_token(token),
        'expires_at_utc': session.expires_at_utc.replace(tzinfo=timezone.utc).isoformat(),
    }


@router.get('/session')
def browser_session(request: Request, response: Response,
                    browser_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE),
                    db: Session = Depends(auth_database)):
    """Restore browser UI state on refresh. No credentials or bearer returned."""
    response.headers['Cache-Control'] = 'no-store'
    result = lookup_session(db, browser_cookie or '')
    if not result:
        raise HTTPException(status_code=401, detail='Session expired or invalid')
    user, session = result
    return {
        'user': safe_user_data(user),
        'csrf_token': _csrf_for_token(browser_cookie),
        'expires_at_utc': session.expires_at_utc.replace(tzinfo=timezone.utc).isoformat(),
    }


@router.post('/logout-cookie')
def browser_logout(response: Response, request: Request,
                   browser_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE),
                   db: Session = Depends(auth_database)):
    """Revoke current browser session and remove the HttpOnly cookie."""
    response.headers['Cache-Control'] = 'no-store'
    if not browser_cookie:
        response.delete_cookie(SESSION_COOKIE, path='/api', samesite='strict')
        return {'message': 'Signed out'}
    result = lookup_session(db, browser_cookie)
    if result:
        supplied = request.headers.get(CSRF_HEADER, '')
        if not hmac.compare_digest(supplied, _csrf_for_token(browser_cookie)):
            raise HTTPException(status_code=403, detail='CSRF verification failed')
        _, session = result
        revoke_session(db, session)
    # A revoked/expired session can safely clear a stale cookie as well.
    response.delete_cookie(SESSION_COOKIE, path='/api', samesite='strict')
    return {'message': 'Signed out'}
