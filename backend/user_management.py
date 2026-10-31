"""Step 38.4: admin-only user management, client grants and security audit.

No remote SSH, OpenVPN, firewall or installation actions are performed here.
Run `python -m backend.user_management init-db` to create the additive audit table
before enabling this API. Existing user, client and server rows are preserved.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, ForeignKey, String, func, select, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from backend.auth_api import auth_database, require_current_session
from backend.auth_models import AuthClientGrant, AuthSession, AuthUser, utcnow, create_auth_tables
from backend.auth_security import hash_password, normalize_username, validate_password, verify_password
from backend.database import Base, Client, engine, DATA_DIR, BASE_DIR


class AuthAuditEvent(Base):
    """Append-only security event for account changes. NEVER store passwords or tokens."""
    __tablename__ = 'auth_audit_events'

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor_user_id: Mapped[str] = mapped_column(ForeignKey('auth_users.id'), nullable=False, index=True)
    target_user_id: Mapped[str] = mapped_column(ForeignKey('auth_users.id'), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    details_json: Mapped[str] = mapped_column(String(4000), nullable=False, default='{}')
    created_at_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


def initialize_user_management_db(bind=None) -> None:
    """Add auth + audit tables only. No ALTER/DROP and no inventory mutation."""
    target = bind or engine
    create_auth_tables(bind=target)
    Base.metadata.create_all(bind=target, tables=[AuthAuditEvent.__table__])


admin_router = APIRouter(prefix='/api/admin', tags=['User management (admin only)'])
account_router = APIRouter(prefix='/api/auth', tags=['Account security'])


def require_admin_session(current=Depends(require_current_session)) -> AuthUser:
    user, _ = current
    if user.role != 'admin' or not user.is_active:
        raise HTTPException(status_code=403, detail='Administrator role required')
    return user


def require_reader_session(current=Depends(require_current_session)) -> AuthUser:
    """Administrators and view accounts may read. Only administrators may change."""
    user, _ = current
    if user.role not in ('admin', 'viewer') or not user.is_active:
        raise HTTPException(status_code=403, detail='This view is limited to administrators and view accounts')
    return user


def no_cache(response: Response) -> None:
    response.headers['Cache-Control'] = 'no-store'


def _display_name(value: str) -> str:
    value = value.strip()
    if not 2 <= len(value) <= 120:
        raise HTTPException(status_code=422, detail='Display name must be 2-120 characters')
    return value


def _normalized_username(value: str) -> str:
    try:
        return normalize_username(value)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err)) from err


def _password_hash(password: str, username: str) -> str:
    try:
        validate_password(password, username)
    except ValueError as err:
        raise HTTPException(status_code=422, detail=str(err)) from err
    return hash_password(password)


def _client_exists(db: Session, client_id: str) -> bool:
    return db.get(Client, client_id) is not None


def _check_client(db: Session, client_id: str) -> None:
    if not _client_exists(db, client_id):
        raise HTTPException(status_code=422, detail='Unknown client_id; select an existing client')


def _check_grant_clients(db: Session, client_ids: list[str]) -> list[str]:
    if len(set(client_ids)) != len(client_ids):
        raise HTTPException(status_code=422, detail='Duplicate client IDs are not allowed')
    if client_ids:
        matched = set(db.scalars(select(Client.id).where(Client.id.in_(client_ids))).all())
        if matched != set(client_ids):
            raise HTTPException(status_code=422, detail='One or more client IDs do not exist')
    return client_ids


def _public_user(db: Session, user: AuthUser) -> dict:
    grant_ids = sorted(db.scalars(
        select(AuthClientGrant.client_id).where(AuthClientGrant.user_id == user.id)
    ).all()) if user.role == 'staff' else []
    return {
        'id': user.id,
        'username': user.username,
        'display_name': user.display_name,
        'role': user.role,
        'is_active': user.is_active,
        'client_id': user.client_id,
        'client_ids': grant_ids,
        'created_at_utc': user.created_at_utc.isoformat() + 'Z',
    }


def _user_or_404(db: Session, user_id: str) -> AuthUser:
    user = db.get(AuthUser, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail='User not found')
    return user


def _revoke_user_sessions(db: Session, user_id: str) -> None:
    sessions = db.scalars(select(AuthSession).where(
        AuthSession.user_id == user_id, AuthSession.revoked_at_utc.is_(None),
    )).all()
    timestamp = utcnow()
    for session in sessions:
        session.revoked_at_utc = timestamp


def _audit(db: Session, actor_id: str, target_id: str, action: str, details: dict | None = None) -> None:
    # Event details must be allowlisted metadata -- NEVER request bodies/passwords/tokens.
    db.add(AuthAuditEvent(
        actor_user_id=actor_id, target_user_id=target_id,
        action=action, details_json=json.dumps(details or {}, sort_keys=True),
    ))


def _require_last_admin_safe(db: Session, target: AuthUser, *, role: str, active: bool) -> None:
    if target.role == 'admin' and target.is_active and (role != 'admin' or not active):
        count = db.scalar(select(func.count(AuthUser.id)).where(
            AuthUser.role == 'admin', AuthUser.is_active.is_(True),
        )) or 0
        if count <= 1:
            raise HTTPException(status_code=409, detail='Cannot disable or demote the last active administrator')


def _commit(db: Session, *, duplicate_username: bool = False) -> None:
    try:
        db.commit()
    except IntegrityError as err:
        db.rollback()
        if duplicate_username:
            raise HTTPException(status_code=409, detail='Username is already in use') from err
        raise HTTPException(status_code=409, detail='Conflicting account update') from err


class CreateUserPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    username: str = Field(min_length=3, max_length=80)
    display_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=14, max_length=128)
    role: Literal['admin', 'staff', 'client', 'viewer']
    client_id: str | None = None
    client_ids: list[str] = Field(default_factory=list, max_length=1000)
    confirm_admin_access: bool = False


class UpdateUserPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    display_name: str | None = Field(default=None, max_length=120)
    role: Literal['admin', 'staff', 'client', 'viewer'] | None = None
    client_id: str | None = None
    is_active: bool | None = None
    confirm_admin_access: bool = False


class StaffGrantsPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    client_ids: list[str] = Field(max_length=1000)


class ResetPasswordPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    new_password: str = Field(min_length=14, max_length=128)


class ChangePasswordPayload(ResetPasswordPayload):
    current_password: str = Field(min_length=1, max_length=128)


class DeleteUserPayload(BaseModel):
    """Extra safeguards for irreversible account deletion."""
    model_config = ConfigDict(extra='forbid')
    confirm_username: str = Field(min_length=3, max_length=80)
    admin_password: str = Field(min_length=1, max_length=128)
    confirm_permanent_delete: bool = False


@admin_router.get('/clients')
def list_clients(response: Response, admin=Depends(require_reader_session), db: Session = Depends(auth_database)):
    """Complete client directory for role/grant assignment, including clients without servers.

    Admin-only. Never use display names as tenant authorization IDs.
    """
    no_cache(response)
    clients = db.scalars(select(Client).order_by(Client.name, Client.id)).all()
    return {'total': len(clients), 'clients': [
        {'id': client.id, 'name': client.name} for client in clients
    ]}


@admin_router.get('/users')
def list_users(response: Response, admin=Depends(require_reader_session), db: Session = Depends(auth_database)):
    no_cache(response)
    users = db.scalars(select(AuthUser).order_by(AuthUser.username)).all()
    return {'total': len(users), 'users': [_public_user(db, user) for user in users]}


@admin_router.get('/users/{user_id}')
def get_user(user_id: str, response: Response, admin=Depends(require_reader_session), db: Session = Depends(auth_database)):
    no_cache(response)
    return _public_user(db, _user_or_404(db, user_id))


@admin_router.post('/users', status_code=201)
def create_user(data: CreateUserPayload, response: Response, admin=Depends(require_admin_session), db: Session = Depends(auth_database)):
    no_cache(response)
    username = _normalized_username(data.username)
    display = _display_name(data.display_name)
    if db.scalar(select(AuthUser.id).where(AuthUser.username == username)):
        raise HTTPException(status_code=409, detail='Username is already in use')
    if data.role == 'admin':
        if not data.confirm_admin_access:
            raise HTTPException(status_code=422, detail='Explicit confirmation required to create an administrator')
        if data.client_id is not None or data.client_ids:
            raise HTTPException(status_code=422, detail='Administrators must not have client bindings')
    elif data.role == 'client':
        if not data.client_id:
            raise HTTPException(status_code=422, detail='A client account requires client_id')
        if data.client_ids:
            raise HTTPException(status_code=422, detail='Client users cannot receive staff grants')
        _check_client(db, data.client_id)
    elif data.role == 'viewer':
        if data.client_id is not None or data.client_ids:
            raise HTTPException(status_code=422, detail='View accounts must not have client bindings')
    else:
        if data.client_id is not None:
            raise HTTPException(status_code=422, detail='Staff access uses explicit client_ids only')
        _check_grant_clients(db, data.client_ids)
    user = AuthUser(
        username=username, display_name=display,
        password_hash=_password_hash(data.password, username), role=data.role,
        client_id=data.client_id if data.role == 'client' else None, is_active=True,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError as err:
        db.rollback()
        raise HTTPException(status_code=409, detail='Username is already in use') from err
    if data.role == 'staff':
        for cid in data.client_ids:
            db.add(AuthClientGrant(user_id=user.id, client_id=cid))
    _audit(db, admin.id, user.id, 'user_created', {'role': data.role, 'client_id': user.client_id, 'client_ids': data.client_ids if data.role == 'staff' else []})
    _commit(db, duplicate_username=True)
    return _public_user(db, user)


@admin_router.patch('/users/{user_id}')
def update_user(user_id: str, data: UpdateUserPayload, response: Response, admin=Depends(require_admin_session), db: Session = Depends(auth_database)):
    no_cache(response)
    target = _user_or_404(db, user_id)
    specified = data.model_fields_set
    if not (specified & {'display_name', 'role', 'client_id', 'is_active'}):
        raise HTTPException(status_code=422, detail='Specify an account field to update')
    for key in ('display_name', 'role', 'is_active'):
        if key in specified and getattr(data, key) is None:
            raise HTTPException(status_code=422, detail=f'{key} cannot be null')
    new_role = data.role if 'role' in specified else target.role
    new_active = data.is_active if 'is_active' in specified else target.is_active
    if target.id == admin.id and (new_role != 'admin' or not new_active):
        raise HTTPException(status_code=409, detail='Cannot disable or demote your own administrator account')
    if target.role != 'admin' and new_role == 'admin' and not data.confirm_admin_access:
        raise HTTPException(status_code=422, detail='Explicit confirmation required to promote an administrator')
    _require_last_admin_safe(db, target, role=new_role, active=new_active)
    client_id = data.client_id if 'client_id' in specified else target.client_id
    if new_role == 'client':
        if not client_id:
            raise HTTPException(status_code=422, detail='A client account requires client_id')
        _check_client(db, client_id)
    elif 'client_id' in specified and client_id is not None:
        raise HTTPException(status_code=422, detail='Only client-role users may have a client_id')
    else:
        client_id = None
    previous_role = target.role
    changes = []
    if 'display_name' in specified:
        target.display_name = _display_name(data.display_name)
        changes.append('display_name')
    if previous_role != new_role:
        changes.append('role')
    if target.client_id != client_id:
        changes.append('client_id')
    if target.is_active != new_active:
        changes.append('is_active')
    target.role = new_role
    target.is_active = new_active
    target.client_id = client_id
    if previous_role == 'staff' and new_role != 'staff':
        for grant in db.scalars(select(AuthClientGrant).where(AuthClientGrant.user_id == target.id)).all():
            db.delete(grant)
    if changes:
        _revoke_user_sessions(db, target.id)
        _audit(db, admin.id, target.id, 'user_updated', {'fields': changes, 'role': new_role, 'client_id': client_id, 'is_active': new_active})
    _commit(db)
    return _public_user(db, target)


@admin_router.delete('/users/{user_id}')
def permanently_delete_user(
    user_id: str, data: DeleteUserPayload, response: Response,
    admin=Depends(require_admin_session), db: Session = Depends(auth_database),
):
    """Irreversibly remove a disabled account and its credentials. No infrastructure changes.

    Because the existing audit table has non-null user FKs, historical events
    referring to the deleted user are removed to maintain referential integrity.
    A minimal actor-only deletion event remains (without username or credentials).
    Operators must retain backups per their security/retention policy.
    """
    no_cache(response)
    target = _user_or_404(db, user_id)
    if target.id == admin.id:
        raise HTTPException(status_code=409, detail='You cannot permanently delete your own administrator account')
    if target.is_active:
        raise HTTPException(status_code=409, detail='Disable this account before permanent deletion')
    if not data.confirm_permanent_delete or data.confirm_username != target.username:
        raise HTTPException(status_code=422, detail='Type the exact username and confirm permanent deletion')
    if not verify_password(data.admin_password, admin.password_hash):
        raise HTTPException(status_code=403, detail='Administrator password is incorrect')

    # Explicitly remove every reference before deleting the account; SQLite
    # installations with PRAGMA foreign_keys=ON must pass, too.
    for session in db.scalars(select(AuthSession).where(AuthSession.user_id == target.id)).all():
        db.delete(session)
    for grant in db.scalars(select(AuthClientGrant).where(AuthClientGrant.user_id == target.id)).all():
        db.delete(grant)
    audit_items = db.scalars(select(AuthAuditEvent).where(or_(
        AuthAuditEvent.actor_user_id == target.id, AuthAuditEvent.target_user_id == target.id,
    ))).all()
    for audit_item in audit_items:
        db.delete(audit_item)
    db.flush()
    removed_role = target.role
    db.delete(target)
    # The deletion event is associated with the *acting* administrator only,
    # rather than retaining an FK or personal details of the removed user.
    _audit(db, admin.id, admin.id, 'user_permanently_deleted', {
        'deleted_role': removed_role, 'purged_prior_audit_events': len(audit_items),
    })
    _commit(db)
    return {'message': 'Account permanently deleted; sessions and grants removed'}


@admin_router.put('/users/{user_id}/grants')
def replace_staff_grants(user_id: str, data: StaffGrantsPayload, response: Response, admin=Depends(require_admin_session), db: Session = Depends(auth_database)):
    no_cache(response)
    target = _user_or_404(db, user_id)
    if target.role != 'staff':
        raise HTTPException(status_code=409, detail='Client grants are available only to staff accounts')
    requested = set(_check_grant_clients(db, data.client_ids))
    previous = set(db.scalars(select(AuthClientGrant.client_id).where(AuthClientGrant.user_id == user_id)).all())
    if requested != previous:
        for grant in db.scalars(select(AuthClientGrant).where(AuthClientGrant.user_id == user_id)).all():
            db.delete(grant)
        db.flush()
        for cid in sorted(requested):
            db.add(AuthClientGrant(user_id=user_id, client_id=cid))
        _revoke_user_sessions(db, user_id)
        _audit(db, admin.id, user_id, 'staff_grants_replaced', {'client_ids': sorted(requested)})
        _commit(db)
    return _public_user(db, target)


@admin_router.post('/users/{user_id}/reset-password')
def reset_user_password(user_id: str, data: ResetPasswordPayload, response: Response, admin=Depends(require_admin_session), db: Session = Depends(auth_database)):
    no_cache(response)
    target = _user_or_404(db, user_id)
    if target.id == admin.id:
        raise HTTPException(status_code=409, detail='Use authenticated change-password for your own account')
    target.password_hash = _password_hash(data.new_password, target.username)
    target.failed_login_count = 0
    target.locked_until_utc = None
    _revoke_user_sessions(db, target.id)
    _audit(db, admin.id, target.id, 'password_reset')
    _commit(db)
    return {'message': 'Password updated; previous sessions revoked'}


@account_router.post('/change-password')
def change_own_password(data: ChangePasswordPayload, response: Response, current=Depends(require_current_session), db: Session = Depends(auth_database)):
    no_cache(response)
    user, _ = current
    target = _user_or_404(db, user.id)
    if not verify_password(data.current_password, target.password_hash):
        raise HTTPException(status_code=403, detail='Current password incorrect')
    if data.current_password == data.new_password:
        raise HTTPException(status_code=422, detail='New password must differ from the current password')
    target.password_hash = _password_hash(data.new_password, target.username)
    _revoke_user_sessions(db, target.id)
    _audit(db, target.id, target.id, 'password_changed')
    _commit(db)
    return {'message': 'Password updated. Sign in again.'}


@admin_router.get('/audit')
def get_admin_audit(response: Response, limit: int = 50, admin=Depends(require_reader_session), db: Session = Depends(auth_database)):
    no_cache(response)
    if not 1 <= limit <= 200:
        raise HTTPException(status_code=422, detail='Limit must be between 1 and 200')
    events = db.scalars(select(AuthAuditEvent).order_by(AuthAuditEvent.created_at_utc.desc(), AuthAuditEvent.id.desc()).limit(limit)).all()
    return {'events': [
        {'id': event.id, 'actor_user_id': event.actor_user_id, 'target_user_id': None if event.action == 'user_permanently_deleted' else event.target_user_id,
         'action': event.action, 'details': json.loads(event.details_json),
         'created_at_utc': event.created_at_utc.isoformat() + 'Z'}
        for event in events
    ]}


def backup_database() -> Path:
    """Online SQLite backup, not a raw copy of an open database."""
    source_path = DATA_DIR / 'sentinel.db'
    if not source_path.is_file():
        raise FileNotFoundError('Existing data/sentinel.db not found. Check project folder.')
    backups_dir = BASE_DIR / 'backups'
    backups_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    destination = backups_dir / f'sentinel-before-user-management-{stamp}.db'
    with sqlite3.connect(str(source_path)) as source:
        with sqlite3.connect(str(destination)) as target:
            source.backup(target)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description='Stag Prime Sentinel User Management database setup')
    parser.add_argument('action', choices=['init-db', 'backup-db'])
    args = parser.parse_args()
    try:
        if args.action == 'backup-db':
            print(f'SUCCESS: SQLite online backup saved to {backup_database()}')
            return 0
        if args.action == 'init-db':
            from backend.database import DATABASE_URL, is_postgres_url
            if is_postgres_url(DATABASE_URL):
                from backend.schema import ensure_schema
                ensure_schema()
                print('SUCCESS: Postgres schema verified/created.')
                return 0
            if not (DATA_DIR / 'sentinel.db').is_file():
                raise FileNotFoundError('Existing data/sentinel.db not found. Check project folder.')
            print(f'SAFETY BACKUP: {backup_database()}')
            initialize_user_management_db()
            print('SUCCESS: Authentication and audit tables verified/created (additive only).')
            print('Existing users, client/server inventory, passwords and SSH profiles preserved.')
            return 0
    except (OSError, sqlite3.Error) as err:
        print(f'STOP: {err}')
        return 1
    return 2


if __name__ == '__main__':
    sys.exit(main())
