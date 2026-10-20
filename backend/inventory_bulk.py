"""Step 45 inventory bulk actions. Database-only operations; NEVER access remote VPS.

Hard deletion is deliberately authenticated, transaction-scoped, explicit and
fail-closed when a new server-linked data table has not been reviewed.
Security audit history is retained as non-secret metadata.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, Integer, String, delete, inspect, select, text, bindparam
from sqlalchemy.orm import Mapped, mapped_column

from backend.admin_access import _require_admin
from backend.database import Base, Server, SessionLocal, engine

router = APIRouter(prefix='/api/inventory', tags=['Inventory bulk management'])


class InventoryRemovalAudit(Base):
    __tablename__ = 'inventory_removal_audit'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[str] = mapped_column(String(36), nullable=False)
    client_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    operation: Mapped[str] = mapped_column(String(32), nullable=False)
    happened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BulkIds(BaseModel):
    model_config = ConfigDict(extra='forbid')
    server_ids: list[str] = Field(min_length=1, max_length=50)


class BulkDelete(BulkIds):
    confirmation: str = Field(min_length=8, max_length=40)


# A newly introduced table with server_id is NOT silently deleted. Review it
# before adding its name to this explicit list. Historical security audit rows
# are intentionally retained and never used to resurrect an inventory server.
SERVER_CHILD_TABLES = frozenset({
    'server_monitoring_configs', 'server_admin_profiles',
    'server_admin_verifications', 'encrypted_ssh_credentials',
    'encrypted_openvpn_client_profiles', 'onboarding_scans',
    'controlled_diagnostic_jobs', 'fresh_setup_progress_events', 'fresh_setup_previews', 'fresh_setup_no_backup_waivers', 'reviewed_command_previews',
    'reviewed_command_runs', 'openvpn_setup_preflights',
    'sentinel_telemetry_samples', 'sentinel_monitor_states',
    'sentinel_monitor_incidents', 'sentinel_session_transitions',
    'sentinel_ssh_maintenance',
    'vpn_issued_clients',
})
RETAINED_AUDIT_TABLES = frozenset({'server_admin_audit', 'inventory_removal_audit', 'fresh_setup_runs', 'fresh_setup_recovery_evidence',
    'vpn_stage_previews', 'vpn_stage_runs', 'vpn_stage_events'})


def _ids(raw):
    if not raw or len(raw) > 50 or len(set(raw)) != len(raw):
        raise HTTPException(422, 'Select 1 to 50 distinct servers')
    try:
        return [str(UUID(item)) for item in raw]
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(422, 'Invalid inventory server ID') from None


def _load_exact(db, ids):
    servers = list(db.scalars(select(Server).where(Server.id.in_(ids))).all())
    if len(servers) != len(ids):
        raise HTTPException(404, 'One or more selected servers no longer exist; refresh inventory')
    return servers


def permanent_delete_records(db, ids: list[str], actor_id: str, *, table_names: set[str] | None = None):
    """Delete strictly reviewed server-owned rows in one DB transaction.

    The caller provides its own transaction; tests use isolated DBs. Keeps
    non-secret security audit rows by policy. No filesystem/remote changes.
    """
    servers = _load_exact(db, ids)
    tables = set(table_names) if table_names is not None else set(inspect(db.bind).get_table_names())
    # Look at actual schema, including installed extension tables; fail closed.
    inspector = inspect(db.bind)
    linked = {name for name in tables if name != 'servers'
              and any(c['name'] == 'server_id' for c in inspector.get_columns(name))}
    unknown = linked - SERVER_CHILD_TABLES - RETAINED_AUDIT_TABLES
    if unknown:
        raise HTTPException(
            409,
            'Unreviewed server-linked data exists; deletion blocked until upgraded '
            f'({", ".join(sorted(unknown))})',
        )
    # Refuse deletion while a privileged install may still be running remotely.
    if 'fresh_setup_runs' in tables:
        pending = db.execute(text(
            'SELECT 1 FROM fresh_setup_runs WHERE server_id IN :ids AND state = :status LIMIT 1'
        ).bindparams(bindparam('ids', expanding=True)), {'ids':ids, 'status':'attempted'}).first()
        if pending:
            raise HTTPException(409, 'An installation attempt is still in progress; review before deleting inventory')
    if 'vpn_stage_runs' in tables:
        inflight = db.execute(text(
            'SELECT 1 FROM vpn_stage_runs WHERE server_id IN :ids AND state IN :states LIMIT 1'
        ).bindparams(bindparam('ids', expanding=True), bindparam('states', expanding=True)), {'ids': ids, 'states':['running','unknown']}).first()
        if inflight:
            raise HTTPException(409,'Privileged VPN setup is running/uncertain; review before inventory deletion')
    if 'vpn_issued_clients' in tables:
        active_clients = db.execute(text(
            'SELECT 1 FROM vpn_issued_clients WHERE server_id IN :ids LIMIT 1'
        ).bindparams(bindparam('ids', expanding=True)), {'ids':ids}).first()
        if active_clients:
            raise HTTPException(409,'Issued VPN credentials exist; revoke/decommission remotely before inventory deletion')
    now = datetime.now(timezone.utc)
    InventoryRemovalAudit.__table__.create(bind=db.bind, checkfirst=True)
    for server in servers:
        db.add(InventoryRemovalAudit(server_id=server.id, client_id=server.client_id,
            actor_id=actor_id, operation='permanent_delete', happened_at=now))
    db.flush()
    # Table names are hardcoded and cannot originate from requests.
    for name in sorted(SERVER_CHILD_TABLES & tables):
        db.execute(text(f'DELETE FROM "{name}" WHERE server_id IN :ids')
                   .bindparams(bindparam('ids', expanding=True)), {'ids': ids})
    db.execute(delete(Server).where(Server.id.in_(ids)))
    return len(servers)


@router.post('/bulk/archive')
def bulk_archive(request: BulkIds, admin=Depends(_require_admin)):
    ids = _ids(request.server_ids)
    with SessionLocal.begin() as db:
        servers = _load_exact(db, ids)
        if any(server.archived_at is not None for server in servers):
            raise HTTPException(409, 'Selection contains an already archived server')
        now = datetime.now(timezone.utc)
        for server in servers: server.archived_at = now
    return {'archived': len(ids), 'remote_changes': False}


@router.post('/bulk/permanent-delete')
def bulk_permanent_delete(request: BulkDelete, admin=Depends(_require_admin)):
    ids = _ids(request.server_ids)
    if request.confirmation != f'DELETE {len(ids)} SERVERS':
        raise HTTPException(422, 'Type the exact confirmation shown in the dialog')
    with SessionLocal.begin() as db:
        deleted = permanent_delete_records(db, ids, admin.id)
    return {'deleted': deleted, 'remote_changes': False,
            'audit_retained': True, 'recoverable_from_application': False}
