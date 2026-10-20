"""Step 40.9: persisted, synchronous, bounded READ-ONLY diagnostic job records.

No background worker, scheduler, sudo, arbitrary command, VPN or power operation.
An authenticated admin may run only the two fixed Step 40.7 diagnostics.
Job state, audit and sanitized numerical metrics survive request completion.
The execution stays synchronous intentionally; a future durable worker requires
separate crash, recovery, concurrency and deployment design.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import DateTime, ForeignKey, String, Text, inspect
from sqlalchemy.orm import Mapped, mapped_column

from backend.admin_access import ServerAdminAudit, ServerAdminProfile, _require_admin, _safe_profile
from backend.database import Base, Server, SessionLocal, engine
from backend.read_only_jobs import (
    DiagnosticName, _acquire, _release, _audit_registry_ready, _run_pinned_diagnostic,
)
from backend.ssh_monitor import SSHConnectionConfig


class ControlledDiagnosticJob(Base):
    __tablename__ = 'controlled_diagnostic_jobs'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    check_name: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    metrics_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


router = APIRouter(prefix='/api/server-operations', tags=['Read-only controlled job history'])


class CreateDiagnosticJob(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')
    check: DiagnosticName


def _utcnow():
    return datetime.now(timezone.utc)


def _ensure_job_table() -> None:
    # Additive schema change ONLY; never drop or rewrite existing tables.
    ControlledDiagnosticJob.__table__.create(bind=engine, checkfirst=True)


def _public_job(job: ControlledDiagnosticJob) -> dict:
    """Never return command, endpoint address, SSH paths, raw stdout or stderr."""
    def iso(dt):
        return (dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt).isoformat() if dt else None

    return {
        'job_id': job.id,
        'server_id': job.server_id,
        'check': job.check_name,
        'status': job.status,
        'started_at_utc': iso(job.started_at),
        'finished_at_utc': iso(job.finished_at),
        'metrics': json.loads(job.metrics_json) if job.status == 'succeeded' and job.metrics_json else None,
        'read_only': True,
        'remote_write_performed': False,
        'background_worker_enabled': False,
        'scheduling_enabled': False,
    }


@router.get('/jobs/catalog')
def jobs_catalog(admin=Depends(_require_admin)):
    return {
        'persisted_job_history': True,
        'execution_mode': 'synchronous_read_only',
        'background_worker_enabled': False,
        'scheduling_enabled': False,
        'power_control_enabled': False,
        'openvpn_control_enabled': False,
        'arbitrary_commands_enabled': False,
        'checks': [{'key': 'load_average', 'label': 'CPU load averages'},
                   {'key': 'memory_snapshot', 'label': 'Memory and swap summary'}],
    }


@router.post('/servers/{server_id}/jobs/read-only')
def create_read_only_job(server_id: str, request: CreateDiagnosticJob, admin=Depends(_require_admin)):
    if not _audit_registry_ready():
        raise HTTPException(status_code=503, detail='Administrative profile registry not initialized')

    # Validate approval and acquire the shared lock before inserting any job.
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None or server.archived_at is not None:
            raise HTTPException(status_code=404, detail='Server not found')
        profile = db.get(ServerAdminProfile, server_id)
        status = _safe_profile(server, profile)
        if not status['inventory_pinned']:
            raise HTTPException(status_code=409, detail='Administrative profile missing or inventory approval changed')
        if not status['verification_ready']:
            raise HTTPException(status_code=503, detail='Approved administrative profile files unavailable')

    if not _acquire(server_id):
        raise HTTPException(status_code=409, detail='Another diagnostic is running for this server')

    try:
        _ensure_job_table()
        job_id = str(uuid4())
        with SessionLocal() as db:
            # Re-check inventory at the action boundary; never accept new target params.
            server = db.get(Server, server_id)
            profile = db.get(ServerAdminProfile, server_id)
            if not server or server.archived_at is not None or not _safe_profile(server, profile)['verification_ready']:
                raise HTTPException(status_code=409, detail='Server approval changed; retry after review')
            config = SSHConnectionConfig(
                host=profile.approved_host, port=profile.approved_port,
                username=profile.approved_username, private_key_path=profile.private_key_path,
                known_hosts_path=profile.known_hosts_path,
            )
            job = ControlledDiagnosticJob(id=job_id, server_id=server_id,
                actor_id=admin.id, check_name=request.check, status='running', started_at=_utcnow())
            audit = ServerAdminAudit(server_id=server_id, actor_id=admin.id,
                operation='controlled_job:' + request.check, result='attempted')
            db.add_all([job, audit])
            db.commit()
            db.refresh(audit)
            audit_id = audit.id

        # Strictly the Step 40.7 fixed read-only engine; no sudo or command input.
        try:
            metrics = _run_pinned_diagnostic(config, request.check)
            outcome = 'succeeded'
        except Exception:
            # Log only a fixed failure status; never propagate remote stderr, key paths or secrets.
            metrics = None
            outcome = 'failed'

        with SessionLocal() as db:
            job = db.get(ControlledDiagnosticJob, job_id)
            audit = db.get(ServerAdminAudit, audit_id)
            job.status = outcome
            job.metrics_json = json.dumps(metrics, sort_keys=True, allow_nan=False) if metrics is not None else None
            job.finished_at = _utcnow()
            audit.result = 'job_' + outcome
            db.commit()
            result = _public_job(job)
        result['audit_recorded'] = True
        return result
    finally:
        _release(server_id)


@router.get('/jobs/{job_id}')
def get_controlled_job(job_id: str, admin=Depends(_require_admin)):
    # Protect against path abuse and normalize missing-job response.
    try:
        from uuid import UUID
        if str(UUID(job_id)) != job_id:
            raise ValueError('not canonical')
    except ValueError:
        raise HTTPException(status_code=404, detail='Job not found') from None
    if 'controlled_diagnostic_jobs' not in inspect(engine).get_table_names():
        raise HTTPException(status_code=404, detail='Job not found')
    with SessionLocal() as db:
        job = db.get(ControlledDiagnosticJob, job_id)
        if job is None:
            raise HTTPException(status_code=404, detail='Job not found')
        return _public_job(job)
