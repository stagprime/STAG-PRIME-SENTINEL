
from datetime import datetime, timezone
import os
from pathlib import Path

from paramiko.ssh_exception import AuthenticationException, BadHostKeyException, SSHException

from fastapi import FastAPI, HTTPException, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, inspect

from backend.database import Client, Server, ServerMonitoringConfig, SessionLocal, engine
from backend.ssh_monitor import SSHConnectionConfig, collect_ssh_health
from backend.auth_api import router as auth_router, require_current_session
from backend.auth_security import can_access_client
from backend.auth_models import AuthClientGrant, AuthUser


app = FastAPI(
    title="Stag Prime Sentinel",
    description="Infrastructure and VPN Monitoring Platform by Stag Prime LLC",
    version="0.4.0",
)


# Step 38.3: session-protected inventory, health and onboarding APIs.
app.include_router(auth_router)

@app.exception_handler(RequestValidationError)
async def sanitize_credential_enrollment_errors(request, exc):
    # Default Pydantic errors can echo invalid inputs. Never reflect credentials.
    if (request.url.path.startswith('/api/server-operations/servers/') and
        (request.url.path.endswith('/credentials') or request.url.path.endswith('/openvpn-profiles'))):
        return JSONResponse(status_code=422, content={'detail': 'Invalid protected enrollment request'})
    return await request_validation_exception_handler(request, exc)


# Step 38.4: admin-managed users and protected self-service password changes.
# Existing SSH monitoring and inventory APIs are unchanged.
from backend.user_management import admin_router as user_admin_router, account_router as user_account_router
app.include_router(user_admin_router)
app.include_router(user_account_router)

@app.middleware("http")
async def prevent_api_response_caching(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


_VIEWER_SAFE_WRITES = {
    ('POST', '/api/auth/logout'),
    ('POST', '/api/auth/logout-cookie'),
    ('POST', '/api/geoip/lookup'),
}


def _signed_in_role(request) -> str | None:
    from backend.auth_security import lookup_session
    header = request.headers.get('authorization', '')
    token = header[7:].strip() if header.lower().startswith('bearer ') else request.cookies.get('sentinel_session')
    if not token:
        return None
    try:
        with SessionLocal() as db:
            found = lookup_session(db, token)
    except Exception:
        return None
    return found[0].role if found else None


@app.middleware('http')
async def viewer_cannot_change(request, call_next):
    """View accounts may open every read API. Writes stay administrator-only."""
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        path = request.url.path.rstrip('/') or '/'
        if (request.method, path) not in _VIEWER_SAFE_WRITES and _signed_in_role(request) == 'viewer':
            return JSONResponse(status_code=403, content={
                'detail': 'View accounts can look through every area but cannot add or change anything.',
            })
    return await call_next(request)



# Every server-scoped API checks permissions SERVER-SIDE. No frontend-only RBAC.
def require_admin(current=Depends(require_current_session)):
    user, _ = current
    if user.role != 'admin':
        raise HTTPException(status_code=403, detail='Administrator role required')
    return user


def scoped_client_ids(db, user: AuthUser):
    """None = admin sees all; [] = no grants. Client names are not authorization IDs."""
    if user.role in ('admin', 'viewer'):
        return None
    if user.role == 'client':
        return [user.client_id] if user.client_id else []
    if user.role == 'staff':
        return list(db.scalars(select(AuthClientGrant.client_id).where(AuthClientGrant.user_id == user.id)).all())
    return []


def require_visible_server(db, user, server):
    if not can_access_client(db, user, server.client_id):
        # Avoid confirming the existence of another client's server.
        raise HTTPException(status_code=404, detail='Server not found')

# ============================================================
# APPLICATION INFORMATION
# ============================================================

@app.get("/")
def home():
    return {
        "application": "Stag Prime Sentinel",
        "company": "Stag Prime LLC",
        "version": "0.4.0",
        "status": "running",
    }


# ============================================================
# BACKEND HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "sentinel-backend",
    }


# ============================================================
# ACTIVE SERVER INVENTORY
# ============================================================

@app.get("/api/servers")
def get_servers(current=Depends(require_current_session)):
    """Active inventory with monitoring enrollment flags for the inventory UI."""
    user, _ = current
    with SessionLocal() as db:
        allowed = scoped_client_ids(db, user)
        query = (select(Server, Client.name)
                 .join(Client, Server.client_id == Client.id)
                 .where(Server.archived_at.is_(None)))
        if allowed is not None:
            query = query.where(Server.client_id.in_(allowed))
        records = db.execute(query.order_by(Server.name)).all()

        servers = []
        enrolled = 0
        for server, client_name in records:
            cfg = db.get(ServerMonitoringConfig, server.id)
            monitoring_enabled = bool(
                cfg and cfg.enabled
                and cfg.approved_host == server.host
                and cfg.approved_ssh_port == (server.ssh_port or 22)
                and cfg.approved_ssh_username == (server.ssh_username or '')
            )
            if monitoring_enabled:
                enrolled += 1
            servers.append({
                "id": server.id,
                "name": server.name,
                "country": server.country,
                "location": server.location,
                "provider": server.provider,
                "ip": server.host,
                "ssh_port": server.ssh_port,
                "ssh_username": server.ssh_username,
                "status": server.monitoring_status,
                "monitoring_enabled": monitoring_enabled,
                "vpn_service": cfg.vpn_service if cfg and monitoring_enabled else None,
                "client": client_name,
            })

        return {
            "total": len(servers),
            "monitoring_enrolled": enrolled,
            "not_enrolled": len(servers) - enrolled,
            "servers": servers,
        }


# ============================================================
# ADD NEW SERVER
# ============================================================

class ServerCreate(BaseModel):
    client_name: str = Field(min_length=2, max_length=150)
    name: str = Field(min_length=2, max_length=150)
    host: str = Field(min_length=3, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str | None = None
    country: str | None = None
    location: str | None = None
    provider: str | None = None


@app.post("/api/servers", status_code=201)
def create_server(data: ServerCreate, admin=Depends(require_admin)):
    with SessionLocal() as db:
        client_name = data.client_name.strip()
        server_name = data.name.strip()
        host = data.host.strip()

        if not client_name or not server_name or not host:
            raise HTTPException(
                status_code=422,
                detail="Required fields cannot be blank",
            )

        client = db.scalar(
            select(Client).where(Client.name == client_name)
        )

        if client is None:
            client = Client(name=client_name)
            db.add(client)
            db.flush()

        existing = db.scalar(
            select(Server).where(
                Server.client_id == client.id,
                Server.name == server_name,
            )
        )

        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail="A server with this name already exists for this client",
            )

        server = Server(
            client_id=client.id,
            name=server_name,
            host=host,
            ssh_port=data.ssh_port,
            ssh_username=data.ssh_username,
            country=data.country,
            location=data.location,
            provider=data.provider,
            monitoring_status="not_connected",
        )

        db.add(server)
        db.commit()
        db.refresh(server)

        return {
            "message": "Server created successfully",
            "id": server.id,
            "name": server.name,
            "client": client_name,
            "status": server.monitoring_status,
        }


# ============================================================
# EDIT EXISTING SERVER
# ============================================================

class ServerUpdate(BaseModel):
    name: str | None = Field(
        default=None, min_length=2, max_length=150
    )
    host: str | None = Field(
        default=None, min_length=3, max_length=255
    )
    ssh_port: int | None = Field(
        default=None, ge=1, le=65535
    )
    ssh_username: str | None = Field(
        default=None, max_length=100
    )
    country: str | None = Field(
        default=None, max_length=100
    )
    location: str | None = Field(
        default=None, max_length=150
    )
    provider: str | None = Field(
        default=None, max_length=150
    )


@app.patch("/api/servers/{server_id}")
def update_server(server_id: str, data: ServerUpdate, admin=Depends(require_admin)):
    with SessionLocal() as db:
        server = db.get(Server, server_id)

        if server is None:
            raise HTTPException(
                status_code=404,
                detail="Server not found",
            )

        changes = data.model_dump(exclude_unset=True)

        for field in ("name", "host", "ssh_port"):
            if field in changes and changes[field] is None:
                raise HTTPException(
                    status_code=422,
                    detail=f"{field} cannot be null",
                )

        for field, value in changes.items():
            if isinstance(value, str):
                value = value.strip()

                if field in ("name", "host") and not value:
                    raise HTTPException(
                        status_code=422,
                        detail=f"{field} cannot be empty",
                    )

                changes[field] = value or None

        new_name = changes.get("name")

        if new_name is not None and new_name != server.name:
            duplicate = db.scalar(
                select(Server).where(
                    Server.client_id == server.client_id,
                    Server.name == new_name,
                    Server.id != server.id,
                )
            )

            if duplicate is not None:
                raise HTTPException(
                    status_code=409,
                    detail="Server name already exists for this client",
                )

        for field, value in changes.items():
            setattr(server, field, value)

        db.commit()
        db.refresh(server)

        return {
            "message": "Server updated successfully",
            "id": server.id,
            "name": server.name,
            "ip": server.host,
            "ssh_port": server.ssh_port,
            "ssh_username": server.ssh_username,
            "country": server.country,
            "location": server.location,
            "provider": server.provider,
            "status": server.monitoring_status,
        }


# ============================================================
# ARCHIVE SERVER
# ============================================================

@app.post("/api/servers/{server_id}/archive")
def archive_server(server_id: str, admin=Depends(require_admin)):
    with SessionLocal() as db:
        server = db.get(Server, server_id)

        if server is None:
            raise HTTPException(
                status_code=404,
                detail="Server not found",
            )

        if server.archived_at is not None:
            raise HTTPException(
                status_code=409,
                detail="Server is already archived",
            )

        server.archived_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(server)

        return {
            "message": "Server archived successfully",
            "id": server.id,
            "name": server.name,
            "archived": True,
            "archived_at": server.archived_at,
        }


# ============================================================
# RESTORE ARCHIVED SERVER
# ============================================================

@app.post("/api/servers/{server_id}/restore")
def restore_server(server_id: str, admin=Depends(require_admin)):
    with SessionLocal() as db:
        server = db.get(Server, server_id)

        if server is None:
            raise HTTPException(
                status_code=404,
                detail="Server not found",
            )

        if server.archived_at is None:
            raise HTTPException(
                status_code=409,
                detail="Server is not archived",
            )

        server.archived_at = None

        db.commit()
        db.refresh(server)

        return {
            "message": "Server restored successfully",
            "id": server.id,
            "name": server.name,
            "archived": False,
            "archived_at": None,
        }

@app.get("/api/servers/archived")
def get_archived_servers(current=Depends(require_current_session)):
    user, _ = current
    with SessionLocal() as db:
        allowed = scoped_client_ids(db, user)
        query = (select(Server, Client.name)
                 .join(Client, Server.client_id == Client.id)
                 .where(Server.archived_at.is_not(None)))
        if allowed is not None:
            query = query.where(Server.client_id.in_(allowed))
        records = db.execute(query.order_by(Server.archived_at.desc())).all()

        servers = [
            {
                "id": server.id,
                "name": server.name,
                "ip": server.host,
                "country": server.country,
                "location": server.location,
                "provider": server.provider,
                "client": client_name,
                "archived": True,
                "archived_at": server.archived_at.isoformat(),
            }
            for server, client_name in records
        ]

        return {
            "total": len(servers),
            "servers": servers,
        }

# ============================================================
# STEP 36.8 - DATABASE-DRIVEN MULTI-CLIENT / MULTI-SERVER HEALTH
# ============================================================
# Each monitored server has an explicitly approved row in
# server_monitoring_configs. No IP/server-name hardcoding.
# No unauthenticated HTTP endpoint for approving or changing SSH targets.
# Local-only backend.monitoring_setup CLI manages approvals until RBAC exists.
# Keep this development API bound ONLY to 127.0.0.1 (not public Internet).


def _monitoring_registry_exists() -> bool:
    return inspect(engine).has_table("server_monitoring_configs")


def _approved_monitor_settings(server: Server, target: ServerMonitoringConfig) -> list[str]:
    """Local readiness; verify database inventory still matches SSH approval."""
    missing = []
    if not target.enabled:
        missing.append("monitoring is disabled")
    if (
        server.host.strip() != target.approved_host
        or (server.ssh_username or "").strip() != target.approved_ssh_username
        or (server.ssh_port or 22) != target.approved_ssh_port
    ):
        missing.append("SSH inventory was modified; monitoring requires re-approval")
    if target.ssh_key_path and target.ssh_key_path.startswith('sentinel-vault:'):
        from backend.credential_vault import credential_ready
        if target.ssh_key_path != 'sentinel-vault:' + server.id or not credential_ready(server.id):
            missing.append("Pinned encrypted SSH credential is unavailable")
    elif not target.ssh_key_path or not Path(target.ssh_key_path).expanduser().is_file():
        missing.append("SSH private key is unavailable on backend computer")
    if target.known_hosts_path and not Path(target.known_hosts_path).expanduser().is_file():
        missing.append("SSH known_hosts file is unavailable on backend computer")
    if not all((target.vpn_service, target.vpn_interface, target.network_interface)):
        missing.append("VPN monitoring parameters missing")
    return missing


@app.get("/api/monitoring/targets")
def get_monitoring_targets_preflight(current=Depends(require_current_session)):
    user, _ = current
    """Discover ALL active servers, with safe local readiness (not live status).

    Never expose key paths or secrets. Returns inventory-only for unapproved
    servers; recording a server in inventory does NOT grant SSH access.
    """
    registry_exists = _monitoring_registry_exists()
    admin_registry_exists = inspect(engine).has_table('server_admin_profiles')
    with SessionLocal() as db:
        allowed = scoped_client_ids(db, user)
        query = (select(Server, Client.name)
                 .join(Client, Server.client_id == Client.id)
                 .where(Server.archived_at.is_(None)))
        if allowed is not None:
            query = query.where(Server.client_id.in_(allowed))
        rows = db.execute(query.order_by(Client.name, Server.name)).all()
        targets = []
        for server, client_name in rows:
            target = db.get(ServerMonitoringConfig, server.id) if registry_exists else None
            missing = _approved_monitor_settings(server, target) if target else [
                "monitoring profile has not been approved"
            ]
            targets.append({
                "server_id": server.id,
                "server_name": server.name,
                "client": client_name,
                "host": server.host,
                "monitoring_configured": target is not None,
                "monitoring_enabled": bool(target.enabled) if target else False,
                "local_configuration_ready": not missing,
                "missing_settings": missing,
                "remote_connection_verified": False,
            })
    return {"total": len(targets), "targets": targets}


@app.get("/api/servers/{server_id}/health")
def get_server_live_health(server_id: str, current=Depends(require_current_session)):
    user, _ = current
    """Read-only live SSH health for an explicitly approved inventory server.

    The approved SSH hostname, username and port are pinned. Inventory updates
    cannot redirect SSH without separate SSH approval.
    """
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise HTTPException(status_code=404, detail="Server not found")
        require_visible_server(db, user, server)
        if server.archived_at is not None:
            raise HTTPException(status_code=409, detail="Archived server cannot be monitored")
        if not _monitoring_registry_exists():
            raise HTTPException(status_code=503, detail="Monitoring registry not initialized")
        target = db.get(ServerMonitoringConfig, server_id)
        if target is None:
            raise HTTPException(
                status_code=409,
                detail="Monitoring is not approved for this server. Configure it locally first",
            )
        missing = _approved_monitor_settings(server, target)
        if missing:
            raise HTTPException(status_code=503, detail="Monitoring unavailable: " + "; ".join(missing))

        server_name = server.name
        host = target.approved_host
        ssh_username = target.approved_ssh_username
        ssh_port = target.approved_ssh_port
        ssh_key_path = target.ssh_key_path
        known_hosts_path = target.known_hosts_path
        vpn_service = target.vpn_service
        vpn_interface = target.vpn_interface
        network_interface = target.network_interface

    config = SSHConnectionConfig(
        host=host,
        username=ssh_username,
        port=ssh_port,
        private_key_path=ssh_key_path,
        known_hosts_path=known_hosts_path,
    )

    try:
        health = collect_ssh_health(
            config,
            vpn_service=vpn_service,
            vpn_interface=vpn_interface,
            network_interface=network_interface,
        )
    except BadHostKeyException as exc:
        raise HTTPException(status_code=502, detail="SSH host key verification failed") from exc
    except AuthenticationException as exc:
        raise HTTPException(status_code=502, detail="SSH authentication failed") from exc
    except SSHException as exc:
        raise HTTPException(status_code=502, detail="SSH connection or host-key trust failed") from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="SSH health check timed out") from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="SSH monitoring file unavailable") from exc
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=502, detail="SSH health collection failed") from exc

    return {
        "server_id": server_id,
        "server_name": server_name,
        "monitoring_source": "verified_ssh",
        **health,
    }

# Step 37.4: Read-only per-client/server onboarding preflight.
# Purely local inventory/approval assessment; no SSH, sudo or remote writes.
# Do not add a public remote provisioning endpoint before login/RBAC/audit controls.
from backend.onboarding_preflight import describe_onboarding
from backend.onboarding_probe import public_snapshot
from backend.onboarding_scan import public_scan
from backend.admin_access import ServerAdminProfile, _safe_profile, public_admin_verification
from backend.onboarding_planner import build_setup_plan


@app.get('/api/onboarding/preflight')
def get_onboarding_preflight(current=Depends(require_current_session)):
    user, _ = current
    registry_exists = _monitoring_registry_exists()
    admin_registry_exists = inspect(engine).has_table('server_admin_profiles')
    with SessionLocal() as db:
        allowed = scoped_client_ids(db, user)
        query = (select(Server, Client.name)
                 .join(Client, Server.client_id == Client.id)
                 .where(Server.archived_at.is_(None)))
        if allowed is not None:
            query = query.where(Server.client_id.in_(allowed))
        rows = db.execute(query.order_by(Client.name, Server.name)).all()
        entries = []
        for server, client_name in rows:
            profile = db.get(ServerMonitoringConfig, server.id) if registry_exists else None
            missing = _approved_monitor_settings(server, profile) if profile else [
                'monitoring profile has not been approved'
            ]
            # Admin-vault approval and monitoring enrollment are different workflows.
            # Use approved pinned ADMIN credentials for admin-only read-only scans.
            admin_profile = db.get(ServerAdminProfile, server.id) if admin_registry_exists else None
            admin_state = _safe_profile(server, admin_profile) if admin_profile else None
            admin_ready = bool(admin_state and admin_state['verification_ready'])
            entry = describe_onboarding(
                server_id=server.id,
                server_name=server.name,
                client=client_name,
                host=server.host,
                ssh_username=server.ssh_username,
                ssh_port=server.ssh_port or 22,
                monitoring_configured=profile is not None,
                monitoring_enabled=bool(profile.enabled) if profile else False,
                local_configuration_ready=not missing,
                missing_settings=missing,
                admin_profile_ready=admin_ready,
                admin_profile_present=bool(admin_profile),
            )
            # Cached, local-only report: this GET never contacts a VPS.
            observation = public_snapshot(server, profile)
            entry["discovery"] = observation
            # No remote SSH on GET. An audited administrator POST starts a scan.
            entry['scan_ready'] = bool(user.role == 'admin' and admin_ready)
            entry['admin_profile_enabled'] = bool(admin_state and admin_state['profile_enabled'])
            entry['onboarding_scan'] = public_scan(server, admin_profile) if admin_profile else None
            evidence = public_admin_verification(server, admin_profile) if admin_profile else None
            entry['admin_verification'] = evidence
            entry['checks']['remote_ssh_test_performed'] = bool(
                (evidence and evidence['state'] == 'success') or
                (entry['onboarding_scan'] and entry['onboarding_scan']['state'] == 'success') or
                (observation and observation['state'] == 'success'))
            entry['checks']['remote_openvpn_discovery_performed'] = bool(
                (entry['onboarding_scan'] and entry['onboarding_scan']['state'] == 'success') or
                (observation and observation['state'] == 'success'))
            # Run advisory planner only AFTER attaching modern scan evidence.
            entry["plan"] = build_setup_plan(entry)
            entries.append(entry)
    return {'total': len(entries), 'read_only': True, 'entries': entries}

# ============================================================
# STEP 39.1 - ON-DEMAND, READ-ONLY OPENVPN SESSION DETAILS
# ============================================================
# No automatic SSH polling or remote writes. Privacy: records include public
# IPs and usernames, and must always remain protected by session + tenant RBAC.
from backend.vpn_sessions import collect_live_vpn_sessions


@app.get('/api/servers/{server_id}/vpn-sessions')
def get_server_live_vpn_sessions(server_id: str, current=Depends(require_current_session)):
    user, _ = current
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise HTTPException(status_code=404, detail='Server not found')
        require_visible_server(db, user, server)
        if server.archived_at is not None:
            raise HTTPException(status_code=409, detail='Archived server cannot be monitored')
        if not _monitoring_registry_exists():
            raise HTTPException(status_code=503, detail='Monitoring registry not initialized')
        target = db.get(ServerMonitoringConfig, server_id)
        if target is None:
            raise HTTPException(status_code=409, detail='SSH monitoring is not approved for this server')
        missing = _approved_monitor_settings(server, target)
        if missing:
            raise HTTPException(status_code=503, detail='Monitoring profile is not ready')
        server_name = server.name
        vpn_service = target.vpn_service
        config = SSHConnectionConfig(
            host=target.approved_host,
            username=target.approved_ssh_username,
            port=target.approved_ssh_port,
            private_key_path=target.ssh_key_path,
            known_hosts_path=target.known_hosts_path,
        )
    try:
        result = collect_live_vpn_sessions(config, vpn_service=vpn_service)
    except BadHostKeyException as exc:
        raise HTTPException(status_code=502, detail='SSH host key verification failed') from exc
    except AuthenticationException as exc:
        raise HTTPException(status_code=502, detail='SSH authentication failed') from exc
    except SSHException as exc:
        raise HTTPException(status_code=502, detail='SSH trust or connection failed') from exc
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail='SSH session collection timed out') from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail='SSH monitoring file unavailable') from exc
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=502, detail='VPN session collection failed') from exc
    return {
        'server_id': server_id,
        'server_name': server_name,
        'monitoring_source': 'verified_ssh_status_file',
        'note': 'One row per VPN connection, not a unique person; shared credentials may repeat.',
        **result,
    }


# Step 40.2.1: admin-only, explicitly pinned SSH privilege preflight.
# No arbitrary shell, installation or repair endpoints are exposed.
from backend.admin_access import router as admin_ssh_router
app.include_router(admin_ssh_router)

from backend.integrations_api import router as integrations_router
app.include_router(integrations_router)

# Step 40.5: admin-only, audit-logged action PREVIEW. Remote execution disabled.
from backend.server_control import router as control_preview_router
app.include_router(control_preview_router)

# Step 40.7: specifically allowlisted, bounded READ-ONLY /proc SSH diagnostics.
# Power/VPN operations, arbitrary shell and schedules remain disabled.
from backend.read_only_jobs import router as read_only_jobs_router
app.include_router(read_only_jobs_router)


# Step 40.9: strictly fixed read-only diagnostics with durable job history.
from backend.controlled_jobs import router as controlled_jobs_router
app.include_router(controlled_jobs_router)


# Step 40.10: approved, audited, read-only server classification. No provisioning.
from backend.onboarding_scan import router as onboarding_scan_router
app.include_router(onboarding_scan_router)

# Step 40.10B: local-dev encrypted admin credential enrollment, no remote writes.
from backend.credential_vault import router as credential_vault_router
app.include_router(credential_vault_router)

# Step 40.10-E.1: reviewed one-shot, audited, read-only commands. No sudo or installation.
from backend.command_preflight import router as reviewed_command_router
app.include_router(reviewed_command_router)

# Step 41A: database-backed monitoring cache. No SSH from GET routes.
from backend.monitoring_api import router as monitoring_cache_router
app.include_router(monitoring_cache_router)

# Step 42A: localhost-only admin enrollment; never runs a remote command.
from backend.monitoring_enrollment import router as monitoring_enrollment_router
app.include_router(monitoring_enrollment_router)

from backend.monitoring_reports import router as monitoring_reports_router
app.include_router(monitoring_reports_router)

from backend.client_directory import router as client_directory_router
app.include_router(client_directory_router)

# Step 43: optional, encrypted local-development OpenVPN client profile management.
# NEVER used for server monitoring and NEVER executed as a VPN client.
from backend.openvpn_profiles import router as openvpn_profiles_router
app.include_router(openvpn_profiles_router)

# Step 43: scoped on-demand OpenVPN service and interface discovery.
from backend.openvpn_discovery import router as openvpn_discovery_router
app.include_router(openvpn_discovery_router)

# Step 45: reviewed, DB-only inventory bulk/archive/hard delete.
from backend.inventory_bulk import router as inventory_bulk_router
app.include_router(inventory_bulk_router)

# Multi-protocol VPN fleet (OpenVPN + WireGuard + IKEv2) + quick onboard.
from backend.vpn_fleet import router as vpn_fleet_router
app.include_router(vpn_fleet_router)
from backend.quick_onboard import router as quick_onboard_router
app.include_router(quick_onboard_router)
from backend.vpn_user_control import router as vpn_user_control_router
app.include_router(vpn_user_control_router)
from backend.geoip_lookup import router as geoip_router
app.include_router(geoip_router)

