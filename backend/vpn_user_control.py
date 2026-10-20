"""Allowlisted VPN user kick / block / unblock over approved SSH.

OpenVPN CE: CCD `disable` + best-effort management kill.
WireGuard: `wg set <iface> peer <pubkey> remove` (identity = peer public key).
IKEv2: swanctl --terminate --ike <id> (best-effort).
"""
from __future__ import annotations

import json
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from backend.admin_access import ServerAdminAudit, ServerAdminProfile, _require_admin, _safe_profile
from backend.credential_vault import _local_only
from backend.database import Server, ServerMonitoringConfig, SessionLocal
from backend.read_only_jobs import _acquire, _release
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified
from backend.vpn_fleet import protocol_from_service

router = APIRouter(prefix='/api/server-operations', tags=['VPN user control'])

Action = Literal['kick', 'block', 'unblock']
_SAFE_ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@+/-]{0,120}$')
_SAFE_UNIT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$')

_REMOTE = r'''
import json, os, pathlib, re, socket, subprocess, sys
action=sys.argv[1]
identity=sys.argv[2]
vpn_service=sys.argv[3]
vpn_interface=sys.argv[4]
safe=lambda s: bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@+/-]{0,120}", s or ""))
if not safe(identity) or action not in ("kick","block","unblock"):
    print(json.dumps({"ok":False,"error":"invalid_args"})); raise SystemExit(2)

def run(cmd, timeout=8):
    try:
        p=subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or "")[:4000], (p.stderr or "")[:2000]
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, "", str(e)[:200]

notes=[]
protocol="openvpn"
if vpn_service.startswith("wg@") or vpn_service.startswith("wg-quick@"):
    protocol="wireguard"
elif vpn_service.startswith("ikev2@"):
    protocol="ikev2"

if protocol=="openvpn":
    instance=""
    if "@" in vpn_service:
        instance=vpn_service.split("@",1)[1].removesuffix(".service")
    conf_candidates=[]
    if instance:
        conf_candidates += [
            f"/etc/openvpn/server/{instance}.conf",
            f"/etc/openvpn/{instance}.conf",
            f"/etc/openvpn/server/{instance}/{instance}.conf",
        ]
    conf_candidates += ["/etc/openvpn/server/server.conf","/etc/openvpn/server.conf"]
    ccd=None
    conf_used=None
    for c in conf_candidates:
        p=pathlib.Path(c)
        if not p.is_file():
            continue
        conf_used=c
        try:
            text=p.read_text(encoding="utf-8", errors="replace")[:120000]
        except OSError:
            continue
        for line in text.splitlines():
            parts=line.strip().split()
            if len(parts)>=2 and parts[0]=="client-config-dir":
                ccd=parts[1]
                break
        if ccd:
            break
    if not ccd:
        # Sensible defaults for openvpn-server@instance layouts
        if instance:
            ccd=f"/etc/openvpn/server/ccd-{instance}"
            if not pathlib.Path(ccd).is_dir():
                ccd=f"/etc/openvpn/server/{instance}/ccd"
        if not ccd or not pathlib.Path(ccd).is_dir():
            ccd="/etc/openvpn/ccd"
    ccd_path=pathlib.Path(ccd)
    target=ccd_path / identity
    if action in ("block","unblock"):
        code,_,err=run(["sudo","-n","mkdir","-p",str(ccd_path)])
        if code!=0:
            print(json.dumps({"ok":False,"error":"ccd_mkdir_failed","detail":err,"ccd":str(ccd_path)})); raise SystemExit(3)
    if action=="block":
        code,out,err=run(["sudo","-n","bash","-lc",f"printf 'disable\\n' > {target.as_posix()!r} && chmod 644 {target.as_posix()!r}"])
        if code!=0:
            print(json.dumps({"ok":False,"error":"block_write_failed","detail":err,"ccd":str(ccd_path)})); raise SystemExit(4)
        notes.append("ccd_disable_written")
        action="kick"  # also disconnect active session
    elif action=="unblock":
        code,_,err=run(["sudo","-n","rm","-f",str(target)])
        if code!=0:
            print(json.dumps({"ok":False,"error":"unblock_failed","detail":err})); raise SystemExit(5)
        notes.append("ccd_disable_removed")
        print(json.dumps({"ok":True,"protocol":"openvpn","action":"unblock","identity":identity,"notes":notes,"conf":conf_used,"ccd":str(ccd_path)}))
        raise SystemExit(0)

    if action=="kick":
        # Best-effort: OpenVPN management sockets
        kicked=False
        for base in ("/run/openvpn-server","/run/openvpn","/var/run/openvpn"):
            b=pathlib.Path(base)
            if not b.is_dir():
                continue
            for sock in list(b.glob("*.sock")) + list(b.glob("*-status.sock")):
                try:
                    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect(str(sock))
                    s.sendall(f'kill "{identity}"\n'.encode())
                    s.recv(512)
                    s.close()
                    kicked=True
                    notes.append(f"mgmt_kill:{sock.name}")
                    break
                except OSError:
                    continue
            if kicked:
                break
        if not kicked:
            notes.append("mgmt_unavailable_ccd_only_or_next_reconnect")
        print(json.dumps({"ok":True,"protocol":"openvpn","action":"kick","identity":identity,"notes":notes,"conf":conf_used,"ccd":str(ccd_path)}))
        raise SystemExit(0)

elif protocol=="wireguard":
    iface=vpn_interface if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", vpn_interface or "") else ""
    if not iface and vpn_service.startswith("wg-quick@"):
        iface=vpn_service.split("@",1)[1]
    if not iface:
        print(json.dumps({"ok":False,"error":"missing_wg_iface"})); raise SystemExit(6)
    if action=="unblock":
        print(json.dumps({"ok":False,"error":"wg_unblock_requires_peer_readd","hint":"Re-add peer via your WG config management."})); raise SystemExit(7)
    if action in ("kick","block"):
        code,out,err=run(["sudo","-n","wg","set",iface,"peer",identity,"remove"])
        if code!=0:
            print(json.dumps({"ok":False,"error":"wg_remove_failed","detail":err or out})); raise SystemExit(8)
        notes.append("wg_peer_removed")
        print(json.dumps({"ok":True,"protocol":"wireguard","action":action,"identity":identity,"interface":iface,"notes":notes}))
        raise SystemExit(0)

else:  # ikev2
    if action=="unblock":
        print(json.dumps({"ok":False,"error":"ikev2_unblock_manual","hint":"Clear swanctl blocklist / cert revoke separately."})); raise SystemExit(9)
    code,out,err=run(["sudo","-n","swanctl","--terminate","--ike",identity])
    if code!=0:
        code2,out2,err2=run(["sudo","-n","ipsec","down",identity])
        if code2!=0:
            print(json.dumps({"ok":False,"error":"ikev2_terminate_failed","detail":(err or err2 or out or out2)[:300]})); raise SystemExit(10)
        notes.append("ipsec_down")
    else:
        notes.append("swanctl_terminate")
    print(json.dumps({"ok":True,"protocol":"ikev2","action":action,"identity":identity,"notes":notes}))
'''


class UserControlRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    action: Action
    identity: str = Field(min_length=1, max_length=120)
    confirm: bool = False


def _validate_identity(value: str) -> str:
    cleaned = value.strip()
    if not _SAFE_ID.match(cleaned):
        raise HTTPException(422, detail='Identity must be a safe Common Name / peer id')
    return cleaned


@router.post('/servers/{server_id}/vpn/users/control')
def control_vpn_user(server_id: str, body: UserControlRequest, request: Request,
                     admin=Depends(_require_admin)):
    """Kick / block / unblock a VPN identity on the enrolled protocol."""
    _local_only(request)
    if body.confirm is not True:
        raise HTTPException(422, detail='confirm=true required')
    identity = _validate_identity(body.identity)
    if not _acquire(server_id):
        raise HTTPException(409, detail='Another operation is already running on this server')
    try:
        with SessionLocal() as db:
            server = db.get(Server, server_id)
            profile = db.get(ServerAdminProfile, server_id)
            mon = db.get(ServerMonitoringConfig, server_id)
            if not server or server.archived_at is not None:
                raise HTTPException(404, detail='Server not found')
            if not profile or not _safe_profile(server, profile)['verification_ready']:
                raise HTTPException(409, detail='Approved SSH profile required')
            if not mon or not mon.enabled:
                raise HTTPException(409, detail='Monitoring enrollment required')
            if not _SAFE_UNIT.match(mon.vpn_service) or not _SAFE_UNIT.match(mon.vpn_interface):
                raise HTTPException(422, detail='Enrolled VPN identifiers unsafe')
            config = SSHConnectionConfig(
                host=profile.approved_host,
                port=profile.approved_port,
                username=profile.approved_username,
                private_key_path=profile.private_key_path,
                known_hosts_path=profile.known_hosts_path,
            )
            vpn_service = mon.vpn_service
            vpn_interface = mon.vpn_interface
            protocol = protocol_from_service(vpn_service)

        # Pass args after script via python -c is messy; use env + heredoc argv.
        remote = (
            "python3 - <<'SENTINEL_VPN_USER_CTRL_V1'\n"
            + _REMOTE
            + "\nSENTINEL_VPN_USER_CTRL_V1\n"
            + f"{body.action!r} {identity!r} {vpn_service!r} {vpn_interface!r}\n"
        )
        # Fix: heredoc can't take argv that way. Embed constants instead.
        remote = (
            "python3 - <<'SENTINEL_VPN_USER_CTRL_V1'\n"
            + f"import sys\nsys.argv=['vpn_user_ctrl',{body.action!r},{identity!r},{vpn_service!r},{vpn_interface!r}]\n"
            + _REMOTE
            + "\nSENTINEL_VPN_USER_CTRL_V1\n"
        )
        client = _connect_verified(config)
        try:
            _stdin, stdout, stderr = client.exec_command(remote, timeout=40)
            raw = stdout.read(60_000).decode('utf-8', errors='replace')
            err = stderr.read(4_000).decode('utf-8', errors='replace')
            code = stdout.channel.recv_exit_status()
        finally:
            client.close()

        payload = None
        for line in reversed(raw.strip().splitlines() or []):
            line = line.strip()
            if line.startswith('{') and line.endswith('}'):
                try:
                    payload = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        ok = code == 0 and isinstance(payload, dict) and payload.get('ok') is True
        with SessionLocal() as db:
            db.add(ServerAdminAudit(
                server_id=server_id,
                actor_id=admin.id,
                operation=f'vpn_user_{body.action}',
                result='success' if ok else 'failed',
            ))
            db.commit()
        if not ok:
            detail = (payload or {}).get('error') if isinstance(payload, dict) else 'remote_failed'
            raise HTTPException(502, detail={
                'code': 'VPN_USER_CONTROL_FAILED',
                'message': str(detail),
                'stderr_tail': err[-200:] if err else None,
                'payload': payload,
            })
        return {
            'server_id': server_id,
            'protocol': protocol,
            'action': body.action,
            'identity': identity,
            'result': payload,
            'message': f'{body.action} applied for {identity}',
        }
    finally:
        _release(server_id)
