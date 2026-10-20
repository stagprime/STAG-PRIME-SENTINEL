"""Step 43: one-shot, audited read-only OpenVPN interface discovery.

Not a continuous monitoring poll; never downloads .ovpn profiles or reads keys.
An admin must explicitly request the scan after current host-key-pinned SSH
verification. Remote script is a fixed constant and uses no sudo/remote writes.
"""
from __future__ import annotations
import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from backend.admin_access import ServerAdminAudit, ServerAdminProfile, _require_admin, _safe_profile, public_admin_verification
from backend.credential_vault import _local_only
from backend.database import Server, SessionLocal
from backend.read_only_jobs import _acquire, _release, _bounded_output
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified

router=APIRouter(prefix='/api/server-operations',tags=['Read-only OpenVPN discovery'])
REMOTE_SCRIPT=r'''import json,os,pathlib,re,subprocess
safe=lambda s:bool(re.fullmatch(r'[A-Za-z0-9_.@-]{1,79}',s))
services=[]
try:
    p=subprocess.run(['systemctl','list-units','--type=service','--all','--no-pager','--no-legend'],capture_output=True,text=True,timeout=4,check=False)
    if p.returncode==0:
        for line in p.stdout[:30000].splitlines():
            x=line.lstrip('● ').split()
            if x and re.fullmatch(r'openvpn(?:-server)?@[A-Za-z0-9_.-]{1,45}\.service',x[0]):
                # Exact tokens only — avoid matching substring "active" inside "activating".
                tokens=set(x[1:6])
                services.append({'name':x[0].removesuffix('.service'),'active': 'active' in tokens and 'running' in tokens})
    except (OSError,subprocess.TimeoutExpired):pass
services=sorted(services,key=lambda x:(not x['active'],x['name']))[:12]
interfaces=[]
try:
    interfaces=[x for x in os.listdir('/sys/class/net') if safe(x)][:80]
except OSError:pass
vpn=sorted(x for x in interfaces if re.fullmatch(r'(?:tun|tap|ovpn)[A-Za-z0-9_.-]{0,60}',x))[:12]
def_route=None
try:
    for line in pathlib.Path('/proc/net/route').read_text(encoding='ascii')[:8192].splitlines()[1:]:
        x=line.split()
        if len(x)>2 and x[1]=='00000000' and safe(x[0]) and x[0] in interfaces:
            def_route=x[0];break
except (OSError,UnicodeError):pass
service=services[0]['name'] if services else None
status=None
if service and service.startswith('openvpn-server@'):
    instance=service.split('@',1)[1]
    if re.fullmatch(r'[A-Za-z0-9_-]{1,45}',instance):
        files=['/run/openvpn-server/status-'+instance+'.log','/run/openvpn/status-'+instance+'.log',
             '/var/log/openvpn/status-'+instance+'.log','/etc/openvpn/server/status-'+instance+'.log']
        for candidate in files:
            try:
                f=pathlib.Path(candidate)
                if f.is_file() and f.stat().st_size<2097152:
                    status={'found':True,'readable':os.access(candidate,os.R_OK)};break
            except OSError:pass
print(json.dumps({'services':services,'tunnel_interfaces':vpn,
 'network_interface':def_route,'suggested_vpn_service':service,
 'suggested_vpn_interface':vpn[0] if vpn else None,
 'status_file':status or {'found':False,'readable':False}},separators=(',',':')))
'''
COMMAND="python3 - <<'SENTINEL_FIXED_OPENVPN_DISCOVERY_V1'\n"+REMOTE_SCRIPT+"\nSENTINEL_FIXED_OPENVPN_DISCOVERY_V1\n"


def validate_discovery(payload):
    if not isinstance(payload,dict):raise ValueError('Invalid discovery response')
    services=payload.get('services')
    interfaces=payload.get('tunnel_interfaces')
    network=payload.get('network_interface')
    chosen=payload.get('suggested_vpn_service')
    tun=payload.get('suggested_vpn_interface')
    status=payload.get('status_file')
    ok=lambda v:isinstance(v,str) and bool(re.fullmatch(r'[A-Za-z0-9_.@-]{1,79}',v))
    if (not isinstance(services,list) or len(services)>12 or
        any(not isinstance(s,dict) or set(s)!={'name','active'} or not ok(s['name']) or type(s['active']) is not bool or not s['name'].startswith('openvpn') for s in services) or
        not isinstance(interfaces,list) or len(interfaces)>12 or any(not ok(x) for x in interfaces) or
        (network is not None and not ok(network)) or (chosen is not None and not ok(chosen)) or
        (tun is not None and not ok(tun)) or
        (chosen is not None and chosen not in {s['name'] for s in services}) or
        (tun is not None and tun not in interfaces) or
        not isinstance(status,dict) or set(status)!={'found','readable'} or
        type(status['found']) is not bool or type(status['readable']) is not bool):
        raise ValueError('Malformed OpenVPN discovery evidence')
    return {'services':services,'tunnel_interfaces':interfaces,'network_interface':network,
            'suggested_vpn_service':chosen,'suggested_vpn_interface':tun,
            'status_file':status,'read_only':True,'installation_authorized':False}


def execute(config):
    client=_connect_verified(config)
    try:
        return validate_discovery(json.loads(_bounded_output(client,COMMAND)))
    finally:client.close()


@router.post('/servers/{server_id}/openvpn/discover')
def discover_openvpn(server_id:str,request:Request,actor=Depends(_require_admin)):
    _local_only(request)
    with SessionLocal() as db:
        server=db.get(Server,server_id)
        profile=db.get(ServerAdminProfile,server_id)
        if not server or server.archived_at is not None:raise HTTPException(404,'Server not found')
        if not profile or not _safe_profile(server,profile)['verification_ready']:
            raise HTTPException(409,'Approved SSH identity required')
        verified=public_admin_verification(server,profile)
        if not verified or verified.get('state')!='success' or not verified.get('ssh_verified'):
            raise HTTPException(409,'Recent host-key-verified SSH evidence required')
        config=SSHConnectionConfig(host=profile.approved_host,port=profile.approved_port,
            username=profile.approved_username,private_key_path=profile.private_key_path,
            known_hosts_path=profile.known_hosts_path)
    if not _acquire(server_id):raise HTTPException(409,'A read-only diagnostic is already running')
    try:
        with SessionLocal.begin() as db:
            db.add(ServerAdminAudit(server_id=server_id,actor_id=actor.id,
                operation='openvpn_discovery',result='attempted'))
        try:result=execute(config)
        except Exception:
            with SessionLocal.begin() as db:
                db.add(ServerAdminAudit(server_id=server_id,actor_id=actor.id,
                    operation='openvpn_discovery',result='failed'))
            raise HTTPException(502,'Read-only OpenVPN discovery failed; check SSH access') from None
        with SessionLocal.begin() as db:
            db.add(ServerAdminAudit(server_id=server_id,actor_id=actor.id,
                operation='openvpn_discovery',result='verified'))
        return {'server_id':server_id,'checked_at_utc':datetime.now(timezone.utc).isoformat(),**result}
    finally:_release(server_id)
