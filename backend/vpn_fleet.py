"""Multi-protocol VPN fleet intelligence: OpenVPN CE, WireGuard, IKEv2/strongSwan.

Read-only discovery and session collection over an already-approved SSH identity.
Never downloads private keys, never mutates remote config from these collectors.
"""
from __future__ import annotations

import json
import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from backend.admin_access import ServerAdminAudit, ServerAdminProfile, _require_admin, _safe_profile
from backend.credential_vault import _local_only
from backend.database import Server, ServerMonitoringConfig, SessionLocal
from backend.read_only_jobs import _acquire, _release
from backend.ssh_monitor import SSHConnectionConfig, _connect_verified, _validate_remote_identifier
from backend.vpn_sessions import collect_live_vpn_sessions

router = APIRouter(prefix='/api/server-operations', tags=['Multi-protocol VPN fleet'])

_SAFE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$')

# Fixed remote discovery: OpenVPN units, WireGuard interfaces, IKEv2/strongSwan.
_DISCOVERY_SCRIPT = r'''
import json, os, pathlib, re, subprocess
safe=lambda s: bool(re.fullmatch(r"[A-Za-z0-9_.@-]{1,79}", s or ""))
out={"protocols":[],"services":[],"interfaces":[],"suggestions":[]}

def run(cmd, timeout=4):
    try:
        p=subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or "")[:40000]
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""

# --- OpenVPN ---
ovpn=[]
code, text = run(["systemctl","list-units","--type=service","--all","--no-pager","--no-legend"])
if code==0:
    for line in text.splitlines():
        parts=line.lstrip("● ").split()
        if not parts: continue
        name=parts[0]
        if re.fullmatch(r"openvpn(?:-server)?@[A-Za-z0-9_.-]{1,45}\.service", name):
            unit=name.removesuffix(".service")
            tokens=set(parts[1:6])
            # Exact tokens only — never treat "activating" as active.
            active=("active" in tokens and "running" in tokens)
            ovpn.append({"protocol":"openvpn","unit":unit,"active":active})
tunnels=[]
try:
    for name in os.listdir("/sys/class/net"):
        if safe(name) and re.fullmatch(r"(?:tun|tap|ovpn)[A-Za-z0-9_.-]{0,60}", name):
            tunnels.append(name)
except OSError:
    pass
tunnels=sorted(tunnels)[:12]
if ovpn:
    out["protocols"].append("openvpn")
    out["services"].extend(ovpn)
    for tun in tunnels:
        out["interfaces"].append({"protocol":"openvpn","name":tun})
    primary=sorted(ovpn, key=lambda x:(not x["active"], x["unit"]))[0]
    instance=primary["unit"].split("@",1)[-1] if "@" in primary["unit"] else ""
    preferred=next((t for t in tunnels if instance and instance.lower() in t.lower()), None)
    iface=preferred or (tunnels[0] if tunnels else "tun0")
    out["suggestions"].append({"protocol":"openvpn","vpn_service":primary["unit"],
        "vpn_interface":iface,"label":"OpenVPN CE"})

# --- WireGuard ---
wg_ifaces=[]
try:
    for name in os.listdir("/sys/class/net"):
        if not safe(name): continue
        if pathlib.Path("/sys/class/net/"+name+"/wireless").exists():
            continue
        # WireGuard interfaces expose /sys/class/net/<if>/carrier and typically appear in `wg show`
        pass
except OSError:
    pass
code, text = run(["wg","show","interfaces"])
if code==0 and text.strip():
    for name in text.split():
        if safe(name):
            wg_ifaces.append(name)
if not wg_ifaces:
    code, text = run(["wg","show","all","dump"])
    if code==0:
        seen=set()
        for line in text.splitlines():
            cols=line.split("\t") if "\t" in line else line.split()
            if len(cols)>=1 and safe(cols[0]) and cols[0] not in seen and len(cols)>=5 and len(cols[1])>20:
                # interface line in dump has private key as col1 (long base64)
                seen.add(cols[0]); wg_ifaces.append(cols[0])
# also detect wg-quick@ units
code, text = run(["systemctl","list-units","--type=service","--all","--no-pager","--no-legend"])
wg_units=[]
if code==0:
    for line in text.splitlines():
        parts=line.lstrip("● ").split()
        if not parts: continue
        name=parts[0]
        m=re.fullmatch(r"wg-quick@([A-Za-z0-9_.-]{1,45})\.service", name)
        if m:
            active=("active" in parts[1:5] and "running" in parts[1:6])
            wg_units.append({"protocol":"wireguard","unit":"wg-quick@"+m.group(1),"interface":m.group(1),"active":active})
if wg_ifaces or wg_units:
    out["protocols"].append("wireguard")
    for u in wg_units:
        out["services"].append(u)
    for iface in wg_ifaces[:12]:
        out["interfaces"].append({"protocol":"wireguard","name":iface})
        if not any(s.get("interface")==iface for s in wg_units):
            out["services"].append({"protocol":"wireguard","unit":"wg@"+iface,"interface":iface,"active":True})
    pick = wg_units[0] if wg_units else {"unit":"wg@"+wg_ifaces[0],"interface":wg_ifaces[0]}
    out["suggestions"].append({"protocol":"wireguard","vpn_service":pick["unit"],
        "vpn_interface":pick.get("interface") or wg_ifaces[0],"label":"WireGuard"})

# --- IKEv2 / strongSwan ---
ike=[]
for unit in ("strongswan.service","strongswan-starter.service","ipsec.service","charon.service"):
    code, text = run(["systemctl","is-active",unit.removesuffix(".service")])
    state=(text or "").strip() or "unknown"
    if state in ("active","inactive","failed","activating","deactivating"):
        ike.append({"protocol":"ikev2","unit":unit.removesuffix(".service"),"active":state=="active","state":state})
# binary presence
has_swan = pathlib.Path("/usr/sbin/swanctl").is_file() or pathlib.Path("/usr/bin/swanctl").is_file()
has_ipsec = pathlib.Path("/usr/sbin/ipsec").is_file()
if ike or has_swan or has_ipsec:
    out["protocols"].append("ikev2")
    if not ike:
        ike.append({"protocol":"ikev2","unit":"ikev2@strongswan","active":False,"state":"unknown"})
    out["services"].extend(ike)
    primary=sorted(ike, key=lambda x:(not x["active"], x["unit"]))[0]
    out["suggestions"].append({"protocol":"ikev2","vpn_service":"ikev2@"+primary["unit"].replace("@","-"),
        "vpn_interface":"ipsec0","label":"IKEv2 / strongSwan"})

# default route interface
def_route=None
try:
    for line in pathlib.Path("/proc/net/route").read_text(encoding="ascii")[:8192].splitlines()[1:]:
        cols=line.split()
        if len(cols)>2 and cols[1]=="00000000" and safe(cols[0]):
            def_route=cols[0]; break
except (OSError, UnicodeError):
    pass
out["network_interface"]=def_route
out["protocols"]=list(dict.fromkeys(out["protocols"]))
print(json.dumps(out, separators=(",",":")))
'''

_SESSION_SCRIPT = r'''
import json, os, pathlib, re, subprocess, time, ipaddress
from datetime import datetime, timezone

service = os.environ.get("SENTINEL_VPN_SERVICE", "").strip()
protocol = os.environ.get("SENTINEL_VPN_PROTOCOL", "").strip() or "auto"
MAX_SESSIONS = 1000
now = int(time.time())

def run(cmd, timeout=5):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or "")[:200000], (p.stderr or "")[:4000]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)[:200]

def pub_ip(value):
    if not isinstance(value, str) or not value.strip():
        return None
    address = value.strip().split("%")[0]
    # strip port
    if address.startswith("["):
        m = re.fullmatch(r"\[([^\]]+)\](?::\d+)?", address)
        address = m.group(1) if m else address
    elif address.count(":") == 1 and not address.startswith(":"):
        host, port = address.rsplit(":", 1)
        if port.isdigit():
            address = host
    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return None

def detect_protocol():
    if protocol in ("openvpn", "wireguard", "ikev2"):
        return protocol
    if service.startswith("openvpn"):
        return "openvpn"
    if service.startswith("wg") or service.startswith("wireguard") or service.startswith("wg-quick@"):
        return "wireguard"
    if service.startswith("ikev2") or "strongswan" in service or service in ("ipsec", "charon"):
        return "ikev2"
    # auto probe
    code, text, _ = run(["wg", "show", "interfaces"])
    if code == 0 and text.strip():
        return "wireguard"
    if pathlib.Path("/usr/sbin/swanctl").is_file() or pathlib.Path("/usr/sbin/ipsec").is_file():
        return "ikev2"
    return "openvpn"

def openvpn_sessions():
    if not service.startswith("openvpn"):
        return {"state": "vpn_not_active", "total": 0, "sessions": [], "protocol": "openvpn"}
    unit = service if service.endswith(".service") else service
    code, text, _ = run(["systemctl", "is-active", unit.removesuffix(".service")])
    active = (text or "").strip() == "active"
    if not active:
        return {"state": "vpn_not_active", "total": 0, "sessions": [], "protocol": "openvpn", "service_status": (text or "").strip()}
    instance = ""
    if "@" in service:
        instance = service.split("@", 1)[1].removesuffix(".service")
    paths = []
    if instance and re.fullmatch(r"[A-Za-z0-9_-]{1,45}", instance):
        paths = [
            f"/run/openvpn-server/status-{instance}.log",
            f"/run/openvpn/status-{instance}.log",
            f"/var/log/openvpn/status-{instance}.log",
            f"/var/log/openvpn/{instance}-status.log",
            f"/etc/openvpn/server/status-{instance}.log",
        ]
    sessions = []
    status_path = None
    for path in paths:
        try:
            p = pathlib.Path(path)
            if not p.is_file() or p.stat().st_size > 2*1024*1024:
                continue
            age = now - int(p.stat().st_mtime)
            text = p.read_text(encoding="utf-8", errors="replace")
            status_path = path
            in_client = False
            for line in text.splitlines():
                if line.startswith("HEADER,CLIENT_LIST") or line.startswith("OpenVPN CLIENT LIST"):
                    in_client = True
                    continue
                if line.startswith("ROUTING") or line.startswith("GLOBAL") or line.startswith("END"):
                    in_client = False
                    continue
                if not in_client and not line.startswith("CLIENT_LIST,"):
                    continue
                cols = line.split(",")
                if line.startswith("CLIENT_LIST,"):
                    cols = cols[1:]
                if len(cols) < 5:
                    continue
                common = cols[0].strip()
                real = pub_ip(cols[1])
                vpn_ip = cols[2].strip() if len(cols) > 2 else None
                sessions.append({
                    "protocol": "openvpn",
                    "identity": common or "unknown",
                    "public_ip": real,
                    "vpn_ip": vpn_ip,
                    "connected_since_unix": None,
                    "bytes_received": int(cols[4]) if len(cols) > 4 and cols[4].isdigit() else None,
                    "bytes_sent": int(cols[5]) if len(cols) > 5 and cols[5].isdigit() else None,
                })
                if len(sessions) >= MAX_SESSIONS:
                    break
            return {
                "state": "available",
                "total": len(sessions),
                "sessions": sessions,
                "protocol": "openvpn",
                "service_status": "active",
                "status_file": status_path,
                "status_age_seconds": age,
            }
        except OSError:
            continue
    return {"state": "status_unavailable", "total": 0, "sessions": [], "protocol": "openvpn", "service_status": "active"}

def wireguard_sessions():
    iface = None
    if "@" in service:
        iface = service.split("@", 1)[1].removesuffix(".service")
    code, text, err = run(["wg", "show", "all", "dump"])
    if code != 0:
        return {"state": "status_unavailable", "total": 0, "sessions": [], "protocol": "wireguard", "error": err[:120]}
    sessions = []
    current_if = None
    for line in text.splitlines():
        cols = line.split("\t") if "\t" in line else line.split()
        if len(cols) == 5 or (len(cols) >= 5 and len(cols[1]) > 30 and len(cols) <= 6):
            # interface line: if private public listen [fwmark]
            current_if = cols[0]
            continue
        if len(cols) >= 8 and current_if:
            if iface and current_if != iface:
                continue
            endpoint = pub_ip(cols[2]) if cols[2] != "(none)" else None
            try:
                handshake = int(cols[4])
            except ValueError:
                handshake = 0
            # treat peer as connected if handshake in last 3 minutes
            connected = handshake > 0 and (now - handshake) <= 180
            if not connected:
                continue
            sessions.append({
                "protocol": "wireguard",
                "identity": (cols[0][:20] + "…") if len(cols[0]) > 22 else cols[0],
                "public_ip": endpoint,
                "vpn_ip": cols[3].split(",")[0] if cols[3] else None,
                "connected_since_unix": handshake or None,
                "bytes_received": int(cols[5]) if cols[5].isdigit() else None,
                "bytes_sent": int(cols[6]) if cols[6].isdigit() else None,
                "interface": current_if,
            })
            if len(sessions) >= MAX_SESSIONS:
                break
    return {
        "state": "available" if sessions or code == 0 else "vpn_not_active",
        "total": len(sessions),
        "sessions": sessions,
        "protocol": "wireguard",
        "service_status": "active",
    }

def ikev2_sessions():
    sessions = []
    code, text, err = run(["swanctl", "--list-sas"])
    if code != 0:
        code, text, err = run(["ipsec", "statusall"])
    if code != 0 and not text.strip():
        return {"state": "status_unavailable", "total": 0, "sessions": [], "protocol": "ikev2", "error": err[:120]}
    # Parse ESTABLISHED lines / remote identities loosely
    for line in text.splitlines():
        if "ESTABLISHED" in line.upper() or "INSTALLED" in line.upper():
            identity = "ike-peer"
            m = re.search(r"remote\s+[^\s]+?\s+\[([^\]]+)\]", line, re.I)
            if m:
                identity = m.group(1)[:120]
            ipm = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
            sessions.append({
                "protocol": "ikev2",
                "identity": identity,
                "public_ip": ipm.group(1) if ipm else None,
                "vpn_ip": None,
                "connected_since_unix": None,
                "bytes_received": None,
                "bytes_sent": None,
            })
            if len(sessions) >= MAX_SESSIONS:
                break
    # unique-ish
    dedup = []
    seen = set()
    for s in sessions:
        key = (s["identity"], s["public_ip"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(s)
    return {
        "state": "available",
        "total": len(dedup),
        "sessions": dedup,
        "protocol": "ikev2",
        "service_status": "active",
    }

def auth_failures(proto):
    """Best-effort failed auth counters from world-readable logs (no sudo)."""
    failed = 0
    paths = []
    if proto == "openvpn":
        paths = list(pathlib.Path("/var/log").glob("openvpn*.log"))[:6]
        paths += list(pathlib.Path("/var/log/openvpn").glob("*.log"))[:6] if pathlib.Path("/var/log/openvpn").is_dir() else []
    elif proto == "ikev2":
        paths = [pathlib.Path(p) for p in ("/var/log/charon.log", "/var/log/strongswan.log", "/var/log/auth.log") if pathlib.Path(p).is_file()]
    patterns = ("AUTH_FAILED", "TLS Error", "authentication failed", "NO_PROPOSAL_CHOSEN", "INVALID_ID", "login failure")
    cutoff = now - 3600
    for path in paths[:8]:
        try:
            if not path.is_file() or path.stat().st_size > 8*1024*1024:
                continue
            # read last ~256KB
            data = path.read_bytes()[-262144:].decode("utf-8", errors="replace")
            for line in data.splitlines()[-2000:]:
                low = line.lower()
                if any(p.lower() in low for p in patterns):
                    failed += 1
        except OSError:
            continue
    return {"window_seconds": 3600, "failed_attempts_observed": failed, "source": "local_readable_logs"}

proto = detect_protocol()
if proto == "wireguard":
    payload = wireguard_sessions()
elif proto == "ikev2":
    payload = ikev2_sessions()
else:
    payload = openvpn_sessions()
payload["auth_failures"] = auth_failures(proto)
payload["collected_at_unix"] = now
payload["monitoring_source"] = "multi_protocol_ssh_status"
print(json.dumps(payload, separators=(",",":")))
'''


def protocol_from_service(vpn_service: str) -> str:
    s = (vpn_service or '').lower()
    if s.startswith('openvpn'):
        return 'openvpn'
    if s.startswith('wg') or s.startswith('wireguard') or s.startswith('wg-quick'):
        return 'wireguard'
    if s.startswith('ikev2') or 'strongswan' in s or s in {'ipsec', 'charon'}:
        return 'ikev2'
    return 'openvpn'


def collect_multi_protocol_sessions(config: SSHConnectionConfig, vpn_service: str,
                                    vpn_protocol: str | None = None) -> dict[str, Any]:
    """Collect sessions for OpenVPN / WireGuard / IKEv2 via fixed remote script."""
    service = _validate_remote_identifier(vpn_service, 'VPN service')
    proto = vpn_protocol or protocol_from_service(service)
    if proto not in {'openvpn', 'wireguard', 'ikev2', 'auto'}:
        proto = 'auto'
    # Prefer legacy OpenVPN collector when clearly OpenVPN for backward compatibility.
    if proto == 'openvpn' and service.startswith('openvpn'):
        return collect_live_vpn_sessions(config, vpn_service=service)

    client = _connect_verified(config)
    try:
        command = (
            "SENTINEL_VPN_SERVICE=" + json.dumps(service) + " "
            "SENTINEL_VPN_PROTOCOL=" + json.dumps(proto) + " "
            "python3 - <<'SENTINEL_MULTI_VPN_SESSIONS_V1'\n"
            + _SESSION_SCRIPT
            + "\nSENTINEL_MULTI_VPN_SESSIONS_V1\n"
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=25)
        raw = stdout.read(512 * 1024 + 1)
        err = stderr.read(4096)
        code = stdout.channel.recv_exit_status()
        if len(raw) > 512 * 1024:
            raise RuntimeError('Remote session payload too large')
        if code != 0:
            detail = err.decode('utf-8', errors='replace').strip()[:180]
            raise RuntimeError(f'Session collector failed ({code}): {detail}')
        data = json.loads(raw.decode('utf-8'))
        if not isinstance(data, dict) or 'state' not in data:
            raise RuntimeError('Invalid session payload')
        data.setdefault('protocol', proto)
        return data
    finally:
        client.close()


def validate_fleet_discovery(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError('Invalid discovery payload')
    protocols = payload.get('protocols') or []
    if not isinstance(protocols, list) or any(p not in {'openvpn', 'wireguard', 'ikev2'} for p in protocols):
        raise ValueError('Invalid protocols list')
    suggestions = payload.get('suggestions') or []
    if not isinstance(suggestions, list) or len(suggestions) > 12:
        raise ValueError('Invalid suggestions')
    for item in suggestions:
        if not isinstance(item, dict):
            raise ValueError('Invalid suggestion')
        for key in ('protocol', 'vpn_service', 'vpn_interface', 'label'):
            if key not in item or not isinstance(item[key], str):
                raise ValueError('Invalid suggestion fields')
        if not _SAFE.match(item['vpn_service']) or not _SAFE.match(item['vpn_interface']):
            raise ValueError('Unsafe suggestion identifiers')
    return payload


@router.post('/servers/{server_id}/vpn/discover-all')
def discover_all_protocols(server_id: str, request: Request, actor=Depends(_require_admin)):
    """Admin one-shot discovery of OpenVPN, WireGuard and IKEv2 on a verified host."""
    _local_only(request)
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None or server.archived_at is not None:
            raise HTTPException(404, detail='Server not found')
        profile = db.get(ServerAdminProfile, server_id)
        if not profile or not _safe_profile(server, profile)['verification_ready']:
            raise HTTPException(409, detail='Approve and verify SSH credentials first')
        if profile.private_key_path != f'sentinel-vault:{server_id}':
            raise HTTPException(409, detail='Encrypted vault credential required')
    if not _acquire(server_id):
        raise HTTPException(409, detail='Another operation is already running on this server')
    try:
        config = SSHConnectionConfig(
            host=server.host, username=server.ssh_username or 'root',
            private_key_path=f'sentinel-vault:{server_id}',
            port=server.ssh_port or 22,
            known_hosts_path=profile.known_hosts_path,
        )
        client = _connect_verified(config)
        try:
            cmd = "python3 - <<'SENTINEL_VPN_FLEET_DISCOVERY_V1'\n" + _DISCOVERY_SCRIPT + "\nSENTINEL_VPN_FLEET_DISCOVERY_V1\n"
            _stdin, stdout, stderr = client.exec_command(cmd, timeout=20)
            raw = stdout.read(120_001)
            stderr.read(4096)
            if stdout.channel.recv_exit_status() != 0 or len(raw) > 120_000:
                raise HTTPException(502, detail='Discovery failed on remote host')
            payload = validate_fleet_discovery(json.loads(raw.decode('utf-8')))
        finally:
            client.close()
        with SessionLocal.begin() as db:
            db.add(ServerAdminAudit(
                server_id=server_id, actor_id=actor.id,
                operation='vpn_fleet_discover', result='success',
            ))
        return {
            'server_id': server_id,
            'discovery': payload,
            'note': 'Read-only multi-protocol discovery. Choose a suggestion then enroll monitoring.',
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, detail=f'Discovery error: {type(exc).__name__}') from exc
    finally:
        _release(server_id)


class ApplyProtocolBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    vpn_service: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$')
    vpn_interface: str = Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$')
    network_interface: str = Field(default='eth0', pattern=r'^[A-Za-z0-9][A-Za-z0-9_.@-]{0,79}$')
    protocol: str = Field(pattern=r'^(openvpn|wireguard|ikev2)$')
    consent: bool = True


@router.post('/servers/{server_id}/vpn/apply-protocol')
def apply_discovered_protocol(server_id: str, data: ApplyProtocolBody, request: Request,
                              actor=Depends(_require_admin)):
    """Update monitoring config to the selected protocol/service (no remote write)."""
    _local_only(request)
    if data.consent is not True:
        raise HTTPException(422, detail='Explicit consent required')
    with SessionLocal.begin() as db:
        server = db.get(Server, server_id)
        if not server or server.archived_at is not None:
            raise HTTPException(404, detail='Server not found')
        row = db.get(ServerMonitoringConfig, server_id)
        if row is None or not row.enabled:
            raise HTTPException(409, detail='Enroll monitoring first')
        row.vpn_service = data.vpn_service
        row.vpn_interface = data.vpn_interface
        row.network_interface = data.network_interface
        db.add(ServerAdminAudit(
            server_id=server_id, actor_id=actor.id,
            operation='vpn_protocol_apply', result=data.protocol,
        ))
        return {
            'server_id': server_id,
            'protocol': data.protocol,
            'vpn_service': data.vpn_service,
            'vpn_interface': data.vpn_interface,
            'monitoring_enabled': True,
        }
