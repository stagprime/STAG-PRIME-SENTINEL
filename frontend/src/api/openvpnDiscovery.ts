import {csrfHeaders,signalAuthExpired} from './auth'
export interface OpenVPNDiscoveryResult {
  services:{name:string;active:boolean}[]
  tunnel_interfaces:string[]
  network_interface:string|null
  suggested_vpn_service:string|null
  suggested_vpn_interface:string|null
  status_file:{found:boolean;readable:boolean}
  checked_at_utc:string
  read_only:boolean
}
export async function discoverOpenVPNService(serverId:string):Promise<OpenVPNDiscoveryResult> {
  const response=await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/openvpn/discover`,{
    method:'POST',credentials:'same-origin',cache:'no-store',headers:csrfHeaders('POST')
  })
  if(response.status===401)signalAuthExpired()
  if(!response.ok){const v=await response.json().catch(()=>null) as {detail?:unknown}|null;throw new Error(typeof v?.detail==='string'?v.detail:`Read-only discovery failed HTTP ${response.status}`)}
  const data=await response.json() as OpenVPNDiscoveryResult
  if(!Array.isArray(data.services)||!Array.isArray(data.tunnel_interfaces)||typeof data.status_file?.found!=='boolean'||!data.read_only)throw new Error('Invalid OpenVPN discovery response')
  return data
}
