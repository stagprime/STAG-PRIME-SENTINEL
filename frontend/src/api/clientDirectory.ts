import { csrfHeaders, signalAuthExpired } from './auth'

export interface ClientDirectoryEntry { id: string; name: string; contact_email: string | null; active_servers: number }
async function request<T>(url:string, method:'GET'|'POST'|'PATCH'='GET', data?:unknown): Promise<T>{
  const res=await fetch(url,{method,credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json',...csrfHeaders(method)},
    body: data === undefined ? undefined : JSON.stringify(data)})
  if (res.status===401)signalAuthExpired()
  if(!res.ok){const x=await res.json().catch(()=>null) as {detail?:unknown}|null;
    throw new Error(typeof x?.detail==='string'?x.detail:`Client API returned HTTP ${res.status}`)}
  return res.json() as Promise<T>
}
export const fetchClients=()=>request<{clients:ClientDirectoryEntry[];total:number}>('/api/clients')
export const createClient=(body:{name:string;contact_email:string|null})=>request<ClientDirectoryEntry>('/api/clients','POST',body)
export const updateClient=(id:string,body:{name:string;contact_email:string|null})=>request<ClientDirectoryEntry>('/api/clients/'+encodeURIComponent(id),'PATCH',body)
