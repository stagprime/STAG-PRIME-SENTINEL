import { useMemo, useState } from 'react'
import { Activity, ArrowUpRight, Building2, Radio, Search, Server, UsersRound } from 'lucide-react'
import type { MonitoringOverview } from '../api/monitoring'
import './Client360.css'
type Asset={id:string;name:string;client:string;region:string;provider:string}
export default function Client360({servers,overview,onOpenServer}:{servers:Asset[];overview:MonitoringOverview|null;onOpenServer:(id:string)=>void}){
 const [search,setSearch]=useState('');const [active,setActive]=useState<string|null>(null)
 const clients=useMemo(()=>[...new Set(servers.map(s=>s.client))].filter(Boolean).sort(),[servers])
 const scoped=clients.filter(name=>name.toLowerCase().includes(search.toLowerCase()))
 const client=active&&clients.includes(active)?active:scoped[0]||null
 const rows=servers.filter(s=>s.client===client)
 const telemetry=rows.map(s=>overview?.servers.find(m=>m.server_id===(s.id.startsWith('api-')?s.id.slice(4):s.id))||null)
 const fresh=telemetry.filter(m=>m?.health.fresh && overview?.worker.status==='running')
 const sources=telemetry.filter(m=>m?.sessions.fresh&&m.sessions.data?.state==='available'&&overview?.worker.status==='running')
 const count=sources.length?sources.reduce((sum,m)=>sum+(m?.sessions.data?.total??0),0):null
 return <section className="ent-client360"><div className="ent-client-head"><div><span>CLIENT / ORGANIZATION COMMAND CENTER</span><h2>Client 360° overview</h2><p>Backend-scoped inventory and verified monitoring coverage for your authorized organizations.</p></div><Building2 size={25}/></div><div className="ent-client-workspace"><div className="ent-client-list"><label><Search size={15}/><input placeholder="Find organizations…" value={search} onChange={e=>setSearch(e.target.value)}/></label>{scoped.map(name=><button className={client===name?'active':''} key={name} onClick={()=>setActive(name)}><Building2 size={15}/><span>{name}</span><b>{servers.filter(s=>s.client===name).length}</b></button>)}{!scoped.length&&<p>No matching client organizations.</p>}</div><div className="ent-client-details">{client?<><div className="ent-client-summary"><h3>{client}</h3><span>Authorized inventory context</span></div><div className="ent-client-kpis"><div><Server size={16}/><b>{rows.length}</b><span>Servers</span></div><div><Activity size={16}/><b>{fresh.length}/{rows.length}</b><span>Fresh host samples</span></div><div><Radio size={16}/><b>{sources.length}/{rows.length}</b><span>VPN data sources</span></div><div><UsersRound size={16}/><b>{count===null?'—':sources.length===rows.length?count:`≥ ${count}`}</b><span>Verified sessions</span></div></div><div className="ent-client-assets">{rows.map(s=><button key={s.id} onClick={()=>onOpenServer(s.id)}><Server size={17}/><div><strong>{s.name}</strong><small>{s.provider} · {s.region}</small></div><ArrowUpRight size={16}/></button>)}</div></>:<div className="ent-client-empty">Select an organization to see its infrastructure summary.</div>}</div></div><p className="ent-client-note">This is an operational overview of existing records. SLA, billing and client-specific traffic attribution require additional authenticated backend sources.</p></section>
}
