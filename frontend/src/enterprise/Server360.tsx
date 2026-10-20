import { useEffect, useState } from 'react'
import { Activity, AlertTriangle, Clock3, Database, Gauge, Info, Wifi } from 'lucide-react'
import type { ServerHealthResponse } from '../api/servers'
import { getServer360Snapshot } from '../api/monitoring'
import type { CachedMonitorServer, Server360Snapshot, Server360HistoryHealth, EvidenceState } from '../api/monitoring'
import './Server360.css'

type Tab = 'Overview'|'Performance'|'Network'|'VPN Services'|'VPN Sessions'|'Security'|'Logs'|'Incidents'|'Capacity'|'Monitoring Config'
const TABS:Tab[]=['Overview','Performance','Network','VPN Services','VPN Sessions','Security','Logs','Incidents','Capacity','Monitoring Config']
type Tile = {label:string;value:string;note?:string}
const displayNum=(n:number|null|undefined,suffix='')=>typeof n==='number'&&Number.isFinite(n)?`${n.toFixed(1)}${suffix}`:'Unavailable'
const totalBytes=(n:number|null|undefined)=>typeof n==='number'&&Number.isFinite(n)&&n>=0?`${n.toLocaleString()} bytes`:'Unavailable'
const observedAt=(value:string|null|undefined)=>{
  if(!value) return 'Not available'
  const ms=Date.parse(value)
  return Number.isFinite(ms)?new Date(ms).toLocaleString():'Not available'
}
const evidenceLabel=(state:EvidenceState|undefined, available:string, fallback?:string)=>{
  if(state==='available') return available
  if(state==='permission_needed') return 'Permission needed on server'
  if(state==='insufficient_samples') return 'Waiting for more auto samples'
  return fallback||'Unavailable'
}
const isCurrent=(value:string|null|undefined,minutes=5)=>{
  if(!value)return false
  const t=Date.parse(value)
  return Number.isFinite(t)&&t<=Date.now()+60000&&Date.now()-t<=minutes*60_000
}
const panel=(label:string,value:string,note?:string):Tile=>({label,value,note})

export default function Server360({serverId,health,observation}:{serverId:string;health:ServerHealthResponse|null;observation:CachedMonitorServer|null}) {
  const [snapshot,setSnapshot]=useState<Server360Snapshot|null>(null)
  const [snapshotError,setSnapshotError]=useState<string|null>(null)
  const [snapshotLoading,setSnapshotLoading]=useState(true)
  useEffect(()=>{
    const controller=new AbortController()
    setSnapshot(null); setSnapshotError(null); setSnapshotLoading(true)
    getServer360Snapshot(serverId,controller.signal).then(result=>{
      if(!controller.signal.aborted && result.server_id===serverId) setSnapshot(result)
    }).catch(error=>{
      if(!controller.signal.aborted) setSnapshotError(error instanceof Error?error.message:'Monitoring history unavailable')
    }).finally(()=>{if(!controller.signal.aborted)setSnapshotLoading(false)})
    return ()=>controller.abort()
  },[serverId])
  const [tab,setTab]=useState<Tab>('Overview')
  const history=snapshot?.history
  const evidence=snapshot?.evidence
  const recentHost=history?.health??[]
  const recentSessions=history?.sessions??[]
  const incidents=snapshot?.incidents??[]
  const observedAverage=(key:keyof Pick<Server360HistoryHealth,'cpu_percent'|'memory_used_percent'|'disk_used_percent'>)=>{
    const values=recentHost.map(point=>point[key]).filter((v):v is number=>typeof v==='number'&&Number.isFinite(v))
    return values.length ? `${(values.reduce((a,b)=>a+b,0)/values.length).toFixed(1)}% (${values.length} samples)` : 'Unavailable'
  }
  const openIncidents=incidents.filter(item=>item.state==='open').length
  const verifiedCounts=recentSessions.map(item=>item.connections).filter((n):n is number=>typeof n==='number'&&Number.isFinite(n))
  const maxObservedConnections=verifiedCounts.length?String(Math.max(...verifiedCounts)):'Unavailable'
  const oldestSample=recentHost[0]?.at_utc
  const newestSample=recentHost[recentHost.length-1]?.at_utc
  // This API is cache-only and its timeline data remains historical even if recent.
  const sourceLabel=snapshotError?'Unavailable':snapshotLoading?'Loading…':snapshot?'Stored SSH telemetry':'Unavailable'

  // A previously valid SSH sample is not automatically a CURRENT sample. Display its time separately.
  const hostCurrent=!!health && isCurrent(health.collected_at_utc)
  const hostVerified=!!health && health.monitoring_source==='verified_ssh' && health.host_key_verified===true && health.status==='connected'
  const safeHost=hostVerified&&hostCurrent ? health : null
  const cachedHost=observation?.health.fresh && isCurrent(observation.health.at_utc) ? observation.health.data : null
  const vpnSource=observation?.sessions.fresh && isCurrent(observation.sessions.at_utc) && observation.sessions.data?.state==='available'
  const verifiedSessionCount=vpnSource&&typeof observation?.sessions.data?.total==='number' ? String(observation.sessions.data.total) : 'Unavailable'
  const vpnState=safeHost?.openvpn.service_status ?? 'Unavailable'
  const hasHostRecord=!!safeHost || !!cachedHost
  const status=observation?.status??'not_enrolled'
  const hostState=hasHostRecord?'Fresh SSH observation':health&&!hostCurrent?'Stale / needs fresh sample':'No fresh host evidence'
  const sourceAt=observedAt(safeHost?.collected_at_utc??observation?.health.at_utc)
  const thr=evidence?.throughput
  const thrValue=thr?.state==='available'&&thr.rx_mbps!=null&&thr.tx_mbps!=null
    ? `↓ ${thr.rx_mbps} / ↑ ${thr.tx_mbps} Mbps`
    : evidenceLabel(thr?.state, '—', 'Unavailable')
  const cert=evidence?.certificate
  const certValue=cert?.state==='available'
    ? (cert.days_remaining!=null?`${cert.days_remaining} days left`:(cert.not_after||'Valid metadata present'))
    : evidenceLabel(cert?.state, '—')
  const auth=evidence?.tls_auth_events
  const authValue=auth?.state==='available'&&auth.failed_attempts_observed!=null
    ? String(auth.failed_attempts_observed)
    : evidenceLabel(auth?.state, '—')
  const journal=evidence?.journal
  const journalValue=journal?.state==='available'
    ? `${journal.lines.length} recent lines`
    : evidenceLabel(journal?.state, '—')
  const details:Record<Tab,Tile[]>={
    'Overview':[
      panel('Host observation',hostState,'Verified host identity and observation freshness'),
      panel('OpenVPN service',vpnState,'Service state from approved read-only SSH check; not an internet connectivity test'),
      panel('Verified VPN connections',verifiedSessionCount,'Session visibility requires a fresh readable OpenVPN status source'),
      panel('Last host observation',sourceAt,'Timestamp of latest known health evidence'),
      panel('Auto collectors',evidence?.collection?.mode==='auto_after_enroll'?'Enabled after enroll':'Pending worker sample',evidence?.collection?.note||'Worker fills evidence automatically'),
    ],
    'Performance':[
      panel('CPU utilization',displayNum(safeHost?.cpu_percent,'%')),
      panel('Memory used',displayNum(safeHost?.memory_used_percent,'%')),
      panel('Root disk used',displayNum(safeHost?.disk_used_percent,'%')),
      panel('Uptime',typeof safeHost?.uptime_seconds==='number'?`${Math.floor(safeHost.uptime_seconds/3600)} h ${Math.floor((safeHost.uptime_seconds%3600)/60)} min`:'Unavailable'),
      panel('Stored CPU average',observedAverage('cpu_percent'),'Mean of the displayed, bounded history; not a live reading'),
      panel('Stored RAM average',observedAverage('memory_used_percent')),
      panel('Stored disk average',observedAverage('disk_used_percent')),
      panel('Historical sample coverage',snapshot?`${recentHost.length} stored samples`:sourceLabel, 'Stored observations; gaps are not interpolated')
    ],
    'Network':[
      panel('Physical NIC',safeHost?.network?.interface??recentHost.at(-1)?.network_interface??'Unavailable'),
      panel('NIC received',totalBytes(safeHost?.network?.rx_bytes_total),'Cumulative since interface reset; not bytes/sec'),
      panel('NIC transmitted',totalBytes(safeHost?.network?.tx_bytes_total),'Cumulative; do not add to VPN tunnel traffic'),
      panel('Measured throughput',thrValue,thr?.note||'Derived from consecutive auto health samples'),
      panel('NIC RX errors',totalBytes(safeHost?.network?.rx_errors_total).replace(' bytes',''),'Cumulative counter'),
      panel('NIC TX errors',totalBytes(safeHost?.network?.tx_errors_total).replace(' bytes',''),'Cumulative counter'),
      panel('Historical NIC source',snapshot?(recentHost.at(-1)?.network_interface||'Unavailable'):sourceLabel,'Interface name as reported by last stored health sample')
    ],
    'VPN Services':[
      panel('Systemd service',safeHost?.openvpn.service??'Unavailable'),
      panel('Observed service state',vpnState,'Host accessibility and service accessibility are separate'),
      panel('Tunnel interface',safeHost?.openvpn.interface??'Unavailable'),
      panel('Tunnel address',safeHost?.openvpn.tunnel_ipv4??'Unavailable'),
      panel('Status file readable',vpnSource?'Yes':'Not verified'),
      panel('End-to-end VPN internet test','Not tested','Requires an independently approved client probe')
    ],
    'VPN Sessions':[
      panel('Verified concurrent sessions',verifiedSessionCount,'Connections, not unique human users'),
      panel('Status source',vpnSource?'Fresh readable OpenVPN status':'Unavailable / stale'),
      panel('Source age',vpnSource&&typeof observation?.sessions.age_seconds==='number'?`${Math.round(observation.sessions.age_seconds)} seconds`:'Unavailable'),
      panel('Observed at',observedAt(observation?.sessions.at_utc)),
      panel('Readable stored samples',snapshot?String(verifiedCounts.length):sourceLabel,'Not every stored session sample is readable'),
      panel('Highest observed connections',maxObservedConnections,'Peak of stored samples; not distinct users or fleet-wide concurrency')
    ],
    'Security':[
      panel('SSH host key',safeHost?.host_key_verified?'Verified':'Not currently verified'),
      panel('Failed auth observations',authValue,auth?.note||'From auto session/log collectors'),
      panel('Certificate validity',certValue,cert?.note||(cert?.path?`Source: ${cert.path}`:undefined)),
      panel('Threat intelligence','Not configured','External feed not wired in this version')
    ],
    'Logs':[
      panel('OpenVPN service journal',journalValue,journal?.note||(journal?.unit?`Unit: ${journal.unit}`:undefined)),
      panel('Log search','Not connected','Full-text search is not part of the auto collector'),
      panel('Credential visibility','Not permitted','Secrets are never returned to the UI'),
      panel('Event retention','Worker history window','Bounded telemetry retention; not a SIEM')
    ],
    'Incidents':[
      panel('Monitoring state',status.replaceAll('_',' ')),
      panel('Collector error',observation?.error_code??'Not provided','Missing error is not proof of healthy service'),
      panel('Open recorded incidents',snapshot?String(openIncidents):sourceLabel,'Only last 20 recorded incidents retrieved; not a lifetime total'),
      panel('Latest incident',incidents[0]?.code??'None recorded in window','A missing incident record is not proof of a healthy service')
    ],
    'Capacity':[
      panel('Observed CPU use',displayNum(safeHost?.cpu_percent,'%')),
      panel('Observed RAM use',displayNum(safeHost?.memory_used_percent,'%')),
      panel('Observed root disk use',displayNum(safeHost?.disk_used_percent,'%')),
      panel('Maximum supported connections','Unknown','Requires capacity evaluation; do not infer from CPU snapshot')
    ],
    'Monitoring Config':[
      panel('Enrollment',observation?.monitoring_enabled?'Enabled':'Not enrolled'),
      panel('Collector state',status.replaceAll('_',' ')),
      panel('Health source',observation?.health.state??'Unknown'),
      panel('Last collected health',observedAt(observation?.health.at_utc)),
      panel('Session source',observation?.sessions.state??'Unknown'),
      panel('Last collected sessions',observedAt(observation?.sessions.at_utc)),
      panel('Monitoring worker',snapshot?.worker.status??sourceLabel,'Worker heartbeat; independent of SSH or VPN health'),
      panel('Stored evidence first seen',observedAt(oldestSample)),
      panel('Stored evidence last seen',observedAt(newestSample))
    ]
  }
  return <section className="ent360" aria-label="Source-backed Server 360 overview">
    <header className="ent360-title"><Gauge size={19}/><div><strong>Server 360°</strong><span>Verified evidence · last observation: {sourceAt}</span></div><span className="ent360-pill">Cached & read-only</span></header>
    <div className="ent360-evidence" role="status">
      <span className={hasHostRecord?'ent360-good':'ent360-warn'}><Activity size={15}/>{hostState}</span>
      <span className={vpnState==='active'?'ent360-good':'ent360-neutral'}><Wifi size={15}/>VPN: {vpnState}</span>
      <span className={vpnSource?'ent360-good':'ent360-neutral'}><Database size={15}/>Sessions: {verifiedSessionCount}</span>
    </div>
    <div className="ent360-tabs" role="tablist" aria-label="Server details views">{TABS.map(t=><button id={`ent360-tab-${TABS.indexOf(t)}`} type="button" role="tab" aria-controls="ent360-content" aria-selected={tab===t} key={t} tabIndex={tab===t?0:-1} className={tab===t?'active':''} onClick={()=>setTab(t)} onKeyDown={e=>{if(e.key==='ArrowRight'||e.key==='ArrowLeft'||e.key==='Home'||e.key==='End'){e.preventDefault();const i=TABS.indexOf(tab);const next=e.key==='Home'?0:e.key==='End'?TABS.length-1:e.key==='ArrowRight'?(i+1)%TABS.length:(i+TABS.length-1)%TABS.length;setTab(TABS[next]);const button=e.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next];button?.focus()}}}>{t}</button>)}</div>
    <div id="ent360-content" className="ent360-body" role="tabpanel" aria-labelledby={`ent360-tab-${TABS.indexOf(tab)}`}>
      <div className="ent360-section-line"><div><h3>{tab}</h3><p>Only available source observations are displayed. No action is executed by switching tabs.</p></div><span><Clock3 size={13}/> Read-only</span></div>
      <p className="ent360-source-label" role="status">
        Server-scoped Backend API: {sourceLabel} · History is cache-only and cannot initiate SSH
        {snapshotError?` · ${snapshotError}`:''}
      </p>
      <div className="ent360-tiles">{details[tab].map(({label,value,note})=><article className="ent360-tile" key={label}><span>{label}</span><strong className={/Unavailable|Unknown|Not collected|Not tested|Not verified|Not connected|Not provided|required|Permission needed|Waiting for more/i.test(value)?'ent360-missing':''}>{value}</strong>{note&&<small>{note}</small>}</article>)}</div>
      {tab==='Logs'&&journal?.state==='available'&&(journal.lines.length>0)&&(
        <div className="ent360-records"><strong>Recent journal (auto collected · read-only)</strong>
          {journal.lines.map((line,i)=><div className="ent360-record-row" key={`${i}-${line.slice(0,24)}`}><span style={{gridColumn:'1 / -1',fontFamily:'ui-monospace,monospace',fontSize:11}}>{line}</span></div>)}
        </div>
      )}
      {tab==='Logs'&&journal?.state==='permission_needed'&&(
        <div className="ent360-warning"><AlertTriangle size={16}/>SSH user needs journal read access for this VPN unit. After ACL grant, the next worker cycle fills logs automatically.</div>
      )}
      {tab==='Incidents'&&incidents.length>0?(<div className="ent360-records"><strong>Recent recorded incidents (maximum 20)</strong>{incidents.map(item=><div className="ent360-record-row" key={item.id}><span>{item.code}</span><span>{item.state}</span><span>{observedAt(item.last_seen_at_utc)}</span></div>)}</div>):null}
      {tab==='Performance'&&recentHost.length>0?(<div className="ent360-records"><strong>Stored host evidence · {recentHost.length} points</strong><p>From {observedAt(oldestSample)} to {observedAt(newestSample)} · averages only; irregular sampling and failed checks are not drawn as continuous lines.</p></div>):null}
      {!hasHostRecord&&<div className="ent360-warning"><AlertTriangle size={16}/>Fresh host evidence is unavailable. Do not treat previous observations as current state.</div>}
      <div className="ent360-help"><Info size={15}/> After enroll, the worker auto-runs read-only collectors. Tabs never start SSH. Permission needed means the SSH user cannot read that source yet.</div>
    </div>
  </section>
}
