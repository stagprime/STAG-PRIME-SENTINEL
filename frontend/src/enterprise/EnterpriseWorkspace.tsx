/**
 * Sentinel 2.0 frontend-only enterprise workspaces.
 * All numeric values are sourced from existing authenticated, tenant-scoped APIs.
 * NEVER synthesize traffic / uptime / capacity / session counts from missing data.
 * No remote SSH or privileged commands originate from these components.
 */
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import {
  Activity, AlertTriangle, ArrowRight, BarChart3, CheckCircle2, ChevronRight, Clock3,
  Database, FileText, Globe2, HardDrive, LockKeyhole, MapPinned,
  Network, Radio, RefreshCw, Search, Server, ShieldAlert, ShieldCheck, UsersRound,
  WifiOff, Gauge, Info, ArrowUpRight,
} from 'lucide-react'
import type { MonitoringOverview, CachedMonitorServer, MonitoringReport, NetworkFleet, PerformanceFleet, SecurityFleet, SessionRow } from '../api/monitoring'
import { getMonitoringNetwork, getMonitoringPerformance, getMonitoringReport, getMonitoringSecurity } from '../api/monitoring'
import { fetchSecurityAudit } from '../api/users'
import type { SecurityAuditEvent } from '../api/users'
import { fetchOperationsAudit, type OperationsAuditEvent } from '../api/platform'
import { buildHighAlerts, cardMetrics } from './dashboardAlerts'
import { geoLabel, useGeoLabels } from '../hooks/useGeoLabels'
import './EnterpriseWorkspace.css'

export type EnterprisePage =
  'dashboard' | 'live' | 'map' | 'vpn-services' | 'network' | 'performance' |
  'security' | 'audit'
export type EnterpriseServer = {
  id:string; name:string; host:string; client:string; country:string; region:string; provider:string
}
type Props = {
  page:EnterprisePage; inventory:EnterpriseServer[]; overview:MonitoringOverview | null
  inventoryReady:boolean; onOpenServer:(id:string)=>void
  onNavigate:(page:string)=>void; refresh:()=>void; scope:string
  onScopeChange:(value:string)=>void
}
function backendId(id:string) { return id.startsWith('api-') ? id.slice(4) : id }
function metricNum(data:Record<string,unknown> | null | undefined, key:string):number|null {
  const value=data?.[key]; return typeof value==='number' && Number.isFinite(value) && value>=0 ? value:null
}
function detailObject(data:Record<string,unknown> | null | undefined, key:string):Record<string,unknown>|null {
  const value=data?.[key]; return value && typeof value==='object' && !Array.isArray(value) ? value as Record<string,unknown>:null
}
function pct(n:number|null) { return n===null?'—':`${n.toFixed(1)}%` }
function bytes(n:number|null) { if(n===null)return '—'; const u=['B','KiB','MiB','GiB','TiB']; let i=0,v=n; while(v>=1024 && i<u.length-1){v/=1024;i++} return `${v.toFixed(i?1:0)} ${u[i]}` }
function time(iso:string|null|undefined) { if (!iso) return 'Never'; const date=new Date(iso); return Number.isNaN(date.valueOf())?'Unknown':date.toLocaleString() }
function sourceFresh(server:CachedMonitorServer) { return server.health.fresh && server.health.data!==null }
function sessionsFresh(server:CachedMonitorServer) { return server.sessions.fresh && server.sessions.data?.state==='available' && typeof server.sessions.data.total==='number' }
function verifiedSessions(servers:CachedMonitorServer[],running:boolean) {
  const enrolled=servers.filter(s=>s.monitoring_enabled)
  const valid=running?enrolled.filter(sessionsFresh):[]
  if(!valid.length)return {label:'—',coverage:`0 / ${enrolled.length}`,count:null as number|null}
  const count=valid.reduce((sum,s)=>sum+(s.sessions.data?.total ?? 0),0)
  return {label:valid.length===enrolled.length?String(count):`≥ ${count}`,coverage:`${valid.length} / ${enrolled.length}`,count}
}
const colors:Record<string,string>={healthy:'good',degraded:'warn',unreachable:'bad',stale:'muted',worker_offline:'muted',not_enrolled:'muted'}
const labels:Record<string,string>={healthy:'Healthy',degraded:'Degraded',unreachable:'Collector unreachable',stale:'Stale',worker_offline:'Worker offline',not_enrolled:'Not enrolled'}
const collectorHints:Record<string,string>={
  connection_timeout:'SSH port unreachable from this PC (firewall / security list / host down)',
  authentication_failed:'SSH username or key/password rejected',
  host_key_mismatch:'Server host key changed — re-verify in inventory',
  credential_unavailable:'Monitoring credential missing from vault',
  ssh_banner_unavailable:'SSH banner timeout — host overloaded or filtered',
  transport_unavailable:'Network transport error to SSH',
  collector_failed:'SSH connected but collector command failed — will auto-retry',
}
function State({state,info}:{state:string;info?:string}) { return <span title={info} className={`ent-state ent-state-${colors[state]||'muted'}`}><i/>{labels[state]||state.replaceAll('_',' ')}</span> }
function CollectorState({metric}:{metric:CachedMonitorServer}) {
  const hint=metric.error_code?(collectorHints[metric.error_code]||metric.error_code):undefined
  return <div className="ent-collector-cell"><State state={metric.status} info={hint}/>{metric.error_code&&metric.status!=='healthy'&&<small title={hint}>{metric.error_code.replaceAll('_',' ')}</small>}</div>
}
function Panel({title,subtitle,children,action}:{title:string;subtitle?:string;children:ReactNode;action?:ReactNode}) {return <section className="ent-panel"><div className="ent-panel-head"><div><h2>{title}</h2>{subtitle&&<p>{subtitle}</p>}</div>{action}</div>{children}</section>}
function Empty({icon:Icon=Info,title,detail}:{icon?:typeof Info;title:string;detail:string}){return <div className="ent-empty"><span className="ent-empty-icon"><Icon size={23}/></span><strong>{title}</strong><p>{detail}</p></div>}
function Stat({label,value,note,icon:Icon,variant='cyan'}:{label:string;value:string|number;note:string;icon:typeof Server;variant?:'cyan'|'teal'|'amber'|'purple'}){return <div className={`ent-stat ent-stat-${variant}`}><div className="ent-stat-head"><span>{label}</span><Icon size={19}/></div><div className="ent-stat-value">{value}</div><small>{note}</small></div>}
function Table({head,children}:{head:string[];children:ReactNode}) {return <div className="ent-table-scroll"><table className="ent-table"><thead><tr>{head.map(h=><th key={h}>{h}</th>)}</tr></thead><tbody>{children}</tbody></table></div>}
function Unknown({reason}:{reason:string}) {return <span className="ent-unknown" title={reason}>— <span>Unavailable</span></span>}
function Coverage({overview}:{overview:MonitoringOverview|null}) {
  const enrolled=overview?.servers.filter(s=>s.monitoring_enabled)||[]
  const fresh=enrolled.filter(sourceFresh).length
  const running=overview?.worker.status==='running'
  return <div className={`ent-coverage ${running?'':'ent-coverage-off'}`}><span className="ent-coverage-dot"/><strong>Monitoring worker: {overview?running?'Running':'Not running':'Not verified'}</strong><span>{overview?`${fresh}/${enrolled.length} fresh server health observations`:'Waiting for authenticated monitoring data'}</span><span>Last heartbeat: {time(overview?.worker.last_seen_utc)}</span></div>
}
function OpenVpnState({server}:{server:CachedMonitorServer}) {
  if(!sourceFresh(server))return <State state="stale" info="Host health snapshot unavailable or expired"/>
  const health=server.health.data as Record<string,unknown>
  const vpn=detailObject(health,'openvpn')
  const status=typeof vpn?.service_status==='string'?vpn.service_status:null
  return status?<span className={`ent-chip ${status==='active'?'ent-chip-good':'ent-chip-warn'}`}>{status==='active'?'Service active':status}</span>:<Unknown reason="OpenVPN service detection is not present in this verified health snapshot"/>
}
function makeRows(inventory:EnterpriseServer[],overview:MonitoringOverview|null,scope:string){
  const sById=new Map((overview?.servers||[]).map(s=>[s.server_id,s]))
  return inventory.filter(s=>scope==='all'||s.client===scope).map(server=>({server,metric:sById.get(backendId(server.id))||null}))
}
function ServerSessionModal({
  row, running, onClose, onOpenInventory,
}: {
  row: { server: EnterpriseServer; metric: CachedMonitorServer | null } | null
  running: boolean
  onClose: () => void
  onOpenInventory: (id: string) => void
}) {
  const m = cardMetrics(row?.metric || null, running)
  const sessions = m.sessionRows as SessionRow[]
  const geo = useGeoLabels(sessions.map((s) => s.public_ip))
  if (!row) return null
  return (
    <div className="ent-card-modal-backdrop" onClick={onClose}>
      <div className="ent-card-modal" role="dialog" aria-modal="true" aria-label={row.server.name} onClick={(e) => e.stopPropagation()}>
        <div className="ent-card-modal-head">
          <div>
            <span className="ent-kicker"><span /> SERVER SNAPSHOT</span>
            <h3>{row.server.name}</h3>
            <p>{row.server.host} · {row.server.client} · {m.hostname || 'host'}</p>
          </div>
          <button type="button" className="ent-card-modal-x" onClick={onClose} aria-label="Close">×</button>
        </div>
        <div className="ent-card-modal-grid">
          <div><em>Status</em><b><State state={m.status} /></b></div>
          <div><em>CPU</em><b>{pct(m.cpu)}</b></div>
          <div><em>RAM</em><b>{pct(m.ram)}</b></div>
          <div><em>Disk</em><b>{pct(m.disk)}</b></div>
          <div><em>VPN service</em><b>{m.vpnStatus || '—'}</b></div>
          <div><em>Tunnel</em><b>{m.tunnel || '—'}</b></div>
          <div><em>Connected users</em><b>{m.sessions === null ? '—' : m.sessions}</b></div>
          <div><em>Uptime</em><b>{m.uptime === null ? '—' : `${Math.floor(m.uptime / 3600)}h`}</b></div>
        </div>
        <div className="ent-card-modal-sessions">
          <h4>VPN connections</h4>
          {sessions.length === 0 ? (
            <p className="ent-mini">{m.sessions === 0 ? 'No users connected right now.' : 'Session list not in the latest fresh sample.'}</p>
          ) : (
            <div className="ent-table-scroll">
              <table className="ent-table">
                <thead>
                  <tr>
                    <th>USER / CN</th>
                    <th>PUBLIC IP</th>
                    <th>LOCATION</th>
                    <th>VPN IP</th>
                    <th>RX</th>
                    <th>TX</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.slice(0, 80).map((s, i) => (
                    <tr key={`${s.common_name}-${s.public_ip}-${i}`}>
                      <td>
                        <strong>{s.common_name || s.username || '—'}</strong>
                        {s.username && s.common_name && s.username !== s.common_name ? <small>{s.username}</small> : null}
                      </td>
                      <td>{s.public_ip || '—'}</td>
                      <td>{geoLabel(geo, s.public_ip)}</td>
                      <td>{s.vpn_ip || '—'}</td>
                      <td>{bytes(typeof s.bytes_received === 'number' ? s.bytes_received : null)}</td>
                      <td>{bytes(typeof s.bytes_sent === 'number' ? s.bytes_sent : null)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
        <div className="ent-card-modal-actions">
          <button type="button" className="ent-link" onClick={() => onOpenInventory(row.server.id)}>Open inventory details <ArrowRight size={14} /></button>
          <button type="button" className="ent-main-action" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  )
}

function Executive({inventory,overview,onNavigate,onOpenServer,scope}:{inventory:EnterpriseServer[];overview:MonitoringOverview|null;onNavigate:Props['onNavigate'];onOpenServer:Props['onOpenServer'];scope:string}) {
  const rows=makeRows(inventory,overview,scope);const ids=new Set(rows.map(x=>backendId(x.server.id)))
  const metrics=(overview?.servers||[]).filter(s=>ids.has(s.server_id)&&s.monitoring_enabled)
  const running=overview?.worker.status==='running'
  const count=verifiedSessions(metrics,running)
  const fresh=running?metrics.filter(sourceFresh):[]
  const healthy=fresh.filter(s=>s.status==='healthy').length
  const highAlerts=buildHighAlerts(overview).filter(a=>ids.has(a.server_id)||a.code==='worker_offline')
  const [cardFocus,setCardFocus]=useState<string|null>(null)
  // Backend-supported summary windows only. These are aggregates, NOT time-series data.
  const [reportHours,setReportHours]=useState<1|6|24>(24)
  const [reportRevision,setReportRevision]=useState(0)
  const [report,setReport]=useState<MonitoringReport|null>(null)
  const [reportLoading,setReportLoading]=useState(true)
  const [reportError,setReportError]=useState<string|null>(null)
  const [resourceMeasure,setResourceMeasure]=useState<'cpu'|'ram'|'disk'>('cpu')
  useEffect(()=>{
    const ctrl=new AbortController()
    setReport(null)
    setReportError(null)
    setReportLoading(true)
    getMonitoringReport(reportHours,ctrl.signal)
      .then(r=>{if(!ctrl.signal.aborted){setReport(r);setReportLoading(false)}})
      .catch(e=>{if(!ctrl.signal.aborted){setReportError(e instanceof Error?e.message:'Report API unavailable');setReportLoading(false)}})
    return()=>ctrl.abort()
  },[reportHours,reportRevision])
  const scopedReport=(report?.servers||[]).filter(s=>ids.has(s.server_id))
  const resourceRows=scopedReport.filter(s=>s.health_samples>0)
  const sessionRows=scopedReport.filter(s=>s.session_samples>0&&typeof s.peak_observed_connections==='number')
  const reportHealthSamples=resourceRows.reduce((sum,r)=>sum+r.health_samples,0)
  const reportSessionSamples=scopedReport.reduce((sum,r)=>sum+r.session_samples,0)
  const measureKey=resourceMeasure==='cpu'?'average_cpu_percent':resourceMeasure==='ram'?'average_ram_percent':'average_disk_percent'
  const rankedResources=resourceRows.filter(r=>typeof r[measureKey]==='number'&&Number.isFinite(r[measureKey])).slice().sort((a,b)=>(b[measureKey]??0)-(a[measureKey]??0)).slice(0,8)
  const rankedPeaks=sessionRows.slice().sort((a,b)=>(b.peak_observed_connections??0)-(a.peak_observed_connections??0)).slice(0,8)
  const maxObservedPeak=Math.max(0,...rankedPeaks.map(r=>r.peak_observed_connections??0))
  const reportStatus=reportLoading?'Loading authenticated summary…':reportError?`Summary unavailable: ${reportError}`:report?`Source: ${report.source} · Generated: ${time(report.generated_at_utc)}`:'No report received'
  return <div className="ent-page">
    <div className="ent-intro"><div><span className="ent-kicker"><span/> STAG PRIME SENTINEL · NOC</span><h2>Live VPN operations.</h2><p>Add a server once with SSH. Health, tunnel status, and connected users stream automatically from the VPS — no client .ovpn required.</p></div><button className="ent-main-action" onClick={()=>onNavigate('live')}>Open live fleet <ArrowRight size={16}/></button></div>
    <Coverage overview={overview}/>
    <div className="ent-stats"><Stat label="Registered servers" value={rows.length} note="Inventory" icon={Server}/><Stat label="Fresh host readings" value={overview?fresh.length:'—'} note={`${metrics.length} monitored`} icon={Activity} variant="teal"/><Stat label="Connected VPN users" value={count.label} note={`Coverage ${count.coverage}`} icon={UsersRound} variant="teal"/><Stat label="High alerts" value={overview?highAlerts.length:'—'} note="Health / overload" icon={AlertTriangle} variant="amber"/></div>
    {highAlerts.length>0 && (
      <div className="ent-high-alerts" role="status">
        <strong><AlertTriangle size={15}/> High alerts</strong>
        <ul>{highAlerts.slice(0,6).map(a=><li key={a.id}><b>{a.server_name}</b> — {a.title}<span>{a.detail}</span></li>)}</ul>
      </div>
    )}
    <Panel title="Servers" subtitle="Click a card for CPU / RAM / disk / VPN users and live sessions" action={<button className="ent-link" onClick={()=>onNavigate('servers')}>Inventory <ArrowRight size={15}/></button>}>
      {rows.length ? (
        <div className="ent-server-cards">
          {rows.map(({server, metric}) => {
            const m = cardMetrics(metric, running)
            const tone = m.status==='healthy'?'good':m.status==='degraded'||m.status==='unreachable'?'bad':m.status==='not_enrolled'?'muted':'warn'
            return (
              <button
                type="button"
                key={server.id}
                className={`ent-server-card ent-server-card-${tone}`}
                onClick={() => setCardFocus(server.id)}
              >
                <div className="ent-server-card-top">
                  <div>
                    <strong>{server.name}</strong>
                    <small>{server.client} · {server.host}</small>
                  </div>
                  <State state={m.status} />
                </div>
                <div className="ent-server-card-metrics">
                  <span><em>CPU</em><b>{pct(m.cpu)}</b></span>
                  <span><em>RAM</em><b>{pct(m.ram)}</b></span>
                  <span><em>Disk</em><b>{pct(m.disk)}</b></span>
                  <span><em>VPN users</em><b>{m.sessions===null?'—':m.sessions}</b></span>
                </div>
                <div className="ent-server-card-foot">
                  <span>VPN {m.vpnStatus || '—'}</span>
                  <span>{server.region || server.country} · {server.provider}</span>
                </div>
              </button>
            )
          })}
        </div>
      ) : <Empty icon={Server} title="No registered servers in scope" detail="Add a server from inventory to begin authorized read-only monitoring."/>}
    </Panel>
    {cardFocus && (
      <ServerSessionModal
        row={rows.find(r => r.server.id === cardFocus) || null}
        running={running}
        onClose={() => setCardFocus(null)}
        onOpenInventory={(id) => { setCardFocus(null); onOpenServer(id) }}
      />
    )}
    <div className="ent-two-col">
      <Panel title="Fleet health distribution" subtitle="Fresh authenticated host snapshots only" action={<button className="ent-link" onClick={()=>onNavigate('live')}>Inspect fleet <ChevronRight size={15}/></button>}>
        {overview?<><div className="ent-health-bar"><div style={{width:`${metrics.length?healthy/metrics.length*100:0}%`}} className="ent-segment ent-segment-green"/><div style={{width:`${metrics.length?(fresh.length-healthy)/metrics.length*100:0}%`}} className="ent-segment ent-segment-amber"/><div style={{width:`${metrics.length?(metrics.length-fresh.length)/metrics.length*100:0}%`}} className="ent-segment ent-segment-grey"/></div><div className="ent-legend"><span><i className="ent-dot good"/> Fresh healthy {healthy}</span><span><i className="ent-dot warn"/> Fresh attention {fresh.length-healthy}</span><span><i className="ent-dot muted"/> Not fresh {metrics.length-fresh.length}</span></div><div className="ent-panel-foot">Denominator: {metrics.length} monitored targets. Host health does not establish VPN usability.</div></>:<Empty title="Waiting for monitoring" detail="The authenticated monitoring overview has not been received."/>}
      </Panel>
      <Panel title="Source & collection coverage" subtitle="Evidence quality across the active fleet">
        <div className="ent-coverage-stats"><div><strong>{fresh.length}/{metrics.length}</strong><span>Host samples fresh</span></div><div><strong>{running?metrics.filter(sessionsFresh).length:0}/{metrics.length}</strong><span>VPN session sources</span></div><div><strong>{rows.length-metrics.length}</strong><span>Not enrolled / unavailable</span></div></div>
        <div className="ent-panel-foot">Unknown session counts are not treated as zero. API availability does not prove that the worker is active.</div>
      </Panel>
    </div>
    <div className="ent-report-toolbar" aria-label="Historical report controls">
      <div><strong>Historical observation summaries</strong><span>Authenticated backend aggregates · not a live timeline</span></div>
      <div className="ent-window-controls" role="group" aria-label="Historical summary window">
        {([1,6,24] as const).map(h=><button type="button" key={h} aria-pressed={reportHours===h} className={reportHours===h?'selected':''} onClick={()=>setReportHours(h)}>{h}h</button>)}
        <button type="button" className="ent-report-retry" onClick={()=>setReportRevision(v=>v+1)} aria-label="Reload historical summary"><RefreshCw size={15}/> Reload</button>
      </div>
    </div>
    <div className="ent-report-evidence" aria-live="polite">
      <span className="ent-evidence-source"><Database size={15}/> {reportStatus}</span>
      {report&&<><span><strong>{resourceRows.length}/{rows.length}</strong> servers with host samples</span><span><strong>{sessionRows.length}/{rows.length}</strong> servers with session samples</span><span><strong>{reportHealthSamples}</strong> host samples · <strong>{reportSessionSamples}</strong> session samples</span></>}
    </div>
    <div className="ent-two-col ent-dashboard-charts">
      <Panel title="Resource utilization by server" subtitle={`${reportHours}-hour average, from observed host samples · unit: percent`} action={<select aria-label="Resource comparison metric" value={resourceMeasure} onChange={e=>setResourceMeasure(e.target.value as 'cpu'|'ram'|'disk')}><option value="cpu">CPU average</option><option value="ram">Memory average</option><option value="disk">Disk average</option></select>}>
        {reportLoading?<div className="ent-chart-loading">Loading observed resource summary…</div>:reportError?<div role="status" className="ent-report-error">Historical resource summary is unavailable. Try Reload.</div>:rankedResources.length?<div className="ent-aggregate-chart" role="list" aria-label="Resource averages by server">
          {rankedResources.map(r=>{const value=r[measureKey];return <div className="ent-aggregate-row" role="listitem" key={r.server_id}><div className="ent-aggregate-label"><strong title={r.server_name}>{r.server_name}</strong><small>{r.health_samples} host samples</small></div><div className="ent-aggregate-track" role="img" aria-label={`${r.server_name} average ${resourceMeasure}: ${pct(value)}`}><span style={{width:`${Math.min(100,Math.max(0,value??0))}%`}}/></div><b>{pct(value)}</b></div>})}
        </div>:<Empty icon={BarChart3} title="No measured resource averages" detail="No valid observations are available for this metric, time window and authorized client scope."/>}
      </Panel>
      <Panel title="Observed VPN connection peaks" subtitle={`${reportHours}-hour per-server highest observed count · NOT fleet-wide simultaneous peak`} action={<button className="ent-link" onClick={()=>onNavigate('sessions')}>VPN Sessions <ArrowRight size={15}/></button>}>
        {reportLoading?<div className="ent-chart-loading">Loading recorded session observations…</div>:reportError?<div role="status" className="ent-report-error">Historical session observations are unavailable. Try Reload.</div>:rankedPeaks.length?<div className="ent-aggregate-chart ent-session-peaks" role="list" aria-label="Observed per-server connection peaks">
          {rankedPeaks.map(r=>{const value=r.peak_observed_connections!;return <div className="ent-aggregate-row" role="listitem" key={r.server_id}><div className="ent-aggregate-label"><strong title={r.server_name}>{r.server_name}</strong><small>{r.session_samples} status observations</small></div><div className="ent-aggregate-track" role="img" aria-label={`${r.server_name} highest observed connections: ${value}`}><span style={{width:`${maxObservedPeak>0?Math.max(0,Math.min(100,value/maxObservedPeak*100)):0}%`}}/></div><b>{value}</b></div>})}
        </div>:<Empty icon={UsersRound} title="No verified session peaks" detail="No readable OpenVPN status observations exist in this report window. Unknown is not zero."/>}
      </Panel>
    </div>
    <div className="ent-chart-disclaimer"><Info size={16}/><span>Bars show <strong>backend-calculated window aggregates</strong>, not a continuous trend. Missing values are omitted—not zero-filled. A real timestamped CPU/RAM/network/VPN line chart requires future read-only historical-series APIs.</span></div>
  </div>
}
function LiveMeter({label,value}:{label:string;value:number|null}){
  const tone=value===null?'':value>=90?'danger':value>=75?'warning':''
  return <div className="live-meter"><div className="live-meter-top"><span>{label}</span><strong>{pct(value)}</strong></div><div className="live-meter-track">{value!==null&&<i className={tone} style={{width:`${Math.min(100,value)}%`}}/>}</div></div>
}
function Live({inventory,overview,onOpenServer,scope}:{inventory:EnterpriseServer[];overview:MonitoringOverview|null;onOpenServer:Props['onOpenServer'];scope:string}){
  const [search,setSearch]=useState('');const [filter,setFilter]=useState('all');const [sort,setSort]=useState<'name'|'health'>('health')
  const rows=makeRows(inventory,overview,scope).filter(({server,metric})=>[server.name,server.host,server.client,server.provider,server.region].join(' ').toLowerCase().includes(search.toLowerCase())&&(filter==='all'||(metric?.status||'not_enrolled')===filter)).sort((a,b)=>sort==='name'?a.server.name.localeCompare(b.server.name):(a.metric?.status||'zz').localeCompare(b.metric?.status||'zz'))
  const running=overview?.worker.status==='running';const confirmed=rows.filter(x=>x.metric&&sessionsFresh(x.metric)&&running)
  return <div className="ent-page"><Coverage overview={overview}/><div className="ent-stats"><Stat icon={Server} label="Servers in scope" value={rows.length} note="Inventory-scoped"/><Stat icon={Activity} label="Fresh observations" value={overview?rows.filter(x=>x.metric&&sourceFresh(x.metric)&&running).length:'—'} note="Host telemetry" variant="teal"/><Stat icon={UsersRound} label="Connected VPN users" value={verifiedSessions(confirmed.map(x=>x.metric!),!!running).label} note={`${confirmed.length} readable sources`} variant="teal"/><Stat icon={WifiOff} label="Unreachable collectors" value={overview?rows.filter(x=>x.metric?.status==='unreachable').length:'—'} note="Collector path only" variant="amber"/></div>
    <Panel title="Live server cards" subtitle="Each card is one server — health, VPN, sessions and resources at a glance" action={<span className="ent-mini">Worker cache · no SSH from this page</span>}>
      <div className="ent-toolbar"><label className="ent-search"><Search size={16}/><input aria-label="Find server" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search server, client, region…"/></label><select aria-label="Health filter" value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All health states</option>{['healthy','degraded','stale','unreachable','worker_offline','not_enrolled'].map(s=><option value={s} key={s}>{labels[s]}</option>)}</select><select aria-label="Sort fleet" value={sort} onChange={e=>setSort(e.target.value as 'name'|'health')}><option value="health">Sort by health</option><option value="name">Sort by name</option></select><span className="ent-mini">{rows.length} cards</span></div>
      {rows.length?<div className="live-card-grid">
        {rows.map(({server,metric})=>{
          const fresh=!!(metric&&sourceFresh(metric)&&running)
          const h=fresh?metric!.health.data as Record<string,unknown>:null
          const cpu=metricNum(h,'cpu_percent');const ram=metricNum(h,'memory_used_percent');const disk=metricNum(h,'disk_used_percent')
          const sessions=metric&&sessionsFresh(metric)&&running?metric.sessions.data!.total:null
          const status=metric?.status||'not_enrolled'
          return <article key={server.id} className={`live-card live-card-${colors[status]||'muted'}`}>
            <header className="live-card-head">
              <div>
                <button type="button" className="live-card-title" onClick={()=>onOpenServer(server.id)}>{server.name}</button>
                <small>{server.host}</small>
              </div>
              {metric?<CollectorState metric={metric}/>:<State state="not_enrolled"/>}
            </header>
            <div className="live-card-meta">
              <span>{server.client}</span>
              <span>{server.region||server.country||'—'}</span>
              <span>{server.provider||'—'}</span>
            </div>
            <div className="live-card-chips">
              <div className="live-chip"><em>VPN</em>{metric?<OpenVpnState server={metric}/>:<Unknown reason="Not enrolled"/>}</div>
              <div className="live-chip"><em>Sessions</em><strong>{sessions===null?'—':sessions}</strong></div>
              <div className="live-chip"><em>Observed</em><strong className="live-chip-time">{time(metric?.last_checked_utc)}</strong></div>
            </div>
            <div className="live-card-meters">
              <LiveMeter label="CPU" value={cpu}/>
              <LiveMeter label="RAM" value={ram}/>
              <LiveMeter label="Disk" value={disk}/>
            </div>
            <footer className="live-card-foot">
              <button type="button" className="live-card-open" onClick={()=>onOpenServer(server.id)}>Open details <ArrowUpRight size={15}/></button>
            </footer>
          </article>
        })}
      </div>:<Empty title="No servers match the filters" detail="Change the filters or select a different authorized client."/>}
    </Panel></div>
}
function uptimeLabel(seconds:number|null|undefined){
  if(typeof seconds!=='number'||!Number.isFinite(seconds)||seconds<0) return '—'
  const d=Math.floor(seconds/86400),h=Math.floor((seconds%86400)/3600),m=Math.floor((seconds%3600)/60)
  if(d>0) return `${d}d ${h}h`
  if(h>0) return `${h}h ${m}m`
  return `${m}m`
}
function Services({inventory,overview,onOpenServer,scope}:{inventory:EnterpriseServer[];overview:MonitoringOverview|null;onOpenServer:Props['onOpenServer'];scope:string}){
  const [search,setSearch]=useState('')
  const [serviceFilter,setServiceFilter]=useState('all')
  const running=overview?.worker.status==='running'
  const rows=makeRows(inventory,overview,scope).filter(({server,metric})=>{
    const vpn=metric?.vpn_observation
    const hay=[server.name,server.host,server.client,server.region,vpn?.service,vpn?.protocol].join(' ').toLowerCase()
    if(search.trim()&&!hay.includes(search.trim().toLowerCase())) return false
    const status=(vpn?.service_status||'').toLowerCase()
    if(serviceFilter==='active'&&status!=='active') return false
    if(serviceFilter==='inactive'&&!(status==='inactive'||status==='failed'||status==='unknown'||!status)) return false
    if(serviceFilter==='missing-status'&&!!vpn?.sessions_fresh) return false
    return true
  })
  const monitored=rows.filter(x=>x.metric?.monitoring_enabled)
  const active=monitored.filter(x=>(x.metric?.vpn_observation?.service_status||'').toLowerCase()==='active')
  const inactive=monitored.filter(x=>{const s=(x.metric?.vpn_observation?.service_status||'').toLowerCase();return s==='inactive'||s==='failed'})
  const missingStatus=monitored.filter(x=>!x.metric?.vpn_observation?.sessions_fresh)
  const sessionSummary=verifiedSessions(monitored.map(x=>x.metric!).filter(Boolean),!!running)
  return <div className="ent-page">
    <Coverage overview={overview}/>
    <div className="ent-stats">
      <Stat icon={Radio} label="Monitored VPN nodes" value={overview?monitored.length:'—'} note="Enrolled collectors"/>
      <Stat icon={CheckCircle2} label="Service active" value={overview?active.length:'—'} note="systemd unit observed" variant="teal"/>
      <Stat icon={UsersRound} label="Connected users" value={sessionSummary.label} note="Readable status files" variant="teal"/>
      <Stat icon={ShieldAlert} label="Attention" value={overview?(inactive.length+missingStatus.length):'—'} note={`${inactive.length} inactive · ${missingStatus.length} status gap`} variant="amber"/>
    </div>
    <Panel title="VPN service health board" subtitle="Unit · tunnel · status file · sessions · host load — from auto SSH collectors" action={<span className="ent-mini">{running?'Live worker':'Worker offline'}</span>}>
      <div className="ent-toolbar">
        <label className="ent-search"><Search size={16}/><input aria-label="Find VPN service" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search server, unit, protocol…"/></label>
        <select aria-label="Service filter" value={serviceFilter} onChange={e=>setServiceFilter(e.target.value)}>
          <option value="all">All services</option>
          <option value="active">Active only</option>
          <option value="inactive">Inactive / failed</option>
          <option value="missing-status">Status source missing</option>
        </select>
        <span className="ent-mini">{rows.length} cards</span>
      </div>
      {rows.length?<div className="vpn-health-grid">
        {rows.map(({server,metric})=>{
          const vpn=metric?.vpn_observation
          const svc=(vpn?.service_status||'').toLowerCase()
          const tone=svc==='active'?'good':svc==='inactive'||svc==='failed'?'bad':metric?.monitoring_enabled?'warn':'muted'
          const sessions=vpn?.sessions_fresh&&typeof vpn.sessions_total==='number'?vpn.sessions_total:null
          return <article key={server.id} className={`vpn-health-card vpn-health-${tone}`}>
            <header className="vpn-health-head">
              <div>
                <button type="button" className="live-card-title" onClick={()=>onOpenServer(server.id)}>{server.name}</button>
                <small>{server.host} · {server.client} · {server.region}</small>
              </div>
              {metric?<CollectorState metric={metric}/>:<State state="not_enrolled"/>}
            </header>
            <div className="vpn-health-status-row">
              <div className={`vpn-pill vpn-pill-${tone}`}>{svc==='active'?'Service active':svc?`Service ${svc}`:'Service unknown'}</div>
              <div className="vpn-pill muted">{vpn?.protocol||'openvpn'}</div>
              <div className={`vpn-pill ${vpn?.sessions_fresh?'good':'muted'}`}>{vpn?.sessions_fresh?'Status file fresh':(vpn?.sessions_state||'No status source')}</div>
            </div>
            <div className="vpn-health-grid-metrics">
              <div><em>Unit</em><strong title={vpn?.service||''}>{vpn?.service||vpn?.configured_service||'—'}</strong></div>
              <div><em>Tunnel</em><strong>{vpn?.tunnel_interface||vpn?.configured_interface||'—'}</strong></div>
              <div><em>Tunnel IP</em><strong>{vpn?.tunnel_ipv4||'—'}</strong></div>
              <div><em>Sessions</em><strong>{sessions===null?'—':sessions}</strong></div>
              <div><em>Status age</em><strong>{typeof vpn?.status_age_seconds==='number'?`${vpn.status_age_seconds}s`:'—'}</strong></div>
              <div><em>Auth fails</em><strong>{typeof vpn?.auth_failures_observed==='number'?vpn.auth_failures_observed:'—'}</strong></div>
              <div><em>CPU</em><strong>{pct(vpn?.cpu_percent??null)}</strong></div>
              <div><em>RAM</em><strong>{pct(vpn?.memory_used_percent??null)}</strong></div>
              <div><em>Uptime</em><strong>{uptimeLabel(vpn?.uptime_seconds)}</strong></div>
            </div>
            <footer className="vpn-health-foot">
              <span className="fo-muted">Observed {time(vpn?.observed_at_utc||metric?.last_checked_utc)}{vpn?.health_fresh?' · fresh':' · last known'}</span>
              <button type="button" className="live-card-open" onClick={()=>onOpenServer(server.id)}>Server details <ArrowUpRight size={14}/></button>
            </footer>
          </article>
        })}
      </div>:<Empty title="No VPN services in view" detail="Enroll servers in Inventory, or clear the filters."/>}
      <div className="ent-note"><Info size={17}/> Service active means the VPN process is running. It is not proof that a client can reach the internet. Missing status file is never counted as zero sessions.</div>
    </Panel>
  </div>
}
function Sparkline({values,tone}:{values:(number|null)[];tone:string}){
  const pts=values.map((v,i)=>({i,v:typeof v==='number'?v:null})).filter(p=>p.v!==null) as {i:number;v:number}[]
  if(pts.length<2) return <div className="perf-spark empty"/>
  const w=120,h=36,pad=2
  const min=0,max=100
  const path=pts.map((p,idx)=>{
    const x=pad+(p.i/(Math.max(1,values.length-1)))*(w-pad*2)
    const y=h-pad-((p.v-min)/(max-min))*(h-pad*2)
    return `${idx?'L':'M'}${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
  return <svg className={`perf-spark tone-${tone}`} viewBox={`0 0 ${w} ${h}`} aria-hidden><path d={path} fill="none" strokeWidth="2"/></svg>
}
function Performance({inventory,overview,onOpenServer,scope}:{inventory:EnterpriseServer[];overview:MonitoringOverview|null;onOpenServer:Props['onOpenServer'];scope:string}){
  const [fleet,setFleet]=useState<PerformanceFleet|null>(null)
  const [perfError,setPerfError]=useState<string|null>(null)
  const [hours,setHours]=useState<1|6|24>(24)
  const [search,setSearch]=useState('')
  const [filter,setFilter]=useState<'all'|'pressure'|'ok'|'missing'>('all')
  const [sortKey,setSortKey]=useState<'pressure'|'cpu'|'memory'|'disk'|'headroom'>('pressure')
  const [tick,setTick]=useState(0)
  useEffect(()=>{
    const ctrl=new AbortController()
    getMonitoringPerformance(hours,ctrl.signal)
      .then(data=>{if(!ctrl.signal.aborted){setFleet(data);setPerfError(null)}})
      .catch(e=>{if(!ctrl.signal.aborted)setPerfError(e instanceof Error?e.message:'Performance API unavailable')})
    return ()=>ctrl.abort()
  },[hours,tick,overview?.worker.last_seen_utc])
  const inventoryIds=new Set(makeRows(inventory,overview,scope).map(r=>backendId(r.server.id)))
  const inventoryById=new Map(makeRows(inventory,overview,scope).map(r=>[backendId(r.server.id),r.server]))
  const pressureRank={critical:3,elevated:2,ok:1,unknown:0}
  const servers=[...(fleet?.servers||[])]
    .filter(s=>inventoryIds.has(s.server_id))
    .filter(s=>{
      const hay=[s.server_name,s.hottest_resource,s.pressure].join(' ').toLowerCase()
      if(search.trim()&&!hay.includes(search.trim().toLowerCase())) return false
      if(filter==='pressure'&&!(s.pressure==='critical'||s.pressure==='elevated')) return false
      if(filter==='ok'&&s.pressure!=='ok') return false
      if(filter==='missing'&&s.pressure!=='unknown') return false
      return true
    })
    .sort((a,b)=>{
      if(sortKey==='pressure') return (pressureRank[b.pressure]||0)-(pressureRank[a.pressure]||0)
      if(sortKey==='cpu') return (b.live.cpu_percent??-1)-(a.live.cpu_percent??-1)
      if(sortKey==='memory') return (b.live.memory_used_percent??-1)-(a.live.memory_used_percent??-1)
      if(sortKey==='disk') return (b.live.disk_used_percent??-1)-(a.live.disk_used_percent??-1)
      return (a.headroom_percent??999)-(b.headroom_percent??999)
    })
  const summary=fleet?.summary
  const pressure=summary?.pressure
  return <div className="ent-page">
    <Coverage overview={overview}/>
    {perfError&&<div className="ent-note ent-note-warn"><AlertTriangle size={16}/> {perfError}</div>}
    <div className="ent-stats">
      <Stat icon={Gauge} label="Observed now" value={summary?`${summary.observed}/${summary.enrolled}`:'—'} note="Fresh CPU/RAM/disk sources"/>
      <Stat icon={Activity} label="Under pressure" value={pressure?(pressure.critical+pressure.elevated):'—'} note={pressure?`${pressure.critical} critical · ${pressure.elevated} elevated`:'Live thresholds ≥75%'} variant="amber"/>
      <Stat icon={HardDrive} label="Avg headroom" value={summary&&summary.avg_headroom_percent!==null?`${summary.avg_headroom_percent.toFixed(0)}%`:'—'} note="100 − hottest live resource" variant="teal"/>
      <Stat icon={Clock3} label="History samples" value={summary?summary.history_samples:'—'} note={`${hours}h window · stored health`} variant="purple"/>
    </div>
    <Panel title="Performance & capacity board" subtitle="Live utilization · window averages/peaks · pressure & headroom — from worker health samples" action={
      <div className="perf-actions">
        <select aria-label="History window" value={hours} onChange={e=>setHours(Number(e.target.value) as 1|6|24)}>
          <option value={1}>Last 1 hour</option>
          <option value={6}>Last 6 hours</option>
          <option value={24}>Last 24 hours</option>
        </select>
        <button type="button" className="ent-link" onClick={()=>setTick(n=>n+1)}><RefreshCw size={14}/> Refresh</button>
      </div>
    }>
      <div className="ent-toolbar">
        <label className="ent-search"><Search size={16}/><input aria-label="Find performance node" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search server or pressure…"/></label>
        <select aria-label="Pressure filter" value={filter} onChange={e=>setFilter(e.target.value as typeof filter)}>
          <option value="all">All nodes</option>
          <option value="pressure">Elevated / critical</option>
          <option value="ok">Healthy pressure</option>
          <option value="missing">Missing samples</option>
        </select>
        <select aria-label="Sort performance" value={sortKey} onChange={e=>setSortKey(e.target.value as typeof sortKey)}>
          <option value="pressure">Sort: pressure</option>
          <option value="cpu">Sort: CPU</option>
          <option value="memory">Sort: memory</option>
          <option value="disk">Sort: disk</option>
          <option value="headroom">Sort: least headroom</option>
        </select>
        <span className="ent-mini">{servers.length} cards</span>
      </div>
      {servers.length?<div className="perf-board">
        {servers.map(s=>{
          const inv=inventoryById.get(s.server_id)
          const tone=s.pressure==='critical'?'bad':s.pressure==='elevated'?'warn':s.pressure==='ok'?'good':'muted'
          const spark=s.series.map(p=>p.cpu_percent)
          return <article key={s.server_id} className={`perf-card perf-${tone}`}>
            <header className="perf-card-head">
              <div>
                <button type="button" className="live-card-title" onClick={()=>onOpenServer(s.server_id)}>{s.server_name}</button>
                <small>{inv?`${inv.host} · ${inv.region}`:s.status} · {s.window.sample_count} samples · up {uptimeLabel(s.live.uptime_seconds)}</small>
              </div>
              <div className="net-pills">
                <span className={`vpn-pill ${tone==='good'?'good':tone==='bad'?'bad':'muted'}`}>{s.pressure}</span>
                {s.hottest_resource&&<span className="vpn-pill muted">Hottest: {s.hottest_resource}</span>}
                <span className={`vpn-pill ${s.health_fresh?'good':'muted'}`}>{s.health_fresh?'Fresh':'Stale'}</span>
              </div>
            </header>
            <div className="perf-live-row">
              {([
                ['CPU',s.live.cpu_percent,s.window.avg_cpu_percent,s.window.peak_cpu_percent],
                ['RAM',s.live.memory_used_percent,s.window.avg_memory_percent,s.window.peak_memory_percent],
                ['Disk',s.live.disk_used_percent,s.window.avg_disk_percent,s.window.peak_disk_percent],
              ] as const).map(([label,live,avg,peak])=>(
                <div key={label} className="perf-metric">
                  <em>{label}</em>
                  <strong>{pct(live)}</strong>
                  <div className="perf-track"><div className={`perf-fill ${(live??0)>=90?'danger':(live??0)>=75?'warning':''}`} style={{width:`${live===null?0:Math.min(100,live)}%`}}/></div>
                  <small>avg {pct(avg)} · peak {pct(peak)}</small>
                </div>
              ))}
              <div className="perf-metric spark-wrap">
                <em>CPU trend</em>
                <Sparkline values={spark} tone={tone}/>
                <small>Headroom {s.headroom_percent===null?'—':`${s.headroom_percent.toFixed(0)}%`}</small>
              </div>
            </div>
            <footer className="net-foot">
              <span className="fo-muted">Observed {time(s.observed_at_utc)} · {hours}h window</span>
              <button type="button" className="live-card-open" onClick={()=>onOpenServer(s.server_id)}>Server details <ArrowUpRight size={14}/></button>
            </footer>
          </article>
        })}
      </div>:<Empty icon={Gauge} title="No performance nodes in view" detail="Enroll collectors, wait for health samples, or clear filters."/>}
    </Panel>
    <div className="ent-note"><Info size={16}/> Pressure uses live thresholds (≥75% elevated, ≥90% critical). Headroom is remaining room under the hottest resource — not a certified capacity forecast, per-core breakdown, or I/O latency SLA.</div>
  </div>
}
function mbpsLabel(n:number|null|undefined){
  if(typeof n!=='number'||!Number.isFinite(n)) return '—'
  if(n>=100) return `${n.toFixed(0)} Mbps`
  if(n>=10) return `${n.toFixed(1)} Mbps`
  return `${n.toFixed(2)} Mbps`
}
function NetworkPage({inventory,overview,onOpenServer,scope}:{inventory:EnterpriseServer[];overview:MonitoringOverview|null;onOpenServer:Props['onOpenServer'];scope:string}){
  const [fleet,setFleet]=useState<NetworkFleet|null>(null)
  const [netError,setNetError]=useState<string|null>(null)
  const [search,setSearch]=useState('')
  const [filter,setFilter]=useState<'all'|'throughput'|'attention'|'missing'>('all')
  const [tick,setTick]=useState(0)
  useEffect(()=>{
    const ctrl=new AbortController()
    getMonitoringNetwork(ctrl.signal)
      .then((data)=>{if(!ctrl.signal.aborted){setFleet(data);setNetError(null)}})
      .catch((e)=>{if(!ctrl.signal.aborted)setNetError(e instanceof Error?e.message:'Network API unavailable')})
    return ()=>ctrl.abort()
  },[tick,overview?.worker.last_seen_utc])
  const inventoryIds=new Set(makeRows(inventory,overview,scope).map(r=>backendId(r.server.id)))
  const servers=(fleet?.servers||[]).filter(s=>inventoryIds.has(s.server_id)).filter(s=>{
    const hay=[s.server_name,s.wan.interface,s.tunnel.interface,s.tunnel.tunnel_ipv4].join(' ').toLowerCase()
    if(search.trim()&&!hay.includes(search.trim().toLowerCase())) return false
    if(filter==='throughput'&&s.wan.throughput.state!=='available') return false
    if(filter==='attention'&&s.link_integrity!=='attention') return false
    if(filter==='missing'&&!( !s.health_fresh || s.wan.rx_bytes_total===null )) return false
    return true
  })
  const summary=fleet?.summary
  const maxWan=Math.max(0.01,...servers.map(s=>(s.wan.throughput.rx_mbps||0)+(s.wan.throughput.tx_mbps||0)))
  const inventoryById=new Map(makeRows(inventory,overview,scope).map(r=>[backendId(r.server.id),r.server]))
  return <div className="ent-page">
    <Coverage overview={overview}/>
    {netError&&<div className="ent-note ent-note-warn"><AlertTriangle size={16}/> {netError}</div>}
    <div className="ent-stats">
      <Stat icon={Network} label="Counter sources" value={summary?summary.counter_sources:'—'} note="Fresh WAN NIC observations"/>
      <Stat icon={Activity} label="Fleet WAN throughput" value={summary&&summary.fleet_wan_rx_mbps!==null?`↓${mbpsLabel(summary.fleet_wan_rx_mbps).replace(' Mbps','')} / ↑${mbpsLabel(summary.fleet_wan_tx_mbps).replace(' Mbps','')}`:'—'} note={summary?`${summary.wan_throughput_servers} servers with Mbps delta`:'Need ≥2 health samples'} variant="teal"/>
      <Stat icon={Radio} label="Tunnel throughput" value={summary&&summary.fleet_tunnel_rx_mbps!==null?`↓${mbpsLabel(summary.fleet_tunnel_rx_mbps).replace(' Mbps','')} / ↑${mbpsLabel(summary.fleet_tunnel_tx_mbps).replace(' Mbps','')}`:'—'} note={summary?`${summary.tunnel_throughput_servers} tunnels with Mbps`:'Tunnel counters after next health poll'} variant="purple"/>
      <Stat icon={ShieldAlert} label="Link integrity" value={summary?summary.link_attention:'—'} note="Servers with NIC errors or drops" variant="amber"/>
    </div>
    <Panel title="Network & bandwidth board" subtitle="WAN NIC Mbps · VPN tunnel Mbps · cumulative counters · errors/drops — from worker health samples" action={<button type="button" className="ent-link" onClick={()=>setTick(n=>n+1)}><RefreshCw size={14}/> Refresh</button>}>
      <div className="ent-toolbar">
        <label className="ent-search"><Search size={16}/><input aria-label="Find network node" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search server, NIC, tunnel…"/></label>
        <select aria-label="Network filter" value={filter} onChange={e=>setFilter(e.target.value as typeof filter)}>
          <option value="all">All nodes</option>
          <option value="throughput">Mbps available</option>
          <option value="attention">Errors / drops</option>
          <option value="missing">Missing counters</option>
        </select>
        <span className="ent-mini">{servers.length} cards</span>
      </div>
      {servers.length?<div className="net-board">
        {servers.map(s=>{
          const inv=inventoryById.get(s.server_id)
          const wanMbps=(s.wan.throughput.rx_mbps||0)+(s.wan.throughput.tx_mbps||0)
          const tone=s.link_integrity==='attention'?'warn':s.wan.throughput.state==='available'?'good':s.health_fresh?'muted':'bad'
          return <article key={s.server_id} className={`net-card net-${tone}`}>
            <header className="net-card-head">
              <div>
                <button type="button" className="live-card-title" onClick={()=>onOpenServer(s.server_id)}>{s.server_name}</button>
                <small>{inv?`${inv.host} · ${inv.region}`:s.status} · {s.sample_count} samples</small>
              </div>
              <div className="net-pills">
                <span className={`vpn-pill ${s.health_fresh?'good':'muted'}`}>{s.health_fresh?'Health fresh':'Stale / missing'}</span>
                <span className={`vpn-pill ${s.link_integrity==='attention'?'bad':s.link_integrity==='ok'?'good':'muted'}`}>
                  {s.link_integrity==='attention'?'Errors/drops':s.link_integrity==='ok'?'Link clean':'Integrity unknown'}
                </span>
              </div>
            </header>
            <div className="net-throughput">
              <div>
                <em>WAN Mbps · {s.wan.interface||'nic'}</em>
                <strong>{s.wan.throughput.state==='available'?`↓ ${mbpsLabel(s.wan.throughput.rx_mbps)} · ↑ ${mbpsLabel(s.wan.throughput.tx_mbps)}`:'—'}</strong>
                <div className="net-bar"><div style={{width:`${s.wan.throughput.state==='available'?Math.max(4,(wanMbps/maxWan)*100):0}%`}}/></div>
                <small>{s.wan.throughput.note||'Need two consecutive samples'}</small>
              </div>
              <div>
                <em>Tunnel Mbps · {s.tunnel.interface||'tun'}</em>
                <strong>{s.tunnel.throughput.state==='available'?`↓ ${mbpsLabel(s.tunnel.throughput.rx_mbps)} · ↑ ${mbpsLabel(s.tunnel.throughput.tx_mbps)}`:'—'}</strong>
                <small>{s.tunnel.tunnel_ipv4||s.tunnel.service_status||'Tunnel counters from health poll'}</small>
              </div>
            </div>
            <div className="net-metrics">
              <div><em>WAN RX total</em><strong>{bytes(s.wan.rx_bytes_total)}</strong></div>
              <div><em>WAN TX total</em><strong>{bytes(s.wan.tx_bytes_total)}</strong></div>
              <div><em>Tunnel RX</em><strong>{bytes(s.tunnel.rx_bytes_total)}</strong></div>
              <div><em>Tunnel TX</em><strong>{bytes(s.tunnel.tx_bytes_total)}</strong></div>
              <div><em>RX errors</em><strong>{s.wan.rx_errors_total??'—'}</strong></div>
              <div><em>TX errors</em><strong>{s.wan.tx_errors_total??'—'}</strong></div>
              <div><em>RX drops</em><strong>{s.wan.rx_dropped_total??'—'}</strong></div>
              <div><em>TX drops</em><strong>{s.wan.tx_dropped_total??'—'}</strong></div>
            </div>
            <footer className="net-foot">
              <span className="fo-muted">Observed {time(s.observed_at_utc)}{typeof s.wan.throughput.window_seconds==='number'?` · Δ ${s.wan.throughput.window_seconds}s`:''}</span>
              <button type="button" className="live-card-open" onClick={()=>onOpenServer(s.server_id)}>Server details <ArrowUpRight size={14}/></button>
            </footer>
          </article>
        })}
      </div>:<Empty icon={Network} title="No network nodes in view" detail="Enroll collectors in Inventory, wait for two health samples, or clear filters."/>}
    </Panel>
    <div className="ent-note"><Info size={16}/> This page shows <strong>observed bandwidth</strong> from SSH health counter deltas — not ISP speed tests or client-side latency. WAN NIC and VPN tunnel counters are separate; never add them. External ping/probe quality still needs an independently approved probe.</div>
  </div>
}
function MapPage({inventory,overview,onOpenServer,scope}:{inventory:EnterpriseServer[];overview:MonitoringOverview|null;onOpenServer:Props['onOpenServer'];scope:string}){
  const [search,setSearch]=useState('')
  const [healthFilter,setHealthFilter]=useState('all')
  const running=overview?.worker.status==='running'
  const rows=makeRows(inventory,overview,scope).filter(({server,metric})=>{
    const hay=[server.name,server.host,server.client,server.country,server.region,server.provider].join(' ').toLowerCase()
    if(search.trim()&&!hay.includes(search.trim().toLowerCase())) return false
    if(healthFilter!=='all'&&(metric?.status||'not_enrolled')!==healthFilter) return false
    return true
  })
  const grouped=Object.entries(rows.reduce<Record<string,typeof rows>>((acc,row)=>{
    const key=row.server.country&&row.server.country!=='Unspecified'?row.server.country:(row.server.region||'Unspecified location')
    ;(acc[key]??=[]).push(row)
    return acc
  },{})).sort(([a],[b])=>a.localeCompare(b))
  const regionStats=grouped.map(([name,items])=>{
    const healthy=items.filter(x=>x.metric?.status==='healthy').length
    const bad=items.filter(x=>x.metric?.status==='unreachable'||x.metric?.status==='degraded').length
    const sessions=items.reduce((sum,x)=>{
      if(x.metric&&sessionsFresh(x.metric)&&running&&typeof x.metric.sessions.data?.total==='number') return sum+x.metric.sessions.data.total
      return sum
    },0)
    const sessionCoverage=items.filter(x=>x.metric&&sessionsFresh(x.metric)&&running).length
    return {name,items,healthy,bad,sessions,sessionCoverage}
  })
  const totalSessions=regionStats.reduce((s,r)=>s+r.sessions,0)
  const attentionRegions=regionStats.filter(r=>r.bad>0).length
  return <div className="ent-page">
    <Coverage overview={overview}/>
    <div className="ent-stats">
      <Stat icon={Globe2} label="Regions" value={regionStats.length} note="Inventory country/region"/>
      <Stat icon={Server} label="Nodes on map" value={rows.length} note="Filtered fleet" variant="teal"/>
      <Stat icon={UsersRound} label="Connected users" value={overview?String(totalSessions):'—'} note="Sum of readable region sources" variant="teal"/>
      <Stat icon={AlertTriangle} label="Regions with issues" value={attentionRegions} note="Degraded / unreachable nodes" variant="amber"/>
    </div>
    <div className="ent-note"><MapPinned size={17}/> Live fleet map by inventory geography · health & sessions from the monitoring worker · not a GPS/IP geocode map.</div>
    <Panel title="Regional fleet map" subtitle="Each region card shows live collector health and VPN load" action={<span className="ent-mini">{running?'Worker live':'Worker offline'}</span>}>
      <div className="ent-toolbar">
        <label className="ent-search"><Search size={16}/><input aria-label="Find on map" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search region, server, host…"/></label>
        <select aria-label="Health filter" value={healthFilter} onChange={e=>setHealthFilter(e.target.value)}>
          <option value="all">All health</option>
          {['healthy','degraded','unreachable','stale','worker_offline','not_enrolled'].map(s=><option key={s} value={s}>{labels[s]}</option>)}
        </select>
        <span className="ent-mini">{regionStats.length} regions</span>
      </div>
      {regionStats.length?<div className="fmap-grid">
        {regionStats.map(region=>(
          <section key={region.name} className={`fmap-region ${region.bad?'fmap-region-alert':region.healthy===region.items.length?'fmap-region-good':''}`}>
            <header className="fmap-region-head">
              <div className="fmap-region-title"><Globe2 size={18}/><div><h3>{region.name}</h3><small>{region.items.length} node{region.items.length===1?'':'s'} · {region.healthy} healthy{region.bad?` · ${region.bad} attention`:''}</small></div></div>
              <div className="fmap-region-kpis">
                <div><em>Sessions</em><strong>{region.sessionCoverage?region.sessions:'—'}</strong></div>
                <div><em>Health</em><strong>{region.healthy}/{region.items.length}</strong></div>
              </div>
            </header>
            <div className="fmap-nodes">
              {region.items.map(({server,metric})=>{
                const status=metric?.status||'not_enrolled'
                const sessions=metric&&sessionsFresh(metric)&&running?metric.sessions.data!.total:null
                const h=metric&&sourceFresh(metric)&&running?metric.health.data as Record<string,unknown>:null
                const cpu=metricNum(h,'cpu_percent')
                return <button type="button" className={`fmap-node fmap-node-${colors[status]||'muted'}`} key={server.id} onClick={()=>onOpenServer(server.id)}>
                  <div className="fmap-node-top">
                    <strong>{server.name}</strong>
                    <State state={status}/>
                  </div>
                  <small>{server.host}</small>
                  <div className="fmap-node-meta">
                    <span>{server.region||server.country||'—'}</span>
                    <span>{server.provider||'—'}</span>
                  </div>
                  <div className="fmap-node-stats">
                    <span>VPN {metric?<OpenVpnState server={metric}/>:'—'}</span>
                    <span>Sessions <b>{sessions===null?'—':sessions}</b></span>
                    <span>CPU <b>{pct(cpu)}</b></span>
                  </div>
                  <span className="fmap-node-open">Open <ChevronRight size={14}/></span>
                </button>
              })}
            </div>
          </section>
        ))}
      </div>:<Empty icon={Globe2} title="No geography in the selected scope" detail="Add country/region metadata in Server Inventory, or clear filters."/>}
    </Panel>
  </div>
}
function AuditTrailPage(){
  const [tab,setTab]=useState<'account'|'operations'>('account')
  const [events,setEvents]=useState<SecurityAuditEvent[]|null>(null)
  const [ops,setOps]=useState<OperationsAuditEvent[]|null>(null)
  const [error,setError]=useState<string|null>(null)
  const [loading,setLoading]=useState(true)
  const [query,setQuery]=useState('')
  const [tick,setTick]=useState(0)
  useEffect(()=>{
    const ctrl=new AbortController()
    setLoading(true)
    Promise.all([fetchSecurityAudit(100), fetchOperationsAudit(100)])
      .then(([account, operations])=>{
        if(ctrl.signal.aborted) return
        setEvents(account.events)
        setOps(operations.events)
        setError(null)
        setLoading(false)
      })
      .catch(e=>{if(!ctrl.signal.aborted){setError(e instanceof Error?e.message:'Audit API unavailable');setEvents(null);setOps(null);setLoading(false)}})
    return()=>ctrl.abort()
  },[tick])
  const accountRows=(events||[]).filter(e=>{
    const hay=[e.action,e.actor_user_id,e.target_user_id||'',JSON.stringify(e.details||{})].join(' ').toLowerCase()
    return hay.includes(query.toLowerCase())
  })
  const opsRows=(ops||[]).filter(e=>{
    const hay=[e.operation,e.result,e.server_name,e.actor_id].join(' ').toLowerCase()
    return hay.includes(query.toLowerCase())
  })
  return <div className="ent-page">
    <div className="ent-cap-hero"><div className="ent-cap-icon"><LockKeyhole size={27}/></div><div><span className="ent-kicker">PLATFORM ADMINISTRATION / AUDIT</span><h2>Administrative audit trail</h2><p>Account changes and privileged server operations. Records omit passwords, keys, hosts, and command text.</p></div><span className="ent-feature-state">Live API</span></div>
    <Panel title={tab==='account'?'Account security events':'Server operation events'} subtitle={tab==='account'?'GET /api/admin/audit':'GET /api/server-operations/operations-audit'} action={<button className="ent-link" onClick={()=>setTick(n=>n+1)}><RefreshCw size={15}/> Reload</button>}>
      <div className="ent-toolbar">
        <label className="ent-search"><Search size={15}/><input placeholder={tab==='account'?'Search action, actor, target…':'Search operation, server, result…'} value={query} onChange={e=>setQuery(e.target.value)}/></label>
        <select aria-label="Audit source" value={tab} onChange={e=>setTab(e.target.value==='operations'?'operations':'account')}><option value="account">Account audit</option><option value="operations">Server operations</option></select>
      </div>
      {loading&&<Empty title="Loading audit events…" detail="Fetching account and operations audit records."/>}
      {error&&<div role="alert" className="ent-error">{error}</div>}
      {!loading&&!error&&tab==='account'&&accountRows.length>0&&<Table head={['WHEN','ACTION','ACTOR','TARGET','DETAILS']}>
        {accountRows.map(e=><tr key={e.id}><td>{time(e.created_at_utc)}</td><td><strong>{e.action.replaceAll('_',' ')}</strong></td><td className="monospaced">{e.actor_user_id.slice(0,8)}…</td><td className="monospaced">{e.target_user_id?`${e.target_user_id.slice(0,8)}…`:'—'}</td><td><small>{Object.keys(e.details||{}).length?JSON.stringify(e.details):'—'}</small></td></tr>)}
      </Table>}
      {!loading&&!error&&tab==='operations'&&opsRows.length>0&&<Table head={['WHEN','OPERATION','SERVER','RESULT','ACTOR']}>
        {opsRows.map(e=><tr key={e.id}><td>{time(e.happened_at_utc)}</td><td><strong>{e.operation.replaceAll('_',' ')}</strong></td><td>{e.server_name}</td><td><span className={`ent-chip ${e.result==='ok'||e.result==='success'?'ent-chip-muted':'ent-chip-warn'}`}>{e.result}</span></td><td className="monospaced">{e.actor_id.slice(0,8)}…</td></tr>)}
      </Table>}
      {!loading&&!error&&tab==='account'&&!accountRows.length&&<Empty icon={ShieldCheck} title={events?.length?'No matching events':'No account audit events yet'} detail={events?.length?'Try a different search.':'User management and password actions will appear here.'}/>}
      {!loading&&!error&&tab==='operations'&&!opsRows.length&&<Empty icon={ShieldCheck} title={ops?.length?'No matching operations':'No server operations recorded yet'} detail={ops?.length?'Try a different search.':'Verify, discover, enroll, and VPN control actions will appear here.'}/>}
    </Panel>
  </div>
}
function SecurityPage({inventory,overview,onOpenServer,scope}:{inventory:EnterpriseServer[];overview:MonitoringOverview|null;onOpenServer:Props['onOpenServer'];scope:string}){
  const [fleet,setFleet]=useState<SecurityFleet|null>(null)
  const [secError,setSecError]=useState<string|null>(null)
  const [search,setSearch]=useState('')
  const [filter,setFilter]=useState<'all'|'attention'|'certs'|'auth'|'missing'>('all')
  const [tick,setTick]=useState(0)
  useEffect(()=>{
    const ctrl=new AbortController()
    getMonitoringSecurity(ctrl.signal)
      .then(data=>{if(!ctrl.signal.aborted){setFleet(data);setSecError(null)}})
      .catch(e=>{if(!ctrl.signal.aborted)setSecError(e instanceof Error?e.message:'Security API unavailable')})
    return ()=>ctrl.abort()
  },[tick,overview?.worker.last_seen_utc])
  const inventoryIds=new Set(makeRows(inventory,overview,scope).map(r=>backendId(r.server.id)))
  const inventoryById=new Map(makeRows(inventory,overview,scope).map(r=>[backendId(r.server.id),r.server]))
  const servers=(fleet?.servers||[]).filter(s=>inventoryIds.has(s.server_id)).filter(s=>{
    const hay=[s.server_name,s.protocol,s.certificate.path,s.journal.unit].join(' ').toLowerCase()
    if(search.trim()&&!hay.includes(search.trim().toLowerCase())) return false
    if(filter==='attention'&&!(s.attention==='high'||s.attention==='medium')) return false
    if(filter==='certs'&&!(s.certificate_attention==='expired'||s.certificate_attention==='critical'||s.certificate_attention==='expiring')) return false
    if(filter==='auth'&&s.auth_attention!=='elevated') return false
    if(filter==='missing'&&!(s.certificate.state!=='available'||s.auth_failures.state!=='available')) return false
    return true
  }).sort((a,b)=>{
    const rank={high:3,medium:2,unknown:1,ok:0}
    return (rank[b.attention]||0)-(rank[a.attention]||0)
  })
  const incidents=(fleet?.incidents||[]).filter(i=>inventoryIds.has(i.server_id))
  const summary=fleet?.summary
  const certLabel=(attn:string,days:number|null)=>{
    if(attn==='expired') return 'Certificate expired'
    if(attn==='critical') return `Expires in ${days}d`
    if(attn==='expiring') return `Expires in ${days}d`
    if(attn==='permission') return 'Cert permission needed'
    if(attn==='ok') return days!==null?`${days}d remaining`:'Cert OK'
    return 'Cert not observed'
  }
  return <div className="ent-page">
    <Coverage overview={overview}/>
    {secError&&<div className="ent-note ent-note-warn"><AlertTriangle size={16}/> {secError}</div>}
    <div className="ent-stats">
      <Stat icon={ShieldAlert} label="High attention" value={summary?summary.servers_high_attention:'—'} note="Cert / auth / open security signals"/>
      <Stat icon={LockKeyhole} label="Certificate watch" value={summary?summary.cert_attention:'—'} note={summary?`${summary.cert_observed} certs readable`:'Public cert metadata only'} variant="amber"/>
      <Stat icon={ShieldCheck} label="Auth fail sources" value={summary?summary.auth_sources:'—'} note={summary?`${summary.auth_elevated} elevated (≥10)`:'VPN/auth log counters'} variant="teal"/>
      <Stat icon={FileText} label="Security incidents" value={summary?summary.open_security_incidents:'—'} note={`${summary?.journal_sources??'—'} journals readable`} variant="purple"/>
    </div>
    <Panel title="Security intelligence board" subtitle="Certificates · auth failures · journal peek · related open incidents — from stored SSH samples" action={<button type="button" className="ent-link" onClick={()=>setTick(n=>n+1)}><RefreshCw size={14}/> Refresh</button>}>
      <div className="ent-toolbar">
        <label className="ent-search"><Search size={16}/><input aria-label="Find security node" value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search server, cert path, unit…"/></label>
        <select aria-label="Security filter" value={filter} onChange={e=>setFilter(e.target.value as typeof filter)}>
          <option value="all">All nodes</option>
          <option value="attention">Needs attention</option>
          <option value="certs">Cert expiring / expired</option>
          <option value="auth">Elevated auth fails</option>
          <option value="missing">Missing cert/auth source</option>
        </select>
        <span className="ent-mini">{servers.length} cards</span>
      </div>
      {servers.length?<div className="sec-board">
        {servers.map(s=>{
          const inv=inventoryById.get(s.server_id)
          const tone=s.attention==='high'?'bad':s.attention==='medium'?'warn':s.attention==='ok'?'good':'muted'
          return <article key={s.server_id} className={`sec-card sec-${tone}`}>
            <header className="sec-card-head">
              <div>
                <button type="button" className="live-card-title" onClick={()=>onOpenServer(s.server_id)}>{s.server_name}</button>
                <small>{inv?`${inv.host} · ${inv.region}`:s.status} · {s.protocol||'vpn'} · {s.open_security_incidents} open signals</small>
              </div>
              <div className="net-pills">
                <span className={`vpn-pill ${tone==='good'?'good':tone==='bad'?'bad':'muted'}`}>{s.attention}</span>
                <span className={`vpn-pill ${s.health_fresh?'good':'muted'}`}>{s.health_fresh?'Health fresh':'Health stale'}</span>
              </div>
            </header>
            <div className="sec-grid">
              <div>
                <em>Certificate</em>
                <strong>{certLabel(s.certificate_attention,s.certificate.days_remaining)}</strong>
                <small>{s.certificate.state}{s.certificate.not_after?` · ${s.certificate.not_after}`:''}</small>
              </div>
              <div>
                <em>Auth failures</em>
                <strong>{s.auth_failures.state==='available'?String(s.auth_failures.failed_attempts_observed):'—'}</strong>
                <small>{s.auth_attention==='elevated'?'Elevated window':(s.auth_failures.note||'No auth counter')}</small>
              </div>
              <div>
                <em>Journal</em>
                <strong>{s.journal.state||'—'}</strong>
                <small>{s.journal.unit||'unit n/a'} · {s.journal.line_count} lines</small>
              </div>
            </div>
            {!!s.journal.lines?.length&&(
              <div className="sec-journal">
                {s.journal.lines.slice(0,3).map((line,idx)=><code key={idx}>{line}</code>)}
              </div>
            )}
            <footer className="net-foot">
              <span className="fo-muted">Observed {time(s.observed_at_utc)}</span>
              <button type="button" className="live-card-open" onClick={()=>onOpenServer(s.server_id)}>Server details <ArrowUpRight size={14}/></button>
            </footer>
          </article>
        })}
      </div>:<Empty icon={ShieldAlert} title="No security nodes in view" detail="Enroll collectors and wait for health/session samples, or clear filters."/>}
    </Panel>
    <Panel title="Related open security incidents" subtitle="Filtered collector incidents · severity from known codes">
      {incidents.length?<Table head={['INCIDENT','SERVER','SEVERITY','LAST SEEN','ACTION']}>
        {incidents.slice(0,40).map(i=><tr key={i.id}>
          <td><strong>{i.title}</strong><small>{i.code.replaceAll('_',' ')} · #{i.id}</small></td>
          <td>{i.server_name}</td>
          <td><span className={`ent-chip ${i.severity==='high'?'ent-chip-warn':'ent-chip-muted'}`}>{i.severity}</span></td>
          <td>{time(i.last_seen_at_utc)}</td>
          <td><button type="button" className="ent-row-link" onClick={()=>onOpenServer(i.server_id)}>Investigate</button></td>
        </tr>)}
      </Table>:<Empty icon={ShieldCheck} title="No related open incidents" detail="Security-relevant open incidents will appear here when the worker records them."/>}
    </Panel>
    <div className="ent-note"><Info size={16}/> This board shows <strong>observed evidence</strong> only — certificate expiry, auth-fail counters, journal peeks. It does not invent compromise scores, geo threat maps, or external threat-intel feeds.</div>
  </div>
}
function CapabilityPage(){
 return <AuditTrailPage/>
}
export default function EnterpriseWorkspace({page,inventory,overview,inventoryReady,onOpenServer,onNavigate,refresh,scope,onScopeChange}:Props) {
 const clients=[...new Set(inventory.map(s=>s.client))].sort()
 const contents=page==='dashboard'?<Executive inventory={inventory} overview={overview} onNavigate={onNavigate} onOpenServer={onOpenServer} scope={scope}/>
 :page==='live'?<Live inventory={inventory} overview={overview} onOpenServer={onOpenServer} scope={scope}/>
 :page==='vpn-services'?<Services inventory={inventory} overview={overview} onOpenServer={onOpenServer} scope={scope}/>
 :page==='performance'?<Performance inventory={inventory} overview={overview} onOpenServer={onOpenServer} scope={scope}/>
 :page==='network'?<NetworkPage inventory={inventory} overview={overview} onOpenServer={onOpenServer} scope={scope}/>
 :page==='map'?<MapPage inventory={inventory} overview={overview} onOpenServer={onOpenServer} scope={scope}/>
 :page==='security'?<SecurityPage inventory={inventory} overview={overview} onOpenServer={onOpenServer} scope={scope}/>
 :<CapabilityPage/>
 return <div className="ent-workspace"><div className="ent-global-bar"><div className="ent-global-context"><Database size={16}/><span>{inventoryReady?'Backend inventory connected':'Inventory not verified'}</span><i/></div><div className="ent-global-controls"><label>Organization <select value={scope} onChange={e=>onScopeChange(e.target.value)}><option value="all">All authorized clients</option>{clients.map(c=><option key={c} value={c}>{c}</option>)}</select></label><button onClick={refresh} title="Refresh cached monitoring overview"><RefreshCw size={15}/> Refresh</button></div></div>{contents}</div>
}
