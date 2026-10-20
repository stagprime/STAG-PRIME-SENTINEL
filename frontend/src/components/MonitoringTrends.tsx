import { useEffect, useMemo, useState } from 'react'
import { Activity, Clock3 } from 'lucide-react'
import type { CachedMonitorServer } from '../api/monitoring'
import './MonitoringTrends.css'

type HistoryPoint = { at_utc: string; state: string; data: Record<string, unknown> }
function fmt(date: string) { return new Date(date).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}) }
function lines(values: {v:number,x:number}[], width:number, height:number):string {
  return values.map((s,i) => `${i===0?'M':'L'}${(s.x*width).toFixed(1)} ${(height-s.v*height/100).toFixed(1)}`).join(' ')
}
export default function MonitoringTrends({servers}: {servers: CachedMonitorServer[]}) {
  const targets=useMemo(()=>servers.filter(s=>s.monitoring_enabled),[servers])
  const [serverId,setServerId]=useState('')
  const selected=targets.some(s=>s.server_id===serverId)?serverId:(targets[0]?.server_id || '')
  const [health,setHealth]=useState<HistoryPoint[]>([])
  const [sessions,setSessions]=useState<HistoryPoint[]>([])
  const [error,setError]=useState<string|null>(null)
  useEffect(()=>{
    if (!selected) {return}
    const controller=new AbortController()
    async function refresh(){
      try{
        const urls= ['health','sessions'].map(kind=>`/api/monitoring/servers/${encodeURIComponent(selected)}/history?kind=${kind}&limit=60`)
        const [a,b]=await Promise.all(urls.map(url=>fetch(url,{credentials:'same-origin',cache:'no-store',signal:controller.signal})))
        if (!a.ok || !b.ok)throw new Error('Monitoring history unavailable')
        const [ap,bp]=await Promise.all([a.json(),b.json()])
        if (!controller.signal.aborted){
          setHealth(Array.isArray(ap.samples)?ap.samples.slice().reverse():[])
          setSessions(Array.isArray(bp.samples)?bp.samples.slice().reverse():[])
          setError(null)
        }
      }catch(e){if(!controller.signal.aborted){setError(e instanceof Error?e.message:'History unavailable');setHealth([]);setSessions([])}}
    }
    void refresh()
    const timer=window.setInterval(()=>void refresh(),60000)
    return ()=>{controller.abort();window.clearInterval(timer)}
  },[selected])
  const numeric=health.map((s,i)=>({x:health.length<=1?.5:i/(health.length-1),v:s.data.cpu_percent})).filter((p):p is {x:number,v:number}=>typeof p.v==='number' && Number.isFinite(p.v))
  const plotted=numeric.length>1
  const sessionTotals=sessions.map(s=>typeof s.data.total==='number'?s.data.total:null)
  const valid=sessionTotals.filter((v):v is number=>v!==null)
  const peak=valid.length?Math.max(...valid):null
  return <section className="mt-panel" aria-label="Historical monitoring trends">
    <header><div><div className="mt-eyebrow">BACKGROUND METRICS / SNAPSHOT HISTORY</div><h2>Performance & VPN capacity</h2><p>Observed readings, not a benchmarked maximum user limit</p></div>
      <select aria-label="Select monitored server for historical trends" value={selected} onChange={e=>setServerId(e.target.value)}>{targets.map(s=><option key={s.server_id} value={s.server_id}>{s.server_name}</option>)}</select>
    </header>
    <div className="mt-charts"><div><h3><Activity size={15}/> CPU usage history</h3>
      {plotted?<><svg viewBox="0 0 420 120" preserveAspectRatio="none" role="img" aria-label="CPU percent trend"><path d="M0 119 H420 M0 60 H420 M0 1 H420" stroke="#dde8ef" fill="none"/><path d={lines(numeric,420,120)} stroke="#0980a3" strokeWidth="3" fill="none" vectorEffect="non-scaling-stroke" strokeLinecap="round"/></svg><div className="mt-time"><span>{fmt(health[0].at_utc)}</span><span>{fmt(health[health.length-1].at_utc)}</span></div></>
      : <div className="mt-empty">{error || 'Waiting for two verified health samples'}</div>}</div>
      <div><h3><Clock3 size={15}/> Observed VPN connections</h3>
        <div className="mt-total"><strong>{peak===null?'—':peak}</strong><span>Peak observed connections (last {sessions.length} snapshots)</span></div>
        {sessions.length && valid.length ? <div className="mt-bars">{sessionTotals.map((n,i)=><span key={i} className={n===null?'unknown':''} title={n===null?'Unavailable':`${n} connections`} style={{height:n===null?'3px':`${Math.max(3,100*n/Math.max(1,peak||1))}%`}}/>)}</div>
        : <div className="mt-empty">Unknown until valid OpenVPN status snapshots arrive</div>}
      </div></div>
    <footer>Health: 60-second samples · VPN: 30-second samples · No live SSH triggered by this chart</footer>
  </section>
}
