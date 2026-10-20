import { useEffect, useMemo, useRef, useState } from 'react'
import { Activity, AlertTriangle, Archive, CalendarClock, ChevronRight, Clock3, HardDrive, Info, LockKeyhole, PauseCircle, PlayCircle, RefreshCw, RotateCcw, Search, Server, ShieldCheck, ShieldOff, Wrench, X } from 'lucide-react'
import { getAdminProfiles } from '../api/serverOperations'
import type { AdminProfileStatus } from '../api/serverOperations'
import {
  executeControlAction, getControlCatalog, getControlReadiness, getDiagnosticCatalog,
  isExecutableAction, requestControlPreview, runDiagnostic,
} from '../api/serverControl'
import type {
  ControlExecuteResult, ControlPreview, ControlReadiness, DiagnosticCheck, DiagnosticResult, ServerControlAction,
} from '../api/serverControl'
import './ServerControlCenter.css'

export type ControlServer = {
  id: string; name: string; client: string; location: string; provider: string
  archived: boolean; observation: string; vpnState: string; observedAt: string | null
}

type ActionKey = ServerControlAction
type ActionDefinition = { key: ActionKey; name: string; description: string; caution: boolean; icon: typeof RotateCcw; requirement: string }
const ACTIONS: ActionDefinition[] = [
  { key: 'restart', name: 'Restart server', description: 'Graceful VPS restart with recovery checks', caution: true, icon: RotateCcw, requirement: 'Confirm a recovery path, active VPN sessions, and a verified admin connection.' },
  { key: 'memory', name: 'Memory health & safe reclaim', description: 'Inspect RAM pressure without blind cache drops', caution: false, icon: Activity, requirement: 'Check swap, RAM pressure and running services. Linux filesystem cache is normally beneficial.' },
  { key: 'housekeeping', name: 'Safe cache & log housekeeping', description: 'Review non-destructive storage cleanup', caution: false, icon: HardDrive, requirement: 'Only approved bounded cleanup with retention limits; never delete VPN credentials, logs needed for audit or configuration.' },
  { key: 'vpn-start', name: 'Start OpenVPN', description: 'Start an identified OpenVPN instance', caution: false, icon: PlayCircle, requirement: 'Discover the exact service unit and verify status and tunnel connectivity after startup.' },
  { key: 'vpn-stop', name: 'Stop OpenVPN', description: 'Disconnects current VPN sessions', caution: true, icon: PauseCircle, requirement: 'Require a VPN-independent management channel and confirmation of user impact.' },
  { key: 'vpn-restart', name: 'Restart OpenVPN', description: 'Temporarily interrupts VPN connections', caution: true, icon: RotateCcw, requirement: 'Require the correct service unit, session impact review, rollback and post-restart health verification.' },
]

export default function ServerControlCenter({ servers, inventoryStatus, onOpenInventory, onRefresh, readOnly = false }: {
  servers: ControlServer[]
  inventoryStatus: 'loading' | 'connected' | 'offline'
  onOpenInventory: () => void
  onRefresh: () => void
  readOnly?: boolean
}) {
  const [search, setSearch] = useState('')
  const [scope, setScope] = useState<'all' | 'registered' | 'archived'>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [profiles, setProfiles] = useState<AdminProfileStatus[] | null>(null)
  const [profileState, setProfileState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [action, setAction] = useState<ActionDefinition | null>(null)
  const [catalogState, setCatalogState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [readiness, setReadiness] = useState<ControlReadiness | null>(null)
  const [readinessState, setReadinessState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [previewState, setPreviewState] = useState<{
    phase: 'loading' | 'verified' | 'error'; result?: ControlPreview; message?: string
  } | null>(null)
  const [executeState, setExecuteState] = useState<{
    phase: 'idle' | 'loading' | 'done' | 'error'
    result?: ControlExecuteResult
    message?: string
  }>({ phase: 'idle' })
  const previewRequestId = useRef(0)
  const [diagnosticCatalogState, setDiagnosticCatalogState] = useState<'loading' | 'ready' | 'error'>('loading')
  const [diagnosticState, setDiagnosticState] = useState<{
    phase: 'loading' | 'verified' | 'error'; check: DiagnosticCheck
    result?: DiagnosticResult; message?: string
  } | null>(null)
  const diagnosticRequestId = useRef(0)
  const [repeat, setRepeat] = useState<'daily' | 'once'>('daily')
  const [date, setDate] = useState('')
  const [time, setTime] = useState('06:00')
  const [timezone, setTimezone] = useState('UTC')
  const [includeHousekeeping, setIncludeHousekeeping] = useState(false)
  const [previewSchedule, setPreviewSchedule] = useState(false)

  const results = useMemo(() => servers.filter(s => {
    if (scope === 'archived' && !s.archived) return false
    if (scope === 'registered' && s.archived) return false
    const q = search.trim().toLowerCase()
    return !q || [s.name, s.client, s.provider, s.location].some(value => value.toLowerCase().includes(q))
  }), [servers, search, scope])
  useEffect(() => {
    if (!results.some(s => s.id === selectedId)) setSelectedId(results[0]?.id ?? null)
  }, [results, selectedId])
  useEffect(() => {
    diagnosticRequestId.current += 1
    setDiagnosticState(null)
  }, [selectedId])
  useEffect(() => {
    previewRequestId.current += 1
    setAction(null)
    setPreviewState(null)
    setExecuteState({ phase: 'idle' })
    setPreviewSchedule(false)
    setRepeat('daily')
    setTime('06:00')
    setDate('')
    setTimezone('UTC')
    setIncludeHousekeeping(false)
  }, [selectedId])
  const serverIds = servers.map(s => s.id).sort().join('|')
  useEffect(() => {
    if (inventoryStatus !== 'connected') { setProfiles(null); setProfileState('loading'); return }
    const controller = new AbortController()
    setProfileState('loading')
    getAdminProfiles(controller.signal)
      .then(data => { if (!controller.signal.aborted) { setProfiles(data.profiles); setProfileState('ready') } })
      .catch(() => { if (!controller.signal.aborted) { setProfiles(null); setProfileState('error') } })
    return () => controller.abort()
  }, [inventoryStatus, serverIds])
  useEffect(() => {
    if (inventoryStatus !== 'connected') { setCatalogState('loading'); return }
    const controller = new AbortController()
    setCatalogState('loading')
    getControlCatalog(controller.signal)
      .then(() => { if (!controller.signal.aborted) setCatalogState('ready') })
      .catch(() => { if (!controller.signal.aborted) setCatalogState('error') })
    return () => controller.abort()
  }, [inventoryStatus])
  useEffect(() => {
    if (inventoryStatus !== 'connected') { setDiagnosticCatalogState('loading'); return }
    const controller = new AbortController()
    setDiagnosticCatalogState('loading')
    getDiagnosticCatalog(controller.signal)
      .then(() => { if (!controller.signal.aborted) setDiagnosticCatalogState('ready') })
      .catch(() => { if (!controller.signal.aborted) setDiagnosticCatalogState('error') })
    return () => controller.abort()
  }, [inventoryStatus])
  useEffect(() => {
    if (inventoryStatus !== 'connected' || !selectedId) {
      setReadiness(null)
      setReadinessState('loading')
      return
    }
    const controller = new AbortController()
    setReadiness(null)
    setReadinessState('loading')
    getControlReadiness(selectedId, controller.signal)
      .then(value => { if (!controller.signal.aborted) { setReadiness(value); setReadinessState('ready') } })
      .catch(() => { if (!controller.signal.aborted) { setReadiness(null); setReadinessState('error') } })
    return () => controller.abort()
  }, [inventoryStatus, selectedId, serverIds])
  const selected = results.find(s => s.id === selectedId) ?? null
  const profile = profiles?.find(p => p.server_id === selected?.id)
  const enrolled = Boolean(profile?.profile_configured && profile.profile_enabled && profile.inventory_pinned && profile.verification_ready)
  const backendReady = Boolean(readiness && selected && readinessState === 'ready'
    && readiness.server_id === selected.id && readiness.registry_initialized
    && !readiness.archived && readiness.local_profile_ready
    && readiness.execution_enabled && !readiness.scheduling_enabled)
  const canPreview = !readOnly && inventoryStatus === 'connected' && Boolean(selected && !selected.archived)
  const canRequestAuditPreview = canPreview && catalogState === 'ready' && Boolean(backendReady)
  const canRunDiagnostic = canRequestAuditPreview && enrolled && diagnosticCatalogState === 'ready'
  const canExecuteVpn = canRequestAuditPreview && enrolled && action != null && isExecutableAction(action.key)
    && previewState?.phase === 'verified' && previewState.result?.execution_enabled === true
  async function executeReadOnlyDiagnostic(check: DiagnosticCheck) {
    if (!selected || !canRunDiagnostic || diagnosticState?.phase === 'loading') return
    const requestId = ++diagnosticRequestId.current
    const serverId = selected.id
    setDiagnosticState({ phase: 'loading', check })
    try {
      const result = await runDiagnostic(serverId, check)
      if (requestId !== diagnosticRequestId.current) return
      if (result.server_id !== serverId || result.check !== check) throw new Error('Server identity mismatch')
      setDiagnosticState({ phase: 'verified', check, result })
    } catch (error) {
      if (requestId === diagnosticRequestId.current) {
        setDiagnosticState({
          phase: 'error', check,
          message: error instanceof Error ? error.message : 'Read-only diagnostic unavailable.',
        })
      }
    }
  }


  function reviewAction(next: ActionDefinition) {
    if (!selected || !canRequestAuditPreview) return
    const serverId = selected.id
    const requestId = ++previewRequestId.current
    setAction(next)
    setPreviewSchedule(false)
    setExecuteState({ phase: 'idle' })
    setPreviewState({ phase: 'loading' })
    void requestControlPreview(serverId, next.key)
      .then(result => {
        if (requestId === previewRequestId.current) setPreviewState({ phase: 'verified', result })
      })
      .catch(error => {
        if (requestId === previewRequestId.current) setPreviewState({
          phase: 'error', message: error instanceof Error ? error.message : 'Preview unavailable.',
        })
      })
  }

  async function runVpnAction() {
    if (!selected || !action || !canExecuteVpn || executeState.phase === 'loading') return
    setExecuteState({ phase: 'loading' })
    try {
      const result = await executeControlAction(selected.id, action.key)
      setExecuteState({ phase: 'done', result })
    } catch (error) {
      setExecuteState({
        phase: 'error',
        message: error instanceof Error ? error.message : 'VPN control failed.',
      })
    }
  }
  const validSchedule = /^([01]\d|2[0-3]):[0-5]\d$/.test(time) && (repeat === 'daily' || /^\d{4}-\d{2}-\d{2}$/.test(date))
  const registered = servers.filter(s => !s.archived).length
  const archived = servers.length - registered

  return <div className="scc-root">
    <header className="scc-hero"><div className="scc-kicker"><ShieldCheck size={15}/> STAG PRIME SENTINEL / SERVER OPERATIONS</div>
      <div className="scc-hero-flex"><div><h2>Control the fleet. <span>Protect every connection.</span></h2><p>Secure restarts, OpenVPN services, memory health and planned maintenance — in one focused operations workspace.</p></div>
        <button type="button" className="scc-secondary" onClick={onRefresh}><RefreshCw size={15}/> Refresh inventory</button></div>
      <div className="scc-stats"><span><Server size={15}/> {registered} registered</span><span><Archive size={15}/> {archived} archived</span><span><LockKeyhole size={15}/> Administrator only</span></div>
    </header>
    <div className="scc-notice" role="status"><Info size={20}/><div><strong>Working controls:</strong> VPN start/stop/restart runs on the enrolled systemd unit after preview + confirm. CPU/RAM diagnostics are live SSH read-only. Host reboot / housekeeping / schedules stay draft-only. SSH secrets are never shown.</div></div>
    <div className="scc-layout">
      <aside className="scc-panel scc-sidebar"><div className="scc-panel-title"><div><div className="scc-kicker">FLEET DIRECTORY</div><h3>Select a server</h3></div><b>{servers.length}</b></div>
        <label className="scc-search"><Search size={16}/><input type="search" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search server or client" aria-label="Search server"/></label>
        <div className="scc-filters">{(['all', 'registered', 'archived'] as const).map(v => <button key={v} type="button" onClick={() => setScope(v)} className={scope === v ? 'selected' : ''}>{v === 'all' ? 'All' : v === 'registered' ? 'Registered' : 'Archived'}</button>)}</div>
        <div className="scc-server-list">{results.map(s => <button key={s.id} type="button" className={'scc-server'+(selectedId === s.id ? ' selected' : '')} onClick={() => setSelectedId(s.id)}><span className="scc-server-icon"><Server size={17}/></span><span><strong>{s.name}</strong><small>{s.client}</small><em>{s.archived ? 'Archived record' : s.observation}</em></span><ChevronRight size={16}/></button>)}
          {inventoryStatus !== 'connected' && <p className="scc-list-note">{inventoryStatus === 'loading' ? 'Loading inventory…' : 'Inventory backend unavailable. Power state is unknown.'}</p>}
          {inventoryStatus === 'connected' && results.length === 0 && <p className="scc-list-note">No matching servers.</p>}</div>
        <button type="button" className="scc-inventory" onClick={onOpenInventory}>Open server inventory <ChevronRight size={15}/></button>
      </aside>
      <main className="scc-content">{selected ? <>
        <section className="scc-panel scc-identity"><div className="scc-kicker">SELECTED SERVER</div><div className="scc-identity-heading"><div><h3>{selected.name}</h3><p>{selected.client} · {selected.location || 'Location unspecified'} · {selected.provider}</p></div><span className="scc-chip">{selected.archived ? 'Archived — controls unavailable' : 'Registered — power state unknown'}</span></div>
          <div className="scc-identity-sub"><span><Activity size={15}/>{selected.observation}</span><span><ShieldCheck size={15}/>{profileState === 'loading' ? 'Checking admin profile…' : profileState === 'error' ? 'Admin profile unavailable' : enrolled ? 'Approved admin profile ready' : 'Admin enrollment not ready'}</span><span><LockKeyhole size={15}/>{readinessState === 'loading' || catalogState === 'loading' ? 'Checking control API…' : readinessState === 'error' || catalogState === 'error' ? 'Control API unavailable' : backendReady ? 'VPN control + diagnostics ready' : 'Control blocked — approve admin profile / enroll monitoring'}</span></div>
          <p className="scc-meta">{selected.observedAt ? `Last verified SSH health: ${selected.observedAt}` : 'No verified live power status. An SSH failure does not prove the VPS is off.'}</p>
        </section>
        <section className="scc-panel scc-operations"><div className="scc-panel-title"><div><div className="scc-kicker">MANUAL OPERATIONS</div><h3>Operations &amp; maintenance</h3></div><span className="scc-draft">{backendReady ? 'VPN execute enabled' : 'Setup required'}</span></div>
          <div className="scc-actions">{ACTIONS.map(a => { const Icon = a.icon; const live = isExecutableAction(a.key); return <button key={a.key} type="button" disabled={!canRequestAuditPreview} className={'scc-action' + (a.caution ? ' caution' : '')} onClick={() => reviewAction(a)}><Icon size={21}/><strong>{a.name}</strong><small>{a.description}</small><span>{live ? 'Preview → execute' : 'Preview only'} <ChevronRight size={14}/></span></button> })}</div>
          {!canRequestAuditPreview && <p className="scc-api-state" role="status">{readOnly ? 'View account: server status is visible. Start, stop, restart, and other changes stay off.' : catalogState === 'error' || readinessState === 'error' ? 'Backend control API unavailable. Refresh the signed-in dashboard and try again.' : 'Need connected inventory + approved admin profile (local key/trust). Enroll monitoring before VPN execute.'}</p>}
          {action && <div className="scc-action-preview" role="region" aria-label="Action review"><button type="button" className="scc-close" onClick={() => { previewRequestId.current += 1; setAction(null); setPreviewState(null); setExecuteState({ phase: 'idle' }) }} aria-label="Close preview"><X size={16}/></button><div className="scc-kicker">BACKEND-CONTROLLED OPERATION REVIEW</div><h4>{action.name} · {selected.name}</h4><p>{action.requirement}</p>
            {previewState?.phase === 'loading' && <div className="scc-api-state" role="status">Requesting admin-authorized preview and audit confirmation…</div>}
            {previewState?.phase === 'error' && <div className="scc-api-error" role="alert">{previewState.message} Preview was not confirmed.</div>}
            {previewState?.phase === 'verified' && previewState.result && <div className="scc-api-success" role="status"><ShieldCheck size={17}/> Preview audited. Risk: {previewState.result.risk}. {previewState.result.message}</div>}
            {canExecuteVpn ? <>
              <div className="scc-warning"><AlertTriangle size={18}/> This will run <code>systemctl</code> on the enrolled VPN unit over verified SSH. Active clients may disconnect.</div>
              <button type="button" className="scc-primary" disabled={executeState.phase === 'loading'} onClick={() => void runVpnAction()}>
                {executeState.phase === 'loading' ? 'Executing…' : `Confirm & ${action.name}`}
              </button>
              {executeState.phase === 'error' && <div className="scc-api-error" role="alert">{executeState.message}</div>}
              {executeState.phase === 'done' && executeState.result && <div className="scc-api-success" role="status">
                <ShieldCheck size={17}/> {executeState.result.message} · unit <code>{executeState.result.unit}</code> · state <strong>{executeState.result.active_state}</strong>
              </div>}
            </> : previewState?.phase === 'verified' ? <div className="scc-warning"><ShieldOff size={18}/> This action is preview/audit only in this build (no remote host reboot or housekeeping).</div> : null}
          </div>}
        </section>
        <section className="scc-panel scc-diagnostics" aria-label="Live read-only diagnostics">
          <div className="scc-panel-title"><div><div className="scc-kicker">LIVE VERIFIED SSH</div><h3>Read-only server diagnostics</h3></div><span className="scc-diagnostic-badge">Audited · no sudo</span></div>
          <p className="scc-description">Run one selected server check at a time. Only bounded CPU load or memory values are returned. No cache clearing, service restart or configuration changes.</p>
          <div className="scc-diagnostic-actions">
            <button type="button" disabled={!canRunDiagnostic || diagnosticState?.phase === 'loading'} onClick={() => void executeReadOnlyDiagnostic('load_average')}><Activity size={18}/> Run CPU load check</button>
            <button type="button" disabled={!canRunDiagnostic || diagnosticState?.phase === 'loading'} onClick={() => void executeReadOnlyDiagnostic('memory_snapshot')}><HardDrive size={18}/> Run memory check</button>
          </div>
          {!canRunDiagnostic && <p className="scc-api-state" role="status">{diagnosticCatalogState === 'error' ? 'Read-only diagnostic API is unavailable. Sign in and refresh the dashboard.' : 'A registered server, approved administrative profile, and available diagnostic catalog are required.'}</p>}
          {diagnosticState?.phase === 'loading' && <p className="scc-api-state" role="status">Contacting {selected.name} through its approved SSH profile. Waiting for a bounded read-only result…</p>}
          {diagnosticState?.phase === 'error' && <p className="scc-api-error" role="alert">{diagnosticState.message} No successful diagnostic was confirmed.</p>}
          {diagnosticState?.phase === 'verified' && diagnosticState.result && <div className="scc-diagnostic-result" role="status">
            <strong><ShieldCheck size={17}/> Verified read-only result · {diagnosticState.result.server_name} · Audit recorded</strong>
            {diagnosticState.check === 'load_average' ? <div className="scc-diagnostic-metrics">
              <span>1 minute <b>{diagnosticState.result.metrics.load_1m.toFixed(2)}</b></span>
              <span>5 minutes <b>{diagnosticState.result.metrics.load_5m.toFixed(2)}</b></span>
              <span>15 minutes <b>{diagnosticState.result.metrics.load_15m.toFixed(2)}</b></span>
            </div> : <div className="scc-diagnostic-metrics">
              <span>RAM total <b>{diagnosticState.result.metrics.total_mib} MiB</b></span>
              <span>RAM available <b>{diagnosticState.result.metrics.available_mib} MiB</b></span>
              <span>Swap total <b>{diagnosticState.result.metrics.swap_total_mib} MiB</b></span>
              <span>Swap free <b>{diagnosticState.result.metrics.swap_free_mib} MiB</b></span>
            </div>}
            <small>SSH and host key verified. Metrics are a point-in-time snapshot; no server settings were changed.</small>
          </div>}
        </section>
        <section className="scc-panel scc-scheduler"><div className="scc-panel-title"><div><div className="scc-kicker">AUTOMATED MAINTENANCE</div><h3>Restart schedule planner</h3></div><CalendarClock size={21}/></div><p className="scc-description">Create a draft for a daily or one-time restart. A saved and running schedule requires the future 24/7 backend scheduler.</p>
          <fieldset className="scc-form" disabled={!canPreview}>
            <label>Frequency<select value={repeat} onChange={e => {setRepeat(e.target.value as 'daily'|'once');setPreviewSchedule(false)}}><option value="daily">Every day</option><option value="once">One time</option></select></label>
            {repeat === 'once' && <label>Date<input type="date" value={date} onChange={e => {setDate(e.target.value);setPreviewSchedule(false)}}/></label>}
            <label>Time (24h)<input type="time" value={time} onChange={e => {setTime(e.target.value);setPreviewSchedule(false)}}/></label>
            <label>Timezone<select value={timezone} onChange={e => {setTimezone(e.target.value);setPreviewSchedule(false)}}><option value="UTC">UTC</option><option value="Asia/Dhaka">Bangladesh / Dhaka</option><option value="Europe/Berlin">Germany / Berlin</option><option value="Asia/Dubai">UAE / Dubai</option></select></label>
            <label className="scc-check"><input type="checkbox" checked={includeHousekeeping} onChange={e => {setIncludeHousekeeping(e.target.checked);setPreviewSchedule(false)}}/> Include approved safe housekeeping before restart</label>
          </fieldset>
          <div className="scc-schedule-bottom"><button type="button" className="scc-primary" disabled={!canPreview || !validSchedule} onClick={() => {setPreviewSchedule(true);setAction(null)}}><Clock3 size={16}/> Preview schedule</button><span><LockKeyhole size={15}/> Not saved · Not active</span></div>
          {previewSchedule && <div className="scc-schedule-preview"><strong>Draft for {selected.name}</strong><p>{repeat === 'daily' ? 'Every day' : date}, {time} ({timezone}). {includeHousekeeping ? 'Housekeeping would require a separate approved plan.' : 'Restart only.'} Nothing was scheduled.</p></div>}
        </section>
        <div className="scc-caution"><AlertTriangle size={19}/><p><strong>Protect remote access:</strong> server restart and VPN stop/restart can interrupt active users. Future execution must verify SSH recovery and never alter SSH keys, users, sudoers, firewall rules or authentication settings.</p></div>
      </> : <section className="scc-panel scc-empty"><Server size={30}/><h3>Select a server</h3><p>Registered and archived inventory records will appear here when available.</p></section>}</main>
    </div><footer className="scc-footer"><Wrench size={15}/> VPN start/stop/restart and read-only diagnostics are live. Host reboot scheduling remains draft-only.</footer>
  </div>
}
