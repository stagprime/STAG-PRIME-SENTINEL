import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertCircle, AlertTriangle, ArrowRight, BookOpen, CheckCircle2, ChevronRight,
  Clipboard, Clock3, Copy, FileCheck2, LockKeyhole, RefreshCw,
  Search, Server, ServerCog, ShieldCheck, ShieldEllipsis, Terminal, Wrench, XCircle,
} from 'lucide-react'
import { getAdminProfiles, verifyAdminSSH } from '../api/serverOperations'
import { csrfHeaders, signalAuthExpired } from '../api/auth'
import type { AdminProfileStatus, AdminSSHVerification } from '../api/serverOperations'
import './ServerOperations.css'
import ReviewedCommandConsole from './ReviewedCommandConsole'

/** Inventory display contract. Administrative SSH is an explicit read-only preflight only. */
export type OperationsServer = {
  id: string
  name: string
  host: string
  client: string
  location: string
  provider: string
  sshUser: string
  sshPort: number
  monitoring: 'verified' | 'checking' | 'attention' | 'inventory_only'
  observation: string
}

type PlanStep = { name: string; detail: string; verification: string }

const REPAIR_STEPS: PlanStep[] = [
  { name: 'Collect health evidence', detail: 'Confirm SSH identity and collect current service health without changing the server.', verification: 'Fresh, authenticated diagnostic evidence' },
  { name: 'Determine root cause', detail: 'Compare logs, OpenVPN instance, status file, firewall and client symptoms.', verification: 'Cause supported by evidence; unknown remains unknown' },
  { name: 'Review repair & rollback', detail: 'Prepare minimum-impact commands, expected effect, backup and recovery path.', verification: 'Administrator approval and maintenance impact reviewed' },
  { name: 'Execute approved repair', detail: 'Run one authorized, audited command at a time with bounded output and timeouts.', verification: 'Execution output recorded; no implied success' },
  { name: 'Recheck live VPN health', detail: 'Confirm service, client tunnel and verified monitoring readings after a change.', verification: 'Issue resolved only with fresh post-repair evidence' },
]



function labelForMonitoring(stage: OperationsServer['monitoring']) {
  if (stage === 'verified') return 'SSH verified'
  if (stage === 'attention') return 'Needs investigation'
  if (stage === 'checking') return 'Verification pending'
  return 'Inventory only'
}

export default function ServerOperations({
  servers, inventoryStatus, onOpenInventory, onAddServer, onOpenHandbook, onRefresh,
}: {
  servers: OperationsServer[]
  inventoryStatus: 'loading' | 'connected' | 'offline'
  onOpenInventory: () => void
  onAddServer: () => void
  onOpenHandbook: () => void
  onRefresh: () => void
}) {
  const [search, setSearch] = useState('')
  const [client, setClient] = useState('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [showAllOnRepair, setShowAllOnRepair] = useState(false)
  const [adminProfiles, setAdminProfiles] = useState<AdminProfileStatus[] | null>(null)
  const [profilesLoading, setProfilesLoading] = useState(false)
  const [profilesError, setProfilesError] = useState<string | null>(null)
  const [profilesReload, setProfilesReload] = useState(0)
  const [verifyingId, setVerifyingId] = useState<string | null>(null)
  const [verification, setVerification] = useState<{ serverId: string; value: AdminSSHVerification; verifiedAt: number } | null>(null)
  const [clock, setClock] = useState(Date.now())
  const [verificationError, setVerificationError] = useState<string | null>(null)
  const [terminalCommand, setTerminalCommand] = useState('sentinel check memory')
  const [terminalBusy, setTerminalBusy] = useState(false)
  const [terminalHistory, setTerminalHistory] = useState<{ serverId: string; lines: string[] } | null>(null)
  const [diagnosticOk, setDiagnosticOk] = useState<string | null>(null)

  const verifySerial = useRef(0)
  // Metadata refresh is cache-only (no SSH). It prevents the UI from retaining
  // expired evidence after an administrator leaves the screen open overnight.
  useEffect(() => {
    const timer = window.setInterval(() => {setClock(Date.now());setProfilesReload(n=>n+1)}, 60_000)
    return () => window.clearInterval(timer)
  }, [])
  const plan = REPAIR_STEPS
  const clientNames = useMemo(() => [...new Set(servers.map(s => s.client))].sort(), [servers])
  const needsAttention = servers.filter(s => s.monitoring === 'attention')
  const verified = servers.filter(s => s.monitoring === 'verified')
  const filtered = useMemo(() => {
    const scope = showAllOnRepair ? servers : needsAttention
    const q = search.trim().toLowerCase()
    return scope.filter(s => (client === 'all' || s.client === client)
      && [s.name, s.client, s.host, s.location, s.provider].some(value => value.toLowerCase().includes(q)))
      .sort((a, b) => {
        const priority = { inventory_only: 0, attention: 1, checking: 2, verified: 3 }
        return priority[a.monitoring] - priority[b.monitoring] || a.name.localeCompare(b.name)
      })
  }, [servers, needsAttention, showAllOnRepair, search, client])
  useEffect(() => {
    if (selectedId && filtered.some(s => s.id === selectedId)) return
    setSelectedId(filtered[0]?.id ?? null)
  }, [selectedId, filtered])
  useEffect(() => { setSearch(''); setClient('all'); setSelectedId(null); setCopied(false) }, [])
  const selected = filtered.find(s => s.id === selectedId) || null
  const serverIdsKey = servers.map(s => s.id).sort().join('|')
  const selectedBackendId = selected?.id.startsWith('api-') ? selected.id.slice(4) : selected?.id
  const selectedProfile = adminProfiles?.find(p => p.server_id === selectedBackendId)
  const cached = selectedProfile?.recent_verification
  const cachedVerification: AdminSSHVerification | null = cached?.state === 'success' && cached.ssh_verified
    ? {server_id: selectedBackendId || '', ssh_verified:true, host_key_verified:true,
       privilege_state: (['root','sudo_nopasswd','sudo_password_required','sudo_unavailable'].includes(cached.privilege_state || '')
         ? cached.privilege_state : 'sudo_unavailable') as AdminSSHVerification['privilege_state'],
       administration_ready: cached.administration_ready === true}
    : null
  const freshVerification = verification && verification.serverId === selectedBackendId && clock - verification.verifiedAt < 14 * 60_000
    ? verification.value : cachedVerification

  // Read metadata only; no SSH connection is made by listing profiles.
  useEffect(() => {
    if (inventoryStatus !== 'connected') {
      setAdminProfiles(null)
      setProfilesError(null)
      setProfilesLoading(false)
      return
    }
    const abort = new AbortController()
    setProfilesLoading(true)
    setProfilesError(null)
    getAdminProfiles(abort.signal)
      .then(data => { if (!abort.signal.aborted) setAdminProfiles(data.profiles) })
      .catch(() => {
        if (!abort.signal.aborted) {
          setAdminProfiles(null)
          setProfilesError('Unable to read approved administrative profiles. Check your authenticated API session.')
        }
      })
      .finally(() => { if (!abort.signal.aborted) setProfilesLoading(false) })
    return () => abort.abort()
  }, [inventoryStatus, serverIdsKey, profilesReload])

  // Never display a verification from a previously selected server as a live result.
  useEffect(() => {
    verifySerial.current += 1
    setVerification(null)
    setVerificationError(null)
    setVerifyingId(null)
    setTerminalCommand('sentinel check memory')
    setTerminalHistory(null)
    setTerminalBusy(false)
  }, [selectedBackendId])

  async function verifySelectedAdminSSH() {
    if (!selectedBackendId || !selectedProfile?.verification_ready || verifyingId) return
    const serial = ++verifySerial.current
    setVerifyingId(selectedBackendId)
    setVerification(null)
    setVerificationError(null)
    try {
      const result = await verifyAdminSSH(selectedProfile.server_id)
      if (serial !== verifySerial.current) return
      if (result.server_id !== selectedProfile.server_id) throw new Error('Server identity mismatch')
      setVerification({serverId: selectedBackendId, value: result, verifiedAt: Date.now()})
      setClock(Date.now())
      setProfilesReload(n => n + 1)
    } catch {
      if (serial === verifySerial.current) {
        setVerificationError('Verification failed. Review the approved SSH profile and backend audit; no install/repair was attempted.')
      }
    } finally {
      if (serial === verifySerial.current) setVerifyingId(null)
    }
  }

  function adminBindingLabel(): string {
    if (profilesLoading) return 'Loading approved profiles…'
    if (profilesError || !adminProfiles) return 'Profile status unavailable'
    if (!selectedProfile?.profile_configured) return 'Not enrolled'
    if (!selectedProfile.profile_enabled) return 'Profile disabled'
    if (!selectedProfile.inventory_pinned) return 'Inventory mismatch — reapproval required'
    if (!selectedProfile.verification_ready) return 'Approved profile — local key/trust file unavailable'
    if (freshVerification?.ssh_verified) return `Recent SSH verification · ${freshVerification.privilege_state}`
    return 'Approved profile · verification available'
  }

  // The editor is intentionally NOT a generic shell. Only the two audited,
  // fixed SSH jobs from Step 40.9 may be executed; arbitrary input fails locally.
  async function runTerminalCheck() {
    if (!selectedBackendId || !selectedProfile?.verification_ready || terminalBusy) return
    const command = terminalCommand.trim()
    const permitted: Record<string, 'memory_snapshot' | 'load_average'> = {
      'sentinel check memory': 'memory_snapshot',
      'sentinel check cpu': 'load_average',
    }
    const check = permitted[command]
    const targetId = selectedBackendId
    const stamp = new Date().toLocaleTimeString()
    if (!check) {
      setTerminalHistory({serverId:targetId, lines:[`[${stamp}] REJECTED · Only sentinel check memory / sentinel check cpu are permitted. No SSH command executed.`]})
      return
    }
    setTerminalBusy(true)
    setTerminalHistory({serverId:targetId, lines:[`[${stamp}] $ ${command}`, 'Contacting approved server over verified SSH…']})
    try {
      const res = await fetch(`/api/server-operations/servers/${encodeURIComponent(targetId)}/jobs/read-only`, {
        method:'POST', credentials:'same-origin', cache:'no-store',
        headers:{...csrfHeaders('POST'), 'Content-Type':'application/json'},
        body: JSON.stringify({check}),
      })
      if (res.status === 401) signalAuthExpired()
      if (!res.ok) throw new Error(`Job HTTP ${res.status} — check SSH host identity, approved credential and server availability.`)
      const data: unknown = await res.json()
      if (!data || typeof data !== 'object' || !('server_id' in data) || data.server_id !== targetId
          || !('status' in data) || !['succeeded','failed'].includes(String(data.status))
          || !('audit_recorded' in data) || data.audit_recorded !== true) {
        throw new Error('Invalid audited diagnostic job response')
      }
      let outcome = `JOB ${String(data.status).toUpperCase()} · Audit recorded`
      if (data.status === 'succeeded' && 'metrics' in data && data.metrics && typeof data.metrics === 'object') {
        const metrics = data.metrics as Record<string,unknown>
        const allow = check === 'load_average' ? ['load_1m','load_5m','load_15m']
          : ['total_mib','available_mib','swap_total_mib','swap_free_mib']
        outcome += '\n' + allow.filter(k => typeof metrics[k] === 'number').map(k => `${k}: ${metrics[k]}`).join(' · ')
      } else if (data.status === 'failed') {
        outcome += '\nRecommendation: Verify SSH authentication and host trust, review administration readiness, then retry.'
      }
      setTerminalHistory({serverId:targetId, lines:[`[${stamp}] $ ${command}`, outcome, 'No remote writes performed.']})
      if (data.status === 'succeeded') setDiagnosticOk(targetId)
    } catch (e) {
      setTerminalHistory({serverId:targetId, lines:[`[${stamp}] $ ${command}`,
        `ERROR · ${e instanceof Error ? e.message : 'Failed to execute job'}`,
        'Recommendation: Verify SSH identity, connectivity and credentials. No server changes confirmed.']})
    } finally { setTerminalBusy(false) }
  }

  async function copyDiagnostic() {
    try {
      await navigator.clipboard.writeText(terminalCommand)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }
  return <div className="so-workspace">
    <section className="so-hero">
      <div>
        <div className="so-eyebrow"><ShieldCheck size={15}/> STAG PRIME SENTINEL / SERVER OPERATIONS</div>
        <h2>Find the cause. <span>Restore with control.</span></h2>
        <p>Evidence-led troubleshooting, reviewed repair commands, and post-fix health verification for every authorized server.</p>
        <div className="so-hero-facts"><span><strong>{servers.length}</strong> registered servers</span><i/><span><strong>{verified.length}</strong> SSH verified</span><i/><span><strong>{needsAttention.length}</strong> requiring health review</span></div>
      </div>
      <div className="so-hero-insignia"><div><Wrench size={36}/></div><span>CONTROLLED ADMIN</span></div>
    </section>

    <section className="so-boundary"><ShieldEllipsis size={20}/><div><strong>Encrypted administrator credentials · verified diagnostic jobs available.</strong><p>Approved SSH credentials can run audited, fixed read-only diagnostics. Fresh Server Setup and automatic OpenVPN installation have been removed. Diagnostics remain explicitly authorized; remote changes are not performed by this page. Never paste secrets into the command editor.</p></div><span className="so-boundary-label">CONTROLLED</span></section>

    <section className="so-stats">
      <div><span>Registered VPS</span><strong>{inventoryStatus === 'connected' ? String(servers.length).padStart(2, '0') : '—'}</strong><small>Backend inventory only</small><Server size={20}/></div>
      <div><span>Investigation scope</span><strong>{inventoryStatus === 'connected' ? String(servers.length).padStart(2, '0') : '—'}</strong><small>Registered servers</small><Server size={20}/></div>
      <div><span>SSH verified</span><strong>{inventoryStatus === 'connected' ? String(verified.length).padStart(2, '0') : '—'}</strong><small>From existing health collector</small><Activity size={20}/></div>
      <div><span>Health attention</span><strong>{inventoryStatus === 'connected' ? String(needsAttention.length).padStart(2, '0') : '—'}</strong><small>Observed failures, not proven VPN outages</small><AlertTriangle size={20}/></div>
    </section>

    <div className="so-layout">
      <section className="so-panel so-registry">
        <header className="so-panel-head"><div><div className="so-panel-label">MULTI-CLIENT INVENTORY</div><h3>Incident candidates</h3><p>Based on authenticated monitoring errors, not guessed outages.</p></div><button className="so-icon-btn" title="Refresh inventory and approved admin profiles" aria-label="Refresh inventory" onClick={() => {onRefresh();setProfilesReload(n => n + 1)}}><RefreshCw size={16}/></button></header>
        <label className="so-option"><input type="checkbox" checked={showAllOnRepair} onChange={event => setShowAllOnRepair(event.target.checked)}/> Show all servers for manual investigation</label>
        <div className="so-filters"><label className="so-search"><Search size={16}/><input aria-label="Search operations servers" placeholder="Search name, IP, client..." value={search} onChange={e => setSearch(e.target.value)}/></label><select aria-label="Filter client organization" value={client} onChange={e => setClient(e.target.value)}><option value="all">All organizations</option>{clientNames.map(name => <option key={name} value={name}>{name}</option>)}</select></div>
        <div className="so-servers">
          {inventoryStatus === 'loading' && <div className="so-empty">Loading authorized inventory…</div>}
          {inventoryStatus === 'offline' && <div className="so-empty"><AlertCircle size={20}/> Inventory API is unavailable. No server status can be verified.</div>}
          {inventoryStatus === 'connected' && filtered.map(s => <button type="button" key={s.id} className={'so-server' + (s.id === selected?.id ? ' selected' : '')} aria-pressed={s.id === selected?.id} onClick={() => {setSelectedId(s.id);setCopied(false)}}><span className="so-server-icon"><Server size={17}/></span><span className="so-server-text"><strong>{s.name}</strong><small>{s.client} · {s.host}</small><em className={'so-monitoring ' + s.monitoring}>{labelForMonitoring(s.monitoring)}</em></span><ChevronRight size={16}/></button>)}
          {inventoryStatus === 'connected' && !filtered.length && <div className="so-empty"><ShieldCheck size={21}/>{!showAllOnRepair ? 'No health-collector errors currently reported. This is not proof that every VPN works.' : 'No matching servers in the active inventory.'}</div>}
        </div>
        <footer className="so-panel-foot"><button onClick={onOpenInventory}>Manage server inventory <ArrowRight size={15}/></button><button onClick={onAddServer}><ServerCog size={14}/> Add new server</button></footer>
      </section>

      <section className="so-detail">
        {selected ? <>
          <section className="so-panel so-target">
            <div className="so-target-head"><div><div className="so-panel-label">ISSUE RESPONSE / INVESTIGATION</div><h3>{selected.name}</h3><p>{selected.client} · {selected.location}</p></div><span className={'so-pill ' + selected.monitoring}>{labelForMonitoring(selected.monitoring)}</span></div>
            <div className="so-server-properties"><div><span>SSH endpoint</span><strong>{selected.host}:{selected.sshPort}</strong></div><div><span>SSH identity</span><strong>{selected.sshUser}</strong></div><div><span>Provider</span><strong>{selected.provider}</strong></div><div><span>Admin credential binding</span><strong className={freshVerification?.ssh_verified ? "so-admin-ready" : "so-pending"}>{adminBindingLabel()}</strong></div></div>
            <div className="so-observation"><Activity size={17}/><p><strong>Current observation:</strong> {freshVerification?.ssh_verified ? `Recently verified admin SSH · privilege: ${freshVerification.privilege_state}. VPN health and monitoring evidence must be verified separately.` : selected.observation}</p></div>
          </section>
          <section className="so-panel so-admin-panel" aria-label="Administrative SSH profile verification">
            <header className="so-panel-head"><div><div className="so-panel-label">VERIFIED IDENTITY / ADMINISTRATIVE SSH</div><h3>Approved admin profile</h3><p>Read-only capability check against the selected inventory server.</p></div><span className="so-stage-tag">VERIFIED SSH</span></header>
            <div className="so-admin-body">
              <div className="so-admin-metadata">
                <div><span>Local approval</span><strong>{profilesLoading ? 'Checking…' : profilesError ? 'Unavailable' : selectedProfile?.profile_enabled ? 'Approved' : 'Not approved'}</strong></div>
                <div><span>Inventory identity pin</span><strong>{profilesLoading ? 'Checking…' : selectedProfile?.inventory_pinned ? 'Matched' : 'Not matched'}</strong></div>
                <div><span>Preflight prerequisites</span><strong>{profilesLoading ? 'Checking…' : selectedProfile?.verification_ready ? 'Ready' : 'Not ready'}</strong></div>
              </div>
              {profilesError && <p className="so-admin-error" role="status">{profilesError}</p>}
              {freshVerification ? <p className={freshVerification.ssh_verified ? 'so-admin-success' : 'so-admin-error'} role="status">
                SSH {freshVerification.ssh_verified ? 'verified' : 'not verified'} · Host key {freshVerification.host_key_verified ? 'verified' : 'not verified'} · Privilege: {freshVerification.privilege_state} · Administration {freshVerification.administration_ready ? 'ready' : 'not ready'}. A recent backend verification is reused until its bounded validity expires; live availability can change.
              </p> : <p className="so-admin-help">A locally approved profile is not proof of current SSH availability. Click Verify to perform a new audited, read-only capability preflight.</p>}
              {verificationError && <p className="so-admin-error" role="alert">{verificationError}</p>}
              <div className="so-admin-actions">
                {!freshVerification?.ssh_verified
                  ? <button type="button" className="so-soft-button" disabled={profilesLoading || !selectedProfile?.verification_ready || Boolean(verifyingId)} onClick={() => void verifySelectedAdminSSH()}><ShieldCheck size={16}/>{verifyingId === selectedBackendId ? 'Verifying SSH…' : 'Verify admin SSH (read-only)'}</button>
                  : <span className="so-admin-success">Verified SSH evidence is available — no repeat click required.</span>}
                <small>Expiry or trust/credential changes require a new bounded check. Any state-changing maintenance requires separate approval.</small>
              </div>
            </div>
          </section>
          <section className="so-panel so-wizard"><header className="so-panel-head"><div><div className="so-panel-label">CONTROLLED RECOVERY / ACTION PLAN</div><h3>Guided investigation & repair</h3><p>{plan.length} stages · Status follows live verify + diagnostic evidence on this page.</p></div><span className="so-stage-tag">LIVE WORKFLOW</span></header>
            <div className="so-steps">{plan.map((step, index) => {
              const sshOk = Boolean(freshVerification?.ssh_verified)
              const diagOk = diagnosticOk === selectedBackendId
              const healthy = selected.monitoring === 'verified'
              const done = index === 0 ? sshOk || diagOk
                : index === 1 ? diagOk
                : index === 2 ? diagOk && sshOk
                : index === 3 ? false
                : healthy && diagOk
              const active = !done && (
                (index === 0 && !sshOk)
                || (index === 1 && sshOk && !diagOk)
                || (index === 2 && diagOk)
                || (index === 4 && diagOk && !healthy)
              )
              return <div className={'so-step' + (done ? ' done' : active ? ' active' : '')} key={step.name}>
                <span className="so-step-num">{done ? <CheckCircle2 size={16}/> : String(index+1).padStart(2,'0')}</span>
                <div><strong>{step.name}</strong><p>{step.detail}</p><small><FileCheck2 size={13}/> {step.verification}</small></div>
                <span className="so-step-state">{done ? <><CheckCircle2 size={13}/> Done</> : active ? <><Activity size={13}/> Now</> : <><Clock3 size={13}/> Waiting</>}</span>
              </div>
            })}</div>
            <div className="so-wizard-foot"><span><LockKeyhole size={15}/> Destructive repairs stay in Server Control (VPN restart) after diagnosis. This page runs verify + read-only jobs.</span><button className="so-soft-button" onClick={onOpenHandbook}><BookOpen size={15}/> Open CE handbook <ArrowRight size={15}/></button></div>
          </section>
          <section className="so-panel so-console" aria-label="Reviewed administrative SSH console">
            <header className="so-panel-head"><div><div className="so-panel-label">ADMINISTRATIVE SSH / AUDITED JOB TERMINAL</div><h3>Review, paste & run a diagnostic</h3><p>Structured SSH output from the encrypted administrator credential. Every run is recorded.</p></div><span className="so-stage-tag">READ-ONLY JOBS</span></header>
            <div className="so-console-status"><span className="so-led"/>{selectedProfile?.verification_ready ? 'APPROVED CREDENTIAL READY' : 'ADMIN PROFILE NOT READY'}<span>·</span> Live SSH is confirmed only when a check succeeds.</div>
            <div className="so-console-screen"><div className="so-console-title"><Terminal size={15}/> Job output <span>server-specific · audited · bounded</span></div><pre>{terminalHistory && terminalHistory.serverId === selectedBackendId ? terminalHistory.lines.join('\n') : 'No diagnostic run during this page session.\nChoose an approved command, then click Run check.'}</pre></div>
            <div className="so-console-command"><div><span><Clipboard size={15}/> Approved command editor</span><span className="so-read-chip">ALLOWLIST ONLY</span></div>
              <label htmlFor="so-terminal-editor" className="so-terminal-editor-label">Supported: sentinel check memory · sentinel check cpu</label>
              <textarea id="so-terminal-editor" className="so-terminal-editor" value={terminalCommand} maxLength={120} spellCheck={false} autoComplete="off" onChange={e=>setTerminalCommand(e.target.value)}/>
            </div>
            <div className="so-console-actions">
              <button className="so-soft-button" type="button" onClick={()=>setTerminalCommand('sentinel check memory')}>Memory command</button>
              <button className="so-soft-button" type="button" onClick={()=>setTerminalCommand('sentinel check cpu')}>CPU command</button>
              <button type="button" className="so-soft-button" onClick={()=>void copyDiagnostic()}><Copy size={16}/>{copied ? 'Copied' : 'Copy command'}</button>
              <button type="button" className="so-soft-button" disabled={!selectedProfile?.verification_ready || terminalBusy} onClick={()=>void runTerminalCheck()}><Terminal size={16}/>{terminalBusy ? 'Checking…' : 'Run check'}</button>
            </div>
            <p className="so-console-note"><AlertCircle size={15}/> This is a restricted diagnostic editor, not an unrestricted OS shell. Unknown commands are rejected without contacting the VPS. This page does not install OpenVPN or accept arbitrary shell commands.</p>
          </section>
          {selectedBackendId && <ReviewedCommandConsole key={'reviewed-command:' + selectedBackendId} serverId={selectedBackendId} ready={Boolean(selectedProfile?.verification_ready && freshVerification?.ssh_verified)}/>}
        </> : <section className="so-panel so-await"><XCircle size={35}/><h3>{inventoryStatus === 'offline' ? 'Inventory backend not available' : 'Select a server to continue'}</h3><p>{inventoryStatus === 'connected' ? 'There may be no current health-probe errors. Show all servers for a manual investigation.' : 'The operations workspace uses current, authorized inventory records. No demonstration servers are created.'}</p></section>}
      </section>
    </div>
  </div>
}
