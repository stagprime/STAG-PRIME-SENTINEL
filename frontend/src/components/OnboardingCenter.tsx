import { signalAuthExpired, csrfHeaders } from "../api/auth";
import { useEffect, useMemo, useState } from 'react'
import { Activity, ArrowRight, CheckCircle2, CircleHelp, ClipboardCopy, LockKeyhole, Radio, RefreshCw, Server, ShieldCheck, Terminal, Workflow } from 'lucide-react'
import { enrollVerifiedMonitoring } from '../api/serverOperations'
import SetupPlanPanel, { type SetupPlan } from './SetupPlanPanel'
import './OnboardingCenter.css'

type Discovery = {
  state: 'success' | 'error' | 'stale'
  checked_at_utc: string
  observation?: { hostname?: string | null; vpn_service?: string | null; vpn_interface?: string | null; vpn_ipv4?: string | null; network_interface?: string | null; status_access?: string | null; ready_for_approval?: boolean | null; warnings?: string[] }
}
type ReadOnlyScan = {
  state: 'success' | 'error' | 'stale'
  checked_at_utc: string
  classification?: 'fresh_candidate' | 'openvpn_detected' | 'openvpn_service_active' | 'needs_review'
  os_family?: string
  os_major?: string
  openvpn_package?: string
  active_services_found?: number
  next_step?: string
}
type AdminVerification = { state: 'success' | 'error' | 'stale'; checked_at_utc: string; privilege_state?: string; ssh_verified?: boolean; administration_ready?: boolean; password_sudo_supported?: boolean }
type CheckName = 'admin_credential_ready' | 'inventory_identity_complete' | 'monitoring_profile_approved' | 'local_configuration_ready' | 'remote_ssh_test_performed' | 'remote_openvpn_discovery_performed' | 'installation_performed'
type Entry = {
  server_id: string
  server_name: string
  client: string
  host: string
  phase: 'inventory_incomplete' | 'approval_required' | 'configuration_attention' | 'eligible_for_read_only_discovery'
  checks: Record<CheckName, boolean>
  next_step: string
  administrative_approval_required: boolean
  remote_changes_allowed: false
  detail_count: number
  discovery?: Discovery | null
  scan_ready?: boolean
  admin_profile_enabled?: boolean
  onboarding_scan?: ReadOnlyScan | null
  admin_verification?: AdminVerification | null
  plan?: SetupPlan | null
}
const descriptions: Record<Entry['phase'], string> = {
  inventory_incomplete: 'Inventory incomplete',
  approval_required: 'Administrator approval required',
  configuration_attention: 'Monitoring profile needs attention',
  eligible_for_read_only_discovery: 'Local profile ready',
}
const PROBE_COMMAND = '.\\.venv\\Scripts\\python.exe -m backend.onboarding_probe --all-approved --confirm-read-only'
const steps: { key: CheckName; title: string; description: string }[] = [
  { key: 'inventory_identity_complete', title: 'Server identity', description: 'Client, host, SSH username and port' },
  { key: 'admin_credential_ready', title: 'Administrator SSH credential', description: 'Encrypted credential, approved pinned server and host-trust readiness' },
  { key: 'local_configuration_ready', title: 'Backend readiness', description: 'Admin vault or monitoring profile can prepare a read-only scan' },
  { key: 'remote_ssh_test_performed', title: 'Live SSH verification', description: 'Approved read-only probe; shown when recently verified' },
  { key: 'remote_openvpn_discovery_performed', title: 'OpenVPN discovery', description: 'Service, interfaces and status-file access' },
  { key: 'installation_performed', title: 'Monitoring enrollment', description: 'Enroll the discovered VPN unit for auto health/session collection' },
]

export default function OnboardingCenter({ onOpenInstall, onOpenInventory, isAdmin }: { onOpenInstall: () => void; onOpenInventory: () => void; isAdmin: boolean }) {
  const [entries, setEntries] = useState<Entry[]>([])
  const [selected, setSelected] = useState('')
  const [client, setClient] = useState('all')
  const [pending, setPending] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  const [copied, setCopied] = useState(false)
  const [scanning, setScanning] = useState<string | null>(null)
  const [scanError, setScanError] = useState<{ serverId: string; text: string } | null>(null)
  const [verifying, setVerifying] = useState<string | null>(null)
  const [verifyResult, setVerifyResult] = useState<{ serverId: string; text: string; ok: boolean } | null>(null)
  const [scanConsole, setScanConsole] = useState<{ serverId: string; text: string } | null>(null)
  const [discovering, setDiscovering] = useState<string | null>(null)
  const [enrolling, setEnrolling] = useState<string | null>(null)
  const [enrollNote, setEnrollNote] = useState<{ serverId: string; text: string; ok: boolean } | null>(null)

  async function discoverOpenVpn(serverId: string) {
    if (!isAdmin || discovering) return
    setDiscovering(serverId)
    setScanError(null)
    try {
      const response = await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/openvpn/discover`, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: csrfHeaders('POST'),
      })
      if (response.status === 401) signalAuthExpired()
      if (!response.ok) {
        const payload = await response.json().catch(() => null) as { detail?: string } | null
        throw new Error(typeof payload?.detail === 'string' ? payload.detail : `Discovery HTTP ${response.status}`)
      }
      const data = await response.json() as {
        vpn_service?: string; vpn_interface?: string; network_interface?: string; status_access?: string
      }
      setScanConsole({
        serverId,
        text: `OpenVPN discovery OK\nService: ${data.vpn_service || '—'}\nTunnel: ${data.vpn_interface || '—'}\nWAN: ${data.network_interface || '—'}\nStatus: ${data.status_access || '—'}`,
      })
      setRevision((v) => v + 1)
    } catch (err) {
      setScanError({ serverId, text: err instanceof Error ? err.message : 'Discovery failed' })
    } finally {
      setDiscovering(null)
    }
  }

  async function enrollMonitoring(serverId: string, obs: NonNullable<Discovery['observation']>) {
    if (!isAdmin || enrolling) return
    const vpn_service = (obs.vpn_service || '').trim()
    const vpn_interface = (obs.vpn_interface || '').trim() || 'tun0'
    const network_interface = (obs.network_interface || '').trim() || 'eth0'
    if (!vpn_service) {
      setEnrollNote({ serverId, text: 'No VPN service detected yet — run Scan / Discover first.', ok: false })
      return
    }
    setEnrolling(serverId)
    setEnrollNote(null)
    try {
      const result = await enrollVerifiedMonitoring(serverId, {
        consent: true,
        vpn_service,
        vpn_interface,
        network_interface,
      })
      setEnrollNote({
        serverId,
        text: `Monitoring enrolled · ${result.vpn_service || vpn_service} / ${result.vpn_interface || vpn_interface} · health ${result.health_status}`,
        ok: true,
      })
      setRevision((v) => v + 1)
    } catch (err) {
      setEnrollNote({ serverId, text: err instanceof Error ? err.message : 'Enrollment failed', ok: false })
    } finally {
      setEnrolling(null)
    }
  }

  async function verifyServer(serverId: string) {
    if (!isAdmin || verifying) return
    setVerifying(serverId)
    setVerifyResult(null)
    try {
      const response = await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/admin/verify`, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: csrfHeaders('POST'),
      })
      if (response.status === 401) signalAuthExpired()
      if (!response.ok) {
        const body: unknown = await response.json().catch(() => null)
        const detail = body && typeof body === 'object' && 'detail' in body ? body.detail : null
        const reason = detail && typeof detail === 'object' && 'code' in detail && 'message' in detail
          && typeof detail.code === 'string' && typeof detail.message === 'string'
          ? `${detail.code}: ${detail.message}` : `SSH verification unsuccessful (HTTP ${response.status}). Check trusted host fingerprint and credential/username.`
        throw new Error(reason)
      }
      const data: unknown = await response.json()
      if (!data || typeof data !== 'object' || !('server_id' in data) || data.server_id !== serverId
        || !('ssh_verified' in data) || data.ssh_verified !== true
        || !('host_key_verified' in data) || data.host_key_verified !== true
        || !('privilege_state' in data) || typeof data.privilege_state !== 'string'
        || !('administration_ready' in data) || typeof data.administration_ready !== 'boolean') {
        throw new Error('SSH returned an invalid verification response')
      }
      setVerifyResult({ serverId, ok: data.administration_ready,
        text: `SSH HOST KEY VERIFIED · Authentication PASS · sudo: ${data.privilege_state} · Admin execution readiness: ${data.administration_ready ? 'READY' : 'NOT READY — privileged execution needs separate approval'}` })
    } catch (err) {
      setVerifyResult({ serverId, ok: false, text: err instanceof Error ? err.message : 'SSH verification failed' })
    } finally { setVerifying(null); setRevision(v => v + 1) }
  }

  async function scanServer(serverId: string) {
    if (!isAdmin || scanning) return
    setScanning(serverId)
    setScanError(null)
    setScanConsole(null)
    try {
      const response = await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/onboarding/scan`, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: csrfHeaders('POST'),
      })
      if (response.status === 401) signalAuthExpired()
      if (!response.ok) {
        const body: unknown = await response.json().catch(() => null)
        const detail = body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string'
          ? body.detail : `Read-only scan failed (HTTP ${response.status})`
        throw new Error(detail)
      }
      const result: unknown = await response.json().catch(() => null)
      if (result && typeof result === 'object' && 'classification' in result && typeof result.classification === 'string') {
        setScanConsole({ serverId, text: `Read-only scan completed. Classification: ${result.classification}. No configuration changes.` })
      }
    } catch (err) {
      setScanError({ serverId, text: err instanceof Error ? err.message : 'Scan failed' })
    } finally { setScanning(null); setRevision(v => v + 1) }
  }

  useEffect(() => {
    let cancelled = false
    const controller = new AbortController()
    setPending(true)
    fetch('/api/onboarding/preflight', { signal: controller.signal, credentials: 'same-origin', cache: 'no-store' })
      .then(async response => {
        if (!response.ok) {
          if (response.status === 401) signalAuthExpired();
          throw new Error(`Backend error HTTP ${response.status}`)
        }
        const data: unknown = await response.json()
        if (!data || typeof data !== 'object' || !('entries' in data) || !Array.isArray(data.entries))
          throw new Error('Invalid onboarding response')
        return data.entries as Entry[]
      })
      .then(list => { if (!cancelled) { setEntries(list); setError(null) } })
      .catch(err => { if (!cancelled) { setEntries([]); setError(err instanceof Error ? err.message : 'Preflight unavailable') } })
      .finally(() => { if (!cancelled) setPending(false) })
    return () => { cancelled = true; controller.abort() }
  }, [revision])

  const clients = useMemo(() => Array.from(new Set(entries.map(item => item.client))).sort(), [entries])
  const visible = useMemo(() => client === 'all' ? entries : entries.filter(item => item.client === client), [entries, client])
  const current = visible.find(item => item.server_id === selected) || visible[0]
  const ready = visible.filter(item => item.phase === 'eligible_for_read_only_discovery').length

  return <section className="sentinel-onboarding" aria-label="Server onboarding readiness">
    <div className="onboarding-banner">
      <div><span className="onboarding-kicker"><Workflow size={15} /> STAG PRIME SENTINEL / ONBOARDING</span>
        <h2>Every new server. <span>One controlled workflow.</span></h2>
        <p>Manage readiness for every client and VPS. This stage checks existing inventory and approved local profiles—without starting a remote connection or modifying a server.</p>
        <div className="onboarding-banner-stats"><span><strong>{entries.length.toString().padStart(2,'0')}</strong> registered servers</span><span><strong>{ready.toString().padStart(2,'0')}</strong> locally ready</span><span><strong>{clients.length.toString().padStart(2,'0')}</strong> clients</span></div>
      </div><div className="onboarding-banner-icon"><ShieldCheck size={39}/><span>SAFE PREFLIGHT</span></div>
    </div>
            <div className="onboarding-alert"><LockKeyhole size={20}/><div><strong>Working onboarding path:</strong> Verify admin SSH → Scan / Discover OpenVPN → Enroll monitoring. No remote OpenVPN package install from this page — inventory + collector enrollment only.</div></div>
    <div className="onboarding-layout">
      <aside className="onboarding-server-list">
        <div className="onboarding-list-heading"><div><span className="tiny-label">MULTI-CLIENT REGISTRY</span><h3>Choose a server</h3></div><button onClick={() => setRevision(v => v + 1)} title="Refresh onboarding" aria-label="Refresh onboarding" disabled={pending}><RefreshCw size={17}/></button></div>
        <label className="onboarding-filter">Client / organization
          <select value={client} onChange={event => { setClient(event.target.value); setSelected('') }}><option value="all">All clients</option>{clients.map(name => <option key={name} value={name}>{name}</option>)}</select>
        </label>
        {pending && <p className="onboarding-list-note">Loading backend readiness…</p>}
        {error && <p className="onboarding-list-error">{error}. Ensure FastAPI is running and the updated backend files are installed.</p>}
        {!pending && !error && visible.length === 0 && <p className="onboarding-list-note">No active servers in this client.</p>}
        {visible.map(item => <button type="button" key={item.server_id} className={'onboarding-server-choice' + (current?.server_id === item.server_id ? ' chosen' : '')} onClick={() => setSelected(item.server_id)}>
          <Server size={19}/><span><strong>{item.server_name}</strong><small>{item.client} · {item.host}</small><em className={item.phase === 'eligible_for_read_only_discovery' ? 'is-ready' : ''}>{descriptions[item.phase]}</em></span><ArrowRight size={16}/>
        </button>)}
        <button className="onboarding-link" onClick={onOpenInventory}>Manage server inventory <ArrowRight size={15}/></button>
      </aside>
      <div className="onboarding-detail">
        {!current ? <div className="onboarding-empty"><CircleHelp size={33}/><h3>Select a server to view onboarding</h3><p>No remote access will be attempted.</p></div> : <>
          <div className="onboarding-detail-head"><div><span className="tiny-label">SERVER READINESS / {current.client.toUpperCase()}</span><h3>{current.server_name}</h3><p>{current.host} · {descriptions[current.phase]}</p></div><div className={'onboarding-state ' + (current.phase === 'eligible_for_read_only_discovery' ? 'is-ready' : '')}>{current.phase === 'eligible_for_read_only_discovery' ? <CheckCircle2 size={16}/> : <LockKeyhole size={16}/>} {current.phase === 'eligible_for_read_only_discovery' ? 'LOCAL PROFILE READY' : 'ACTION REQUIRED'}</div></div>
          <div className="onboarding-steps">{steps.map((step,index) => <div className={'onboarding-step ' + (current.checks[step.key] ? 'completed' : '')} key={step.key}><span className="onboarding-step-number">{current.checks[step.key] ? <CheckCircle2 size={18}/> : String(index+1).padStart(2,'0')}</span><div><strong>{step.title}</strong><p>{step.description}</p></div><span className="onboarding-step-badge">{current.checks[step.key] ? 'Ready' : index >= 3 ? 'Not run' : 'Pending'}</span></div>)}</div>
          <div className="onboarding-next"><Activity size={21}/><div><strong>Recommended next action</strong><p>{current.next_step}</p><small>Preflight GET does not contact VPS. Cached discovery may reflect a prior explicit read-only SSH probe; no VPN installation, firewall changes or restarts were performed.</small></div></div>
            <section className="onboarding-scan-card" aria-label="Verified OpenVPN classification">
            <div className="onboarding-scan-top"><div><span className="tiny-label">SECURE / SERVER CLASSIFICATION</span>
              <h4>Verified OpenVPN detection</h4><p>Admin-approved, host-key-verified, read-only SSH scan. No sudo or server changes.</p></div>
              {isAdmin && <div className="onboarding-verify-controls">
                <button type="button" className="btn-secondary" disabled={!current.scan_ready || Boolean(verifying)} onClick={() => void verifyServer(current.server_id)}>
                  <ShieldCheck size={15}/>{verifying === current.server_id ? 'Verifying…' : 'Verify SSH'}</button>
                <button type="button" className="btn-primary" disabled={!current.scan_ready || !!scanning} onClick={() => void scanServer(current.server_id)}>
                  <Activity size={15}/>{scanning === current.server_id ? 'Scanning…' : 'Scan server'}</button>
                <button type="button" className="btn-secondary" disabled={!current.scan_ready || !!discovering} onClick={() => void discoverOpenVpn(current.server_id)}>
                  <Radio size={15}/>{discovering === current.server_id ? 'Discovering…' : 'Discover OpenVPN'}</button>
              </div>}</div>
            {isAdmin && current.admin_verification?.state !== 'success' && <div className="onboarding-verify-controls">
              <small>{current.checks.admin_credential_ready ? 'Run Verify SSH first, then Discover, then Enroll monitoring below.' : 'Admin credential is not yet ready. Review inventory SSH username and host trust.'}</small>
            </div>}
            {isAdmin && !current.scan_ready && <p className="onboarding-scan-note">Admin SSH credential / pinned inventory or host trust is not ready. Recheck the saved SSH username and credential enrollment.</p>}
            {verifyResult?.serverId === current.server_id && <div className="onboarding-command-result" role="status"><Terminal size={16}/><pre>{verifyResult.text}</pre></div>}
            {scanConsole?.serverId === current.server_id && <div className="onboarding-command-result" role="status"><Terminal size={16}/><pre>{scanConsole.text}</pre></div>}
            {scanError?.serverId === current.server_id && <p className="onboarding-scan-error" role="alert">{scanError.text}</p>}
            {current.admin_verification?.state === 'success' && verifyResult?.serverId !== current.server_id && <p className="onboarding-scan-note">Last verified SSH: {new Date(current.admin_verification.checked_at_utc).toLocaleString()} · {current.admin_verification.privilege_state} · {current.admin_verification.administration_ready ? 'ready for separate change approval' : 'privileged execution not ready'}</p>}
            {current.onboarding_scan?.state === 'success' ? <div className="onboarding-scan-result">
              <strong>{current.onboarding_scan.classification === 'fresh_candidate' ? 'Fresh installation candidate' : current.onboarding_scan.classification === 'openvpn_service_active' ? 'OpenVPN service appears active' : current.onboarding_scan.classification === 'openvpn_detected' ? 'Existing OpenVPN components detected' : 'Manual review required'}</strong>
              <span>OS: {current.onboarding_scan.os_family || 'Unknown'} {current.onboarding_scan.os_major || ''} · Package: {current.onboarding_scan.openvpn_package || 'unknown'} · Active services: {current.onboarding_scan.active_services_found ?? '—'}</span>
              <p>{current.onboarding_scan.next_step}</p>
              <small>Checked: {new Date(current.onboarding_scan.checked_at_utc).toLocaleString()} · Read-only · No installation authorized</small>
            </div> : <p className="onboarding-scan-note">{current.onboarding_scan?.state === 'error' ? 'Last SSH scan failed. Review trusted host identity and credentials.' : current.onboarding_scan?.state === 'stale' ? 'Previous scan expired; recheck before relying on its classification.' : 'No verified classification yet. The server is not automatically considered fresh.'}</p>}
          </section>

          <section className="onboarding-discovery-panel" aria-label="Read-only SSH discovery results">
            <div className="onboarding-discovery-title"><div><span className="tiny-label">AUTOMATIC SSH DISCOVERY / CACHED OBSERVATION</span><h4>OpenVPN discovery report</h4></div><span className={'onboarding-discovery-pill ' + (current.discovery?.state === 'success' ? 'success' : '')}>{current.discovery?.state === 'success' ? 'OBSERVATION READY' : current.discovery?.state === 'error' ? 'SSH PROBE FAILED' : current.discovery?.state === 'stale' ? 'RESULT EXPIRED' : 'NOT TESTED'}</span></div>
          {current.discovery?.state === 'success' && current.discovery.observation ? <>
              <div className="onboarding-observation-grid">
                <div><small>OpenVPN service</small><strong>{current.discovery.observation.vpn_service || 'Not detected'}</strong></div>
                <div><small>VPN tunnel</small><strong>{current.discovery.observation.vpn_interface || 'Not detected'}</strong></div>
                <div><small>Default WAN</small><strong>{current.discovery.observation.network_interface || 'Not detected'}</strong></div>
                <div><small>Status file access</small><strong>{current.discovery.observation.status_access || 'Unknown'}</strong></div>
              </div>
              {current.discovery.observation.warnings && current.discovery.observation.warnings.length > 0 && <p className="onboarding-observation-warnings">{current.discovery.observation.warnings.join(' · ')}</p>}
              {isAdmin && current.discovery.observation.vpn_service && !current.checks.monitoring_profile_approved && (
                <button type="button" className="btn-primary" style={{ marginTop: 12 }} disabled={!!enrolling} onClick={() => void enrollMonitoring(current.server_id, current.discovery!.observation!)}>
                  <Radio size={15}/>{enrolling === current.server_id ? 'Enrolling…' : 'Enroll monitoring collector'}
                </button>
              )}
              {enrollNote?.serverId === current.server_id && (
                <p className={enrollNote.ok ? 'onboarding-scan-note' : 'onboarding-scan-error'} role="status">{enrollNote.text}</p>
              )}
            </> : <p className="onboarding-discovery-help">{current.discovery?.state === 'error' ? 'Read-only SSH discovery was unsuccessful. Verify the approved host, SSH trust and network access; no VPS changes were made.' : current.discovery?.state === 'stale' ? 'The previous snapshot is older than 15 minutes. Run Discover OpenVPN again.' : 'Click Discover OpenVPN (or run the local probe command) after Verify SSH succeeds.'}</p>}
            {current.discovery && <small className="onboarding-observation-date">Checked: {new Date(current.discovery.checked_at_utc).toLocaleString()}</small>}
            <div className="onboarding-discovery-command"><code>{PROBE_COMMAND}</code><button type="button" onClick={() => { void navigator.clipboard.writeText(PROBE_COMMAND).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 2000) }) }} title="Copy local discovery command"><ClipboardCopy size={15}/>{copied ? 'Copied' : 'Copy command'}</button></div>
            <p className="onboarding-discovery-caution">This is a local operator-initiated, read-only probe of explicitly approved SSH targets. Refresh the server list after running the command. The separate legacy monitoring discovery command remains local-only. The administrator scan above is independently approved, audited, and read-only; installation and provisioning remain disabled.</p>
          </section>
          <SetupPlanPanel plan={current.plan} serverName={current.server_name} onOpenInstall={onOpenInstall}/>
          <div className="onboarding-detail-actions"><button className="btn-secondary" onClick={onOpenInstall}>Open installation guide <ArrowRight size={15}/></button><button className="btn-primary" onClick={onOpenInventory}>Edit server inventory <ArrowRight size={15}/></button></div>
        </>}
      </div>
    </div>
  </section>
}
