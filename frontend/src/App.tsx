import type { AuthUser } from "./api/auth";
import { changePassword } from "./api/auth";
import { useEffect, useMemo, useState, useRef } from 'react'
import type { FormEvent, ReactNode } from 'react'
import {
  Activity, Archive, ArrowRight, ArrowUpRight, Bell, BellRing,
  Building2, Check, ChevronRight,
  Download, FileBarChart2,
  LayoutDashboard, LockKeyhole, Menu, Pencil, RotateCcw, FolderOpen, KeyRound,
  Network, Plus, Radio, Search, Server, Settings2, Wrench, ServerCog,
  ShieldCheck, UsersRound, X, BookOpen, Workflow, UserRound, LogOut, ChevronDown, Trash2, AlertTriangle,
  Globe2, Gauge, ShieldAlert, PanelLeftClose, MoonStar,
} from 'lucide-react'
import {
  addServer as createServer, getServers, getArchivedServers,
  editServer as updateServer, archiveServer as archiveServerApi, restoreServer as restoreServerApi,
  getMonitoringTargets, bulkArchiveServers, permanentlyDeleteServers,
} from './api/servers'
import type { ArchivedServer, ServerHealthResponse, MonitoringTarget } from './api/servers'
import { enrollFromLocalDefaultKey, enrollSSHCredential, getSSHCredentialStatus } from './api/sshCredentials'
import { verifyAdminSSH, enrollVerifiedMonitoring } from './api/serverOperations'
import { authMethodLabel, type SSHAuthMethod, type SSHCredentialStatus } from './api/sshCredentials'
import stagPrimeMark from './assets/stag-prime-symbol.png'
import './App.css'
import InstallationCenter from './components/InstallationCenter'
import OnboardingCenter from './components/OnboardingCenter'
import UserManagementCenter from './components/UserManagementCenter'
import ServerOperations from './components/ServerOperations'
import type { OperationsServer } from './components/ServerOperations'
import MonitoringLive from './components/MonitoringLive'
import InventorySSHEnrollment from './components/InventorySSHEnrollment'
import './components/InventorySSHEnrollment.css'
import ClientDirectory from './components/ClientDirectory'
import { createClient, fetchClients } from './api/clientDirectory'
import type { ClientDirectoryEntry } from './api/clientDirectory'
import { getMonitoringOverview } from './api/monitoring'
import type { MonitoringOverview } from './api/monitoring'
import ServerControlCenter from './components/ServerControlCenter'
import type { ControlServer } from './components/ServerControlCenter'
import EnterpriseWorkspace from './enterprise/EnterpriseWorkspace'
import type { EnterprisePage } from './enterprise/EnterpriseWorkspace'
import Server360 from './enterprise/Server360'
import EnterpriseIncidents from './enterprise/EnterpriseIncidents'
import EnterpriseReports from './enterprise/EnterpriseReports'
import EnterpriseSettings from './enterprise/EnterpriseSettings'
import IntegrationsCenter from './enterprise/IntegrationsCenter'
import Client360 from './enterprise/Client360'
import FleetOpsCenter from './components/FleetOpsCenter'
import { classifySshKeyMaterial, readKeyFromFile } from './utils/sshKeyMaterial'
import { buildHighAlerts } from './enterprise/dashboardAlerts'

type Section = 'dashboard' | 'fleet-ops' | 'live' | 'map' | 'servers' | 'vpn-services' | 'sessions' | 'network' | 'performance' | 'alerts' | 'security' | 'operations-repair' | 'operations-control' | 'reports' | 'clients' | 'settings' | 'install-center' | 'onboarding' | 'users' | 'integrations' | 'audit'

const SECTION_PATHS: Record<Section, string> = {
  dashboard: '/dashboard', 'fleet-ops': '/fleet-ops', live: '/operations/live', map: '/infrastructure/map',
  servers: '/servers', 'vpn-services': '/vpn/services', sessions: '/vpn/sessions',
  network: '/network', performance: '/performance', alerts: '/incidents',
  security: '/security',
  'operations-repair': '/operations/diagnostics', 'operations-control': '/operations/maintenance',
  reports: '/reports', clients: '/clients', users: '/users', settings: '/settings',
  integrations: '/integrations', audit: '/audit',
  'install-center': '/knowledge-base', onboarding: '/onboarding',
}
const LEGACY_ROUTE_REDIRECTS:Record<string,Section> = {
  '/': 'dashboard', '/overview':'dashboard', '/sessions':'sessions', '/alerts':'alerts',
  '/logs': 'alerts', '/events': 'alerts',
  '/reliability': 'performance', '/sla': 'performance', '/uptime': 'performance',
  '/server-operations/repair':'operations-repair', '/server-operations/control':'operations-control',
  '/install-center':'install-center',
}
function canAccessPage(page:Section,role:AuthUser['role']) {
  return role==='admin' || role==='viewer' || !(['users','operations-repair','operations-control','audit','integrations'] as Section[]).includes(page)
}
function sectionFromHash(hash:string,role:AuthUser['role']):Section {
  const route=(hash.startsWith('#')?hash.slice(1):hash).replace(/\/+$/,'').toLowerCase() || '/'
  const candidate=LEGACY_ROUTE_REDIRECTS[route] || (Object.entries(SECTION_PATHS) as [Section,string][]).find(([,url])=>url===route)?.[0] || 'dashboard'
  return canAccessPage(candidate,role)?candidate:'dashboard'
}
type ServerRecord = {
  id: string; name: string; host: string; region: string; country: string;
  provider: string; sshUser: string; sshPort: number; client: string;
  protocol: string; source?: 'backend' | 'local' | 'sample';
}

type Notice = { id: string; text: string; tone: 'success' | 'error' }
type ServerDraft = { name: string; host: string; region: string; country: string; provider: string; sshUser: string; sshPort: string; client: string }

function backendId(uiId: string) {
  return uiId.startsWith('api-') ? uiId.slice(4) : uiId
}

function fromServerRecord(server: ServerRecord): ServerDraft {
  return {
    name: server.name, host: server.host,
    region: server.region === 'Unspecified' ? '' : server.region,
    country: server.country === 'Unspecified' ? '' : server.country,
    provider: server.provider === 'Not specified' ? '' : server.provider,
    sshUser: server.sshUser === 'Not configured' ? '' : server.sshUser,
    sshPort: String(server.sshPort), client: server.client,
  }
}

function validateServerDraft(draft: ServerDraft): string | null {
  if (!draft.name.trim() || !draft.host.trim() || !draft.client.trim())
    return 'Server name, host and client are required.'
  if (!/^[A-Za-z0-9.:-]+$/.test(draft.host.trim()))
    return 'Use an IP address or hostname without http:// or https://'
  const port = Number(draft.sshPort)
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    return 'SSH port must be between 1 and 65535.'
  return null
}


function parseBackendInventory(payload: unknown): ServerRecord[] {
  if (!payload || typeof payload !== 'object' || !('servers' in payload) || !Array.isArray(payload.servers)) {
    throw new Error('Unexpected server inventory response')
  }
  return payload.servers.map((item: unknown): ServerRecord => {
    if (!item || typeof item !== 'object') throw new Error('Invalid inventory record')
    const s = item as Record<string, unknown>
    for (const field of ['id', 'name', 'ip', 'client']) {
      if (typeof s[field] !== 'string' || !s[field]) throw new Error(`Invalid field: ${field}`)
    }
    return {
      id: `api-${s.id}`,
      name: s.name as string,
      host: s.ip as string,
      region: typeof s.location === 'string' && s.location ? s.location : 'Unspecified',
      country: typeof s.country === 'string' && s.country ? s.country : 'Unspecified',
      provider: typeof s.provider === 'string' && s.provider ? s.provider : 'Not specified',
      sshUser: typeof s.ssh_username === 'string' && s.ssh_username ? s.ssh_username : 'Not configured',
      sshPort: typeof s.ssh_port === 'number' ? s.ssh_port : 22,
      client: s.client as string,
      protocol: 'OpenVPN',
      source: 'backend',
    }
  })
}

type EnterpriseNavGroup = 'command' | 'infrastructure' | 'security' | 'operations' | 'business' | 'platform'
const NAV_GROUPS: {key:EnterpriseNavGroup; title:string}[] = [
  {key:'command',title:'COMMAND CENTER'}, {key:'infrastructure',title:'INFRASTRUCTURE'},
  {key:'security',title:'SECURITY & RELIABILITY'}, {key:'operations',title:'SERVER OPERATIONS'},
  {key:'business',title:'BUSINESS MANAGEMENT'}, {key:'platform',title:'PLATFORM ADMINISTRATION'},
]
const NAV: {key:Section; title:string; icon:typeof LayoutDashboard; group:EnterpriseNavGroup; pending?:boolean}[] = [
 {key:'dashboard',title:'Executive Dashboard',icon:LayoutDashboard,group:'command'},
 {key:'fleet-ops',title:'Fleet Ops Center',icon:Radio,group:'command'},
 {key:'live',title:'Live Operations',icon:Activity,group:'command'},
 {key:'map',title:'Infrastructure Map',icon:Globe2,group:'command'},
 {key:'servers',title:'Server Inventory',icon:Server,group:'infrastructure'},
 {key:'vpn-services',title:'VPN Service Health',icon:Radio,group:'infrastructure'},
 {key:'sessions',title:'VPN Sessions',icon:UsersRound,group:'infrastructure'},
 {key:'network',title:'Network & Bandwidth',icon:Network,group:'infrastructure'},
 {key:'performance',title:'Performance & Capacity',icon:Gauge,group:'infrastructure'},
 {key:'alerts',title:'Alerts & Incidents',icon:BellRing,group:'security'},
 {key:'security',title:'Security Intelligence',icon:ShieldAlert,group:'security'},
 {key:'operations-repair',title:'Issue Diagnosis & Repair',icon:Wrench,group:'operations'},
 {key:'operations-control',title:'Server Control & Maintenance',icon:ServerCog,group:'operations'},
 {key:'onboarding',title:'Server Onboarding',icon:FolderOpen,group:'operations'},
 {key:'clients',title:'Clients & Organizations',icon:Building2,group:'business'},
 {key:'reports',title:'Reports & Analytics',icon:FileBarChart2,group:'business'},
 {key:'users',title:'Users & Access',icon:UsersRound,group:'business'},
 {key:'settings',title:'Platform Settings',icon:Settings2,group:'platform'},
 {key:'integrations',title:'Integrations',icon:Workflow,group:'platform'},
 {key:'audit',title:'Audit Trail',icon:ShieldCheck,group:'platform'},
 {key:'install-center',title:'Knowledge Base',icon:BookOpen,group:'platform'},
]
const HEADINGS:Record<Section,{title:string;desc:string}> = {
 dashboard:{title:'Operations dashboard',desc:'Live fleet health and connected VPN users — auto-collected over SSH after you add a server.'},
 'fleet-ops':{title:'Fleet Ops',desc:'NOC board — live users, geo, auth fails, issues→fixes, and VPN start/stop across the fleet.'},
 live:{title:'Live operations',desc:'Live server cards — health, VPN, sessions and CPU/RAM/Disk at a glance.'},
 map:{title:'Infrastructure map',desc:'Live regional fleet map — health, VPN and sessions by country/region.'},
 servers:{title:'Server Inventory',desc:'Add servers once — SSH verify, enroll monitoring, and manage the live fleet.'},
 'vpn-services':{title:'VPN Service Health',desc:'Per-server VPN unit, tunnel, status file, sessions and host load.'},
 sessions:{title:'VPN Sessions',desc:'Live connection intelligence — sessions, traffic, geo, churn and host context.'},
 network:{title:'Network & Bandwidth',desc:'WAN + tunnel Mbps, cumulative counters, errors/drops and link integrity.'},
 performance:{title:'Performance & Capacity',desc:'Live CPU/RAM/disk pressure, headroom, peaks and recent sample trends.'},
 alerts:{title:'Alerts & Incidents',desc:'Severity-ranked incidents with fix guidance and per-server attention.'},
 security:{title:'Security Intelligence',desc:'Certificates, auth failures, journal evidence and security incidents.'},
 'operations-repair':{title:'Issue Diagnosis & Repair',desc:'Verify SSH, run audited diagnostics, and follow a live investigation plan.'},
 'operations-control':{title:'Server Control & Maintenance',desc:'Live VPN start/stop/restart plus read-only CPU/RAM diagnostics.'},
 clients:{title:'Clients & Organizations',desc:'Authorized multi-client infrastructure directory.'},
 reports:{title:'Reports & Analytics',desc:'Verified monitoring summaries and authorized exports.'},
 users:{title:'Users & Access',desc:'Manage accounts and client-scoped permissions.'},
 settings:{title:'Platform Settings',desc:'Appearance, collector intervals, alert channels, and application readiness.'},
 integrations:{title:'Integrations',desc:'In-app alerts and the HTTPS webhook used for open incidents.'},
 audit:{title:'Audit Trail',desc:'Account changes and privileged server operations, without secrets.'},
 'install-center':{title:'Knowledge Base',desc:'Operator handbook and troubleshooting, with review progress kept in this browser.'},
 onboarding:{title:'Server Onboarding',desc:'Verify SSH, discover OpenVPN, and enroll monitoring collectors.'},
}
function MiniLabel({ children }: { children: ReactNode }) { return <span className="tiny-label">{children}</span> }
type HealthState = { health: ServerHealthResponse | null; loading: boolean; error: string | null; checkedAt: Date | null }

function isVerifiedHealth(state: HealthState | undefined, server?: ServerRecord) {
  if (!state?.health || !server) return false
  const h = state.health
  return h.server_id === backendId(server.id) && h.host === server.host &&
    h.monitoring_source === 'verified_ssh' && h.status === 'connected' &&
    h.host_key_verified === true
}

function StatusPill({ state, monitored, configured = false, server }: {
  state?: HealthState; monitored?: boolean; configured?: boolean; server?: ServerRecord
}) {
  const verified = isVerifiedHealth(state, server)
  if (verified && state?.health) {
    return <span className="status-pill" title="Verified SSH host-key and observed host sample; VPN service health is a separate metric" style={{background:'#e9f8f7',color:'#136f70',border:'1px solid #c6e6df'}}>
      <span className="status-pulse" style={{background:'#19a3a5'}}/>SSH verified · host observed
    </span>
  }
  if (monitored) return <span className="status-pill" style={{background:'#f0f3f7',color:'#58677a'}}>
    <span className="status-pulse" style={{background:'#96a0b1'}}/>{state?.loading?'Checking metrics…':state?.error?.includes('worker_offline')?'Worker offline':state?.error?.includes('stale')?'Metrics stale':state?.error?.includes('unreachable')?'Collector unreachable':state?.error?'Monitoring unavailable':'Awaiting worker sample'}
  </span>
  if (configured) return <span className="status-pill"><span className="status-pulse"/> Monitoring setup pending</span>
  return <span className="status-pill"><span className="status-pulse"/> Inventory only</span>
}

function Metric({ icon: Icon, label, value, hint, badge }: { icon: typeof Server; label: string; value: string; hint: string; badge?: string }) {
  return <div className="metric-card">
    <div className="metric-head"><span>{label}</span><span className="metric-icon"><Icon size={19} /></span></div>
    <div className="metric-value">{value}</div><div className="metric-foot">{badge && <span className="metric-badge">{badge}</span>}<span>{hint}</span></div>
  </div>
}
function RegionFlag({ country }: { country: string }) { return <span className="region-flag" aria-label={country}>{country === 'Germany' ? '🇩🇪' : country === 'United Arab Emirates' ? '🇦🇪' : '🌐'}</span> }

// Values come from the server-specific verified SSH collector. Network totals are cumulative, not Mbps.
function humanPercent(value: number | null | undefined): string {
  return typeof value === 'number' && Number.isFinite(value) ? `${value.toFixed(1)}%` : '—'
}

function humanBytes(value: number | null | undefined): string {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '—'
  if (value === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / Math.pow(1024, exponent)).toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`
}

function App({ currentUser, onSignOut }: { currentUser: AuthUser; onSignOut: () => void }) {
  const [section, setSection] = useState<Section>(() => sectionFromHash(window.location.hash, currentUser.role))
  const [expandedGroups,setExpandedGroups] = useState<EnterpriseNavGroup[]>(['command','infrastructure','security','operations','business','platform'])
  const [sidebarQuery,setSidebarQuery] = useState('')
  const [navCollapsed,setNavCollapsed] = useState(false)
  const [theme,setTheme] = useState<'light'|'dark'>(() => {
    try { return localStorage.getItem('sentinel-theme') === 'dark' ? 'dark' : 'light' } catch { return 'light' }
  })
  useEffect(() => {
    try { localStorage.setItem('sentinel-theme', theme) } catch { /* private browsing */ }
  }, [theme])
  const [globalScope,setGlobalScope] = useState('all')
  const [servers, setServers] = useState<ServerRecord[]>([])
  const [inventoryApiStatus, setInventoryApiStatus] = useState<'loading' | 'connected' | 'offline'>('loading')
  const [monitoringTargets, setMonitoringTargets] = useState<MonitoringTarget[]>([])
  const [, setTargetStatus] = useState<'loading' | 'ready' | 'error'>('loading')
  const [, setTargetError] = useState<string | null>(null)
  const [targetsRevision, setTargetsRevision] = useState(0)
  const [healthById, setHealthById] = useState<Record<string, HealthState>>({})
  const [monitoringOverview, setMonitoringOverview] = useState<MonitoringOverview | null>(null)
  const [healthRefresh, setHealthRefresh] = useState(0)
  const [, setBackendCount] = useState(0)
  const [archivedServers, setArchivedServers] = useState<ArchivedServer[]>([])
  const [inventoryTab, setInventoryTab] = useState<'active' | 'archived'>('active')
  const [editingServer, setEditingServer] = useState<ServerRecord | null>(null)
  const [editDraft, setEditDraft] = useState<ServerDraft | null>(null)
  const [archivingServer, setArchivingServer] = useState<ServerRecord | null>(null)
  // Secrets stay only in this modal's in-memory state until user explicitly saves.
  // Neither SSH keys nor passwords are stored in localStorage, URLs or logs.
  const [keyChooserServer, setKeyChooserServer] = useState<ServerRecord | null>(null)
  const [credentialMethod, setCredentialMethod] = useState<SSHAuthMethod>('private_key')
  const [credentialFile, setCredentialFile] = useState<File | null>(null)
  const [credentialPassword, setCredentialPassword] = useState('')
  const [credentialBusy, setCredentialBusy] = useState(false)
  const [savedCredential, setSavedCredential] = useState<SSHCredentialStatus | null>(null)
  const [credentialStatusError, setCredentialStatusError] = useState<string | null>(null)
  const [credentialStatusLoading, setCredentialStatusLoading] = useState(false)
  const privateKeyFileInput = useRef<HTMLInputElement | null>(null)

  const [busyAction, setBusyAction] = useState<string | null>(null)
  const [savingServer, setSavingServer] = useState(false)
  const [search, setSearch] = useState('')
  const [clientFilter, setClientFilter] = useState('all')
  const [monitorFilter, setMonitorFilter] = useState('all')
  const [selectedRows, setSelectedRows] = useState<string[]>([])
  const [deleteSelection, setDeleteSelection] = useState<string[] | null>(null)
  const [deleteConfirmation, setDeleteConfirmation] = useState('')
  const [draftMethod, setDraftMethod] = useState<SSHAuthMethod>('private_key')
  const [draftPassword, setDraftPassword] = useState('')
  const [draftKey, setDraftKey] = useState<File | null>(null)
  const [draftKeyText, setDraftKeyText] = useState('')
  const [credentialKeyText, setCredentialKeyText] = useState('')
  const [ppkPassphrase, setPpkPassphrase] = useState('')
  const [draftPpkPassphrase, setDraftPpkPassphrase] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [newOpen, setNewOpen] = useState(false)
  const [orgOptions, setOrgOptions] = useState<ClientDirectoryEntry[]>([])
  const [orgOptionsError, setOrgOptionsError] = useState<string | null>(null)
  const [orgDraftName, setOrgDraftName] = useState('')
  const [orgSaving, setOrgSaving] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [profileMenuOpen, setProfileMenuOpen] = useState(false)
  const [profileDetailsOpen, setProfileDetailsOpen] = useState(false)
  const [passwordForm, setPasswordForm] = useState({ current: '', next: '', confirm: '' })
  const [passwordBusy, setPasswordBusy] = useState(false)
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null)
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const profileMenuRef = useRef<HTMLDivElement | null>(null)
  const profileButtonRef = useRef<HTMLButtonElement | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [draft, setDraft] = useState({ name: '', host: '', region: '', country: '', provider: '', sshUser: '', sshPort: '22', client: '' })

  // Restore the page after refresh; also respond to Back/Forward and direct links.
  // Invalid or forbidden destinations go to Overview; backend RBAC remains authoritative.
  useEffect(() => {
    function syncPageFromUrl() {
      const next = sectionFromHash(window.location.hash, currentUser.role)
      const canonical = `#${SECTION_PATHS[next]}`
      if (window.location.hash !== canonical) {
        window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}${canonical}`)
      }
      setSection(next)
      setSelected(null)
      setSearch('')
      setNotificationsOpen(false)
      setProfileMenuOpen(false)
      setMobileOpen(false)
    }
    syncPageFromUrl()
    window.addEventListener('hashchange', syncPageFromUrl)
    return () => window.removeEventListener('hashchange', syncPageFromUrl)
  }, [currentUser.role])

  // The avatar opens a menu; it must never silently sign the user out.
  useEffect(() => {
    if (!profileMenuOpen) return
    function handlePointerDown(event: PointerEvent) {
      if (profileMenuRef.current && !profileMenuRef.current.contains(event.target as Node)) {
        setProfileMenuOpen(false)
      }
    }
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setProfileMenuOpen(false)
        profileButtonRef.current?.focus()
      }
    }
    document.addEventListener('pointerdown', handlePointerDown)
    document.addEventListener('keydown', handleEscape)
    return () => {
      document.removeEventListener('pointerdown', handlePointerDown)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [profileMenuOpen])

  useEffect(() => {
    if (!profileDetailsOpen) return
    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') setProfileDetailsOpen(false)
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [profileDetailsOpen])

  useEffect(() => {
    if (!newOpen) return
    let canceled = false
    setOrgOptionsError(null)
    fetchClients()
      .then((payload) => {
        if (canceled) return
        const list = payload.clients || []
        setOrgOptions(list)
        setDraft((prev) => {
          if (prev.client && list.some((c) => c.name === prev.client)) return prev
          return { ...prev, client: list[0]?.name || '' }
        })
      })
      .catch(() => {
        if (!canceled) {
          setOrgOptions([])
          setOrgOptionsError('Could not load organizations. Open Clients & Organizations first, then retry.')
        }
      })
    return () => { canceled = true }
  }, [newOpen])

useEffect(() => {
  let canceled = false
  Promise.all([getServers(), getArchivedServers()])
    .then(([result, archived]) => {
      if (canceled) return
      const activeRecords = parseBackendInventory(result)
      setServers(activeRecords)
    setSelectedRows(previous => previous.filter(id => activeRecords.some(record => record.id === id)))
      setBackendCount(activeRecords.length)
      setArchivedServers(archived.servers)
      setInventoryApiStatus('connected')
    })
    .catch(() => {
      if (!canceled) setInventoryApiStatus('offline')
    })
  return () => { canceled = true }
}, [])

  // Server inventory is never an SSH allowlist. The backend approves and pins SSH targets.
  useEffect(() => {
    if (inventoryApiStatus !== 'connected') {
      if (inventoryApiStatus === 'offline') {
        setMonitoringTargets([])
        setTargetStatus('error')
        setTargetError('Inventory backend unavailable')
      }
      return
    }
    let cancelled = false
    let requestRunning = false
    const controller = new AbortController()
    setTargetStatus('loading')
    setTargetError(null)
    async function refreshApprovals() {
      if (requestRunning || cancelled) return
      requestRunning = true
      try {
        const result = await getMonitoringTargets(controller.signal)
        if (cancelled) return
        setMonitoringTargets(result.targets)
        setTargetStatus('ready')
        setTargetError(null)
      } catch (err) {
        if (cancelled) return
        setMonitoringTargets([])
        setTargetStatus('error')
        setTargetError(err instanceof Error ? err.message : 'Monitoring approval registry unavailable')
      } finally { requestRunning = false }
    }
    void refreshApprovals()
    // Detect newly approved backend targets without a page reload.
    const timer = window.setInterval(() => { void refreshApprovals() }, 120_000)
    return () => { cancelled = true; controller.abort(); window.clearInterval(timer) }
  }, [inventoryApiStatus, targetsRevision])

  const targetById = useMemo(
    () => new Map(monitoringTargets.map(target => [target.server_id, target])),
    [monitoringTargets],
  )
  const readyServers = useMemo(() => servers.filter(server => {
    const target = targetById.get(backendId(server.id))
    return target?.monitoring_enabled === true && target?.local_configuration_ready === true &&
      target.host === server.host
  }), [servers, targetById])
  const highAlerts = useMemo(() => buildHighAlerts(monitoringOverview), [monitoringOverview])
  const verifiedCount = readyServers.filter(server => isVerifiedHealth(healthById[backendId(server.id)], server)).length
  const controlServers = useMemo<ControlServer[]>(() => [
    ...servers.map(server => {
      const state = healthById[backendId(server.id)]
      const verified = isVerifiedHealth(state, server)
      return {
        id: backendId(server.id), name: server.name, client: server.client,
        location: [server.region, server.country].filter(part => part && part !== 'Unspecified').join(', '),
        provider: server.provider, archived: false,
        observation: verified
          ? (state?.health?.openvpn.service_status === 'active' ? 'Verified SSH · VPN active' : 'Verified SSH · VPN status: ' + String(state?.health?.openvpn.service_status ?? 'unknown'))
          : (state?.error ? 'Monitoring check failed · power state unknown' : 'Live power state not established'),
        vpnState: verified ? (state?.health?.openvpn.service_status ?? 'unknown') : 'unknown',
        observedAt: verified ? state?.checkedAt?.toLocaleString() ?? null : null,
      }
    }),
    ...archivedServers.map(server => ({
      id: server.id, name: server.name, client: server.client,
      location: [server.location, server.country].filter(Boolean).join(', '),
      provider: server.provider ?? 'Not specified', archived: true,
      observation: 'Archived inventory record · actual server power state unknown',
      vpnState: 'unknown', observedAt: null,
    })),
  ], [servers, archivedServers, healthById])

  // Server Operations is a frontend planning layer over existing backend inventory.
  // A failed SSH sample is an observation, not proof that OpenVPN is down.
  const operationsServers = useMemo<OperationsServer[]>(() => servers.map(server => {
    const target = targetById.get(backendId(server.id))
    const approved = target?.monitoring_enabled === true && target?.local_configuration_ready === true && target.host === server.host
    const state = healthById[backendId(server.id)]
    const verified = approved && isVerifiedHealth(state, server)
    let monitoring: OperationsServer['monitoring'] = 'inventory_only'
    let observation = 'Registered in inventory; no verified administrative SSH connection or monitoring enrollment has been established.'
    if (approved && verified && state?.health?.openvpn.service_status === 'active') {
      monitoring = 'verified'
      observation = 'Authenticated SSH health sample verified. The OpenVPN service was active in the last sample.'
    } else if (approved && verified) {
      monitoring = 'attention'
      observation = 'SSH is verified, but the latest OpenVPN service state was not active. Confirm the instance and client connectivity before classifying the outage.'
    } else if (approved && state?.error) {
      monitoring = 'attention'
      observation = 'The latest SSH monitoring check failed or was unverified. This is not proof that the VPS or VPN is offline.'
    } else if (approved) {
      monitoring = 'checking'
      observation = 'A monitoring target is approved, but no current verified health sample is available yet.'
    }
    return {
      id: server.id, name: server.name, host: server.host, client: server.client,
      location: server.region, provider: server.provider, sshUser: server.sshUser,
      sshPort: server.sshPort, monitoring, observation,
    }
  }), [servers, targetById, healthById])

  // Step 41A: UI reads database cache ONLY. Browser navigation never opens SSH.
  useEffect(() => {
    if (inventoryApiStatus !== 'connected') { setHealthById({}); setMonitoringOverview(null); return }
    const controller = new AbortController()
    let busy = false
    async function loadCache() {
      if (busy || controller.signal.aborted) return
      busy = true
      try {
        const payload = await getMonitoringOverview(controller.signal)
        if (controller.signal.aborted) return
        setMonitoringOverview(payload)
        const next: Record<string, HealthState> = {}
        for (const item of payload.servers) {
          const health = item.health.fresh && item.health.data ? {
            ...item.health.data, server_id: item.server_id, server_name: item.server_name,
            monitoring_source: 'verified_ssh',
          } as ServerHealthResponse : null
          next[item.server_id] = {health, loading: false,
            error: health ? null : item.monitoring_enabled
              ? (`Monitoring ${item.status}; no fresh SSH reading${item.error_code ? ` (${item.error_code})` : ''}`) : null,
            checkedAt: item.health.at_utc ? new Date(item.health.at_utc) : null}
        }
        setHealthById(next)
      } catch {
        if (!controller.signal.aborted) {setHealthById({});setMonitoringOverview(null)}
      } finally { busy = false }
    }
    void loadCache()
    const timer = window.setInterval(() => { void loadCache() }, 30_000)
    return () => {controller.abort(); window.clearInterval(timer)}
  }, [inventoryApiStatus, healthRefresh])

  async function refreshInventory() {
    const [active, archived] = await Promise.all([getServers(), getArchivedServers()])
    const activeRecords = parseBackendInventory(active)
    setServers(activeRecords)
    setSelectedRows(previous => previous.filter(id => activeRecords.some(record => record.id === id)))
    setBackendCount(activeRecords.length)
    setArchivedServers(archived.servers)
    setInventoryApiStatus('connected')
    setTargetsRevision(n => n + 1)
  }

  function openEdit(server: ServerRecord) {
    setSelected(null)
    setEditDraft(fromServerRecord(server))
    setEditingServer(server)
  }

  function closeCredentialModal() {
    if (credentialBusy) return
    setCredentialFile(null)
    setCredentialPassword('')
    setCredentialKeyText('')
    setPpkPassphrase('')
    setCredentialMethod('private_key')
    setSavedCredential(null)
    setKeyChooserServer(null)
  }

  function openCredentialModal(server: ServerRecord) {
    setSelected(null)
    setCredentialMethod('private_key')
    setCredentialFile(null)
    setCredentialPassword('')
    setCredentialKeyText('')
    setPpkPassphrase('')
    setSavedCredential(null)
    setCredentialStatusError(null)
    setKeyChooserServer(server)
  }

  // Load status on every modal open, without ever returning secret/key material.
  useEffect(() => {
    if (!keyChooserServer || keyChooserServer.source !== 'backend') return
    const controller = new AbortController()
    setCredentialStatusLoading(true)
    setCredentialStatusError(null)
    getSSHCredentialStatus(backendId(keyChooserServer.id), controller.signal)
      .then(status => {if (!controller.signal.aborted) {setSavedCredential(status); if (status.configured && status.auth_method) setCredentialMethod(status.auth_method)}})
      .catch(error => {if (!controller.signal.aborted) setCredentialStatusError(error instanceof Error ? error.message : 'Unable to read saved credential status')})
      .finally(() => {if (!controller.signal.aborted) setCredentialStatusLoading(false)})
    return () => controller.abort()
  }, [keyChooserServer?.id])

  async function selectPrivateKey(file: File | undefined) {
    if (!file) return
    const checked = await readKeyFromFile(file)
    if (!checked.ok) {
      showNotice(checked.reason, 'error')
      setCredentialFile(null)
      setCredentialKeyText('')
      return
    }
    setCredentialFile(file)
    setCredentialKeyText(checked.secret)
  }

  async function saveSSHCredential() {
    if (!keyChooserServer || credentialBusy || keyChooserServer.source !== 'backend') return
    setCredentialBusy(true)
    try {
      let secret = credentialMethod === 'password' ? credentialPassword : (credentialKeyText || (credentialFile ? await credentialFile.text() : ''))
      if (credentialMethod === 'private_key' || credentialMethod === 'key_and_password') {
        const checked = classifySshKeyMaterial(secret, credentialFile?.name || '')
        if (!checked.ok) throw new Error(checked.reason)
        secret = checked.secret
      }
      if (!secret) throw new Error('Enter the SSH password, choose any private-key file, or paste the private key text.')
      if (credentialMethod === 'key_and_password' && !credentialPassword) {
        throw new Error('This host needs the SSH login password together with the private key.')
      }
      const looksLikePpk = secret.includes('PuTTY-User-Key-File') || (secret.includes('Private-MAC:') && secret.includes('Private-Lines:'))
      const result = await enrollSSHCredential(
        backendId(keyChooserServer.id),
        credentialMethod,
        secret,
        {
          ppkPassphrase: looksLikePpk ? ppkPassphrase : undefined,
          loginPassword: credentialMethod === 'key_and_password' ? credentialPassword : undefined,
        },
      )
      const persisted = await getSSHCredentialStatus(backendId(keyChooserServer.id))
      if (!persisted.configured || persisted.auth_method !== credentialMethod || !persisted.vault_accessible) {
        throw new Error('Credential saved, but vault read-back verification was unsuccessful. Review the vault configuration before SSH verification.')
      }
      setSavedCredential(persisted)
      setCredentialPassword('')
      setCredentialFile(null)
      setCredentialKeyText('')
      setPpkPassphrase('')
      setKeyChooserServer(null)
      setSelected(keyChooserServer.id)
      showNotice(`${authMethodLabel(result.auth_method)} encrypted and read-back verified. Open Server Details to verify SSH and activate monitoring.`)
    } catch (error) {
      setCredentialPassword('')
      showNotice(error instanceof Error ? error.message : 'SSH credentials were NOT saved.', 'error')
    } finally {
      setCredentialBusy(false)
    }
  }

  async function saveFromLocalDefaultKey() {
    if (!keyChooserServer || credentialBusy || keyChooserServer.source !== 'backend') return
    setCredentialBusy(true)
    try {
      const result = await enrollFromLocalDefaultKey(backendId(keyChooserServer.id), ppkPassphrase || undefined)
      const persisted = await getSSHCredentialStatus(backendId(keyChooserServer.id))
      if (!persisted.configured || !persisted.vault_accessible) {
        throw new Error('Local key enrolled, but vault read-back failed.')
      }
      setSavedCredential(persisted)
      setCredentialPassword('')
      setCredentialFile(null)
      setCredentialKeyText('')
      setPpkPassphrase('')
      setKeyChooserServer(null)
      setSelected(keyChooserServer.id)
      showNotice(`${result.auth_method === 'password' ? 'Password' : 'SSH key'} loaded from saved local path and encrypted. Verify SSH next.`)
    } catch (error) {
      showNotice(error instanceof Error ? error.message : 'Could not enroll local default key.', 'error')
    } finally {
      setCredentialBusy(false)
    }
  }

  async function saveEditedServer(e: FormEvent) {
    e.preventDefault()
    if (!editingServer || !editDraft || busyAction) return
    const validationError = validateServerDraft(editDraft)
    if (validationError) { showNotice(validationError, 'error'); return }
    setBusyAction('edit')
    try {
      await updateServer(backendId(editingServer.id), {
        name: editDraft.name.trim(), host: editDraft.host.trim(),
        location: editDraft.region.trim() || null,
        country: editDraft.country.trim() || null,
        provider: editDraft.provider.trim() || null,
        ssh_username: editDraft.sshUser.trim() || null,
        ssh_port: Number(editDraft.sshPort),
      })
      setEditingServer(null)
      setEditDraft(null)
      try {
        await refreshInventory()
        showNotice('Server details updated in database.')
      } catch {
        showNotice('Server updated, but inventory refresh failed. Reload this page.', 'error')
      }
    } catch (error) {
      showNotice(error instanceof Error ? error.message : 'Could not update server.', 'error')
    } finally {
      setBusyAction(null)
    }
  }

  async function confirmArchive() {
    if (!archivingServer || busyAction) return
    setBusyAction('archive')
    try {
      await archiveServerApi(backendId(archivingServer.id))
      setArchivingServer(null)
      setSelected(null)
      try {
        await refreshInventory()
        showNotice('Server archived. You can restore it from Archived servers.')
      } catch {
        showNotice('Server archived, but inventory refresh failed. Reload this page.', 'error')
      }
    } catch (error) {
      showNotice(error instanceof Error ? error.message : 'Could not archive server.', 'error')
    } finally {
      setBusyAction(null)
    }
  }

  async function archiveSelectedServers() {
    if (busyAction || selectedRows.length === 0) return
    setBusyAction('bulk-archive')
    try {
      const response = await bulkArchiveServers(selectedRows.map(backendId))
      setSelectedRows([])
      await refreshInventory()
      showNotice(`${response.archived} server(s) archived. No remote VPS changes were made.`)
    } catch (error) {
      showNotice(error instanceof Error ? error.message : 'Bulk archive failed.', 'error')
    } finally { setBusyAction(null) }
  }

  async function deleteSelectedServers() {
    if (busyAction || !deleteSelection || deleteSelection.length === 0) return
    if (deleteConfirmation !== `DELETE ${deleteSelection.length} SERVERS`) return
    setBusyAction('bulk-delete')
    try {
      const response = await permanentlyDeleteServers(deleteSelection.map(backendId), deleteConfirmation)
      setDeleteSelection(null)
      setDeleteConfirmation('')
      setSelectedRows([])
      setSelected(null)
      await refreshInventory()
      setHealthRefresh(n => n + 1)
      showNotice(`${response.deleted} inventory record(s) permanently deleted. Remote VPSes unchanged; historical security audit retained.`)
    } catch (error) {
      showNotice(error instanceof Error ? error.message : 'Permanent deletion failed. No partial delete accepted.', 'error')
    } finally { setBusyAction(null) }
  }
  function toggleServerSelection(serverId: string, checked: boolean) {
    setSelectedRows(old => checked ? [...new Set([...old,serverId])] : old.filter(id => id !== serverId))
  }

  async function restoreArchived(server: ArchivedServer) {
    if (busyAction) return
    setBusyAction('restore-' + server.id)
    try {
      await restoreServerApi(server.id)
      try {
        await refreshInventory()
        showNotice('Server restored to active inventory.')
      } catch {
        showNotice('Server restored, but inventory refresh failed. Reload this page.', 'error')
      }
    } catch (error) {
      showNotice(error instanceof Error ? error.message : 'Could not restore server.', 'error')
    } finally {
      setBusyAction(null)
    }
  }
  const filtered = useMemo(() => servers.filter((s) => {
    const matchesText = [s.name, s.host, s.region, s.country, s.provider, s.client].join(' ').toLowerCase().includes(search.toLowerCase())
    if (!matchesText || (section==='servers' && clientFilter!=='all' && s.client!==clientFilter)) return false
    if (section!=='servers' || monitorFilter==='all') return true
    const target = monitoringTargets.find(t=>t.server_id===backendId(s.id))
    const active = !!target?.monitoring_enabled
    return monitorFilter==='enrolled' ? active : !active
  }), [servers, search, section, clientFilter, monitorFilter, monitoringTargets])
  const record = servers.find((s) => s.id === selected)
  const profileInitials = (currentUser.display_name.trim() || currentUser.username).split(/\s+/).map(word => word[0]).slice(0, 2).join('').toUpperCase()
  function showNotice(text: string, tone: 'success' | 'error' = 'success') { setNotice({ id: String(Date.now()), text, tone }) }
  function moveTo(key: Section) {
    if (!canAccessPage(key, currentUser.role)) return
    setSection(key)
    setSelected(null)
    setSearch('')
    setNotificationsOpen(false)
    setProfileMenuOpen(false)
    setMobileOpen(false)
    const destination = `#${SECTION_PATHS[key]}`
    // Writing a different hash creates a browser-history entry and emits hashchange.
    if (window.location.hash !== destination) window.location.hash = destination
  }
  async function createOrganization() {
    const name = orgDraftName.trim()
    if (name.length < 2 || orgSaving) return
    setOrgSaving(true)
    setOrgOptionsError(null)
    try {
      const created = await createClient({ name, contact_email: null })
      setOrgOptions((prev) => [...prev.filter((item) => item.id !== created.id), created].sort((a, b) => a.name.localeCompare(b.name)))
      setDraft((prev) => ({ ...prev, client: created.name }))
      setOrgDraftName('')
    } catch (err) {
      setOrgOptionsError(err instanceof Error ? err.message : 'Could not create the organization')
    } finally {
      setOrgSaving(false)
    }
  }

  async function addServer(e: FormEvent) {
    e.preventDefault()
    if (savingServer) return
    if (inventoryApiStatus !== 'connected') {
      showNotice('Backend is unavailable. Server was NOT saved.', 'error')
      return
    }
    const validationError = validateServerDraft(draft)
    if (validationError) { showNotice(validationError, 'error'); return }
    if (!draft.sshUser.trim() ||
        (draftMethod === 'password'
          ? draftPassword.length < 8
          : draftMethod === 'key_and_password'
            ? !(draftKey || draftKeyText.trim()) || !draftPassword
            : !(draftKey || draftKeyText.trim()))) {
      showNotice('SSH username and password, private key, or key+password are required for live monitoring.', 'error')
      return
    }
    setSavingServer(true)
    let createdId: string | null = null
    let registered = false
    try {
      const created = await createServer({
        client_name: draft.client.trim(), name: draft.name.trim(), host: draft.host.trim(),
        ssh_port: Number(draft.sshPort), ssh_username: draft.sshUser.trim() || null,
        country: draft.country.trim() || null, location: draft.region.trim() || null,
        provider: draft.provider.trim() || null,
      })
      createdId = created.id
      registered = true
      // Always go live: vault → verify → discover VPN unit → enroll monitoring.
      let secret = draftMethod === 'password' ? draftPassword : draftKeyText
      if (draftMethod === 'private_key' || draftMethod === 'key_and_password') {
        if (draftKey && !secret.trim()) {
          const checkedFile = await readKeyFromFile(draftKey)
          if (!checkedFile.ok) throw new Error(checkedFile.reason)
          secret = checkedFile.secret
        } else {
          const checked = classifySshKeyMaterial(secret, draftKey?.name || '')
          if (!checked.ok) throw new Error(checked.reason)
          secret = checked.secret
        }
      }
      const looksLikePpk = secret.includes('PuTTY-User-Key-File') || (secret.includes('Private-MAC:') && secret.includes('Private-Lines:'))
      await enrollSSHCredential(created.id, draftMethod, secret, {
        ppkPassphrase: looksLikePpk ? draftPpkPassphrase : undefined,
        loginPassword: draftMethod === 'key_and_password' ? draftPassword : undefined,
      })
      const status = await getSSHCredentialStatus(created.id)
      if (!status.configured || !status.vault_accessible || !status.host_pinned)
        throw new Error('Encrypted credential read-back failed')
      const verified = await verifyAdminSSH(created.id)
      if (!verified.ssh_verified || !verified.host_key_verified)
        throw new Error('SSH host identity could not be verified')
      const enrollment = await enrollVerifiedMonitoring(created.id, {
        consent: true, vpn_service: 'auto', vpn_interface: 'auto', network_interface: 'auto',
      })
      if (!enrollment.monitoring_enabled) throw new Error('Server monitoring enrollment not confirmed')
      setNewOpen(false)
      setDraft({name:'',host:'',region:'',country:'',provider:'',sshUser:'',sshPort:'22',client:''})
      setDraftPassword('');setDraftKey(null);setDraftKeyText('');setDraftPpkPassphrase('')
      await refreshInventory()
      setHealthRefresh(n=>n+1)
      showNotice(`Live monitoring started (${enrollment.vpn_service || 'auto'} / ${enrollment.vpn_interface || 'auto'}). Dashboard updates after the first worker sample.`)
    } catch (error) {
      setDraftPassword('');setDraftKey(null);setDraftKeyText('');setDraftPpkPassphrase('')
      if (registered) {
        setNewOpen(false)
        await refreshInventory().catch(()=>{})
        showNotice(`Server saved${createdId ? ' (ID '+createdId.slice(0,8)+')' : ''}, but live activation failed: ${error instanceof Error ? error.message : 'unknown error'}. Open Server Details → Start live monitoring.`, 'error')
      } else showNotice(error instanceof Error ? error.message : 'Server was NOT saved.', 'error')
    } finally { setSavingServer(false) }
  }
  function exportInventory() {
    const safe = servers.map(({ sshUser, sshPort, ...rest }) => rest)
    const content = JSON.stringify({ exportedAt: new Date().toISOString(), monitored: false, servers: safe }, null, 2)
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([content], { type: 'application/json' })); a.download = 'sentinel-server-inventory.json'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1500)
    showNotice('Inventory exported. No credentials included.')
  }
  return <div className={"sentinel-app ent-shell"+(navCollapsed?" sidebar-collapsed":"")} data-ent-theme={theme}>
    <style>{`
      .sp-account-anchor { position: relative; display: flex; align-items: center; }
      .sp-account-avatar { cursor: pointer; border: 2px solid transparent; transition: box-shadow .17s, transform .17s; }
      .sp-account-avatar:hover, .sp-account-avatar[aria-expanded="true"] { box-shadow: 0 0 0 3px rgba(33, 167, 207, .17); transform: translateY(-1px); }
      .sp-account-avatar:focus-visible, .sp-account-action:focus-visible { outline: 3px solid #36afd6; outline-offset: 3px; }
      .sp-account-menu { position: absolute; top: calc(100% + 14px); right: 0; width: min(308px, calc(100vw - 20px)); background: #ffffff; color: #132b45; border: 1px solid #d9e5f0; border-radius: 15px; box-shadow: 0 20px 65px rgba(8, 30, 57, .19); z-index: 300; overflow: hidden; }
      .sp-account-header { background: linear-gradient(120deg, #f0f8fe, #f8fbff); display:flex; align-items:center; gap:12px; padding:18px 17px; border-bottom:1px solid #e4edf5; }
      .sp-account-header-avatar { width:43px; height:43px; border-radius:13px; display:grid; place-items:center; font-weight:900; color:#ffffff; background:linear-gradient(145deg,#0e3454,#126991); box-shadow:0 4px 12px rgba(13, 63, 102, .18); flex-shrink:0; }
      .sp-account-name { font-size:13px; font-weight:800; line-height:1.45; overflow-wrap:anywhere; }
      .sp-account-meta { font-size:11px; color:#69809a; margin-top:3px; overflow-wrap:anywhere; }
      .sp-account-actions { padding:8px; }
      .sp-account-action { display:flex; align-items:center; width:100%; gap:11px; border:0; border-radius:9px; padding:12px 11px; background:transparent; text-align:left; color:#203c59; font-size:12px; font-weight:750; cursor:pointer; }
      .sp-account-action svg { color:#537895; flex-shrink:0; }
      .sp-account-action:hover { background:#edf6fc; color:#073e67; }
      .sp-account-action:hover svg { color:#0093bc; }
      .sp-account-action span { flex:1; }
      .sp-account-rule { border-top:1px solid #e7edf4; margin:6px 5px; }
      .sp-account-action.sp-sign-out { color:#a33840; }
      .sp-account-action.sp-sign-out svg { color:#bb4d57; }
      .sp-account-action.sp-sign-out:hover { background:#fff0f0; color:#962632; }
      .sp-account-foot { padding:10px 18px 13px; background:#f8fafc; border-top:1px solid #edf1f5; color:#788da1; font-size:10px; line-height:1.5; }
      .sp-profile-info { margin:0 27px 21px; border:1px solid #e3ebf4; border-radius:11px; overflow:hidden; }
      .sp-profile-row { display:flex; gap:16px; align-items:start; justify-content:space-between; padding:14px 16px; border-bottom:1px solid #edf1f5; font-size:12px; }
      .sp-profile-row:last-child { border-bottom:0; }
      .sp-profile-row span { color:#708399; }
      .sp-profile-row strong { color:#183550; font-size:12px; text-align:right; overflow-wrap:anywhere; }
      @media (max-width:760px) { .sp-account-menu { right:-4px; top:calc(100% + 9px); } }
    `}</style>
    <div className="mobile-shade" style={{ display: mobileOpen ? 'block' : undefined }} onClick={() => setMobileOpen(false)} />
    <aside className={'sidebar' + (mobileOpen ? ' mobile-open' : '')} aria-label="Enterprise navigation">
      <div className="brand">
        <div className="brand-emblem brand-emblem-official"><img src={stagPrimeMark} alt="Stag Prime symbol"/></div>
        <div className="brand-copy">
          <span className="brand-name">Stag Prime</span>
          <span className="brand-product">Sentinel</span>
          <span className="brand-subtitle">VPN operations monitor</span>
        </div>
      </div>
      <div className="product-title"><span className="product-dot"/><span className="product-title-text">Enterprise observability</span><span className="product-version">v2.0</span></div>
      <div className="ent-sidebar-tools"><button title="Collapse sidebar" aria-label="Toggle compact sidebar" type="button" onClick={()=>setNavCollapsed(x=>!x)}><PanelLeftClose size={15}/><span>{navCollapsed?'Expand':'Compact'}</span></button><button type="button" title="Toggle light/dark theme" aria-label="Toggle light/dark theme" onClick={()=>setTheme(v=>v==='light'?'dark':'light')}><MoonStar size={15}/></button></div>
      <label className="ent-search-nav"><Search size={15}/><input value={sidebarQuery} onChange={e=>setSidebarQuery(e.target.value)} placeholder="Find a workspace…" aria-label="Search navigation modules"/></label>
      {NAV_GROUPS.map(g=>{const links=NAV.filter(n=>n.group===g.key && canAccessPage(n.key,currentUser.role) && n.title.toLowerCase().includes(sidebarQuery.toLowerCase()));if(!links.length)return null;const expanded=sidebarQuery.trim().length>0 || expandedGroups.includes(g.key);return <div key={g.key} className="ent-nav-group"><button type="button" className="ent-group-toggle" onClick={()=>setExpandedGroups(a=>a.includes(g.key)?a.filter(x=>x!==g.key):[...a,g.key])} aria-expanded={expanded}><span>{g.title}</span>{expanded?<ChevronDown size={13}/>:<ChevronRight size={13}/>}</button>{expanded&&<nav className="nav-list" aria-label={g.title}>{links.map(({key,title,icon:Icon,pending})=><button type="button" title={title} key={key} className={'nav-button'+(section===key?' active':'')+(pending?' ent-nav-pending':'')} onClick={()=>moveTo(key)}><Icon size={17} strokeWidth={1.85}/><span>{title}</span>{key==='servers'&&<span className="nav-count">{servers.length}</span>}{section===key&&<span className="active-bar"/>}</button>)}</nav>}</div>})}
      <div className="sidebar-bottom"><div className="agent-box"><span className="agent-icon"><Radio size={17}/></span><strong>{verifiedCount} servers with fresh verified health</strong><p>{readyServers.length} monitoring target{readyServers.length===1?'':'s'} approved and ready. Session metrics are collected by the approved background worker when available.</p><button onClick={() => moveTo('servers')}>Manage servers <ArrowRight size={15}/></button></div><div className="sidebar-profile"><span className="avatar brand-avatar"><img src={stagPrimeMark} alt="" /></span><div><strong>{currentUser.display_name}</strong><span>{currentUser.role.toUpperCase()} · {currentUser.username}</span></div><button type="button" className="icon-button" title="Sign out" aria-label="Sign out" onClick={onSignOut}><LockKeyhole size={18}/></button></div></div>
    </aside>
    <div className="app-content">
      <header className="topbar"><div className="top-left"><button className="icon-button mobile-menu" aria-label="Open menu" onClick={() => setMobileOpen(true)}><Menu size={20}/></button><div className="breadcrumb">Workspace <ChevronRight size={14}/> <strong>{HEADINGS[section].title}</strong></div></div><div className="top-right"><span className={"ent-top-worker" + (monitoringOverview?.worker.status==='running'?' running':'')}><i/> Worker: {monitoringOverview?.worker.status==='running'?'Running':'Not verified'}</span><span className="preview-tag"><span/> {inventoryApiStatus === 'connected' ? 'INVENTORY API CONNECTED' : inventoryApiStatus === 'offline' ? 'BACKEND UNAVAILABLE' : 'CONNECTING BACKEND'}</span><div className="notification-anchor"><button className={'icon-button notification-button' + (notificationsOpen ? ' highlighted' : '') + (highAlerts.length ? ' has-alerts' : '')} title="Notifications" aria-label="Notifications" onClick={() => setNotificationsOpen(!notificationsOpen)}><Bell size={20}/>{highAlerts.length > 0 && <span className="notification-badge">{highAlerts.length}</span>}</button>{notificationsOpen && <div className="notification-popover"><div className="popover-heading"><strong>High alerts</strong><span>Health bad / too many VPN users</span></div>{highAlerts.length === 0 ? <div style={{padding:18}}><p>No high alerts right now. Worker keeps checking every minute.</p><button className="btn-secondary" type="button" onClick={() => moveTo('alerts')}>Open Alerts <ChevronRight size={15}/></button></div> : <ul className="notification-alert-list">{highAlerts.slice(0, 12).map((a) => <li key={a.id}><strong>{a.server_name}</strong><span>{a.title}</span><em>{a.detail}</em></li>)}<div style={{padding:'10px 14px 14px'}}><button className="btn-secondary" type="button" onClick={() => { setNotificationsOpen(false); moveTo('dashboard') }}>Open dashboard <ChevronRight size={15}/></button></div></ul>}</div>}</div><div className="sp-account-anchor" ref={profileMenuRef}>
      <button type="button" ref={profileButtonRef} className="user-badge sp-account-avatar"
        aria-label="Open account menu" aria-haspopup="menu" aria-expanded={profileMenuOpen}
        aria-controls={profileMenuOpen ? 'sentinel-account-menu' : undefined}
        title={`Signed in as ${currentUser.display_name} · Account menu`}
        onClick={() => { setNotificationsOpen(false); setProfileMenuOpen(open => !open) }}>
        {profileInitials}<ChevronDown size={10} style={{position:'absolute', bottom:-5, right:-6, background:'#ffffff', border:'1px solid #d8e4ee', borderRadius:8, color:'#2a5977'}}/>
      </button>
      {profileMenuOpen && <div className="sp-account-menu" role="menu" aria-label="Account options" id="sentinel-account-menu">
        <div className="sp-account-header">
          <span className="sp-account-header-avatar">{profileInitials}</span>
          <div style={{minWidth:0}}>
            <div className="sp-account-name">{currentUser.display_name}</div>
            <div className="sp-account-meta">@{currentUser.username} · {currentUser.role.toUpperCase()}</div>
          </div>
        </div>
        <div className="sp-account-actions">
          <button type="button" role="menuitem" className="sp-account-action" onClick={() => {setProfileMenuOpen(false); setProfileDetailsOpen(true)}}>
            <UserRound size={18}/><span>My Profile</span><ChevronRight size={15}/>
          </button>
          <button type="button" role="menuitem" className="sp-account-action" onClick={() => moveTo('settings')}>
            <Settings2 size={18}/><span>Account &amp; Platform Settings</span><ChevronRight size={15}/>
          </button>
          <div role="separator" className="sp-account-rule" />
          <button type="button" role="menuitem" className="sp-account-action sp-sign-out" onClick={() => {setProfileMenuOpen(false); onSignOut()}}>
            <LogOut size={18}/><span>Sign Out</span><ArrowRight size={15}/>
          </button>
        </div>
        <div className="sp-account-foot">Stag Prime Sentinel · Protected workspace</div>
      </div>}
    </div></div></header>
      <main className="main-content"><div className="page-heading"><div><div className="eyebrow"><span/> STAG PRIME SENTINEL / {section.toUpperCase()}</div><h1>{HEADINGS[section].title}</h1><p>{HEADINGS[section].desc}</p></div><div className="heading-actions">{currentUser.role === 'admin' && section === 'servers' && <button className="btn-primary" onClick={() => setNewOpen(true)}><Plus size={18}/> Add server</button>}</div></div>{currentUser.role === 'viewer' && <p className="secure-form-note" style={{margin:'12px 0 0'}}><ShieldCheck size={18}/> View only. Every area is open to look at. Adding, editing, deleting, and SSH changes stay off.</p>}
        {(['dashboard','live','map','vpn-services','network','performance','security','audit'] as Section[]).includes(section) &&
          <EnterpriseWorkspace page={section as EnterprisePage} inventory={servers.map(s=>({id:s.id,name:s.name,host:s.host,client:s.client,country:s.country,region:s.region,provider:s.provider}))} overview={monitoringOverview} inventoryReady={inventoryApiStatus==='connected'} onOpenServer={setSelected} onNavigate={key=>moveTo(key as Section)} refresh={()=>setHealthRefresh(n=>n+1)} scope={globalScope} onScopeChange={setGlobalScope}/>}
        {section === 'servers' && <>
          <div className="sp-inventory-stats">
            <Metric icon={Server} label="Active fleet" value={String(servers.length)} hint="Authorized inventory"/>
            <Metric icon={Activity} label="Live monitoring" value={String(readyServers.length)} hint="Worker collecting health/sessions"/>
            <Metric icon={AlertTriangle} label="Needs enroll" value={String(Math.max(0, servers.length-readyServers.length))} hint="SSH verify + monitoring not finished"/>
            <Metric icon={Archive} label="Archived" value={String(archivedServers.length)} hint="Hidden from active fleet"/>
          </div>
          <div className="sp-inventory-tools">
            <div className="sp-inventory-toolcopy"><strong>Server Inventory</strong><span>Add once here · auto SSH verify · read-only monitoring. Bulk actions never change the remote VPS.</span></div>
            <label>Client<select aria-label="Filter inventory by client" value={clientFilter} onChange={e=>{setClientFilter(e.target.value);setSelectedRows([])}}><option value="all">All clients</option>{[...new Set(servers.map(s=>s.client))].sort().map(client=><option key={client} value={client}>{client}</option>)}</select></label>
            <label>Monitoring<select aria-label="Filter inventory by monitoring" value={monitorFilter} onChange={e=>{setMonitorFilter(e.target.value);setSelectedRows([])}}><option value="all">All statuses</option><option value="enrolled">Enrolled</option><option value="not-enrolled">Not enrolled</option></select></label>
            <button type="button" className="btn-secondary" onClick={exportInventory}><Download size={16}/> Export</button>
          </div>
          <div className="sp-inventory-tabs" role="tablist" aria-label="Inventory lists">
            <button type="button" role="tab" aria-selected={inventoryTab === 'active'} className={inventoryTab === 'active' ? 'on' : ''} onClick={() => {setInventoryTab('active');setSearch('')}}>
              <Server size={15}/> Active <span>{servers.length}</span>
            </button>
            <button type="button" role="tab" aria-selected={inventoryTab === 'archived'} className={inventoryTab === 'archived' ? 'on' : ''} onClick={() => {setInventoryTab('archived');setSearch('')}}>
              <Archive size={15}/> Archived <span>{archivedServers.length}</span>
            </button>
          </div>
          {inventoryTab === 'active' ?
            <ServerTable servers={filtered} search={search} setSearch={setSearch} onSelect={setSelected}
              targetById={targetById} healthById={healthById} selectedRows={selectedRows}
              onCheck={currentUser.role==='admin' ? toggleServerSelection : undefined}
              onSelectAll={currentUser.role==='admin' ? (checked) => setSelectedRows(checked ? filtered.map(x=>x.id) : []) : undefined}
              selectionActions={currentUser.role==='admin' && selectedRows.length > 0 ? <div className="sp-bulk-actions" role="group" aria-label="Selected server actions">
                <strong>{selectedRows.length} server{selectedRows.length!==1?'s':''} selected</strong>
                <button type="button" className="btn-secondary" disabled={!!busyAction} onClick={()=>void archiveSelectedServers()}><Archive size={15}/> Archive selected</button>
                <button type="button" className="sp-danger-outline" disabled={!!busyAction} onClick={()=>{setDeleteConfirmation('');setDeleteSelection([...selectedRows])}}><Trash2 size={15}/> Permanent delete</button>
                <button type="button" className="sp-clear-selection" onClick={()=>setSelectedRows([])}>Clear selection</button>
              </div> : undefined} /> :
            <ArchivedServerTable
              servers={archivedServers}
              busyAction={busyAction}
              onRestore={restoreArchived}
              onPermanentDelete={currentUser.role === 'admin' ? (server) => {
                setDeleteConfirmation('')
                setDeleteSelection([server.id])
              } : undefined}
              canRestore={currentUser.role === 'admin'}
            />
          }
        </>}
        {(currentUser.role === 'admin' || currentUser.role === 'viewer') && section === 'operations-repair' &&
          <ServerOperations
            servers={operationsServers}
            inventoryStatus={inventoryApiStatus}
            readOnly={currentUser.role === 'viewer'}
            onOpenInventory={() => moveTo('servers')}
            onAddServer={() => setNewOpen(true)}
            onOpenHandbook={() => moveTo('install-center')}
            onRefresh={() => { void refreshInventory().catch(() => setInventoryApiStatus('offline')); setHealthRefresh(n => n + 1) }}
          />}
        {(currentUser.role === 'admin' || currentUser.role === 'viewer') && section === 'operations-control' && <ServerControlCenter
          servers={controlServers}
          inventoryStatus={inventoryApiStatus}
          readOnly={currentUser.role === 'viewer'}
          onOpenInventory={() => moveTo('servers')}
          onRefresh={() => { void refreshInventory().catch(() => setInventoryApiStatus('offline')); setHealthRefresh(n => n + 1) }}
        />}
        {section === 'fleet-ops' && (
          <FleetOpsCenter
            isAdmin={currentUser.role === 'admin'}
            onOpenServer={(id) => {
              const match = servers.find((s) => s.id === id || s.id === `api-${id}` || s.id.replace(/^api-/, '') === id)
              setSelected(match ? match.id : id)
            }}
            onGoInventory={() => moveTo('servers')}
          />
        )}
        {section === 'sessions' && (
          <MonitoringLive
            view="sessions"
            onOpenServer={(id) => {
              const match = servers.find((s) => s.id === id || s.id === `api-${id}` || s.id.replace(/^api-/, '') === id)
              setSelected(match ? match.id : id)
            }}
          />
        )}
        {section === 'alerts' && (
          <EnterpriseIncidents
            onOpenServer={(id) => {
              const match = servers.find((s) => s.id === id || s.id === `api-${id}` || s.id.replace(/^api-/, '') === id)
              setSelected(match ? match.id : id)
            }}
          />
        )}
        {section === 'reports' && <EnterpriseReports/>}
        {section === 'clients' && <><Client360 servers={servers.map(s=>({id:s.id,name:s.name,client:s.client,region:s.region,provider:s.provider}))} overview={monitoringOverview} onOpenServer={setSelected}/><ClientDirectory isAdmin={currentUser.role==='admin'} onChange={() => { void refreshInventory().catch(()=>setInventoryApiStatus('offline')) }}/></>}
        {section === 'users' && (currentUser.role === 'admin' || currentUser.role === 'viewer' ? <UserManagementCenter currentUser={currentUser}/> : <div className="panel standalone-panel">Administrator access required.</div>)}
        {section === 'install-center' && (currentUser.role === 'admin' || currentUser.role === 'viewer' ? <InstallationCenter/> : <div className="panel standalone-panel" style={{padding:32}}>The installation handbook is restricted to administrators in this version.</div>)}
        {section === 'onboarding' && <OnboardingCenter isAdmin={currentUser.role === 'admin'} onOpenInstall={() => moveTo('install-center')} onOpenInventory={() => moveTo('servers')} />}
        {section === 'settings' && <EnterpriseSettings overview={monitoringOverview} inventoryReady={inventoryApiStatus==='connected'} theme={theme} onThemeChange={setTheme} isAdmin={currentUser.role==='admin'} onOpenIntegrations={()=>moveTo('integrations')}/>}
        {section === 'integrations' && <IntegrationsCenter readOnly={currentUser.role === 'viewer'}/>}
        <div className="footerline"><span>© 2026 Stag Prime LLC · Sentinel Control Center</span><span><span className="footer-dot"/> Dynamic read-only SSH monitoring · Background collector · verify worker status</span></div>
      </main>
    </div>
    {profileDetailsOpen && <div className="modal-backdrop" onClick={() => !passwordBusy && setProfileDetailsOpen(false)}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="My Profile" style={{width:'min(100%, 520px)'}} onClick={event => event.stopPropagation()}>
        <div className="modal-head">
          <div><MiniLabel>STAG PRIME SENTINEL / ACCOUNT</MiniLabel><h2>My Profile</h2><p>Signed-in account details and authenticated password change.</p></div>
          <button type="button" className="icon-button" aria-label="Close My Profile" disabled={passwordBusy} onClick={() => setProfileDetailsOpen(false)}><X size={20}/></button>
        </div>
        <div className="sp-profile-info">
          <div className="sp-profile-row"><span>Display name</span><strong>{currentUser.display_name}</strong></div>
          <div className="sp-profile-row"><span>Username</span><strong>{currentUser.username}</strong></div>
          <div className="sp-profile-row"><span>Account role</span><strong>{currentUser.role.toUpperCase()}</strong></div>
          <div className="sp-profile-row"><span>Workspace</span><strong>Stag Prime Sentinel</strong></div>
        </div>
        <form style={{padding:'8px 27px 0'}} onSubmit={async (event) => {
          event.preventDefault()
          setPasswordError(null)
          setPasswordMessage(null)
          if (passwordForm.next !== passwordForm.confirm) {
            setPasswordError('New password and confirmation do not match.')
            return
          }
          setPasswordBusy(true)
          try {
            const message = await changePassword(passwordForm.current, passwordForm.next)
            setPasswordMessage(message)
            setPasswordForm({ current: '', next: '', confirm: '' })
            setTimeout(() => { onSignOut() }, 900)
          } catch (err) {
            setPasswordError(err instanceof Error ? err.message : 'Password change failed.')
          } finally {
            setPasswordBusy(false)
          }
        }}>
          {currentUser.role === 'viewer' ? <><p className="secure-form-note">This view account cannot change its password. An administrator can reset it.</p><div className="modal-actions" style={{padding:'16px 0 25px'}}><button type="button" className="btn-secondary" onClick={() => setProfileDetailsOpen(false)}>Close</button></div></> : <>
          <MiniLabel>CHANGE PASSWORD</MiniLabel>
          <div className="form-grid" style={{marginTop:10}}>
            <label>Current password<input type="password" autoComplete="current-password" required value={passwordForm.current} onChange={e => setPasswordForm(v => ({...v, current: e.target.value}))}/></label>
            <label>New password<input type="password" autoComplete="new-password" required minLength={14} value={passwordForm.next} onChange={e => setPasswordForm(v => ({...v, next: e.target.value}))}/></label>
            <label>Confirm new password<input type="password" autoComplete="new-password" required minLength={14} value={passwordForm.confirm} onChange={e => setPasswordForm(v => ({...v, confirm: e.target.value}))}/></label>
          </div>
          {passwordError && <div role="alert" className="form-error" style={{marginTop:10}}>{passwordError}</div>}
          {passwordMessage && <div role="status" className="form-success" style={{marginTop:10}}>{passwordMessage}</div>}
          <div className="secure-form-note" style={{margin:'12px 0 0'}}><ShieldCheck size={18}/> Password updates are verified by the backend. All sessions are revoked after a successful change — you will need to sign in again. MFA is not enabled in this build.</div>
          <div className="modal-actions" style={{padding:'16px 0 25px'}}>
            <button type="button" className="btn-secondary" disabled={passwordBusy} onClick={() => setProfileDetailsOpen(false)}>Close</button>
            <button type="submit" className="btn-primary" disabled={passwordBusy}>{passwordBusy ? 'Updating…' : 'Update password'}</button>
          </div>
          </>}
        </form>
      </div>
    </div>}
    {record && (() => {
      const target = targetById.get(backendId(record.id))
      const monitored = target?.monitoring_enabled === true && target?.local_configuration_ready === true && target.host === record.host
      const state = healthById[backendId(record.id)]
      const health = isVerifiedHealth(state, record) ? state?.health ?? null : null
      return <div className="drawer-backdrop" onClick={() => setSelected(null)}><aside className="detail-drawer sp-server360-drawer" role="dialog" aria-modal="true" aria-label={`Server details: ${record.name}`} onClick={(e) => e.stopPropagation()}>
      <div className="drawer-heading"><span>SERVER DETAILS</span><button className="icon-button" onClick={() => setSelected(null)}><X size={20}/></button></div>
      <div className="drawer-avatar"><Server size={29}/></div><h2>{record.name}</h2><p className="drawer-subtitle">{record.region}, {record.country}</p>
      <StatusPill server={record} state={state} monitored={monitored} configured={!!target?.monitoring_configured}/>
      <Server360 key={record.id} serverId={backendId(record.id)} health={health} observation={monitoringOverview?.servers.find(m => m.server_id === backendId(record.id)) || null}/>
      <div className="drawer-divider"/><MiniLabel>INVENTORY DETAILS</MiniLabel>
      <dl className="detail-list"><dt>Host address</dt><dd className="monospaced">{record.host}</dd><dt>Provider</dt><dd>{record.provider}</dd><dt>VPN protocol</dt><dd>{record.protocol}</dd><dt>SSH username</dt><dd>{record.sshUser}</dd><dt>SSH port</dt><dd>{record.sshPort || 'Not configured'}</dd><dt>Client</dt><dd>{record.client}</dd></dl>
      {monitored ? <div className="drawer-health">
        <strong>Verified SSH health · {record.name}</strong>
        {health ? <div className="drawer-health-values">
          <div>CPU <b>{humanPercent(health.cpu_percent)}</b> · RAM <b>{humanPercent(health.memory_used_percent)}</b></div>
          <div>Disk <b>{humanPercent(health.disk_used_percent)}</b> · VPN <b>{health.openvpn.service_status}</b></div>
          <div>Tunnel <b>{health.openvpn.tunnel_ipv4 || 'Unavailable'}</b></div>
          <div>Network RX <b>{humanBytes(health.network.rx_bytes_total)}</b> · TX <b>{humanBytes(health.network.tx_bytes_total)}</b></div>
          <small>Network totals are cumulative. VPN session details are available under VPN Sessions when monitored.</small>
        </div> : <p>{state?.error ? `Health check failed: ${state.error}` : state?.loading ? 'Collecting verified SSH health…' : 'No fresh verified sample available.'}</p>}
        <button type="button" className="btn-secondary" disabled={readyServers.some(s => healthById[backendId(s.id)]?.loading)} style={{marginTop:12}} onClick={() => setHealthRefresh(n=>n+1)}><RotateCcw size={16}/> Refresh monitored servers</button>
      </div> : <div className="drawer-warning"><LockKeyhole size={19}/><div><strong>Live monitoring not ready</strong><p>{target?.missing_settings?.join('; ') || 'Inventory-only. An approved backend monitoring profile is required before SSH access.'}</p></div></div>}
      {currentUser.role === 'admin' && <InventorySSHEnrollment key={backendId(record.id)} serverId={backendId(record.id)} serverName={record.name} monitored={monitored} onChange={()=>{setTargetsRevision(n=>n+1);setHealthRefresh(n=>n+1)}}/>}
      <div style={{display:'flex', flexDirection:'column', gap:10, marginTop:22}}>
      {currentUser.role === 'admin' && <button className="btn-primary" onClick={() => openEdit(record)} disabled={inventoryApiStatus !== 'connected'}><Pencil size={17}/> Edit server details</button>}
      {currentUser.role === 'admin' && <button className="btn-secondary" onClick={() => openCredentialModal(record)}><KeyRound size={17}/> Configure SSH access (Key / Password)</button>}
      {currentUser.role === 'admin' && <button className="btn-secondary" onClick={() => {setSelected(null);setArchivingServer(record)}} disabled={inventoryApiStatus !== 'connected'}><Archive size={17}/> Archive server</button>}
      {currentUser.role === 'admin' && <button type="button" className="sp-danger-outline" onClick={() => {setDeleteConfirmation('');setDeleteSelection([record.id]);setSelected(null)}} disabled={inventoryApiStatus !== 'connected' || !!busyAction}><Trash2 size={17}/> Permanently delete</button>}
      <button className="btn-secondary drawer-close" onClick={()=>setSelected(null)}>Close details</button>
    </div></aside></div>
    })()}
    {currentUser.role === 'admin' && newOpen && <div className="drawer-backdrop sp-onboard-backdrop" onClick={()=>{if(!savingServer)setNewOpen(false)}}>
      <aside className="detail-drawer sp-onboard-drawer" role="dialog" aria-modal="true" aria-label="Add server and start monitoring" onClick={e=>e.stopPropagation()}>
        <div className="drawer-heading"><span>STAG PRIME SENTINEL / SERVER ENROLLMENT</span><button type="button" className="icon-button" disabled={savingServer} aria-label="Close" onClick={()=>setNewOpen(false)}><X size={20}/></button></div>
        <h2>Add server</h2><p className="sp-onboard-lead">Enter host + SSH access. Sentinel verifies, discovers the VPN service, and starts live monitoring automatically — no .ovpn upload.</p>
        <form onSubmit={addServer} className="sp-onboard-form">
          <div className="sp-form-step"><span>1</span><div><strong>Server</strong><small>Inventory identity for your fleet</small></div></div>
          <div className="sp-form-fields">
            <label>Server name *<input required maxLength={150} placeholder="Germany - EU 01" value={draft.name} onChange={e=>setDraft({...draft,name:e.target.value})}/></label>
            <label>Host / Public IP *<input required maxLength={255} placeholder="vpn.example.com" value={draft.host} onChange={e=>setDraft({...draft,host:e.target.value})}/></label>
            <div className="sp-form-split"><label>Region<input maxLength={150} placeholder="Falkenstein" value={draft.region} onChange={e=>setDraft({...draft,region:e.target.value})}/></label><label>Country<input maxLength={100} placeholder="Germany" value={draft.country} onChange={e=>setDraft({...draft,country:e.target.value})}/></label></div>
            <label>Client / organization *
              <select
                required
                value={draft.client}
                onChange={(e) => setDraft({ ...draft, client: e.target.value })}
              >
                <option value="">{orgOptions.length === 0 ? 'No organization yet' : 'Select organization…'}</option>
                {orgOptions.map((org) => (
                  <option key={org.id} value={org.name}>{org.name}</option>
                ))}
              </select>
            </label>
            <div className="sp-form-split">
              <label>New organization
                <input maxLength={150} placeholder="Type a name, then create" value={orgDraftName} onChange={(e) => setOrgDraftName(e.target.value)} />
              </label>
              <label>Create
                <button type="button" className="btn-secondary" disabled={orgSaving || orgDraftName.trim().length < 2} onClick={() => { void createOrganization() }}>{orgSaving ? 'Creating…' : 'Add to list'}</button>
              </label>
            </div>
            {orgOptionsError && <p className="sentinel-credential-hint" style={{margin:0,color:'#a13530'}}>{orgOptionsError}</p>}
            <label>Cloud provider<input maxLength={150} placeholder="Hetzner, Oracle, AWS…" value={draft.provider} onChange={e=>setDraft({...draft,provider:e.target.value})}/></label>
          </div>
          <div className="sp-form-step"><span>2</span><div><strong>SSH access</strong><small>Encrypted vault · used only for read-only live collection</small></div></div>
          <div className="sp-form-fields">
            <div className="sp-auth-options" role="group" aria-label="SSH authentication method">
              <label><input type="radio" name="new-auth" checked={draftMethod==='password'} onChange={()=>{setDraftMethod('password');setDraftKey(null);setDraftKeyText('')}}/> SSH password</label>
              <label><input type="radio" name="new-auth" checked={draftMethod==='private_key'} onChange={()=>{setDraftMethod('private_key');setDraftPassword('')}}/> Private key</label>
              <label><input type="radio" name="new-auth" checked={draftMethod==='key_and_password'} onChange={()=>setDraftMethod('key_and_password')}/> Key + login password</label>
            </div>
            <div className="sp-form-split"><label>SSH username *<input maxLength={100} required placeholder="tariq / root / ubuntu (lowercase)" value={draft.sshUser} onChange={e=>setDraft({...draft,sshUser:e.target.value})}/></label><label>SSH port<input required type="number" min="1" max="65535" value={draft.sshPort} onChange={e=>setDraft({...draft,sshPort:e.target.value})}/></label></div>
            <p className="sentinel-credential-hint" style={{margin:'0 0 4px'}}>Linux SSH usernames are case-sensitive — usually all lowercase (tariq, not Tariq).</p>
            {draftMethod==='password' ? <label>SSH password *<input type="password" autoComplete="new-password" minLength={8} maxLength={1024} required value={draftPassword} onChange={e=>setDraftPassword(e.target.value)} placeholder="Linux SSH password"/></label> : <>
              <label>Private key file
                <input type="file" accept="*/*" required={!draftKeyText.trim()} onChange={async e=>{
                  const file = e.target.files?.[0] || null
                  if (!file) { setDraftKey(null); return }
                  const checked = await readKeyFromFile(file)
                  if (!checked.ok) { showNotice(checked.reason, 'error'); setDraftKey(null); e.target.value=''; return }
                  setDraftKey(file); setDraftKeyText(checked.secret)
                }}/>
              </label>
              {draftKey && <p className="sentinel-credential-hint" style={{margin:'0 0 8px'}}>Selected: {draftKey.name} ({draftKey.size} bytes)</p>}
              <label>Or paste private key
                <textarea rows={5} spellCheck={false} value={draftKeyText} onChange={e=>{setDraftKeyText(e.target.value); if(!e.target.value.trim()) setDraftKey(null)}} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----  or  PuTTY-User-Key-File-…" style={{width:'100%',fontFamily:'ui-monospace,Consolas,monospace',fontSize:11,borderRadius:8,border:'1px solid #dfe7ee',padding:10}}/>
              </label>
              {(draftKeyText.includes('PuTTY-User-Key-File') || (draftKey?.name||'').toLowerCase().endsWith('.ppk')) && (
                <label>PuTTY passphrase (only if encrypted)
                  <input type="password" autoComplete="new-password" value={draftPpkPassphrase} onChange={e=>setDraftPpkPassphrase(e.target.value)} placeholder="Leave empty if none"/>
                </label>
              )}
              {draftMethod==='key_and_password' && (
                <label>SSH login password *<input type="password" autoComplete="new-password" required maxLength={1024} value={draftPassword} onChange={e=>setDraftPassword(e.target.value)} placeholder="Password asked after key login"/></label>
              )}
            </>}
          </div>
          <div className="sp-onboard-note"><ShieldCheck size={17}/><span><strong>Automatic live path:</strong> verify SSH → discover VPN unit → enroll monitoring. Worker pulls health every 60s and sessions every 30s. No .ovpn / VPN user-pass required.</span></div>
          <div className="sp-onboard-actions"><button type="button" className="btn-secondary" disabled={savingServer} onClick={()=>setNewOpen(false)}>Cancel</button><button type="submit" className="btn-primary" disabled={savingServer||inventoryApiStatus!=='connected'||!draft.client||orgOptions.length===0}><ShieldCheck size={17}/>{savingServer?'Enrolling…':'Add server & go live'}</button></div>
        </form>
      </aside>
    </div>}
    {currentUser.role === 'admin' && editingServer && editDraft && <div className="modal-backdrop" onClick={() => {if (!busyAction) {setEditingServer(null);setEditDraft(null)}}}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Edit server details" onClick={e=>e.stopPropagation()}>
        <div className="modal-head"><div><MiniLabel>SERVER MANAGEMENT</MiniLabel><h2>Edit {editingServer.name}</h2><p>Update server inventory details in the database. This does not change the remote VPS configuration.</p></div><button className="icon-button" onClick={()=>{if(!busyAction){setEditingServer(null);setEditDraft(null)}}} disabled={!!busyAction}><X size={20}/></button></div>
        <form onSubmit={saveEditedServer}>
          <div className="form-grid">
            <label>Server name *<input required maxLength={150} value={editDraft.name} onChange={e=>setEditDraft({...editDraft,name:e.target.value})}/></label>
            <label>Host / Public IP *<input required maxLength={255} value={editDraft.host} onChange={e=>setEditDraft({...editDraft,host:e.target.value})}/></label>
            <label>City / Region<input maxLength={150} value={editDraft.region} onChange={e=>setEditDraft({...editDraft,region:e.target.value})}/></label>
            <label>Country<input maxLength={100} value={editDraft.country} onChange={e=>setEditDraft({...editDraft,country:e.target.value})}/></label>
            <label>Cloud provider<input maxLength={150} value={editDraft.provider} onChange={e=>setEditDraft({...editDraft,provider:e.target.value})}/></label>
            <label>Client / Organization<input disabled value={editDraft.client} title="Moving servers between clients requires a separate client reassignment API."/></label>
            <label>SSH username<input maxLength={100} value={editDraft.sshUser} onChange={e=>setEditDraft({...editDraft,sshUser:e.target.value})}/></label>
            <label>SSH port *<input required type="number" min="1" max="65535" value={editDraft.sshPort} onChange={e=>setEditDraft({...editDraft,sshPort:e.target.value})}/></label>
          </div>
          <div className="secure-form-note"><ShieldCheck size={18}/> Client reassignment and encrypted SSH credentials will be handled separately. Do not paste private keys or passwords.</div>
          <div className="modal-actions"><button type="button" className="btn-secondary" disabled={!!busyAction} onClick={()=>{setEditingServer(null);setEditDraft(null)}}>Cancel</button><button type="submit" className="btn-primary" disabled={!!busyAction || inventoryApiStatus !== 'connected'}><Check size={17}/> {busyAction === 'edit' ? 'Saving...' : 'Save changes'}</button></div>
        </form>
      </div>
    </div>}
    {currentUser.role === 'admin' && archivingServer && <div className="modal-backdrop" onClick={()=>{if(!busyAction)setArchivingServer(null)}}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Confirm archive server" onClick={e=>e.stopPropagation()}>
        <div className="modal-head"><div><MiniLabel>CONFIRM ARCHIVE</MiniLabel><h2>Archive {archivingServer.name}?</h2><p>This will hide the server from the active inventory. It can be restored later.</p></div><button className="icon-button" onClick={()=>{if(!busyAction)setArchivingServer(null)}} disabled={!!busyAction}><X size={20}/></button></div>
        <div className="secure-form-note"><Archive size={19}/> Server: {archivingServer.name} · {archivingServer.host}. This only updates the Sentinel database. No remote server processes, networking or connectivity will be changed.</div>
        <div className="modal-actions" style={{paddingTop:18}}><button type="button" className="btn-secondary" disabled={!!busyAction} onClick={()=>setArchivingServer(null)}>Cancel</button><button type="button" className="btn-primary" disabled={!!busyAction} onClick={confirmArchive}><Archive size={17}/> {busyAction === 'archive' ? 'Archiving...' : 'Confirm archive'}</button></div>
      </div>
    </div>}
    {currentUser.role === 'admin' && keyChooserServer && <div className="modal-backdrop" onClick={closeCredentialModal}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Secure SSH authentication" onClick={e => e.stopPropagation()}>
        <div className="modal-head">
          <div><MiniLabel>SSH ACCESS / ENCRYPTED CREDENTIAL VAULT</MiniLabel><h2>Configure SSH access</h2>
            <p>Private key, password, or both (hosts that ask for a password after key login).</p>
          </div>
          <button type="button" className="icon-button" aria-label="Close credentials" onClick={closeCredentialModal} disabled={credentialBusy}><X size={20}/></button>
        </div>
        <div className="sentinel-credential-content">
          <div className="sentinel-credential-server"><strong>{keyChooserServer.name}</strong><span>{keyChooserServer.client} · {keyChooserServer.host}:{keyChooserServer.sshPort} · {keyChooserServer.sshUser}</span></div>
          <div role="status" className="secure-form-note" style={{margin:0,alignItems:'flex-start'}}>
            <ShieldCheck size={18}/><span>{credentialStatusLoading ? 'Checking encrypted vault record…' : credentialStatusError ? `Credential status unavailable: ${credentialStatusError}` : savedCredential?.configured ? (
              <><strong>Saved in encrypted vault: {authMethodLabel(savedCredential.auth_method)}</strong> · {savedCredential.host_pinned && savedCredential.vault_accessible ? 'Storage/decryption verified' : 'Review required — credential cannot currently be used'}.
              {savedCredential.last_updated_at_utc ? ` Last updated: ${new Date(savedCredential.last_updated_at_utc).toLocaleString()}.` : ''} Secret contents are never displayed. Select a file or enter a password only to replace it.</>
            ) : 'No encrypted SSH credential is currently saved for this server.'}</span>
          </div>
          <div className="sentinel-credential-method" role="group" aria-label="SSH authentication method">
            <button type="button" aria-pressed={credentialMethod === 'private_key'} className={credentialMethod === 'private_key' ? 'active' : ''} disabled={credentialBusy} onClick={() => {setCredentialMethod('private_key');setCredentialPassword('')}}><KeyRound size={16}/> SSH private key</button>
            <button type="button" aria-pressed={credentialMethod === 'password'} className={credentialMethod === 'password' ? 'active' : ''} disabled={credentialBusy} onClick={() => {setCredentialMethod('password');setCredentialFile(null);setCredentialKeyText('')}}><LockKeyhole size={16}/> SSH password</button>
            <button type="button" aria-pressed={credentialMethod === 'key_and_password'} className={credentialMethod === 'key_and_password' ? 'active' : ''} disabled={credentialBusy} onClick={() => setCredentialMethod('key_and_password')}><KeyRound size={16}/> Key + password</button>
          </div>
          {credentialMethod === 'password' ? <>
            <label className="sentinel-credential-label" htmlFor="sentinel-ssh-password">SSH login password</label>
            <input id="sentinel-ssh-password" className="sentinel-credential-input" type="password" autoComplete="new-password" spellCheck={false} minLength={8} maxLength={1024} value={credentialPassword} disabled={credentialBusy} onChange={e=>setCredentialPassword(e.currentTarget.value)} placeholder="Enter the password for the SSH username above" />
            <p className="sentinel-credential-hint">This is the Linux SSH login password, not your Oracle Cloud account password. The server must already permit password-based SSH authentication.</p>
          </> : <>
            {savedCredential?.local_default_key?.configured && savedCredential.local_default_key.exists && credentialMethod === 'private_key' && (
              <div style={{display:'grid',gap:8,marginBottom:4}}>
                <button type="button" className="btn-primary" disabled={credentialBusy} onClick={() => void saveFromLocalDefaultKey()}>
                  <KeyRound size={16}/> Use saved local key ({savedCredential.local_default_key.path})
                </button>
                <p className="sentinel-credential-hint" style={{margin:0}}>Remembered on this PC — no need to browse the .ppk again.</p>
              </div>
            )}
            <label className="sentinel-credential-label">Private key file (any filename — content must be private)</label>
            <input ref={privateKeyFileInput} type="file" accept="*/*" aria-label="Select private SSH key" tabIndex={-1} disabled={credentialBusy} style={{position:'absolute',width:1,height:1,opacity:0,pointerEvents:'none'}} onChange={event => {void selectPrivateKey(event.currentTarget.files?.[0]);event.currentTarget.value=''}}/>
            <button type="button" className="btn-secondary" disabled={credentialBusy} onClick={() => privateKeyFileInput.current?.click()}><FolderOpen size={16}/> Browse any key file</button>
            <p className="sentinel-credential-hint">{credentialFile ? `Selected: ${credentialFile.name} (${credentialFile.size} bytes) · validated` : 'Any file name OK — OpenSSH / PEM / PuTTY .ppk. Rejects .pub public keys.'}</p>
            <label className="sentinel-credential-label" htmlFor="sentinel-ssh-key-paste">Or paste private key</label>
            <textarea id="sentinel-ssh-key-paste" className="sentinel-credential-input" rows={6} spellCheck={false} disabled={credentialBusy} value={credentialKeyText} onChange={e=>{setCredentialKeyText(e.currentTarget.value); if(!e.currentTarget.value.trim()) setCredentialFile(null)}} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----  or  PuTTY-User-Key-File-…" style={{fontFamily:'ui-monospace,Consolas,monospace',fontSize:11,resize:'vertical'}}/>
            {(credentialKeyText.includes('PuTTY-User-Key-File') || (credentialFile?.name||'').toLowerCase().endsWith('.ppk')) && (
              <>
                <label className="sentinel-credential-label" htmlFor="sentinel-ppk-pass">PuTTY key passphrase (only if .ppk is encrypted)</label>
                <input id="sentinel-ppk-pass" className="sentinel-credential-input" type="password" autoComplete="new-password" disabled={credentialBusy} value={ppkPassphrase} onChange={e=>setPpkPassphrase(e.currentTarget.value)} placeholder="Leave empty if no passphrase"/>
              </>
            )}
            {credentialMethod === 'key_and_password' && <>
              <label className="sentinel-credential-label" htmlFor="sentinel-ssh-login-password">SSH login password (asked after key)</label>
              <input id="sentinel-ssh-login-password" className="sentinel-credential-input" type="password" autoComplete="new-password" spellCheck={false} maxLength={1024} value={credentialPassword} disabled={credentialBusy} onChange={e=>setCredentialPassword(e.currentTarget.value)} placeholder="Password required with the key" />
              <p className="sentinel-credential-hint">Use this when the VPS accepts the key but still prompts for the account password (publickey + password).</p>
            </>}
          </>}
          <div className="secure-form-note" style={{margin:0, alignItems:'flex-start'}}><ShieldCheck size={19}/><span>Credentials are encrypted by the local backend, not stored in browser storage or returned in API responses. Enrollment does not enable SSH password login on the VPS, nor does it automatically authorize server changes. Host-key verification and an audited Admin SSH check are still required. This form is for local development only.</span></div>
        </div>
        <div className="modal-actions">
          <button type="button" className="btn-secondary" disabled={credentialBusy} onClick={closeCredentialModal}>Cancel</button>
          <button type="button" className="btn-primary" disabled={credentialBusy || (credentialMethod === 'password' ? credentialPassword.length < 8 : credentialMethod === 'key_and_password' ? !(credentialFile || credentialKeyText.trim()) || !credentialPassword : !(credentialFile || credentialKeyText.trim()))} onClick={() => void saveSSHCredential()}><ShieldCheck size={16}/>{credentialBusy ? 'Encrypting…' : 'Save credential securely'}</button>
        </div>
      </div>
    </div>}
    {currentUser.role==='admin' && deleteSelection && <div className="modal-backdrop" onClick={()=>{if(!busyAction)setDeleteSelection(null)}}>
      <div className="modal sp-delete-dialog" role="dialog" aria-modal="true" aria-label="Confirm permanent delete" onClick={e=>e.stopPropagation()}>
        <div className="modal-head"><div><MiniLabel>DESTRUCTIVE INVENTORY ACTION</MiniLabel><h2><AlertTriangle size={23}/> Permanently delete {deleteSelection.length} server{deleteSelection.length!==1?'s':''}?</h2><p>Deletes selected inventory entries, encrypted credentials, monitoring configuration, snapshots and VPN client profile records. This cannot be undone within the application.</p></div><button className="icon-button" disabled={!!busyAction} onClick={()=>setDeleteSelection(null)} aria-label="Close"><X size={19}/></button></div>
        <div className="sp-delete-content"><div className="sp-delete-list">{deleteSelection.map(id=><div key={id}>{servers.find(s=>s.id===id)?.name || archivedServers.find(s=>s.id===id)?.name || id}</div>)}</div><p><strong>No remote VPS will be stopped, restarted or deleted.</strong> Removes this server from Sentinel inventory (credentials, monitoring, samples). Non-secret security audit history is retained. A verified backup is recommended before permanent removal.</p>
        <label>Type <strong>{`DELETE ${deleteSelection.length} SERVERS`}</strong> to confirm<input autoComplete="off" spellCheck={false} value={deleteConfirmation} onChange={e=>setDeleteConfirmation(e.target.value)}/></label></div>
        <div className="modal-actions sp-delete-actions"><button className="btn-secondary" type="button" disabled={!!busyAction} onClick={()=>setDeleteSelection(null)}>Cancel</button><button type="button" className="sp-danger-solid" disabled={!!busyAction || deleteConfirmation!==`DELETE ${deleteSelection.length} SERVERS`} onClick={()=>void deleteSelectedServers()}><Trash2 size={16}/>{busyAction==='bulk-delete'?'Deleting…':'Permanently delete'}</button></div>
      </div>
    </div>}
    {notice && <div className={'toast ' + notice.tone}><span>{notice.tone==='success'?<Check size={17}/>:<X size={17}/>}</span>{notice.text}<button aria-label="Close notification" onClick={()=>setNotice(null)}><X size={16}/></button></div>}
  </div>
}

function ServerTable({ servers, search, setSearch, onSelect, onAll, targetById, healthById, compact=false, selectedRows=[], onCheck, onSelectAll, selectionActions }: {
  servers: ServerRecord[]; search: string; setSearch: (s: string) => void; onSelect: (id:string)=>void; onAll?:()=>void;
  targetById: Map<string, MonitoringTarget>; healthById: Record<string, HealthState>; compact?:boolean
  selectedRows?: string[]; onCheck?: (id:string,checked:boolean)=>void; onSelectAll?: (checked:boolean)=>void; selectionActions?:ReactNode
}) {
  const allSelected = servers.length > 0 && servers.every(s => selectedRows.includes(s.id))
  const someSelected = servers.some(s => selectedRows.includes(s.id)) && !allSelected
  return <div className="panel server-table-panel inv-board">
    <div className="panel-header server-panel-head">
      <div><MiniLabel>SERVER INVENTORY</MiniLabel><h2>{compact ? 'Your infrastructure' : 'Fleet directory'}</h2></div>
      <div className="table-actions">
        {onSelectAll && (
          <label className="inv-select-all">
            <input type="checkbox" aria-label="Select all visible servers" checked={allSelected} ref={el=>{if(el)el.indeterminate=someSelected}} onChange={e=>onSelectAll(e.target.checked)}/>
            Select all
          </label>
        )}
        <label className="table-search"><Search size={17}/><input aria-label="Search servers" placeholder="Search name, IP, region…" value={search} onChange={e=>setSearch(e.target.value)}/></label>
        {compact && onAll && <button className="view-all" onClick={onAll}>View all <ArrowRight size={16}/></button>}
      </div>
    </div>
    {selectionActions}
    <div className="inv-card-grid">
      {servers.map((server) => {
        const target = targetById.get(backendId(server.id))
        const monitored = target?.monitoring_enabled === true && target?.local_configuration_ready === true && target.host === server.host
        const healthState = healthById[backendId(server.id)]
        const observed = isVerifiedHealth(healthState, server) ? healthState?.health : null
        const observationMs = observed?.collected_at_utc ? Date.parse(observed.collected_at_utc) : NaN
        const recent = !!observed && Number.isFinite(observationMs) && observationMs <= Date.now() + 60_000 && Date.now()-observationMs <= 300_000
        const openvpnState = recent ? observed?.openvpn.service_status : null
        const vpnLabel = openvpnState === 'active' ? 'VPN active' : openvpnState === 'inactive' || openvpnState === 'failed' ? 'VPN stopped' : 'VPN unknown'
        const vpnTone = openvpnState === 'active' ? 'good' : openvpnState === 'inactive' || openvpnState === 'failed' ? 'warn' : 'unknown'
        const selected = selectedRows.includes(server.id)
        return (
          <article key={server.id} className={`inv-card ${selected ? 'selected' : ''} ${monitored ? 'live' : 'pending'}`}>
            <header className="inv-card-head">
              <div className="inv-card-identity">
                {onCheck && (
                  <input type="checkbox" aria-label={`Select ${server.name}`} checked={selected} onChange={e=>onCheck(server.id,e.target.checked)} onClick={e=>e.stopPropagation()}/>
                )}
                <span className="server-icon"><Server size={17}/></span>
                <div>
                  <strong>{server.name}</strong>
                  <small>{server.host}:{server.sshPort}</small>
                </div>
              </div>
              <StatusPill server={server} monitored={monitored} configured={!!target?.monitoring_configured} state={healthState}/>
            </header>
            <div className="inv-card-meta">
              <span><RegionFlag country={server.country}/> {server.region || '—'} · {server.country || '—'}</span>
              <span>{server.provider || 'Provider n/a'}</span>
              <span>{server.client}</span>
            </div>
            <div className="inv-card-chips">
              <span className={`sp-vpn-evidence sp-vpn-evidence-${vpnTone}`}>{vpnLabel}</span>
              <span className={`inv-chip ${monitored ? 'on' : ''}`}>{monitored ? 'Monitoring on' : 'Not enrolled'}</span>
              <span className="inv-chip muted">SSH {server.sshUser}</span>
            </div>
            <footer className="inv-card-foot">
              <button type="button" className="inv-open" onClick={()=>onSelect(server.id)}>Open details <ChevronRight size={15}/></button>
            </footer>
          </article>
        )
      })}
    </div>
    {servers.length===0 && <div className="no-results">No matching servers found.</div>}
    <div className="table-bottom"><span>{servers.length} server{servers.length!==1?'s':''} · card directory</span><span>Details drawer is read-only evidence · Add server enrolls monitoring automatically <ArrowUpRight size={14}/></span></div>
  </div>
}


function ArchivedServerTable({ servers, busyAction, onRestore, onPermanentDelete, canRestore }: {
  servers: ArchivedServer[]
  canRestore: boolean
  busyAction: string | null
  onRestore: (server: ArchivedServer) => void
  onPermanentDelete?: (server: ArchivedServer) => void
}) {
  return <div className="panel server-table-panel">
    <div className="panel-header server-panel-head"><div><MiniLabel>ARCHIVED SERVER REGISTRY</MiniLabel><h2>Archived infrastructure</h2></div>
      <span className="subdued-chip">{servers.length} archived</span>
    </div>
    <div className="table-scroller"><table className="server-table"><thead><tr><th>SERVER</th><th>LOCATION</th><th>CLIENT</th><th>ARCHIVED AT</th><th>ACTION</th></tr></thead>
      <tbody>{servers.map(s => <tr key={s.id}>
        <td><div className="server-cell"><span className="server-icon"><Archive size={18}/></span><div><strong>{s.name}</strong><span>{s.ip}</span></div></div></td>
        <td>{s.location || s.country || 'Unspecified'}</td><td>{s.client}</td>
        <td>{new Date(s.archived_at).toLocaleString()}</td>
        <td>
          {canRestore ? (
            <div style={{display:'flex',flexWrap:'wrap',gap:8}}>
              <button type="button" className="btn-secondary" disabled={!!busyAction} onClick={()=>onRestore(s)}><RotateCcw size={16}/> {busyAction === 'restore-' + s.id ? 'Restoring...' : 'Restore'}</button>
              {onPermanentDelete && (
                <button type="button" className="sp-danger-outline" disabled={!!busyAction} onClick={()=>onPermanentDelete(s)}><Trash2 size={16}/> Permanently delete</button>
              )}
            </div>
          ) : <span className="subdued-chip">Read only</span>}
        </td>
      </tr>)}</tbody></table>
      {servers.length === 0 && <div className="no-results">No archived servers. Archive a server to see it here.</div>}
    </div>
    <div className="table-bottom"><span>{servers.length} archived server{servers.length === 1 ? '' : 's'}</span><span>Restore to use again, or permanently delete from Sentinel.</span></div>
  </div>
}

export default App;
