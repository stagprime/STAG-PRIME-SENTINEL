/** Server Control API — preview catalog + allowlisted VPN execute + read-only diagnostics. */
import { csrfHeaders, signalAuthExpired } from './auth'

export type ServerControlAction = 'restart' | 'memory' | 'housekeeping' | 'vpn-start' | 'vpn-stop' | 'vpn-restart'
const ALLOWED_ACTIONS: readonly ServerControlAction[] = [
  'restart', 'memory', 'housekeeping', 'vpn-start', 'vpn-stop', 'vpn-restart',
]
const EXECUTABLE_ACTIONS: readonly ServerControlAction[] = ['vpn-start', 'vpn-stop', 'vpn-restart']

export type ControlCatalog = {
  preview_only: boolean
  execution_enabled: boolean
  executable_actions: string[]
  scheduling_enabled: boolean
  actions: {
    key: ServerControlAction
    name: string
    risk: string
    prerequisite: string
    executable?: boolean
  }[]
}

export type ControlReadiness = {
  server_id: string
  server_name: string
  archived: boolean
  profile_configured: boolean
  profile_enabled: boolean
  inventory_pinned: boolean
  local_profile_ready: boolean
  remote_privilege_confirmed_now: boolean
  execution_enabled: boolean
  executable_actions?: string[]
  scheduling_enabled: boolean
  registry_initialized: boolean
}

export type ControlPreview = {
  server_id: string
  server_name: string
  action: ServerControlAction
  label: string
  risk: string
  prerequisite: string
  preview_only: boolean
  execution_enabled: boolean
  scheduling_enabled: boolean
  remote_connection_attempted: boolean
  message: string
}

export type ControlExecuteResult = {
  server_id: string
  server_name: string
  action: ServerControlAction
  vpn_service: string
  unit: string
  active_state: string
  execution_enabled: true
  message: string
}

function serverPath(serverId: string): string {
  if (!/^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$/.test(serverId)) {
    throw new Error('Invalid server identifier')
  }
  return `/api/server-operations/servers/${encodeURIComponent(serverId)}/control`
}

function obj(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Unexpected server-control API response')
  }
  return value as Record<string, unknown>
}

async function request(url: string, method: 'GET' | 'POST', body?: unknown, signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(url, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      ...csrfHeaders(method),
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
    signal,
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { detail?: unknown } | null
    const detail = payload?.detail
    if (typeof detail === 'string') throw new Error(detail)
    if (detail && typeof detail === 'object' && 'message' in detail && typeof (detail as { message: unknown }).message === 'string') {
      throw new Error((detail as { message: string }).message)
    }
    const details: Record<number, string> = {
      401: 'Administrator session expired. Sign in again.',
      403: 'This administrator action is not permitted.',
      404: 'Server not found in the current inventory.',
      409: 'Server is archived, busy, or needs monitoring enrollment / profile approval.',
      422: 'Action request rejected by the backend.',
      502: 'Remote VPN control failed (check passwordless sudo / unit).',
      503: 'Administrative profile files or registry are not ready.',
    }
    throw new Error(`${details[response.status] ?? 'Control API unavailable.'} (HTTP ${response.status})`)
  }
  return response.json() as Promise<unknown>
}

export async function getControlCatalog(signal?: AbortSignal): Promise<ControlCatalog> {
  const data = obj(await request('/api/server-operations/control/actions', 'GET', undefined, signal))
  if (typeof data.execution_enabled !== 'boolean' || typeof data.scheduling_enabled !== 'boolean'
    || !Array.isArray(data.actions) || data.actions.length !== ALLOWED_ACTIONS.length) {
    throw new Error('Backend action catalog is invalid')
  }
  const seen = new Set<string>()
  for (const item of data.actions) {
    const a = obj(item)
    if (typeof a.key !== 'string' || !ALLOWED_ACTIONS.includes(a.key as ServerControlAction) || seen.has(a.key)
      || typeof a.name !== 'string' || typeof a.risk !== 'string' || typeof a.prerequisite !== 'string') {
      throw new Error('Invalid backend action catalog entry')
    }
    seen.add(a.key)
  }
  return data as ControlCatalog
}

export async function getControlReadiness(serverId: string, signal?: AbortSignal): Promise<ControlReadiness> {
  const data = obj(await request(`${serverPath(serverId)}/readiness`, 'GET', undefined, signal))
  for (const key of ['archived', 'profile_configured', 'profile_enabled', 'inventory_pinned',
    'local_profile_ready', 'remote_privilege_confirmed_now', 'registry_initialized', 'execution_enabled'] as const) {
    if (typeof data[key] !== 'boolean') throw new Error('Invalid backend readiness response')
  }
  if (data.server_id !== serverId || typeof data.server_name !== 'string') {
    throw new Error('Unexpected server-control readiness state')
  }
  return data as ControlReadiness
}

export async function requestControlPreview(serverId: string, action: ServerControlAction): Promise<ControlPreview> {
  if (!ALLOWED_ACTIONS.includes(action)) throw new Error('Action not permitted')
  const data = obj(await request(`${serverPath(serverId)}/preview`, 'POST', { action }))
  if (data.server_id !== serverId || data.action !== action || typeof data.server_name !== 'string'
    || typeof data.label !== 'string' || typeof data.risk !== 'string' || typeof data.prerequisite !== 'string'
    || typeof data.message !== 'string' || typeof data.preview_only !== 'boolean'
    || typeof data.execution_enabled !== 'boolean' || data.remote_connection_attempted !== false) {
    throw new Error('Preview response failed validation')
  }
  return data as ControlPreview
}

export async function executeControlAction(
  serverId: string,
  action: ServerControlAction,
): Promise<ControlExecuteResult> {
  if (!EXECUTABLE_ACTIONS.includes(action)) throw new Error('Action is not remotely executable')
  const data = obj(await request(`${serverPath(serverId)}/execute`, 'POST', { action, confirm: true }))
  if (data.server_id !== serverId || data.action !== action || typeof data.message !== 'string'
    || typeof data.unit !== 'string' || data.execution_enabled !== true) {
    throw new Error('Execute response failed validation')
  }
  return data as ControlExecuteResult
}

export function isExecutableAction(action: ServerControlAction): boolean {
  return EXECUTABLE_ACTIONS.includes(action)
}

/** Allowlisted audited read-only /proc diagnostics. */
export type DiagnosticCheck = 'load_average' | 'memory_snapshot'
export type DiagnosticCatalog = {
  read_only_execution_enabled: true
  arbitrary_commands_enabled: false
  power_control_enabled: false
  openvpn_control_enabled: false
  scheduling_enabled: false
  checks: { key: DiagnosticCheck; label: string }[]
}
export type DiagnosticResult = {
  server_id: string
  server_name: string
  check: DiagnosticCheck
  metrics: Record<string, number>
  ssh_verified: true
  host_key_verified: true
  audit_recorded: true
  read_only: true
  power_or_vpn_changed: false
}
const DIAGNOSTIC_CHECKS: readonly DiagnosticCheck[] = ['load_average', 'memory_snapshot']
const METRIC_KEYS: Record<DiagnosticCheck, readonly string[]> = {
  load_average: ['load_1m', 'load_5m', 'load_15m'],
  memory_snapshot: ['total_mib', 'available_mib', 'swap_total_mib', 'swap_free_mib'],
}
export async function getDiagnosticCatalog(signal?: AbortSignal): Promise<DiagnosticCatalog> {
  const data = obj(await request('/api/server-operations/diagnostics/catalog', 'GET', undefined, signal))
  if (data.read_only_execution_enabled !== true || data.arbitrary_commands_enabled !== false
    || data.power_control_enabled !== false || data.openvpn_control_enabled !== false
    || data.scheduling_enabled !== false || !Array.isArray(data.checks)
    || data.checks.length !== DIAGNOSTIC_CHECKS.length) {
    throw new Error('Diagnostic catalog does not match the safe allowlist')
  }
  const seen = new Set<string>()
  for (const entry of data.checks) {
    const check = obj(entry)
    if (typeof check.key !== 'string' || !DIAGNOSTIC_CHECKS.includes(check.key as DiagnosticCheck)
      || typeof check.label !== 'string' || seen.has(check.key)) {
      throw new Error('Diagnostic catalog contains an invalid check')
    }
    seen.add(check.key)
  }
  return data as DiagnosticCatalog
}
export async function runDiagnostic(serverId: string, check: DiagnosticCheck): Promise<DiagnosticResult> {
  if (!DIAGNOSTIC_CHECKS.includes(check)) throw new Error('Diagnostic not permitted')
  const base = serverPath(serverId).replace(/\/control$/, '')
  const data = obj(await request(`${base}/diagnostics/run`, 'POST', { check }))
  if (data.server_id !== serverId || typeof data.server_name !== 'string' || data.check !== check
    || data.ssh_verified !== true || data.host_key_verified !== true || data.audit_recorded !== true
    || data.read_only !== true || data.power_or_vpn_changed !== false) {
    throw new Error('Diagnostic safety or identity validation failed')
  }
  const metrics = obj(data.metrics)
  const allowed = METRIC_KEYS[check]
  if (Object.keys(metrics).length !== allowed.length || allowed.some((key) => {
    const value = metrics[key]
    return typeof value !== 'number' || !Number.isFinite(value) || value < 0
  })) throw new Error('Unexpected diagnostic metrics')
  return data as DiagnosticResult
}
