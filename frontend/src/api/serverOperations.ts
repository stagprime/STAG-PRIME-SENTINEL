/** Step 40.3: narrow authenticated API contract. Never expose SSH key details. */
import { csrfHeaders, signalAuthExpired } from './auth'

export interface AdminProfileStatus {
  server_id: string
  server_name: string
  profile_configured: boolean
  profile_enabled: boolean
  inventory_pinned: boolean
  verification_ready: boolean
  privilege_state: string
  recent_verification?: {
    state: string
    checked_at_utc: string
    privilege_state?: string
    ssh_verified?: boolean
    administration_ready?: boolean
  } | null
}

export interface AdminSSHVerification {
  server_id: string
  ssh_verified: boolean
  host_key_verified: boolean
  privilege_state: 'root' | 'sudo_nopasswd' | 'sudo_password_required' | 'sudo_unavailable'
  administration_ready: boolean
}

async function adminRequest(url: string, method: 'GET' | 'POST', signal?: AbortSignal): Promise<unknown> {
  const response = await fetch(url, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { ...csrfHeaders(method) },
    signal,
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as {detail?: unknown} | null
    const detail = payload?.detail
    const sanitized = typeof detail === 'string' ? detail : (
      detail && typeof detail === 'object' && 'message' in detail && typeof detail.message === 'string'
        ? detail.message : null)
    throw new Error(sanitized || `Administrative access check failed (HTTP ${response.status})`)
  }
  return response.json() as Promise<unknown>
}

export async function getAdminProfiles(signal?: AbortSignal): Promise<{ profiles: AdminProfileStatus[] }> {
  const data = await adminRequest('/api/server-operations/admin-profiles', 'GET', signal)
  if (!data || typeof data !== 'object' || !('profiles' in data) || !Array.isArray(data.profiles)) {
    throw new Error('Invalid admin profile API response')
  }
  for (const entry of data.profiles) {
    if (!entry || typeof entry !== 'object' || typeof entry.server_id !== 'string'
      || typeof entry.profile_configured !== 'boolean' || typeof entry.profile_enabled !== 'boolean'
      || typeof entry.inventory_pinned !== 'boolean' || typeof entry.verification_ready !== 'boolean') {
      throw new Error('Invalid administrative profile entry')
    }
  }
  return { profiles: data.profiles as AdminProfileStatus[] }
}

export async function verifyAdminSSH(serverId: string): Promise<AdminSSHVerification> {
  // serverId comes from the authenticated admin profile response, never a user-entered command.
  if (!/^[0-9a-fA-F-]{36}$/.test(serverId)) throw new Error('Invalid inventory server ID')
  const data = await adminRequest(
    `/api/server-operations/servers/${encodeURIComponent(serverId)}/admin/verify`, 'POST',
  )
  if (!data || typeof data !== 'object'
    || !('server_id' in data) || data.server_id !== serverId
    || !('ssh_verified' in data) || typeof data.ssh_verified !== 'boolean'
    || !('host_key_verified' in data) || typeof data.host_key_verified !== 'boolean'
    || !('administration_ready' in data) || typeof data.administration_ready !== 'boolean'
    || !('privilege_state' in data) || !['root', 'sudo_nopasswd', 'sudo_password_required', 'sudo_unavailable'].includes(String(data.privilege_state))) {
    throw new Error('Invalid SSH verification API response')
  }
  return data as AdminSSHVerification
}

/** Step 42A: enrollment is an explicit administrator-approved, read-only operation.
 * It never initiates SSH: an existing successful backend verification is required.
 */
export type MonitorEnrollmentSettings = {
  consent: true
  vpn_service: string
  vpn_interface: string
  network_interface: string
}
export async function enrollVerifiedMonitoring(serverId: string, settings: MonitorEnrollmentSettings) {
  if (!/^[0-9a-fA-F-]{36}$/.test(serverId)) throw new Error('Invalid inventory server ID')
  const response = await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/monitoring/enroll`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': 'application/json', ...csrfHeaders('POST')},
    body: JSON.stringify(settings),
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as {detail?: unknown} | null
    throw new Error(typeof payload?.detail === 'string' ? payload.detail : `Monitoring enrollment HTTP ${response.status}`)
  }
  return response.json() as Promise<{
    server_id: string
    monitoring_enabled: boolean
    health_status: string
    vpn_service?: string
    vpn_interface?: string
    network_interface?: string
  }>
}
export async function disableVerifiedMonitoring(serverId: string) {
  if (!/^[0-9a-fA-F-]{36}$/.test(serverId)) throw new Error('Invalid inventory server ID')
  const response = await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/monitoring/disable`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: csrfHeaders('POST'),
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) throw new Error(`Monitoring disable HTTP ${response.status}`)
  return response.json() as Promise<{server_id: string; monitoring_enabled: boolean}>
}
