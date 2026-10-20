// Step 40.10B: authenticated, admin-only local-development credential enrollment.
// Secrets are submitted once and never stored in browser storage or returned by API.
import { csrfHeaders, signalAuthExpired } from './auth'

export type SSHAuthMethod = 'private_key' | 'password' | 'key_and_password'
export interface CredentialEnrollResult {
  server_id: string
  configured: boolean
  auth_method: SSHAuthMethod
  verification_required: boolean
  host_key_verified: boolean
}

export async function enrollSSHCredential(
  serverId: string,
  method: SSHAuthMethod,
  secret: string,
  options?: { ppkPassphrase?: string; loginPassword?: string },
): Promise<CredentialEnrollResult> {
  const body: Record<string, string> = { auth_method: method, secret }
  if (options?.ppkPassphrase) body.ppk_passphrase = options.ppkPassphrase
  if (options?.loginPassword) body.login_password = options.loginPassword
  const response = await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/credentials`, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', ...csrfHeaders('POST') },
    body: JSON.stringify(body),
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { detail?: string } | null
    throw new Error(typeof payload?.detail === 'string' ? payload.detail : `Credential enrollment failed (HTTP ${response.status})`)
  }
  return response.json() as Promise<CredentialEnrollResult>
}

export interface LocalDefaultKeyInfo {
  configured: boolean
  path: string | null
  exists: boolean
  size_bytes: number | null
}

export interface SSHCredentialStatus {
  server_id: string
  configured: boolean
  auth_method: SSHAuthMethod | null
  host_pinned: boolean
  vault_accessible: boolean
  last_updated_at_utc: string | null
  verification_required: boolean
  local_default_key?: LocalDefaultKeyInfo
}

export async function enrollFromLocalDefaultKey(
  serverId: string,
  ppkPassphrase?: string,
): Promise<CredentialEnrollResult> {
  const body: Record<string, string> = {}
  if (ppkPassphrase) body.ppk_passphrase = ppkPassphrase
  const response = await fetch(
    `/api/server-operations/servers/${encodeURIComponent(serverId)}/credentials/from-local-default`,
    {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'Content-Type': 'application/json', ...csrfHeaders('POST') },
      body: JSON.stringify(body),
    },
  )
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { detail?: string } | null
    throw new Error(typeof payload?.detail === 'string' ? payload.detail : `Local key enroll failed (HTTP ${response.status})`)
  }
  return response.json() as Promise<CredentialEnrollResult>
}

/** Read-only credential metadata. Never fetches the password/key. */
export async function getSSHCredentialStatus(serverId: string, signal?: AbortSignal): Promise<SSHCredentialStatus> {
  const response = await fetch(`/api/server-operations/servers/${encodeURIComponent(serverId)}/credentials/status`, {
    method: 'GET', credentials: 'same-origin', cache: 'no-store', signal,
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as {detail?: unknown} | null
    throw new Error(typeof payload?.detail === 'string' ? payload.detail : `Credential status unavailable (HTTP ${response.status})`)
  }
  const status = await response.json() as SSHCredentialStatus
  if (status.server_id !== serverId || typeof status.configured !== 'boolean' ||
      typeof status.host_pinned !== 'boolean' || typeof status.vault_accessible !== 'boolean') {
    throw new Error('Invalid credential status API response')
  }
  return status
}

export function authMethodLabel(method: SSHAuthMethod | null | undefined): string {
  if (method === 'password') return 'SSH password'
  if (method === 'key_and_password') return 'SSH key + login password'
  if (method === 'private_key') return 'SSH private key'
  return 'SSH credential'
}
