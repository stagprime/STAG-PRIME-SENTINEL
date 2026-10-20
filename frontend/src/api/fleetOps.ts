import { csrfHeaders, signalAuthExpired } from './auth';

export type FleetIssue = {
  code: string;
  title: string;
  severity: string;
  summary: string;
  solution: string;
};

export type FleetSession = {
  common_name?: string;
  username?: string;
  public_ip?: string;
  vpn_ip?: string;
  connected_since?: string | number | null;
  bytes_received?: number | null;
  bytes_sent?: number | null;
};

export type FleetServerRow = {
  server_id: string;
  server_name?: string;
  status?: string;
  monitoring_enabled?: boolean;
  protocol?: string | null;
  connected_users?: number | null;
  failed_auth_observations?: number;
  active_sessions?: FleetSession[];
  issues: FleetIssue[];
};

export type FleetAlert = {
  at_utc?: string;
  server_id?: string;
  server_name?: string;
  code?: string;
  state?: string;
  detail?: string;
};

export type FleetOpsResponse = {
  worker: { status?: string; last_seen_utc?: string | null };
  summary: {
    enrolled_servers: number;
    connected_users: number | null;
    connected_source_servers: number;
    failed_auth_observations: number;
    open_issue_signals: number;
    connected_by_protocol: Record<string, number>;
    note?: string;
  };
  servers: FleetServerRow[];
  recent_alerts?: FleetAlert[];
};

async function api<T>(url: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    ...init,
    cache: 'no-store',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...csrfHeaders(init.method || 'GET'),
      ...init.headers,
    },
  });
  if (response.status === 401) {
    signalAuthExpired();
    throw new Error('Session expired. Please sign in again.');
  }
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    const detail = payload && typeof payload === 'object' && 'detail' in payload
      ? (payload as { detail: unknown }).detail : null;
    throw new Error(typeof detail === 'string' ? detail : `Request failed (HTTP ${response.status}).`);
  }
  return (await response.json()) as T;
}

export const getFleetOps = (signal?: AbortSignal) =>
  api<FleetOpsResponse>('/api/monitoring/fleet-ops', { signal });

export type QuickOnboardPayload = {
  client_id: string;
  name: string;
  host: string;
  ssh_port: number;
  ssh_username: string;
  auth_method: 'password' | 'private_key' | 'key_and_password';
  secret: string;
  login_password?: string;
  ppk_passphrase?: string;
  country?: string;
  location?: string;
  provider?: string;
  consent_monitoring: true;
};

export type QuickOnboardResult = {
  server_id: string;
  name: string;
  host: string;
  protocol?: string;
  vpn_service: string;
  vpn_interface: string;
  discovery?: { protocols?: string[]; suggestions?: Array<Record<string, string>> };
  next?: string;
};

export const quickOnboardServer = (body: QuickOnboardPayload) =>
  api<QuickOnboardResult>('/api/server-operations/quick-onboard', {
    method: 'POST',
    body: JSON.stringify(body),
  });

export const executeVpnControl = (serverId: string, action: 'vpn-start' | 'vpn-stop' | 'vpn-restart') =>
  api<{ message: string; unit: string; active_state?: string }>(
    `/api/server-operations/servers/${encodeURIComponent(serverId)}/control/execute`,
    { method: 'POST', body: JSON.stringify({ action, confirm: true }) },
  );

export const controlVpnUser = (
  serverId: string,
  action: 'kick' | 'block' | 'unblock',
  identity: string,
) =>
  api<{ message: string; action: string; identity: string }>(
    `/api/server-operations/servers/${encodeURIComponent(serverId)}/vpn/users/control`,
    {
      method: 'POST',
      body: JSON.stringify({ action, identity, confirm: true }),
    },
  );
