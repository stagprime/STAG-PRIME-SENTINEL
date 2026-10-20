import { csrfHeaders, signalAuthExpired } from "./auth";

export interface ServerRecord {
  id: string;
  name: string;
  ip: string;
  client: string;
  country: string | null;
  location: string | null;
  provider: string | null;
  ssh_port: number;
  ssh_username: string | null;
  status: string;
}

export interface ArchivedServer {
  id: string;
  name: string;
  ip: string;
  client: string;
  country: string | null;
  location: string | null;
  provider: string | null;
  archived: boolean;
  archived_at: string;
}

export interface ServerCreate {
  client_name: string;
  name: string;
  host: string;
  ssh_port?: number;
  ssh_username?: string | null;
  country?: string | null;
  location?: string | null;
  provider?: string | null;
}

export type ServerUpdate = Partial<
  Omit<ServerCreate, "client_name">
>;

interface ServerList<T> {
  total: number;
  servers: T[];
}

async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const response = await fetch(path, {
    ...options,
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json",
      ...csrfHeaders(options.method || "GET"),
      ...options.headers,
    },
  });

  if (!response.ok) {
    if (response.status === 401) signalAuthExpired();
    const error = await response.json().catch(() => null);

    throw new Error(
      typeof error?.detail === "string"
        ? error.detail
        : `Request failed: HTTP ${response.status}`
    );
  }

  return (await response.json()) as T;
}

export function getServers() {
  return apiRequest<ServerList<ServerRecord>>("/api/servers");
}

export function getArchivedServers() {
  return apiRequest<ServerList<ArchivedServer>>(
    "/api/servers/archived"
  );
}

export function addServer(data: ServerCreate) {
  return apiRequest<{id:string;name:string;status:string}>("/api/servers", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function editServer(id: string, data: ServerUpdate) {
  return apiRequest(`/api/servers/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function archiveServer(id: string) {
  return apiRequest(
    `/api/servers/${encodeURIComponent(id)}/archive`,
    { method: "POST" }
  );
}

export function restoreServer(id: string) {
  return apiRequest(
    `/api/servers/${encodeURIComponent(id)}/restore`,
    { method: "POST" }
  );
}


// Read-only verified SSH health endpoint for an approved server (by database ID).
// Byte counters are cumulative, NOT live bandwidth speeds.
export interface ServerHealthResponse {
  server_id: string;
  server_name: string;
  monitoring_source: "verified_ssh";
  status: string;
  host: string;
  username: string;
  ssh_port: number;
  host_key_verified: boolean;
  collected_at_utc: string;
  hostname: string;
  uptime_seconds: number | null;
  cpu_percent: number | null;
  memory_total_bytes: number | null;
  memory_used_bytes: number | null;
  memory_available_bytes: number | null;
  memory_used_percent: number | null;
  disk_total_bytes: number | null;
  disk_used_bytes: number | null;
  disk_free_bytes: number | null;
  disk_used_percent: number | null;
  network: {
    interface: string;
    rx_bytes_total: number | null;
    tx_bytes_total: number | null;
    rx_errors_total: number | null;
    tx_errors_total: number | null;
    rx_dropped_total: number | null;
    tx_dropped_total: number | null;
  };
  openvpn: {
    service: string;
    service_status: string;
    interface: string;
    tunnel_ipv4: string | null;
  };
  vpn_connected_sessions: number | null;
}

export function getServerHealth(id: string, signal?: AbortSignal) {
  return apiRequest<ServerHealthResponse>(
    `/api/servers/${encodeURIComponent(id)}/health`,
    { method: "GET", signal }
  );
}

// Database-backed monitoring preflight; NEVER includes private-key paths or secrets.
export interface MonitoringTarget {
  server_id: string;
  server_name: string;
  client: string;
  host: string;
  monitoring_configured: boolean;
  monitoring_enabled: boolean;
  local_configuration_ready: boolean;
  missing_settings: string[];
  // Preflight never opens an SSH session; this is expected to be false.
  remote_connection_verified: boolean;
}

export function getMonitoringTargets(signal?: AbortSignal) {
  return apiRequest<{ total: number; targets: MonitoringTarget[] }>(
    "/api/monitoring/targets",
    { method: "GET", signal }
  );
}

/** Strictly admin-scoped, database-only bulk operations. No remote VPS calls. */
export function bulkArchiveServers(serverIds: string[]) {
  return apiRequest<{archived:number;remote_changes:false}>('/api/inventory/bulk/archive', {
    method:'POST',body:JSON.stringify({server_ids:serverIds}),
  });
}

export function permanentlyDeleteServers(serverIds: string[], confirmation:string) {
  return apiRequest<{deleted:number;remote_changes:false;audit_retained:true}>('/api/inventory/bulk/permanent-delete', {
    method:'POST',body:JSON.stringify({server_ids:serverIds,confirmation}),
  });
}
