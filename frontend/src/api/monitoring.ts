import { signalAuthExpired } from './auth'

export type SessionRow = {
  connection_number?: number | null
  common_name?: string | null
  username?: string | null
  public_ip?: string | null
  vpn_ip?: string | null
  bytes_received?: number | null
  bytes_sent?: number | null
  connected_since_unix?: number | null
  client_id?: number | null
  [key: string]: unknown
}
export type CachedKind<T> = {
  state: string
  at_utc: string | null
  age_seconds: number | null
  fresh: boolean
  data: T | null
}
export type VpnObservation = {
  configured_service?: string | null
  configured_interface?: string | null
  service?: string | null
  service_status?: string | null
  tunnel_interface?: string | null
  tunnel_ipv4?: string | null
  health_fresh?: boolean
  sessions_state?: string | null
  sessions_total?: number | null
  sessions_fresh?: boolean
  status_age_seconds?: number | null
  protocol?: string | null
  auth_failures_observed?: number | null
  cpu_percent?: number | null
  memory_used_percent?: number | null
  disk_used_percent?: number | null
  uptime_seconds?: number | null
  observed_at_utc?: string | null
}
export type CachedMonitorServer = {
  server_id: string
  server_name: string
  client_id: string
  monitoring_enabled: boolean
  status: 'not_enrolled' | 'healthy' | 'degraded' | 'unreachable' | 'stale' | 'worker_offline'
  error_code: string | null
  last_checked_utc: string | null
  health: CachedKind<{
    status: string; host: string; host_key_verified: boolean
    collected_at_utc: string; [key: string]: unknown
  }>
  sessions: CachedKind<{state: string; total: number | null; sessions: SessionRow[]; status_age_seconds: number | null; protocol?: string | null; auth_failures?: {failed_attempts_observed?: number | null}}>
  vpn_observation?: VpnObservation | null
}
export type MonitoringOverview = {
  worker: { status: 'running' | 'not_running'; last_seen_utc: string | null }
  config: {sessions_interval_seconds: number; health_interval_seconds: number; worker_heartbeat_seconds: number; events: string}
  servers: CachedMonitorServer[]
}
export type Incident = {
  id: number
  server_id: string
  server_name: string
  code: string
  state: 'open' | 'resolved'
  opened_at_utc: string
  last_seen_at_utc: string
  resolved_at_utc: string | null
  title?: string
  severity?: 'critical' | 'high' | 'medium' | 'low'
  summary?: string
  solution?: string
}
export type IncidentSummary = {
  open: number
  resolved: number
  critical_open: number
  high_open: number
  medium_open: number
  low_open: number
  affected_servers: number
  by_code: Array<{code: string; count: number; title: string; severity: string}>
}
export type SessionEvent = {id: number; server_id: string; server_name: string; event: 'appeared' | 'disappeared'; observed_at_utc: string; username_or_common_name: string; public_ip: string | null; vpn_ip: string | null; source: 'snapshot_inferred'; disconnect_reason: null}
export type SessionEventSummary = {
  appeared: number
  disappeared: number
  unique_identities: number
  by_server: Array<{server_id: string; server_name: string; appeared: number; disappeared: number}>
  window_note: string
}

async function load<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {credentials: 'same-origin', cache: 'no-store', signal})
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) throw new Error(`Monitoring API HTTP ${response.status}`)
  return response.json() as Promise<T>
}
export const getMonitoringOverview = (signal?: AbortSignal) => load<MonitoringOverview>('/api/monitoring/overview', signal)
export const getMonitoringIncidents = (signal?: AbortSignal) =>
  load<{incidents: Incident[]; total: number; summary?: IncidentSummary}>('/api/monitoring/incidents', signal)
export const getMonitoringSessionEvents = (signal?: AbortSignal) =>
  load<{events: SessionEvent[]; total: number; summary?: SessionEventSummary}>('/api/monitoring/session-events', signal)

export type NetworkThroughput = {
  state: EvidenceState
  rx_mbps: number | null
  tx_mbps: number | null
  window_seconds: number | null
  note?: string | null
}
export type NetworkFleetServer = {
  server_id: string
  server_name: string
  monitoring_enabled: boolean
  status: string
  health_fresh: boolean
  observed_at_utc: string | null
  wan: {
    interface: string | null
    rx_bytes_total: number | null
    tx_bytes_total: number | null
    rx_errors_total: number | null
    tx_errors_total: number | null
    rx_dropped_total: number | null
    tx_dropped_total: number | null
    throughput: NetworkThroughput
  }
  tunnel: {
    interface: string | null
    tunnel_ipv4: string | null
    service_status: string | null
    rx_bytes_total: number | null
    tx_bytes_total: number | null
    throughput: NetworkThroughput
  }
  link_integrity: 'ok' | 'attention' | 'unknown'
  sample_count: number
}
export type NetworkFleet = {
  worker: MonitoringOverview['worker']
  summary: {
    enrolled: number
    counter_sources: number
    wan_throughput_servers: number
    tunnel_throughput_servers: number
    fleet_wan_rx_mbps: number | null
    fleet_wan_tx_mbps: number | null
    fleet_tunnel_rx_mbps: number | null
    fleet_tunnel_tx_mbps: number | null
    link_attention: number
    note: string
  }
  servers: NetworkFleetServer[]
}
export const getMonitoringNetwork = (signal?: AbortSignal) =>
  load<NetworkFleet>('/api/monitoring/network', signal)

export type PerformanceSeriesPoint = {
  at_utc: string
  cpu_percent: number | null
  memory_used_percent: number | null
  disk_used_percent: number | null
}
export type PerformanceFleetServer = {
  server_id: string
  server_name: string
  monitoring_enabled: boolean
  status: string
  health_fresh: boolean
  observed_at_utc: string | null
  live: {
    cpu_percent: number | null
    memory_used_percent: number | null
    disk_used_percent: number | null
    uptime_seconds: number | null
  }
  window: {
    hours: number
    sample_count: number
    avg_cpu_percent: number | null
    avg_memory_percent: number | null
    avg_disk_percent: number | null
    peak_cpu_percent: number | null
    peak_memory_percent: number | null
    peak_disk_percent: number | null
  }
  pressure: 'ok' | 'elevated' | 'critical' | 'unknown'
  hottest_resource: 'cpu' | 'memory' | 'disk' | null
  headroom_percent: number | null
  series: PerformanceSeriesPoint[]
}
export type PerformanceFleet = {
  worker: MonitoringOverview['worker']
  period_hours: number
  generated_at_utc: string
  summary: {
    enrolled: number
    observed: number
    history_samples: number
    pressure: { critical: number; elevated: number; ok: number; unknown: number }
    avg_headroom_percent: number | null
    note: string
  }
  servers: PerformanceFleetServer[]
}
export const getMonitoringPerformance = (hours: 1 | 6 | 24, signal?: AbortSignal) =>
  load<PerformanceFleet>(`/api/monitoring/performance?hours=${hours}`, signal)

export type SecurityFleetServer = {
  server_id: string
  server_name: string
  monitoring_enabled: boolean
  status: string
  health_fresh: boolean
  sessions_fresh: boolean
  observed_at_utc: string | null
  certificate: {
    state: EvidenceState | string
    path: string | null
    not_after: string | null
    not_after_utc: string | null
    days_remaining: number | null
    note?: string | null
  }
  certificate_attention: 'ok' | 'expiring' | 'critical' | 'expired' | 'permission' | 'unknown'
  auth_failures: {
    state: string
    failed_attempts_observed: number | null
    window_seconds: number | null
    note?: string | null
  }
  auth_attention: 'ok' | 'elevated' | 'unknown'
  journal: {
    state: string | null
    unit: string | null
    line_count: number
    lines: string[]
    note?: string | null
  }
  protocol?: string | null
  open_security_incidents: number
  attention: 'ok' | 'medium' | 'high' | 'unknown'
}
export type SecurityFleetIncident = {
  id: number
  server_id: string
  server_name: string
  code: string
  title: string
  severity: string
  summary: string
  solution: string
  opened_at_utc: string
  last_seen_at_utc: string
}
export type SecurityFleet = {
  worker: MonitoringOverview['worker']
  generated_at_utc: string
  summary: {
    enrolled: number
    cert_observed: number
    cert_attention: number
    auth_sources: number
    auth_elevated: number
    journal_sources: number
    open_security_incidents: number
    servers_high_attention: number
    note: string
  }
  servers: SecurityFleetServer[]
  incidents: SecurityFleetIncident[]
}
export const getMonitoringSecurity = (signal?: AbortSignal) =>
  load<SecurityFleet>('/api/monitoring/security', signal)

export type MonitoringReportRow = {
  server_id: string; server_name: string; client_id: string
  session_samples: number; peak_observed_connections: number | null
  average_observed_connections: number | null; health_samples: number
  average_cpu_percent: number | null; average_ram_percent: number | null
  average_disk_percent: number | null; incidents_opened: number
  last_session_sample_utc: string | null
}
export type MonitoringReport = {
  period_hours: number; generated_at_utc: string
  scope: string; source: string; note: string; servers: MonitoringReportRow[]
}
export const getMonitoringReport = (hours: 1 | 6 | 24, signal?: AbortSignal) =>
  load<MonitoringReport>(`/api/monitoring/reports/summary?hours=${hours}`, signal)
export async function downloadMonitoringReport(hours: 1 | 6 | 24): Promise<void> {
  const response = await fetch(`/api/monitoring/reports/summary.csv?hours=${hours}`, {
    credentials: 'same-origin', cache: 'no-store',
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) throw new Error(`Report export HTTP ${response.status}`)
  const blob = await response.blob()
  const uri = URL.createObjectURL(blob)
  try {
    const a = document.createElement('a')
    a.href = uri
    a.download = `stagprime-sentinel-monitoring-${hours}h.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
  } finally {
    URL.revokeObjectURL(uri)
  }
}


export type Server360HistoryHealth = {
  at_utc: string; state: string
  cpu_percent: number | null; memory_used_percent: number | null
  disk_used_percent: number | null; uptime_seconds: number | null
  network_interface: string | null
  rx_bytes_total?: number | null
  tx_bytes_total?: number | null
}
export type Server360HistorySession = {at_utc: string; state: string; connections: number | null}
export type Server360Incident = {
  id: number; code: string; state: string; opened_at_utc: string
  last_seen_at_utc: string; resolved_at_utc: string | null
}
export type EvidenceState = 'available' | 'permission_needed' | 'unavailable' | 'insufficient_samples'
export type Server360Evidence = {
  throughput: {
    state: EvidenceState
    rx_mbps: number | null
    tx_mbps: number | null
    window_seconds: number | null
    note?: string | null
  }
  journal: {
    state: EvidenceState
    unit: string | null
    lines: string[]
    note?: string | null
  }
  certificate: {
    state: EvidenceState
    path: string | null
    not_after: string | null
    not_after_utc: string | null
    days_remaining: number | null
    note?: string | null
  }
  tls_auth_events: {
    state: EvidenceState
    failed_attempts_observed: number | null
    window_seconds?: number | null
    note?: string | null
  }
  collection?: { mode: string; note?: string }
}
export type Server360Snapshot = {
  server_id: string; source: 'stored_ssh_snapshots'
  worker: MonitoringOverview['worker']
  monitor: {server_id:string;status:string;monitoring_enabled:boolean;error_code:string|null;last_checked_utc:string|null;health:Omit<CachedKind<never>,'data'>;sessions:Omit<CachedKind<never>,'data'>}
  history: {health: Server360HistoryHealth[]; sessions: Server360HistorySession[]}
  evidence?: Server360Evidence
  incidents: Server360Incident[]
  limits: {history_max_points_per_kind: number; incidents_max_records: number; history_is_live: false}
}
export const getServer360Snapshot = (serverId: string, signal?: AbortSignal) =>
  load<Server360Snapshot>(`/api/monitoring/servers/${encodeURIComponent(serverId)}/360?limit=48`, signal)
