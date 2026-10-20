import type { CachedMonitorServer, MonitoringOverview } from '../api/monitoring'

export type HighAlert = {
  id: string
  severity: 'high'
  server_id: string
  server_name: string
  code: string
  title: string
  detail: string
}

const SESSION_OVERLOAD = 40

export function buildHighAlerts(overview: MonitoringOverview | null): HighAlert[] {
  if (!overview) return []
  const workerOk = overview.worker.status === 'running'
  const out: HighAlert[] = []
  for (const server of overview.servers) {
    if (!server.monitoring_enabled) continue
    const name = server.server_name
    const sid = server.server_id
    if (!workerOk) {
      out.push({
        id: `${sid}-worker`,
        severity: 'high',
        server_id: sid,
        server_name: name,
        code: 'worker_offline',
        title: 'Monitoring worker offline',
        detail: 'Fresh samples will stop until START_ALL / worker is running.',
      })
      break
    }
    if (server.status === 'degraded' || server.status === 'unreachable') {
      out.push({
        id: `${sid}-health`,
        severity: 'high',
        server_id: sid,
        server_name: name,
        code: server.status,
        title: server.status === 'unreachable' ? 'Server unreachable' : 'Server health degraded',
        detail: server.error_code
          ? `Collector: ${server.error_code}`
          : 'No reliable fresh SSH health reading.',
      })
    }
    const health = server.health.fresh ? server.health.data : null
    if (health) {
      const cpu = num(health.cpu_percent)
      const ram = num(health.memory_used_percent)
      const disk = num(health.disk_used_percent)
      if (cpu !== null && cpu >= 90) {
        out.push(alert(sid, name, 'high_cpu', 'High CPU', `${cpu.toFixed(0)}% CPU on ${name}`))
      }
      if (ram !== null && ram >= 90) {
        out.push(alert(sid, name, 'high_ram', 'High memory', `${ram.toFixed(0)}% RAM on ${name}`))
      }
      if (disk !== null && disk >= 90) {
        out.push(alert(sid, name, 'high_disk', 'Disk nearly full', `${disk.toFixed(0)}% disk on ${name}`))
      }
      const vpn = asObj(health.openvpn)
      const vpnStatus = typeof vpn?.service_status === 'string' ? vpn.service_status : null
      if (vpnStatus && vpnStatus !== 'active') {
        out.push(alert(sid, name, 'vpn_down', 'VPN service not active', `${name}: ${vpnStatus}`))
      }
    }
    const sessions = server.sessions.fresh ? server.sessions.data : null
    if (sessions?.state === 'available' && typeof sessions.total === 'number' && sessions.total >= SESSION_OVERLOAD) {
      out.push(alert(
        sid,
        name,
        'session_overload',
        'Too many VPN users',
        `${sessions.total} connected on ${name} (alert ≥ ${SESSION_OVERLOAD})`,
      ))
    }
  }
  return out
}

function alert(server_id: string, server_name: string, code: string, title: string, detail: string): HighAlert {
  return { id: `${server_id}-${code}`, severity: 'high', server_id, server_name, code, title, detail }
}

function num(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function asObj(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
}

export function cardMetrics(server: CachedMonitorServer | null, workerRunning: boolean) {
  const health = workerRunning && server?.health.fresh ? server.health.data : null
  const sessions = workerRunning && server?.sessions.fresh ? server.sessions.data : null
  const vpn = health ? asObj(health.openvpn) : null
  return {
    status: server?.status || 'not_enrolled',
    cpu: num(health?.cpu_percent),
    ram: num(health?.memory_used_percent),
    disk: num(health?.disk_used_percent),
    sessions: sessions?.state === 'available' && typeof sessions.total === 'number' ? sessions.total : null,
    sessionRows: sessions?.state === 'available' && Array.isArray(sessions.sessions) ? sessions.sessions : [],
    vpnStatus: typeof vpn?.service_status === 'string' ? vpn.service_status : null,
    tunnel: typeof vpn?.tunnel_ipv4 === 'string' ? vpn.tunnel_ipv4 : null,
    hostname: typeof health?.hostname === 'string' ? health.hostname : null,
    uptime: num(health?.uptime_seconds),
  }
}
