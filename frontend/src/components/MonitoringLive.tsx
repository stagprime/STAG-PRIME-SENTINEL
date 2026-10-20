import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertCircle, ArrowUpRight, Clock3, Copy, Globe2, HardDrive,
  Radio, RefreshCw, Search, Server, Users, WifiOff, X,
} from 'lucide-react'
import { getMonitoringOverview, getMonitoringIncidents, getMonitoringSessionEvents } from '../api/monitoring'
import type { CachedMonitorServer, MonitoringOverview, Incident, SessionEvent, SessionEventSummary, SessionRow } from '../api/monitoring'
import { geoLabel, useGeoLabels } from '../hooks/useGeoLabels'
import './MonitoringLive.css'

type View = 'overview' | 'sessions' | 'alerts'
type SortKey = 'traffic' | 'duration' | 'identity' | 'server'
type SessionEntry = {
  server: string
  id: string
  row: SessionRow
  metric: CachedMonitorServer
  identity: string
  traffic: number
  durationSec: number
  location: string
}

const stateLabel: Record<string, string> = {
  healthy: 'Healthy', degraded: 'Degraded', unreachable: 'Unreachable (collector)',
  stale: 'No fresh sample', worker_offline: 'Monitoring worker offline', not_enrolled: 'Not enrolled',
}

function size(n: number | null | undefined) {
  if (n == null || !Number.isFinite(n) || n < 0) return '—'
  const i = Math.min(4, Math.floor(Math.log(Math.max(1, n)) / Math.log(1024)))
  return `${(n / (1024 ** i)).toFixed(i === 0 ? 0 : 1)} ${['B', 'KB', 'MB', 'GB', 'TB'][i]}`
}

function duration(start: number | null) {
  if (!start) return '—'
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - start))
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (h >= 24) return `${Math.floor(h / 24)}d ${h % 24}h`
  return `${h}h ${m}m`
}

function ageText(iso: string | null) {
  return iso ? new Date(iso).toLocaleTimeString() : 'Never'
}

function pct(n: number | null | undefined) {
  return typeof n === 'number' && Number.isFinite(n) ? `${n.toFixed(0)}%` : '—'
}

function countryFromGeo(label: string) {
  if (!label || label === '—' || label.toLowerCase().includes('unknown')) return 'Unknown'
  const parts = label.split(',').map((p) => p.trim()).filter(Boolean)
  return parts[parts.length - 1] || label
}

export default function MonitoringLive({
  view,
  onOpenServer,
}: {
  view: View
  onOpenServer?: (serverId: string) => void
}) {
  const [overview, setOverview] = useState<MonitoringOverview | null>(null)
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [events, setEvents] = useState<SessionEvent[]>([])
  const [eventSummary, setEventSummary] = useState<SessionEventSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  const [search, setSearch] = useState('')
  const [serverFilter, setServerFilter] = useState('all')
  const [sortKey, setSortKey] = useState<SortKey>('traffic')
  const [selected, setSelected] = useState<SessionEntry | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let busy = false
    async function refresh() {
      if (busy || controller.signal.aborted) return
      busy = true
      try {
        const [state, active, history] = await Promise.all([
          getMonitoringOverview(controller.signal),
          view === 'alerts' ? getMonitoringIncidents(controller.signal) : Promise.resolve(null),
          view === 'sessions' ? getMonitoringSessionEvents(controller.signal) : Promise.resolve(null),
        ])
        if (!controller.signal.aborted) {
          setOverview(state)
          if (active) setIncidents(active.incidents)
          if (history) {
            setEvents(history.events)
            setEventSummary(history.summary ?? null)
          }
          setError(null)
        }
      } catch (e) {
        if (!controller.signal.aborted) setError(e instanceof Error ? e.message : 'Monitoring unavailable')
      } finally {
        busy = false
      }
    }
    void refresh()
    const timer = window.setInterval(() => { void refresh() }, 30000)
    return () => { controller.abort(); window.clearInterval(timer) }
  }, [view, revision])

  const enrolled = useMemo(() => overview?.servers.filter((s) => s.monitoring_enabled) || [], [overview])
  const fresh = enrolled.filter((s) => s.health.fresh)
  const active = enrolled.filter((s) => s.sessions.fresh && s.sessions.data?.state === 'available')
  const knownTotal = active.reduce((sum, s) => sum + (s.sessions.data?.total || 0), 0)
  const unknownCount = enrolled.length - active.length
  const running = overview?.worker.status === 'running'

  const allSessions: SessionEntry[] = useMemo(() => {
    return active.flatMap((s) => (s.sessions.data?.sessions || []).map((row) => {
      const rx = typeof row.bytes_received === 'number' ? row.bytes_received : 0
      const tx = typeof row.bytes_sent === 'number' ? row.bytes_sent : 0
      const start = typeof row.connected_since_unix === 'number' ? row.connected_since_unix : null
      return {
        server: s.server_name,
        id: s.server_id,
        row,
        metric: s,
        identity: row.username || row.common_name || 'Unknown',
        traffic: rx + tx,
        durationSec: start ? Math.max(0, Math.round(Date.now() / 1000 - start)) : 0,
        location: '',
      }
    }))
  }, [active])

  const geo = useGeoLabels(allSessions.map((s) => s.row.public_ip))

  const sessionsWithGeo = useMemo(() => allSessions.map((s) => ({
    ...s,
    location: geoLabel(geo, s.row.public_ip),
  })), [allSessions, geo])

  const filteredSessions = useMemo(() => {
    const q = search.trim().toLowerCase()
    let rows = sessionsWithGeo.filter((s) => {
      if (serverFilter !== 'all' && s.id !== serverFilter) return false
      if (!q) return true
      const hay = [s.server, s.identity, s.row.public_ip, s.row.vpn_ip, s.location, s.metric.vpn_observation?.protocol]
        .join(' ').toLowerCase()
      return hay.includes(q)
    })
    rows = [...rows].sort((a, b) => {
      if (sortKey === 'traffic') return b.traffic - a.traffic
      if (sortKey === 'duration') return b.durationSec - a.durationSec
      if (sortKey === 'identity') return a.identity.localeCompare(b.identity)
      return a.server.localeCompare(b.server)
    })
    return rows
  }, [sessionsWithGeo, search, serverFilter, sortKey])

  const totalTraffic = sessionsWithGeo.reduce((sum, s) => sum + s.traffic, 0)
  const longest = sessionsWithGeo.reduce((best, s) => (s.durationSec > best ? s.durationSec : best), 0)
  const geoBuckets = useMemo(() => {
    const map = new Map<string, number>()
    for (const s of sessionsWithGeo) {
      const key = countryFromGeo(s.location)
      map.set(key, (map.get(key) || 0) + 1)
    }
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8)
  }, [sessionsWithGeo])

  const perServer = useMemo(() => {
    return enrolled.map((s) => {
      const vpn = s.vpn_observation
      const sessionsOk = s.sessions.fresh && s.sessions.data?.state === 'available'
      const total = sessionsOk && typeof s.sessions.data?.total === 'number' ? s.sessions.data.total : null
      return {
        id: s.server_id,
        name: s.server_name,
        total,
        status: s.status,
        protocol: vpn?.protocol || s.sessions.data?.protocol || 'openvpn',
        cpu: vpn?.cpu_percent ?? null,
        ram: vpn?.memory_used_percent ?? null,
        authFails: vpn?.auth_failures_observed ?? s.sessions.data?.auth_failures?.failed_attempts_observed ?? null,
        fresh: sessionsOk,
      }
    }).sort((a, b) => (b.total ?? -1) - (a.total ?? -1))
  }, [enrolled])

  const maxServerSessions = Math.max(1, ...perServer.map((s) => s.total ?? 0))
  const openIncidents = incidents.filter((i) => i.state === 'open')
  const maxTraffic = Math.max(1, ...filteredSessions.map((s) => s.traffic))

  function copyText(value: string) {
    void navigator.clipboard?.writeText(value).then(() => {
      setNotice(`Copied ${value}`)
      window.setTimeout(() => setNotice(null), 1800)
    })
  }

  return (
    <section className="ml-wrap">
      <div className="ml-header">
        <div>
          <span className="ml-eyebrow">STAG PRIME SENTINEL / LIVE TELEMETRY</span>
          <h2>
            {view === 'sessions' ? 'VPN connection intelligence'
              : view === 'alerts' ? 'Monitoring incidents'
                : 'Background monitoring status'}
          </h2>
          <p>
            {view === 'sessions'
              ? 'Verified live sessions, traffic, geography and observed connect churn — worker cache only, no SSH from this page.'
              : 'Cached backend telemetry. Opening this page never initiates an SSH connection.'}
          </p>
        </div>
        <button className="btn-secondary" type="button" onClick={() => setRevision((n) => n + 1)}>
          <RefreshCw size={16} /> Refresh data
        </button>
      </div>

      {error && (
        <p role="alert" className="ml-error">{error} — Last available data is displayed only when marked fresh.</p>
      )}
      {notice && <div className="ml-notice" role="status">{notice}</div>}

      <div className="ml-status">
        <span className={`ml-indicator ${running ? 'ml-green' : 'ml-amber'}`} />
        Worker: <strong>{running ? 'Running' : overview ? 'Offline / not started' : 'Checking…'}</strong>
        <span> · Last heartbeat: {ageText(overview?.worker.last_seen_utc || null)}</span>
        <span> · VPN {overview?.config.sessions_interval_seconds || 30}s / Health {overview?.config.health_interval_seconds || 60}s</span>
      </div>

      <div className={`ml-metrics ${view === 'sessions' ? 'ml-metrics-6' : ''}`}>
        <div><Server size={18} /><span>Enrolled servers</span><strong>{overview ? enrolled.length : '—'}</strong></div>
        <div><Activity size={18} /><span>Fresh health</span><strong>{overview ? `${fresh.length} / ${enrolled.length}` : '—'}</strong></div>
        <div>
          <Users size={18} /><span>Known VPN connections</span>
          <strong>{overview ? knownTotal : '—'}</strong>
          <small>{unknownCount} server(s) unavailable/unverified</small>
        </div>
        {view === 'sessions' ? (
          <>
            <div><HardDrive size={18} /><span>Session traffic</span><strong>{overview ? size(totalTraffic) : '—'}</strong><small>Σ RX+TX verified</small></div>
            <div><Globe2 size={18} /><span>Locations</span><strong>{overview ? geoBuckets.length : '—'}</strong><small>Distinct geo labels</small></div>
            <div>
              <Clock3 size={18} /><span>Observed churn</span>
              <strong>{eventSummary ? eventSummary.appeared + eventSummary.disappeared : events.length}</strong>
              <small>
                {eventSummary
                  ? `+${eventSummary.appeared} / −${eventSummary.disappeared}`
                  : 'Snapshot transitions'}
              </small>
            </div>
          </>
        ) : (
          <div><AlertCircle size={18} /><span>Health warnings</span><strong>{overview ? enrolled.filter((s) => s.status !== 'healthy').length : '—'}</strong></div>
        )}
      </div>

      {view === 'overview' && (
        <div className="ml-grid">
          {enrolled.map((s) => (
            <article className="ml-card" key={s.server_id}>
              <div className="ml-server">
                <strong>{s.server_name}</strong>
                <span className={`ml-tag ${s.status === 'healthy' ? 'ml-tag-green' : 'ml-tag-warn'}`}>
                  {stateLabel[s.status] || s.status}
                </span>
              </div>
              <small>Health: {s.health.fresh ? 'Fresh' : 'Stale or unavailable'} · Last: {ageText(s.health.at_utc)}</small>
              {s.health.fresh && s.health.data ? (
                <div className="ml-vitals">
                  {(['cpu_percent', 'memory_used_percent', 'disk_used_percent'] as const).map((key, i) => (
                    <div key={key}>
                      <small>{['CPU', 'RAM', 'Disk'][i]}</small>
                      <strong>{typeof s.health.data?.[key] === 'number' ? `${Number(s.health.data[key]).toFixed(1)}%` : '—'}</strong>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="ml-muted">Last reading cannot be trusted as live.</p>
              )}
              <div className="ml-vpn-count">
                <Radio size={15} /> VPN:{' '}
                {s.sessions.fresh && s.sessions.data?.state === 'available'
                  ? `${s.sessions.data.total} active connections`
                  : s.sessions.fresh ? s.sessions.data?.state : 'Status unavailable'}
              </div>
              {s.error_code && <small>Issue: {s.error_code}</small>}
            </article>
          ))}
          {overview && !enrolled.length && (
            <p className="ml-muted">No approved monitoring enrollment. Configure and enable a pinned monitoring profile first; server inventory alone does not authorize SSH.</p>
          )}
        </div>
      )}

      {view === 'sessions' && (
        <>
          <div className="ml-info">
            <WifiOff size={17} />
            Only VPN services with fresh, readable status files contribute to the total. A missing status is never counted as zero.
          </div>

          <div className="ml-sess-board">
            <div className="ml-sess-main">
              <div className="ml-sess-panel">
                <div className="ml-sess-panel-head">
                  <div>
                    <h3>Per-server session load</h3>
                    <p>Live connection counts with host CPU / RAM when health is fresh</p>
                  </div>
                  <span className="ml-mini">{perServer.length} nodes</span>
                </div>
                <div className="ml-server-load">
                  {perServer.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      className={`ml-load-row ${serverFilter === s.id ? 'on' : ''}`}
                      onClick={() => setServerFilter((cur) => (cur === s.id ? 'all' : s.id))}
                    >
                      <div className="ml-load-meta">
                        <strong>{s.name}</strong>
                        <span>
                          {s.protocol}
                          {s.fresh ? '' : ' · status gap'}
                          {typeof s.authFails === 'number' && s.authFails > 0 ? ` · ${s.authFails} auth fails` : ''}
                        </span>
                      </div>
                      <div className="ml-load-track">
                        {s.total !== null && (
                          <div className="ml-load-fill" style={{ width: `${Math.max(4, (s.total / maxServerSessions) * 100)}%` }} />
                        )}
                      </div>
                      <div className="ml-load-stats">
                        <b>{s.total === null ? '—' : s.total}</b>
                        <small>CPU {pct(s.cpu)} · RAM {pct(s.ram)}</small>
                      </div>
                    </button>
                  ))}
                  {!perServer.length && <p className="ml-muted">No enrolled collectors yet.</p>}
                </div>
              </div>

              <div className="ml-sess-panel">
                <div className="ml-sess-panel-head">
                  <div>
                    <h3>Active sessions</h3>
                    <p>
                      {filteredSessions.length} shown
                      {longest ? ` · longest ${duration(Math.round(Date.now() / 1000) - longest)}` : ''}
                    </p>
                  </div>
                </div>
                <div className="ml-toolbar">
                  <label className="ml-search">
                    <Search size={15} />
                    <input
                      aria-label="Search sessions"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="Find user, IP, city, server…"
                    />
                  </label>
                  <select aria-label="Server filter" value={serverFilter} onChange={(e) => setServerFilter(e.target.value)}>
                    <option value="all">All servers</option>
                    {perServer.map((s) => (
                      <option key={s.id} value={s.id}>{s.name}</option>
                    ))}
                  </select>
                  <select aria-label="Sort sessions" value={sortKey} onChange={(e) => setSortKey(e.target.value as SortKey)}>
                    <option value="traffic">Sort: traffic</option>
                    <option value="duration">Sort: duration</option>
                    <option value="identity">Sort: identity</option>
                    <option value="server">Sort: server</option>
                  </select>
                </div>

                <div className="ml-session-list">
                  {filteredSessions.map((entry, i) => {
                    const rx = entry.row.bytes_received
                    const tx = entry.row.bytes_sent
                    const vpn = entry.metric.vpn_observation
                    const key = `${entry.id}-${entry.row.client_id}-${entry.row.connection_number}-${i}`
                    const selectedKey = selected
                      ? `${selected.id}-${selected.row.client_id}-${selected.row.connection_number}`
                      : ''
                    const thisKey = `${entry.id}-${entry.row.client_id}-${entry.row.connection_number}`
                    return (
                      <button
                        key={key}
                        type="button"
                        className={`ml-session-row ${selectedKey === thisKey ? 'on' : ''}`}
                        onClick={() => setSelected(entry)}
                      >
                        <div className="ml-session-id">
                          <strong>{entry.identity}</strong>
                          <span>
                            {entry.server}
                            {vpn?.protocol ? ` · ${vpn.protocol}` : ''}
                          </span>
                        </div>
                        <div className="ml-session-geo">
                          <span className="ml-chip">{entry.location || '—'}</span>
                          <span className="ml-mono">
                            {entry.row.public_ip || '—'}
                            {entry.row.public_ip && (
                              <i
                                role="presentation"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  copyText(entry.row.public_ip!)
                                }}
                              >
                                <Copy size={11} />
                              </i>
                            )}
                          </span>
                          <span className="ml-mono muted">{entry.row.vpn_ip || '—'}</span>
                        </div>
                        <div className="ml-session-age">
                          <em>{duration(entry.row.connected_since_unix ?? null)}</em>
                          <small>connected</small>
                        </div>
                        <div className="ml-session-traffic">
                          <div className="ml-traffic-bar">
                            <div style={{ width: `${Math.max(3, (entry.traffic / maxTraffic) * 100)}%` }} />
                          </div>
                          <span>↓ {size(rx)} · ↑ {size(tx)}</span>
                        </div>
                      </button>
                    )
                  })}
                  {!filteredSessions.length && (
                    <p className="ml-muted">No verified active sessions match this filter.</p>
                  )}
                </div>
              </div>
            </div>

            <aside className="ml-sess-side">
              <div className="ml-sess-panel">
                <div className="ml-sess-panel-head">
                  <div>
                    <h3>Session detail</h3>
                    <p>Selected connection context</p>
                  </div>
                  {selected && (
                    <button type="button" className="ml-icon-btn" aria-label="Clear selection" onClick={() => setSelected(null)}>
                      <X size={15} />
                    </button>
                  )}
                </div>
                {selected ? (
                  <div className="ml-detail">
                    <div className="ml-detail-hero">
                      <strong>{selected.identity}</strong>
                      <span>{selected.server}</span>
                    </div>
                    <dl className="ml-detail-grid">
                      <div><dt>Public IP</dt><dd className="ml-mono">{selected.row.public_ip || '—'}</dd></div>
                      <div><dt>VPN IP</dt><dd className="ml-mono">{selected.row.vpn_ip || '—'}</dd></div>
                      <div><dt>Location</dt><dd>{selected.location || '—'}</dd></div>
                      <div><dt>Connected</dt><dd>{duration(selected.row.connected_since_unix ?? null)}</dd></div>
                      <div><dt>Received</dt><dd>{size(selected.row.bytes_received)}</dd></div>
                      <div><dt>Sent</dt><dd>{size(selected.row.bytes_sent)}</dd></div>
                      <div><dt>Protocol</dt><dd>{selected.metric.vpn_observation?.protocol || selected.metric.sessions.data?.protocol || '—'}</dd></div>
                      <div><dt>Host CPU / RAM</dt><dd>{pct(selected.metric.vpn_observation?.cpu_percent)} / {pct(selected.metric.vpn_observation?.memory_used_percent)}</dd></div>
                      <div><dt>Status age</dt><dd>{typeof selected.metric.sessions.data?.status_age_seconds === 'number' ? `${selected.metric.sessions.data.status_age_seconds}s` : '—'}</dd></div>
                      <div><dt>Collector</dt><dd>{stateLabel[selected.metric.status] || selected.metric.status}</dd></div>
                    </dl>
                    {onOpenServer && (
                      <button type="button" className="ml-open-server" onClick={() => onOpenServer(selected.id)}>
                        Open Server 360 <ArrowUpRight size={14} />
                      </button>
                    )}
                  </div>
                ) : (
                  <p className="ml-muted">Select a session row to inspect identity, traffic and host context.</p>
                )}
              </div>

              <div className="ml-sess-panel">
                <div className="ml-sess-panel-head">
                  <div>
                    <h3>Geography</h3>
                    <p>Active sessions by location label</p>
                  </div>
                </div>
                <div className="ml-geo-list">
                  {geoBuckets.map(([name, count]) => (
                    <div key={name} className="ml-geo-row">
                      <span>{name}</span>
                      <div className="ml-geo-track">
                        <div style={{ width: `${Math.max(8, (count / Math.max(1, knownTotal)) * 100)}%` }} />
                      </div>
                      <b>{count}</b>
                    </div>
                  ))}
                  {!geoBuckets.length && <p className="ml-muted">No geo-resolved sessions yet.</p>}
                </div>
              </div>

              <div className="ml-sess-panel">
                <div className="ml-sess-panel-head">
                  <div>
                    <h3>Observed churn</h3>
                    <p>Snapshot-inferred appear / disappear — not logout reasons</p>
                  </div>
                  <span className="ml-mini">{events.length}</span>
                </div>
                <div className="ml-timeline">
                  {events.slice(0, 40).map((e) => (
                    <div key={e.id} className={`ml-timeline-item ${e.event}`}>
                      <span className="ml-timeline-dot" />
                      <div>
                        <strong>{e.event === 'appeared' ? 'Appeared' : 'Disappeared'}</strong>
                        <span>{e.username_or_common_name}</span>
                        <small>{e.server_name} · {ageText(e.observed_at_utc)}</small>
                      </div>
                    </div>
                  ))}
                  {!events.length && <p className="ml-muted">No transition events in the recent window.</p>}
                </div>
              </div>
            </aside>
          </div>
        </>
      )}

      {view === 'alerts' && (
        <>
          <h3>Open incidents ({openIncidents.length})</h3>
          <div className="ml-grid">
            {incidents.map((i) => (
              <article key={i.id} className="ml-card">
                <div className="ml-server">
                  <strong>{i.server_name}</strong>
                  <span className={`ml-tag ${i.state === 'resolved' ? 'ml-tag-green' : 'ml-tag-warn'}`}>{i.state}</span>
                </div>
                <p>{i.code.replace(/_/g, ' ')}</p>
                <small>Opened: {ageText(i.opened_at_utc)} · Updated: {ageText(i.last_seen_at_utc)}</small>
              </article>
            ))}
            {!incidents.length && (
              <p className="ml-muted">No incident records available. This does not confirm that every server is healthy.</p>
            )}
          </div>
        </>
      )}
    </section>
  )
}
