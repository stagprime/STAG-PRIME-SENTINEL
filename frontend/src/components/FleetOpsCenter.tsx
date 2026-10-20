/**
 * Stag Prime Sentinel — Fleet Ops command center.
 * Live VPN users, auth failures, issues→fixes, service control.
 * Server enrollment lives only in Server Inventory (single professional entry).
 */
import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, ArrowRight, CheckCircle2, Copy,
  RefreshCw, Search, Server, UsersRound, Wrench,
} from 'lucide-react'
import {
  controlVpnUser, executeVpnControl, getFleetOps,
} from '../api/fleetOps'
import type { FleetOpsResponse, FleetServerRow, FleetSession } from '../api/fleetOps'
import { geoLabel, useGeoLabels } from '../hooks/useGeoLabels'
import './FleetOpsCenter.css'

type Props = {
  isAdmin: boolean
  onOpenServer: (id: string) => void
  onGoInventory?: () => void
}
type Tab = 'attention' | 'sessions' | 'servers'

const severityClass: Record<string, string> = {
  high: 'fo-sev-high', medium: 'fo-sev-med', low: 'fo-sev-low',
}

function fmtBytes(n?: number | null) {
  if (typeof n !== 'number' || !Number.isFinite(n) || n < 0) return null
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(2)} GB`
}

function sessionAge(since?: string | number | null) {
  if (since == null || since === '') return null
  let ms: number | null = null
  if (typeof since === 'number') ms = since > 1e12 ? since : since * 1000
  else {
    const parsed = Date.parse(since)
    if (!Number.isNaN(parsed)) ms = parsed
    else {
      const asNum = Number(since)
      if (Number.isFinite(asNum)) ms = asNum > 1e12 ? asNum : asNum * 1000
    }
  }
  if (ms == null) return null
  const sec = Math.max(0, Math.floor((Date.now() - ms) / 1000))
  if (sec < 60) return `${sec}s`
  if (sec < 3600) return `${Math.floor(sec / 60)}m`
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`
  return `${Math.floor(sec / 86400)}d`
}

function protoLabel(p?: string | null) {
  if (!p) return '—'
  if (p === 'ikev2') return 'IKEv2'
  if (p === 'wireguard') return 'WireGuard'
  if (p === 'openvpn') return 'OpenVPN'
  return p
}

export default function FleetOpsCenter({ isAdmin, onOpenServer, onGoInventory }: Props) {
  const [data, setData] = useState<FleetOpsResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  const [secondsLeft, setSecondsLeft] = useState(15)
  const [busyAction, setBusyAction] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('sessions')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [protoFilter, setProtoFilter] = useState('all')

  useEffect(() => {
    const ctrl = new AbortController()
    setLoading(true)
    getFleetOps(ctrl.signal)
      .then((payload) => {
        if (!ctrl.signal.aborted) {
          setData(payload)
          setError(null)
          setLoading(false)
          setSecondsLeft(15)
        }
      })
      .catch((err) => {
        if (!ctrl.signal.aborted) {
          setError(err instanceof Error ? err.message : 'Fleet ops unavailable')
          setLoading(false)
        }
      })
    return () => ctrl.abort()
  }, [tick])

  useEffect(() => {
    const refresh = window.setInterval(() => setTick((n) => n + 1), 15_000)
    const countdown = window.setInterval(() => setSecondsLeft((s) => (s <= 1 ? 15 : s - 1)), 1000)
    return () => {
      window.clearInterval(refresh)
      window.clearInterval(countdown)
    }
  }, [])

  const summary = data?.summary
  const workerOk = data?.worker?.status === 'running'
  const servers = data?.servers || []

  const sessionIpList = servers.flatMap((row) =>
    (row.active_sessions || []).map((s) => s.public_ip).filter(Boolean) as string[],
  )
  const geo = useGeoLabels(sessionIpList)

  const attention = useMemo(() => {
    const rows: Array<{
      server: FleetServerRow
      code: string
      title: string
      severity: string
      summary: string
      solution: string
    }> = []
    for (const server of servers) {
      for (const issue of server.issues || []) {
        rows.push({
          server,
          code: issue.code,
          title: issue.title,
          severity: issue.severity,
          summary: issue.summary,
          solution: issue.solution,
        })
      }
    }
    const rank = { high: 0, medium: 1, low: 2 } as Record<string, number>
    return rows.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9))
  }, [servers])

  const sessions = useMemo(() => {
    const q = search.trim().toLowerCase()
    const rows: Array<{ server: FleetServerRow; session: FleetSession; key: string }> = []
    for (const server of servers) {
      if (statusFilter !== 'all' && (server.status || '') !== statusFilter) continue
      if (protoFilter !== 'all' && (server.protocol || '') !== protoFilter) continue
      const list = server.active_sessions?.length
        ? server.active_sessions
        : (server.connected_users
          ? [{ common_name: `(${server.connected_users} connected — waiting for names)` }]
          : [])
      for (let i = 0; i < list.length; i++) {
        const session = list[i]
        const hay = [
          server.server_name, server.protocol, session.common_name, session.username,
          session.public_ip, session.vpn_ip,
          session.public_ip ? geoLabel(geo, session.public_ip) : '',
        ].join(' ').toLowerCase()
        if (q && !hay.includes(q)) continue
        rows.push({ server, session, key: `${server.server_id}-${i}-${session.common_name || session.username}` })
      }
    }
    return rows
  }, [servers, search, statusFilter, protoFilter, geo])

  const serverCards = useMemo(() => {
    const q = search.trim().toLowerCase()
    return servers.filter((s) => {
      if (statusFilter !== 'all' && (s.status || '') !== statusFilter) return false
      if (protoFilter !== 'all' && (s.protocol || '') !== protoFilter) return false
      if (!q) return true
      const hay = [s.server_name, s.status, s.protocol, ...(s.issues || []).map((i) => i.title)].join(' ').toLowerCase()
      return hay.includes(q)
    })
  }, [servers, search, statusFilter, protoFilter])

  async function runControl(server: FleetServerRow, action: 'vpn-start' | 'vpn-stop' | 'vpn-restart') {
    if (!isAdmin) return
    const label = `${action}:${server.server_id}`
    setBusyAction(label)
    setNotice(null)
    try {
      const result = await executeVpnControl(server.server_id, action)
      setNotice(result.message)
      setTick((n) => n + 1)
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'VPN control failed')
    } finally {
      setBusyAction(null)
    }
  }

  async function runUserAction(server: FleetServerRow, action: 'kick' | 'block' | 'unblock', session: FleetSession) {
    if (!isAdmin) return
    const identity = (session.common_name || session.username || '').trim()
    if (!identity || identity.startsWith('(')) {
      setNotice('No identity on this session to control')
      return
    }
    const label = `${action}:${server.server_id}:${identity}`
    setBusyAction(label)
    setNotice(null)
    try {
      const result = await controlVpnUser(server.server_id, action, identity)
      setNotice(result.message)
      setTick((n) => n + 1)
    } catch (err) {
      setNotice(err instanceof Error ? err.message : 'User control failed')
    } finally {
      setBusyAction(null)
    }
  }

  function copyText(value: string) {
    void navigator.clipboard?.writeText(value).then(() => setNotice(`Copied ${value}`))
  }

  const byProto = summary?.connected_by_protocol || {}

  return (
    <div className="fo-root">
      <div className="fo-top">
        <div className="fo-top-copy">
          <h2>Fleet Ops</h2>
          <p>
            Live NOC board — who is online, where they connect from, failed logins,
            broken services, and one-click fixes. New servers are added only from Server Inventory.
          </p>
        </div>
        <div className="fo-top-actions">
          <span className={`fo-pill ${workerOk ? 'ok' : 'off'}`}>
            <i /> Worker {workerOk ? 'running' : 'offline'}
          </span>
          <span className="fo-pill muted">Refresh in {secondsLeft}s</span>
          <button type="button" className="fo-btn ghost" onClick={() => setTick((n) => n + 1)}>
            <RefreshCw size={14} /> Refresh
          </button>
          {onGoInventory && (
            <button type="button" className="fo-btn ghost" onClick={onGoInventory}>
              Server Inventory <ArrowRight size={14} />
            </button>
          )}
        </div>
      </div>

      {notice && <div className="fo-notice" role="status">{notice}</div>}
      {error && <div className="fo-error" role="alert">{error}</div>}

      <div className="fo-metrics">
        <div className="fo-metric good">
          <em>Online now</em>
          <strong>{summary?.connected_users ?? '—'}</strong>
          <span>Verified sessions</span>
        </div>
        <div className="fo-metric warn">
          <em>Auth fails</em>
          <strong>{summary?.failed_auth_observations ?? 0}</strong>
          <span>Last hour logs</span>
        </div>
        <div className="fo-metric">
          <em>Fleet</em>
          <strong>{summary?.enrolled_servers ?? 0}</strong>
          <span>Enrolled servers</span>
        </div>
        <div className="fo-metric bad">
          <em>Issues</em>
          <strong>{summary?.open_issue_signals ?? 0}</strong>
          <span>Open signals</span>
        </div>
        <div className="fo-metric">
          <em>OpenVPN</em>
          <strong>{byProto.openvpn ?? 0}</strong>
          <span>Connected</span>
        </div>
        <div className="fo-metric">
          <em>WG · IKEv2</em>
          <strong>{(byProto.wireguard ?? 0) + (byProto.ikev2 ?? 0)}</strong>
          <span>{byProto.wireguard ?? 0} WG · {byProto.ikev2 ?? 0} IKEv2</span>
        </div>
      </div>

      <div className="fo-tabs" role="tablist">
        <button type="button" className={`fo-tab ${tab === 'sessions' ? 'on' : ''}`} onClick={() => setTab('sessions')}>
          <UsersRound size={13} /> Sessions
          <span className="fo-badge">{sessions.length}</span>
        </button>
        <button type="button" className={`fo-tab ${tab === 'attention' ? 'on' : ''} ${attention.length ? 'alert' : ''}`} onClick={() => setTab('attention')}>
          <AlertTriangle size={13} /> Attention
          <span className="fo-badge">{attention.length}</span>
        </button>
        <button type="button" className={`fo-tab ${tab === 'servers' ? 'on' : ''}`} onClick={() => setTab('servers')}>
          <Server size={13} /> Servers
          <span className="fo-badge">{serverCards.length}</span>
        </button>
      </div>

      <div className="fo-toolbar">
        <label className="fo-search">
          <Search size={15} />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={tab === 'sessions' ? 'Find user, IP, city, server…' : 'Find server or issue…'}
            aria-label="Search fleet ops"
          />
        </label>
        <select aria-label="Health filter" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="all">All health</option>
          {['healthy', 'degraded', 'unreachable', 'stale', 'worker_offline', 'not_enrolled'].map((s) => (
            <option key={s} value={s}>{s.replaceAll('_', ' ')}</option>
          ))}
        </select>
        <select aria-label="Protocol filter" value={protoFilter} onChange={(e) => setProtoFilter(e.target.value)}>
          <option value="all">All protocols</option>
          <option value="openvpn">OpenVPN</option>
          <option value="wireguard">WireGuard</option>
          <option value="ikev2">IKEv2</option>
        </select>
      </div>

      {tab === 'attention' && (
        <section className="fo-board">
          <div className="fo-board-head">
            <h3>Needs attention</h3>
            <span>Highest severity first · guided fix per signal</span>
          </div>
          {attention.length === 0 ? (
            <div className="fo-empty"><CheckCircle2 size={16} /> No open issue signals right now.</div>
          ) : (
            <div className="fo-attention">
              {attention.map((row) => (
                <div key={`${row.server.server_id}-${row.code}`} className={`fo-attention-row ${row.severity === 'high' ? 'high' : ''}`}>
                  <strong>
                    <button type="button" className="fo-link" onClick={() => onOpenServer(row.server.server_id)}>
                      {row.server.server_name || row.server.server_id.slice(0, 8)}
                    </button>
                    <div className="fo-muted">{row.title}</div>
                  </strong>
                  <span>
                    {row.summary}
                    <em style={{ display: 'flex', gap: 5, marginTop: 4, color: '#0f766e', fontStyle: 'normal' }}>
                      <Wrench size={12} /> {row.solution}
                    </em>
                  </span>
                  <em>{row.severity}</em>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      {tab === 'sessions' && (
        <section className="fo-board">
          <div className="fo-board-head">
            <h3>Connected users</h3>
            <span>Kick / block · geo · session age · traffic</span>
          </div>
          <div className="fo-table-wrap">
            <table className="fo-table">
              <thead>
                <tr>
                  <th>Server</th>
                  <th>User / CN</th>
                  <th>Public IP</th>
                  <th>Location</th>
                  <th>VPN IP</th>
                  <th>Age</th>
                  <th>Traffic</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(({ server, session, key }) => {
                  const identity = session.common_name || session.username || '—'
                  const age = sessionAge(session.connected_since)
                  const rx = fmtBytes(session.bytes_received)
                  const tx = fmtBytes(session.bytes_sent)
                  return (
                    <tr key={key}>
                      <td>
                        <button type="button" className="fo-link" onClick={() => onOpenServer(server.server_id)}>
                          {server.server_name || server.server_id.slice(0, 8)}
                        </button>
                        <div><span className="fo-proto-tag">{protoLabel(server.protocol)}</span></div>
                      </td>
                      <td><strong>{identity}</strong></td>
                      <td className="fo-mono">
                        {session.public_ip || '—'}
                        {session.public_ip && (
                          <button type="button" className="fo-copy" title="Copy IP" onClick={() => copyText(session.public_ip!)}>
                            <Copy size={11} />
                          </button>
                        )}
                      </td>
                      <td>{session.public_ip ? geoLabel(geo, session.public_ip) : '—'}</td>
                      <td className="fo-mono">{session.vpn_ip || '—'}</td>
                      <td>{age || '—'}</td>
                      <td>
                        {rx || tx ? (
                          <>
                            <span className="fo-bw">↓ {rx || '—'}</span>
                            <span className="fo-bw">↑ {tx || '—'}</span>
                          </>
                        ) : '—'}
                      </td>
                      <td>
                        {isAdmin && identity !== '—' && !String(identity).startsWith('(') ? (
                          <div className="fo-controls">
                            {(['kick', 'block', 'unblock'] as const).map((action) => (
                              <button
                                key={action}
                                type="button"
                                className={`fo-mini ${action === 'block' ? 'danger' : ''}`}
                                disabled={!!busyAction}
                                onClick={() => void runUserAction(server, action, session)}
                              >
                                {busyAction?.startsWith(`${action}:${server.server_id}:`) ? '…' : action}
                              </button>
                            ))}
                          </div>
                        ) : (
                          <span className="fo-muted">—</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
                {!loading && sessions.length === 0 && (
                  <tr><td colSpan={8} className="fo-empty">No connected users match this filter.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {tab === 'servers' && (
        <section className="fo-board">
          <div className="fo-board-head">
            <h3>Server command cards</h3>
            <span>{loading ? 'Loading…' : `${serverCards.length} in view`}</span>
          </div>
          {serverCards.length === 0 ? (
            <div className="fo-empty">
              No enrolled servers yet.
              {onGoInventory && (
                <> Use <button type="button" className="fo-link" onClick={onGoInventory}>Server Inventory → Add server</button>.</>
              )}
            </div>
          ) : (
            <div className="fo-server-grid">
              {serverCards.map((row) => (
                <article key={row.server_id} className={`fo-server-card ${(row.issues?.length || 0) > 0 ? 'has-issue' : ''}`}>
                  <div className="fo-server-top">
                    <div>
                      <h4>
                        <button type="button" className="fo-link" onClick={() => onOpenServer(row.server_id)}>
                          {row.server_name || row.server_id.slice(0, 8)}
                        </button>
                      </h4>
                      <div className="fo-server-meta">
                        <span className={`fo-status fo-status-${row.status || 'muted'}`}>{row.status || 'unknown'}</span>
                        <span className="fo-proto-tag">{protoLabel(row.protocol)}</span>
                      </div>
                    </div>
                    {isAdmin && (
                      <div className="fo-controls">
                        {(['vpn-start', 'vpn-restart', 'vpn-stop'] as const).map((action) => (
                          <button
                            key={action}
                            type="button"
                            className={`fo-mini ${action === 'vpn-stop' ? 'danger' : ''}`}
                            disabled={!!busyAction}
                            onClick={() => void runControl(row, action)}
                          >
                            {busyAction === `${action}:${row.server_id}` ? '…' : action.replace('vpn-', '')}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="fo-server-stats">
                    <div><em>Users</em><strong>{row.connected_users ?? '—'}</strong></div>
                    <div><em>Auth fail</em><strong>{row.failed_auth_observations ?? 0}</strong></div>
                    <div><em>Issues</em><strong>{row.issues?.length ?? 0}</strong></div>
                  </div>
                  {(row.issues?.length || 0) === 0 ? (
                    <span className="fo-muted" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', color: '#15803d', fontWeight: 650 }}>
                      <CheckCircle2 size={14} /> No open signals
                    </span>
                  ) : (
                    <ul className="fo-issue-list">
                      {row.issues.map((issue) => (
                        <li key={issue.code} className={severityClass[issue.severity] || ''}>
                          <strong>{issue.title}</strong>
                          <p>{issue.summary}</p>
                          <em><Wrench size={12} /> {issue.solution}</em>
                        </li>
                      ))}
                    </ul>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  )
}
