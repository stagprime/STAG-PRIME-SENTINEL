import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, ArrowUpRight, BellRing, CheckCircle2, Clock3, Info,
  RefreshCw, Search, Server, Wrench, X,
} from 'lucide-react'
import { getMonitoringIncidents } from '../api/monitoring'
import type { Incident, IncidentSummary } from '../api/monitoring'
import './EnterpriseIncidents.css'

type Props = { onOpenServer?: (serverId: string) => void }
type Severity = 'high' | 'medium' | 'low' | 'critical'

const sevRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }

function fmt(v: string | null | undefined) {
  if (!v) return '—'
  const d = new Date(v)
  return Number.isNaN(d.valueOf()) ? '—' : d.toLocaleString()
}

function ageLabel(iso: string | null | undefined) {
  if (!iso) return '—'
  const ms = Date.now() - new Date(iso).getTime()
  if (!Number.isFinite(ms) || ms < 0) return fmt(iso)
  const m = Math.floor(ms / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function titleOf(i: Incident) {
  return i.title || i.code.replaceAll('_', ' ')
}

export default function EnterpriseIncidents({ onOpenServer }: Props) {
  const [rows, setRows] = useState<Incident[] | null>(null)
  const [summary, setSummary] = useState<IncidentSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState<'all' | 'open' | 'resolved'>('open')
  const [severity, setSeverity] = useState<'all' | Severity>('all')
  const [serverFilter, setServerFilter] = useState('all')
  const [selected, setSelected] = useState<Incident | null>(null)

  useEffect(() => {
    const ctrl = new AbortController()
    getMonitoringIncidents(ctrl.signal)
      .then((res) => {
        if (!ctrl.signal.aborted) {
          setRows(res.incidents)
          setSummary(res.summary ?? null)
          setError(null)
        }
      })
      .catch((e) => {
        if (!ctrl.signal.aborted) setError(e instanceof Error ? e.message : 'Incident API unavailable')
      })
    return () => ctrl.abort()
  }, [revision])

  const servers = useMemo(() => {
    const map = new Map<string, string>()
    for (const i of rows || []) map.set(i.server_id, i.server_name)
    return [...map.entries()].sort((a, b) => a[1].localeCompare(b[1]))
  }, [rows])

  const list = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (rows || [])
      .filter((i) => {
        if (status !== 'all' && i.state !== status) return false
        if (severity !== 'all' && (i.severity || 'medium') !== severity) return false
        if (serverFilter !== 'all' && i.server_id !== serverFilter) return false
        if (!q) return true
        return [i.code, i.server_name, i.server_id, i.title, i.summary, i.solution]
          .join(' ').toLowerCase().includes(q)
      })
      .sort((a, b) => {
        if (a.state !== b.state) return a.state === 'open' ? -1 : 1
        const sr = (sevRank[b.severity || 'medium'] || 0) - (sevRank[a.severity || 'medium'] || 0)
        if (sr) return sr
        return new Date(b.last_seen_at_utc).getTime() - new Date(a.last_seen_at_utc).getTime()
      })
  }, [rows, query, status, severity, serverFilter])

  const openHigh = (summary?.high_open ?? 0) + (summary?.critical_open ?? 0)
  const byServer = useMemo(() => {
    const map = new Map<string, { name: string; open: number; high: number }>()
    for (const i of (rows || []).filter((x) => x.state === 'open')) {
      const cur = map.get(i.server_id) || { name: i.server_name, open: 0, high: 0 }
      cur.open += 1
      if ((i.severity || '') === 'high' || i.severity === 'critical') cur.high += 1
      map.set(i.server_id, cur)
    }
    return [...map.entries()].sort((a, b) => b[1].open - a[1].open || b[1].high - a[1].high).slice(0, 8)
  }, [rows])

  return (
    <div className="ent-incidents">
      <div className="ent-inc-summary">
        <div><BellRing size={18} /><span>Recorded</span><strong>{rows?.length ?? '—'}</strong></div>
        <div><AlertTriangle size={18} /><span>Active open</span><strong>{summary?.open ?? (rows ? rows.filter((i) => i.state === 'open').length : '—')}</strong></div>
        <div><Server size={18} /><span>Servers affected</span><strong>{summary?.affected_servers ?? '—'}</strong><em>{openHigh} high severity open</em></div>
        <div><CheckCircle2 size={18} /><span>Resolved</span><strong>{summary?.resolved ?? (rows ? rows.filter((i) => i.state === 'resolved').length : '—')}</strong></div>
      </div>

      <div className="ent-inc-layout">
        <section className="ent-inc-panel">
          <header>
            <div>
              <h2>Incident command board</h2>
              <p>Severity + fix guidance from collector codes · no fake acknowledgements or escalation</p>
            </div>
            <button type="button" className="btn-secondary" onClick={() => setRevision((v) => v + 1)}>
              <RefreshCw size={15} /> Refresh
            </button>
          </header>

          <div className="ent-inc-filters">
            <label>
              <Search size={16} />
              <input
                placeholder="Search incidents, servers, codes…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Search incidents"
              />
            </label>
            <select value={status} onChange={(e) => setStatus(e.target.value as typeof status)} aria-label="Filter incident status">
              <option value="open">Open</option>
              <option value="resolved">Resolved</option>
              <option value="all">All states</option>
            </select>
            <select value={severity} onChange={(e) => setSeverity(e.target.value as typeof severity)} aria-label="Filter severity">
              <option value="all">All severity</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select value={serverFilter} onChange={(e) => setServerFilter(e.target.value)} aria-label="Filter server">
              <option value="all">All servers</option>
              {servers.map(([id, name]) => (
                <option key={id} value={id}>{name}</option>
              ))}
            </select>
          </div>

          {error && <p role="alert" className="ent-inc-error">{error}</p>}

          {list.length ? (
            <div className="ent-inc-cards">
              {list.map((i) => {
                const sev = (i.severity || 'medium') as string
                return (
                  <article key={i.id} className={`ent-inc-card sev-${sev} state-${i.state}`}>
                    <div className="ent-inc-card-top">
                      <div>
                        <strong>{titleOf(i)}</strong>
                        <small>#{i.id} · {i.code.replaceAll('_', ' ')}</small>
                      </div>
                      <div className="ent-inc-badges">
                        <span className={`ent-inc-sev sev-${sev}`}>{sev}</span>
                        <span className={i.state === 'open' ? 'ent-inc-open' : 'ent-inc-resolved'}>{i.state}</span>
                      </div>
                    </div>
                    <p className="ent-inc-summary-line">{i.summary || 'Recorded monitoring incident.'}</p>
                    <div className="ent-inc-meta">
                      <span><Server size={13} /> {i.server_name}</span>
                      <span><Clock3 size={13} /> Seen {ageLabel(i.last_seen_at_utc)}</span>
                      <span>Opened {fmt(i.opened_at_utc)}</span>
                    </div>
                    {i.solution && (
                      <div className="ent-inc-fix">
                        <Wrench size={14} />
                        <span>{i.solution}</span>
                      </div>
                    )}
                    <div className="ent-inc-actions">
                      <button type="button" onClick={() => setSelected(i)}>Details</button>
                      {onOpenServer && (
                        <button type="button" className="primary" onClick={() => onOpenServer(i.server_id)}>
                          Open server <ArrowUpRight size={13} />
                        </button>
                      )}
                    </div>
                  </article>
                )
              })}
            </div>
          ) : (
            <div className="ent-inc-empty">
              <Info size={21} />
              <strong>{rows ? 'No matching incidents' : 'Checking incident records'}</strong>
              <p>Changing filters does not initiate an SSH command.</p>
            </div>
          )}

          <footer>
            <Info size={15} />
            Severity and fix steps are derived from known incident codes. Operator assignment, notes, and external escalation still need dedicated workflow APIs — this page does not invent them.
          </footer>
        </section>

        <aside className="ent-inc-side">
          <div className="ent-inc-side-panel">
            <h3>Open by code</h3>
            <p>Active incident mix</p>
            <div className="ent-inc-code-list">
              {(summary?.by_code || []).length ? summary!.by_code.map((c) => (
                <button
                  key={c.code}
                  type="button"
                  className="ent-inc-code-row"
                  onClick={() => { setStatus('open'); setQuery(c.code.replaceAll('_', ' ')) }}
                >
                  <span>
                    <b>{c.title}</b>
                    <small>{c.code} · {c.severity}</small>
                  </span>
                  <strong>{c.count}</strong>
                </button>
              )) : <p className="ent-inc-muted">No open incidents in window.</p>}
            </div>
          </div>
          <div className="ent-inc-side-panel">
            <h3>Servers under attention</h3>
            <p>Open incident count</p>
            <div className="ent-inc-code-list">
              {byServer.length ? byServer.map(([id, info]) => (
                <button
                  key={id}
                  type="button"
                  className="ent-inc-code-row"
                  onClick={() => { setServerFilter(id); setStatus('open') }}
                >
                  <span>
                    <b>{info.name}</b>
                    <small>{info.high} high · {info.open} open</small>
                  </span>
                  <strong>{info.open}</strong>
                </button>
              )) : <p className="ent-inc-muted">No open server incidents.</p>}
            </div>
          </div>
        </aside>
      </div>

      {selected && (
        <div className="ent-inc-overlay" onClick={() => setSelected(null)}>
          <aside role="dialog" aria-modal="true" aria-label="Incident details" onClick={(e) => e.stopPropagation()}>
            <div className="ent-inc-drawer-top">
              <strong>INCIDENT #{selected.id}</strong>
              <button type="button" aria-label="Close details" onClick={() => setSelected(null)}><X size={19} /></button>
            </div>
            <div className="ent-inc-badges" style={{ marginTop: 14 }}>
              <span className={`ent-inc-sev sev-${selected.severity || 'medium'}`}>{selected.severity || 'medium'}</span>
              <span className={selected.state === 'open' ? 'ent-inc-open' : 'ent-inc-resolved'}>{selected.state}</span>
            </div>
            <h2>{titleOf(selected)}</h2>
            <p>{selected.summary || 'Verified incident record · no automatic remediation'}</p>
            <dl>
              <dt>Code</dt><dd>{selected.code}</dd>
              <dt>Server</dt><dd>{selected.server_name}</dd>
              <dt>Opened</dt><dd>{fmt(selected.opened_at_utc)}</dd>
              <dt>Last observed</dt><dd>{fmt(selected.last_seen_at_utc)}</dd>
              <dt>Resolved</dt><dd>{fmt(selected.resolved_at_utc)}</dd>
              <dt>Server ID</dt><dd className="ent-inc-monospace">{selected.server_id}</dd>
            </dl>
            {selected.solution && (
              <div className="ent-inc-fix drawer">
                <Wrench size={15} />
                <div>
                  <strong>Suggested fix</strong>
                  <p>{selected.solution}</p>
                </div>
              </div>
            )}
            {onOpenServer && (
              <button type="button" className="ent-inc-open-server" onClick={() => onOpenServer(selected.server_id)}>
                Open Server 360 <ArrowUpRight size={14} />
              </button>
            )}
            <div className="ent-inc-note">
              Viewing this record never starts SSH or changes the remote server. Acknowledgements / assignment need a future workflow API.
            </div>
          </aside>
        </div>
      )}
    </div>
  )
}
