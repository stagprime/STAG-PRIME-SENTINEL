import { useEffect, useState } from 'react'
import { Activity, Download, RefreshCw, FileBarChart2 } from 'lucide-react'
import { getMonitoringReport, downloadMonitoringReport } from '../api/monitoring'
import type { MonitoringReport } from '../api/monitoring'
import './MonitoringReports.css'

const percent = (n: number | null) => n === null ? '—' : `${n.toFixed(1)}%`
const number = (n: number | null) => n === null ? '—' : String(n)

export default function MonitoringReports() {
  const [hours, setHours] = useState<1 | 6 | 24>(24)
  const [result, setResult] = useState<MonitoringReport | null>(null)
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    const ctrl = new AbortController()
    setBusy(true)
    setResult(null)
    getMonitoringReport(hours, ctrl.signal)
      .then(data => { if (!ctrl.signal.aborted) { setResult(data); setError(null) } })
      .catch(err => { if (!ctrl.signal.aborted) setError(err instanceof Error ? err.message : 'Report API unavailable') })
      .finally(() => { if (!ctrl.signal.aborted) setBusy(false) })
    return () => ctrl.abort()
  }, [hours, revision])
  async function exportCsv() {
    setBusy(true)
    try { await downloadMonitoringReport(hours); setError(null) }
    catch (err) { setError(err instanceof Error ? err.message : 'Could not export report') }
    finally { setBusy(false) }
  }
  return <section className="mr-wrap">
    <div className="mr-heading">
      <div><span className="ml-eyebrow">STAG PRIME SENTINEL / HISTORICAL REPORTING</span>
        <h2>Verified monitoring reports</h2>
        <p>Client-scoped historical SSH observations; no fresh SSH connection is triggered by this page.</p></div>
      <div className="mr-actions">
        <label htmlFor="report-hours">Window</label>
        <select id="report-hours" value={hours} disabled={busy} onChange={e => setHours(Number(e.target.value) as 1 | 6 | 24)}>
          <option value={1}>Last hour</option><option value={6}>Last 6 hours</option><option value={24}>Last 24 hours</option>
        </select>
        <button type="button" className="btn-secondary" disabled={busy} onClick={() => setRevision(v => v + 1)}><RefreshCw size={15}/> Refresh</button>
        <button type="button" className="btn-primary" disabled={busy || !result} onClick={() => void exportCsv()}><Download size={15}/> Download CSV</button>
      </div>
    </div>
    {error && <p className="mr-error" role="alert">Report error: {error}. No metrics were fabricated.</p>}
    {busy && <p role="status">Loading verified snapshot history…</p>}
    {result && <>
      <div className="mr-summary"><Activity size={18}/> {result.servers.length} visible servers · Generated {new Date(result.generated_at_utc).toLocaleString()} · Window {result.period_hours}h</div>
      <div className="mr-table-wrap"><table className="mr-table">
        <thead><tr><th>Server</th><th>VPN Samples</th><th>Peak observed</th><th>Avg. connections</th><th>Health Samples</th><th>Avg. CPU</th><th>Avg. RAM</th><th>Avg. Disk</th><th>Incidents opened</th></tr></thead>
        <tbody>{result.servers.map(s => <tr key={s.server_id}>
          <td><strong>{s.server_name}</strong><small>{s.server_id}</small></td>
          <td>{s.session_samples}</td><td>{number(s.peak_observed_connections)}</td><td>{number(s.average_observed_connections)}</td>
          <td>{s.health_samples}</td><td>{percent(s.average_cpu_percent)}</td><td>{percent(s.average_ram_percent)}</td>
          <td>{percent(s.average_disk_percent)}</td><td>{s.incidents_opened}</td>
        </tr>)}</tbody>
      </table></div>
      {!result.servers.length && <div className="mr-empty"><FileBarChart2 size={20}/> No authorized active servers to report.</div>}
      <p className="mr-caption">{result.note} Missing readings are shown as —, never as zero connected users. Snapshot history is bounded by collection retention.</p>
    </>}
  </section>
}
