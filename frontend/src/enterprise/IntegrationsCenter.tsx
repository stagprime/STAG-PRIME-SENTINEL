import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Bell, CheckCircle2, Clock3, Cloud, RefreshCw, Webhook } from 'lucide-react'
import { clearAlertWebhook, fetchIntegrationStatus, saveAlertWebhook, type IntegrationStatus } from '../api/platform'
import './EnterpriseWorkspace.css'

function time(iso: string | null | undefined) {
  if (!iso) return '—'
  const date = new Date(iso)
  return Number.isNaN(date.valueOf()) ? 'Unknown' : date.toLocaleString()
}

export default function IntegrationsCenter() {
  const [status, setStatus] = useState<IntegrationStatus | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    const ctrl = new AbortController()
    setLoading(true)
    fetchIntegrationStatus()
      .then(data => {
        if (ctrl.signal.aborted) return
        setStatus(data)
        setError(null)
        setLoading(false)
      })
      .catch(err => {
        if (ctrl.signal.aborted) return
        setError(err instanceof Error ? err.message : 'Integrations API unavailable')
        setStatus(null)
        setLoading(false)
      })
    return () => ctrl.abort()
  }, [tick])

  async function save(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      await saveAlertWebhook(url.trim())
      setUrl('')
      setNotice('Webhook saved. The full address stays on the server and is not shown again.')
      setTick(n => n + 1)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save webhook')
    } finally {
      setBusy(false)
    }
  }

  async function clear() {
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      await clearAlertWebhook()
      setNotice('Saved webhook file cleared.')
      setTick(n => n + 1)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not clear webhook')
    } finally {
      setBusy(false)
    }
  }

  const webhook = status?.webhook
  return <div className="ent-workspace">
    <div className="ent-page">
      <div className="ent-cap-hero">
        <div className="ent-cap-icon"><Cloud size={27}/></div>
        <div>
          <span className="ent-kicker">PLATFORM / ALERT DELIVERY</span>
          <h2>Integrations</h2>
          <p>In-app incidents stay in Sentinel. Open incidents can also POST to one https webhook. Email, Telegram, and Slack apps are not connected.</p>
        </div>
        <span className="ent-feature-state">{webhook?.configured ? 'Webhook on' : 'Webhook off'}</span>
      </div>
      {error && <div role="alert" className="ent-error">{error}</div>}
      {notice && <div role="status" className="ent-note"><CheckCircle2 size={16}/>{notice}</div>}
      <div className="ent-two-col">
        <section className="ent-panel">
          <div className="ent-panel-head"><div><h2>Delivery channels</h2><p>What this deployment can send today</p></div></div>
          <div className="ent-list-check">
            <div><Bell size={17}/> In-app incidents and the notification bell</div>
            <div><Webhook size={17}/> HTTPS webhook {webhook?.configured ? `· ${webhook.masked}` : '· not configured'}</div>
          </div>
          <div className="ent-list-pending">
            <div><Clock3 size={16}/> Email</div>
            <div><Clock3 size={16}/> Telegram</div>
            <div><Clock3 size={16}/> Slack app</div>
          </div>
          <div className="ent-panel-foot">{status?.note || 'Open incidents are written locally and posted when a webhook is configured.'}</div>
        </section>
        <section className="ent-panel">
          <div className="ent-panel-head"><div><h2>Alert webhook</h2><p>{webhook?.locked_by_env ? 'SENTINEL_ALERT_WEBHOOK is set on the server and overrides a saved URL.' : 'https only. The saved address is masked after save.'}</p></div></div>
          <form className="ent-webhook-form" onSubmit={e => { void save(e) }}>
            <label>
              <span>HTTPS endpoint</span>
              <input value={url} onChange={e => setUrl(e.target.value)} autoComplete="off" spellCheck={false} placeholder="https://hooks.example.com/…" disabled={busy || webhook?.locked_by_env} />
            </label>
            <div className="ent-webhook-actions">
              <button type="submit" className="btn-primary" disabled={busy || webhook?.locked_by_env || !url.trim()}>Save webhook</button>
              <button type="button" className="btn-secondary" disabled={busy || !webhook?.configured || webhook.source === 'environment'} onClick={() => { void clear() }}>Clear saved URL</button>
            </div>
          </form>
          <div className="ent-panel-foot">Current: {loading ? 'Checking…' : webhook?.configured ? `${webhook.masked} (${webhook.source})` : 'No webhook configured'}</div>
        </section>
      </div>
      <section className="ent-panel">
        <div className="ent-panel-head">
          <div><h2>Today’s alert deliveries</h2><p>Local JSONL written when incidents open or close. Webhook POST runs for open incidents only.</p></div>
          <button type="button" className="ent-link" onClick={() => setTick(n => n + 1)}><RefreshCw size={15}/> Reload</button>
        </div>
        {loading && <div className="ent-empty"><strong>Loading deliveries…</strong><p>Reading today’s local alert log.</p></div>}
        {!loading && (status?.recent.length ?? 0) > 0 && <div className="ent-table-scroll"><table className="ent-table"><thead><tr><th>WHEN</th><th>STATE</th><th>SERVER</th><th>CODE</th><th>DETAIL</th></tr></thead><tbody>
          {status!.recent.map((row, index) => <tr key={`${row.at_utc}-${row.server_id}-${index}`}>
            <td>{time(row.at_utc)}</td>
            <td><span className={`ent-chip ${row.state === 'open' ? 'ent-chip-warn' : 'ent-chip-muted'}`}>{row.state}</span></td>
            <td>{row.server_name}</td>
            <td><strong>{row.code.replaceAll('_', ' ')}</strong></td>
            <td><small>{row.detail || '—'}</small></td>
          </tr>)}
        </tbody></table></div>}
        {!loading && !(status?.recent.length) && <div className="ent-empty"><strong>No deliveries recorded today</strong><p>New open and resolved incidents appear here after the monitoring worker writes them.</p></div>}
      </section>
    </div>
  </div>
}
