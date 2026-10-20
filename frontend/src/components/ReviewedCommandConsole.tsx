import { useEffect, useState } from 'react'
import { ClipboardCheck, Copy, ShieldCheck, Terminal, AlertCircle } from 'lucide-react'
import { csrfHeaders, signalAuthExpired } from '../api/auth'
import './ReviewedCommandConsole.css'

type Check = { check_id: string; label: string; command: string; read_only: boolean; privileged: boolean; requires_preview: boolean }
type Preview = { preview_id: string; server_id: string; check_id: string; label: string; exact_command: string; read_only: true; privileged: boolean; sudo: boolean; required_confirmation: string | null; expires_at_utc: string }
type Run = { run_id: string; server_id: string; check_id: string; status: 'succeeded' | 'failed'; result: Record<string, string | number | boolean> | null; failure_category: string | null; audit_recorded: boolean; privileged: boolean; sudo_used: boolean }

async function api<T>(url: string, method: 'GET' | 'POST', body?: object): Promise<T> {
  const res = await fetch(url, { method, credentials: 'same-origin', cache: 'no-store',
    headers: { ...csrfHeaders(method), ...(body ? {'Content-Type':'application/json'} : {}) },
    ...(body ? {body:JSON.stringify(body)} : {}) })
  if (res.status === 401) signalAuthExpired()
  if (!res.ok) throw new Error(`HTTP ${res.status} — command was not confirmed; review SSH verification and approval`)
  return await res.json() as T
}

export default function ReviewedCommandConsole({serverId,ready}:{serverId:string;ready:boolean}) {
  const [checks,setChecks]=useState<Check[]>([])
  const [chosen,setChosen]=useState('identity_uid')
  const [preview,setPreview]=useState<Preview | null>(null)
  const [approved,setApproved]=useState(false)
  const [privilegedText,setPrivilegedText]=useState('')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [result,setResult]=useState<Run|null>(null)
  useEffect(()=>{
    let cancelled=false
    api<{checks:Check[]}>('/api/server-operations/command-runner/catalog','GET')
      .then(d=>{if (!cancelled) setChecks(d.checks.filter(x=>x.read_only && x.requires_preview))})
      .catch(()=>{if (!cancelled) setError('Read-only command catalog unavailable.')})
    return ()=>{cancelled=true}
  },[])
  const selected=checks.find(x=>x.check_id===chosen)
  async function makePreview() {
    setPreview(null);setApproved(false);setPrivilegedText('');setResult(null);setError('')
    if(!ready || !selected) return
    setBusy(true)
    try {
      const r=await api<Preview>(`/api/server-operations/servers/${encodeURIComponent(serverId)}/command-runner/preview`,'POST',{check_id:selected.check_id})
      if(r.server_id!==serverId || r.check_id!==selected.check_id || r.read_only!==true || r.exact_command!==selected.command || r.privileged!==selected.privileged) throw new Error('Preview identity or command mismatch')
      setPreview(r)
    } catch(e) {setError(e instanceof Error ? e.message : 'Preview failed')}
    finally {setBusy(false)}
  }
  async function runApproved() {
    if(!preview || !approved || busy || preview.server_id!==serverId || (preview.privileged && privilegedText!==preview.required_confirmation) || new Date(preview.expires_at_utc).getTime()<Date.now()) return
    const requested=preview
    setBusy(true);setError('');setPreview(null);setApproved(false);setPrivilegedText('')
    try {
      const r=await api<Run>(`/api/server-operations/servers/${encodeURIComponent(serverId)}/command-runner/execute`,'POST',{preview_id:requested.preview_id,approve:true,...(requested.privileged?{privileged_confirmation:privilegedText}:{})})
      if(r.server_id!==serverId || r.check_id!==requested.check_id || !r.audit_recorded) throw new Error('Server or audit response mismatch')
      setResult(r)
    } catch(e) {setError(e instanceof Error?e.message:'Audited command failed; verify history before retry')}
    finally {setBusy(false)}
  }
  const expired=preview ? new Date(preview.expires_at_utc).getTime()<Date.now() : false
  return <section className="rc-panel" aria-label="Reviewed read-only command runner">
    <header className="rc-header"><div><div className="rc-kicker">STEP 40.10-E.4 / SCOPED SUDO DIAGNOSTIC</div>
      <h3><Terminal size={19}/> Preview → Approve → Run</h3>
      <p>Server-bound one-time approval. Only a fixed sudo root-identity proof is permitted; no general shell, install, VPN/firewall writes or repair commands.</p></div><span>READ ONLY</span></header>
    <div className="rc-body">
      <label htmlFor="rc-choice">Choose a backend-approved command</label>
      <select id="rc-choice" value={chosen} disabled={busy} onChange={e=>{setChosen(e.target.value);setPreview(null);setApproved(false);setPrivilegedText('');setResult(null);setError('')}}>
        {checks.map(c=><option key={c.check_id} value={c.check_id}>{c.label}</option>)}
      </select>
      <div className="rc-code"><code>{selected?.command??'Loading available commands…'}</code><button type="button" disabled={!selected} onClick={()=>void navigator.clipboard.writeText(selected?.command??'')} aria-label="Copy fixed command"><Copy size={15}/></button></div>
      <div className="rc-buttons"><button type="button" disabled={!ready || !selected || busy} onClick={()=>void makePreview()}><ClipboardCheck size={16}/> {busy?'Please wait…':'Review command'}</button></div>
      {preview && <div className="rc-preview" role="region" aria-label="Server command approval">
        <strong><ShieldCheck size={17}/> Confirm exact reviewed command</strong>
        <p>Selected server ID: <code>{serverId}</code></p><p>Command: <code>{preview.exact_command}</code></p>
        <p>One use only · expires {new Date(preview.expires_at_utc).toLocaleTimeString()} · {preview.privileged ? 'SUDO elevation for fixed read-only identity proof only; may use vault-backed SSH password.' : 'No privilege escalation.'}</p>
        <label className="rc-checkbox"><input type="checkbox" checked={approved} onChange={e=>setApproved(e.target.checked)}/> I approve this exact {preview.privileged ? "privileged read-only" : "read-only"} command on the selected server.</label>
        {preview.privileged && <div className="rc-sudo-confirm">
          <strong>Privileged action: sudo will be invoked on this VPS.</strong>
          <label htmlFor="rc-sudo-phrase">Type <code>{preview.required_confirmation}</code> to authorize one use.</label>
          <input id="rc-sudo-phrase" value={privilegedText} autoComplete="off" spellCheck={false} onChange={e=>setPrivilegedText(e.target.value)}/>
        </div>}
        <button type="button" disabled={!approved||busy||expired||(preview.privileged&&privilegedText!==preview.required_confirmation)} onClick={()=>void runApproved()}>{expired?'Preview expired — review again':busy?'Executing…':'Approve and run once'}</button>
      </div>}
      {result && <div className="rc-result" role="status"><strong>Audited run: {result.status.toUpperCase()}</strong>
        <pre>{result.status==='succeeded' && result.result ? Object.entries(result.result).map(([k,v])=>`${k}: ${v}`).join('\n') : `Failure category: ${result.failure_category||'COMMAND_RESULT_UNAVAILABLE'}\nReview host trust, SSH access and diagnostic status.`}</pre>
        <small>Run ID: {result.run_id} · {result.privileged ? 'Sudo proof only · ' : ''}Read only · structured, bounded output</small></div>}
      {error && <p className="rc-error" role="alert"><AlertCircle size={16}/> {error}</p>}
      {!ready && <p className="rc-error">An approved administrative credential and fresh SSH verification are required before execution.</p>}
    </div>
  </section>
}
