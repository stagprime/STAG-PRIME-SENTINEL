import { useState } from 'react'
import { AlertTriangle, ArrowRight, CheckCircle2, ClipboardCopy, Clock3, LockKeyhole, ShieldCheck, Workflow } from 'lucide-react'
import './SetupPlanPanel.css'

export type SetupPlan = {
  version: number
  status: 'blocked' | 'needs_discovery' | 'review_required' | 'monitoring_prepared'
  template: string
  title: string
  summary: string
  evidence: string
  source_state: 'success' | 'error' | 'stale' | 'not_tested'
  status_access: 'readable' | 'permission_required' | 'status_unavailable' | 'unverified'
  service_verified: boolean
  tunnel_verified: boolean
  potential_impact: string
  maintenance_window_review: boolean
  administrator_approval_required: true
  remote_execution_enabled: false
  blockers: string[]
  actions: { code: string; title: string; guidance: string; impact: 'read_only' | 'review' }[]
}

const statusNames: Record<SetupPlan['status'], string> = {
  blocked: 'ACTION BLOCKED',
  needs_discovery: 'NEEDS DISCOVERY',
  review_required: 'ADMIN REVIEW NEEDED',
  monitoring_prepared: 'MONITORING CANDIDATE',
}

export default function SetupPlanPanel({ plan, serverName, onOpenInstall }: {
  plan?: SetupPlan | null
  serverName: string
  onOpenInstall: () => void
}) {
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState(false)

  const copyPlan = async () => {
    if (!plan) return
    const lines = [
      `Stag Prime Sentinel — Advisory Setup Plan: ${serverName}`,
      `Plan: ${plan.title}`,
      `Status: ${statusNames[plan.status]}`,
      `Evidence: ${plan.evidence}`,
      `Change impact: ${plan.potential_impact}`,
      `Administrator approval required: Yes`,
      `Remote execution available: No`,
      '',
      ...plan.actions.map((action, i) => `${i + 1}. ${action.title}\n   ${action.guidance}`),
      '',
      'This is an advisory plan, NOT an approval or a script to run.',
    ]
    try {
      await navigator.clipboard.writeText(lines.join('\n'))
      setCopied(true)
      setCopyError(false)
    } catch {
      setCopied(false)
      setCopyError(true)
    }
  }

  if (!plan || plan.version !== 1 || !Array.isArray(plan.actions)) {
    return <section className="setup-plan" aria-label="Automatic setup plan">
      <div className="setup-plan-heading"><div><span className="tiny-label">STEP 37.12 / AUTOMATED SETUP PLANNER</span><h4>Setup plan not available</h4></div><LockKeyhole size={19}/></div>
      <p className="setup-plan-subtitle">Install the updated Backend and reload the onboarding page. Remote changes remain disabled.</p>
    </section>
  }

  return <section className="setup-plan" aria-label="Advisory automated server setup plan">
    <div className="setup-plan-heading">
      <div><span className="tiny-label">STEP 37.12 / AUTOMATED SETUP PLANNER</span><h4>Recommended setup plan</h4></div>
      <span className={'setup-plan-status ' + plan.status}>{plan.status === 'monitoring_prepared' ? <CheckCircle2 size={14}/> : <AlertTriangle size={14}/>} {statusNames[plan.status]}</span>
    </div>
    <div className="setup-plan-summary">
      <span className="setup-plan-round"><Workflow size={23}/></span>
      <div><h5>{plan.title}</h5><p>{plan.summary}</p></div>
    </div>
    <div className="setup-plan-metadata">
      <div><span><ShieldCheck size={15}/> CHANGE AUTHORIZATION</span><strong>Admin approval required</strong></div>
      <div><span><Clock3 size={15}/> MAINTENANCE IMPACT</span><strong>{plan.maintenance_window_review ? 'Review maintenance window' : 'No remote changes planned'}</strong></div>
      <div><span><LockKeyhole size={15}/> REMOTE EXECUTION</span><strong>Disabled · planning only</strong></div>
    </div>
    <p className="setup-plan-evidence">{plan.evidence}. Cached discovery: <strong>{plan.source_state.replaceAll('_', ' ')}</strong>. File access: <strong>{plan.status_access.replaceAll('_', ' ')}</strong>.</p>
    <div className="setup-plan-content-heading"><span>RECOMMENDED ACTIONS</span><small>{plan.actions.length} review steps · no commands executed</small></div>
    <ol className="setup-plan-actions">
      {plan.actions.map((action, index) => <li key={`${index}-${action.code}`}>
        <div className="setup-plan-num">{String(index + 1).padStart(2, '0')}</div>
        <div><strong>{action.title}</strong><p>{action.guidance}</p></div>
        <span className={'setup-plan-action-tag ' + (action.impact === 'read_only' ? 'read' : '')}>{action.impact === 'read_only' ? 'READ ONLY' : 'REVIEW'}</span>
      </li>)}
    </ol>
    {plan.blockers.length > 0 && <div className="setup-plan-blockers"><AlertTriangle size={17}/><div><strong>Safety & authorization gates</strong><p>{plan.blockers.join(' · ')}</p></div></div>}
    <div className="setup-plan-footer">
      <p><LockKeyhole size={13}/> No automatic SSH, sudo, installation, firewall change or VPN restart can be initiated here.</p>
      <div>
        <button type="button" className="setup-plan-btn secondary" onClick={() => { void copyPlan() }}><ClipboardCopy size={14}/> {copied ? 'Copied' : copyError ? 'Copy unavailable' : 'Copy advisory plan'}</button>
        <button type="button" className="setup-plan-btn primary" onClick={onOpenInstall}>Open CE handbook <ArrowRight size={15}/></button>
      </div>
    </div>
  </section>
}
