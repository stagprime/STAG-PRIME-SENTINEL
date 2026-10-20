import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, ArrowRight, BookOpen, Check, CheckCircle2, ChevronLeft,
  ChevronRight, CircleHelp, Copy, ExternalLink, Filter,
  KeyRound, LockKeyhole, MonitorDown, Search, Server, Settings2, ShieldCheck,
  Terminal, Wrench, X,
} from 'lucide-react'
import { GUIDE_STEPS, HELP_ITEMS, OFFICIAL_LINKS, type GuideBlock, type CommandKind, type RiskLevel } from './InstallationHandbookData'
import './InstallationCenter.css'

type VariableKey = 'VPN_CLIENT_ID' | 'VPN_USERNAME' | 'SERVER_PUBLIC_IP' | 'SSH_HOST' | 'SSH_USERNAME' | 'PPK_PATH' | 'WINDOWS_DEST' | 'AUTH_MODE'
type TabName = 'handbook' | 'troubleshooting'
const DEFAULT_VALUES: Record<VariableKey, string> = {
  VPN_CLIENT_ID: 'client-device-01',
  VPN_USERNAME: 'vpnuser01',
  SERVER_PUBLIC_IP: '',
  SSH_HOST: '',
  SSH_USERNAME: 'ubuntu',
  PPK_PATH: 'D:\\keys\\server-key.ppk',
  WINDOWS_DEST: 'D:\\VPN-Profiles',
  AUTH_MODE: 'certificate',
}
const VARIABLE_FIELDS: {name: VariableKey; label: string; help: string}[] = [
  {name:'VPN_CLIENT_ID',label:'VPN Client / Device ID',help:'Certificate Common Name; unique per device'},
  {name:'VPN_USERNAME',label:'VPN Login Username (PAM only)',help:'Only if PAM Password Mode enabled'},
  {name:'SERVER_PUBLIC_IP',label:'OpenVPN public IP / DNS',help:'The IP clients connect to; not private 10.0.0.x'},
  {name:'SSH_HOST',label:'SSH Host / Bastion address',help:'Use the address PuTTY reaches'},
  {name:'SSH_USERNAME',label:'SSH Linux username',help:'e.g. ubuntu, tariq; must have approved access'},
  {name:'PPK_PATH',label:'Windows PuTTY private key path',help:'Local path only. Do not upload key content.'},
  {name:'WINDOWS_DEST',label:'Windows download folder',help:'Folder where .ovpn file is downloaded'},
]
const TOKEN_RE = /\{\{([A-Z_]+)\}\}/g
function valid(name: VariableKey, value: string): boolean {
  if (name === 'AUTH_MODE') return value === 'certificate' || value === 'pam'
  if (name === 'VPN_CLIENT_ID' || name === 'VPN_USERNAME') return /^[A-Za-z][A-Za-z0-9_-]{1,39}$/.test(value)
  if (name === 'SSH_USERNAME') return /^[a-z_][a-z0-9_-]{0,31}$/.test(value)
  if (name === 'SERVER_PUBLIC_IP' || name === 'SSH_HOST') return /^(?=.{3,253}$)[A-Za-z0-9][A-Za-z0-9.-]*$/.test(value) && !value.includes('..')
  if (name === 'PPK_PATH' || name === 'WINDOWS_DEST') return /^[A-Za-z]:\\[A-Za-z0-9_.\- \\/]*$/.test(value) && !value.includes('!')
  return false
}
function renderCommand(source: string, values: Record<VariableKey, string>): {code: string; missing: VariableKey[]} {
  const missing: VariableKey[] = []
  const code = source.replace(TOKEN_RE, (_, token: string) => {
    const key = token as VariableKey
    if (!(key in values) || !valid(key, values[key])) {
      if (!missing.includes(key)) missing.push(key)
      return `{{${token}}}`
    }
    return values[key]
  })
  return {code, missing}
}
const KIND_LABEL: Record<CommandKind, string> = {linux:'Ubuntu VPS · PuTTY', windows:'Windows PC · CMD',config:'Configuration text · Editor only',information:'Reference only'}
const RISK_LABEL: Record<RiskLevel, string> = {read:'READ-ONLY',change:'CHANGES SERVER',sensitive:'SECURITY-SENSITIVE',reference:'DO NOT EXECUTE'}
function CommandCard({block, variables}: {block: GuideBlock; variables: Record<VariableKey,string>}) {
  const [copied,setCopied] = useState(false)
  const {code,missing} = useMemo(()=>renderCommand(block.code, variables),[block.code,variables])
  const kind = block.kind ?? 'linux'
  const risk = block.risk ?? 'read'
  async function copy() {
    if (missing.length) return
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      window.setTimeout(()=>setCopied(false),1700)
    } catch {
      setCopied(false)
      window.alert('Clipboard permission denied. Select the text and copy manually.')
    }
  }
  return <article className="install-command-card">
    <div className="install-code-heading">
      <div className="install-code-headcopy">
        <strong><Terminal size={15}/> {block.title}</strong>
        <p>{block.detail}</p>
      </div>
      <button type="button" className="install-copy" disabled={missing.length>0} title={missing.length ? 'Complete the highlighted fields to enable copy' : 'Copy command'} onClick={()=>{void copy()}}>
        {copied ? <Check size={15}/> : <Copy size={15}/>} {copied?'Copied':'Copy'}
      </button>
    </div>
    <div className="install-code-tags"><span>{KIND_LABEL[kind]}</span><span className={'install-risk risk-'+risk}>{RISK_LABEL[risk]}</span></div>
    <pre tabIndex={0}><code>{code}</code></pre>
    {missing.length>0 && <p className="install-need-field"><AlertTriangle size={15}/> Copy করার আগে Personalization-এ পূরণ করো: {missing.join(', ')}</p>}
    {block.note && <p className="install-note"><CheckCircle2 size={15}/>{block.note}</p>}
  </article>
}

function loadReviewed(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem('sentinel-kb-reviewed')
    const parsed = raw ? JSON.parse(raw) as Record<string, unknown> : {}
    const next: Record<string, boolean> = {}
    for (const [key, value] of Object.entries(parsed)) if (value === true) next[key] = true
    return next
  } catch { return {} }
}
function loadVariables(): Record<VariableKey, string> {
  const next = { ...DEFAULT_VALUES }
  try {
    const raw = localStorage.getItem('sentinel-kb-vars')
    const parsed = raw ? JSON.parse(raw) as Partial<Record<VariableKey, string>> : {}
    for (const field of VARIABLE_FIELDS) {
      if (field.name === 'PPK_PATH') continue
      const value = parsed[field.name]
      if (typeof value === 'string') next[field.name] = value
    }
    if (parsed.AUTH_MODE === 'certificate' || parsed.AUTH_MODE === 'pam') next.AUTH_MODE = parsed.AUTH_MODE
  } catch { /* keep defaults */ }
  return next
}
export default function InstallationCenter() {
  const [tab,setTab] = useState<TabName>('handbook')
  const [active,setActive] = useState(0)
  const [reviewed,setReviewed] = useState<Record<string,boolean>>(loadReviewed)
  const [variables,setVariables] = useState<Record<VariableKey,string>>(loadVariables)
  useEffect(() => {
    try { localStorage.setItem('sentinel-kb-reviewed', JSON.stringify(reviewed)) } catch { /* private browsing */ }
  }, [reviewed])
  useEffect(() => {
    const stored = { ...variables, PPK_PATH: '' }
    try { localStorage.setItem('sentinel-kb-vars', JSON.stringify(stored)) } catch { /* private browsing */ }
  }, [variables])
  const [showVars,setShowVars] = useState(true)
  const [query,setQuery] = useState('')
  const [category,setCategory] = useState('All topics')
  const [openedHelp,setOpenedHelp] = useState<string | null>(null)
  const step = GUIDE_STEPS[active]
  const complete = Object.values(reviewed).filter(Boolean).length
  const allCategories = ['All topics',...Array.from(new Set(HELP_ITEMS.map(item=>item.area)))]
  const filteredHelp = HELP_ITEMS.filter(item=>(category==='All topics' || category===item.area) &&
    `${item.issue} ${item.cause} ${item.fix} ${item.area}`.toLowerCase().includes(query.trim().toLowerCase()))
  function chooseStep(index: number) {setTab('handbook'); setActive(index)}
  return <div className="install-center install-v2">
    <section className="install-hero">
      <div className="install-hero-content">
        <span className="install-kicker"><BookOpen size={15}/> STAG PRIME SENTINEL / COMMUNITY EDITION HANDBOOK</span>
        <h2>Install with confidence.<br/><span>Support every server.</span></h2>
        <p>OpenVPN Community Edition · Ubuntu 24.04 LTS · Individual Device IDs · Optional PAM Login · Secure Windows Profile Download · Practical Troubleshooting</p>
        <div className="install-hero-stats"><span><Server size={15}/> {GUIDE_STEPS.length} practical chapters</span><span><CircleHelp size={15}/> {HELP_ITEMS.length} troubleshooting topics</span><span><Terminal size={15}/> copy-ready instructions</span></div>
      </div>
      <div className="install-hero-icon"><ShieldCheck size={68} strokeWidth={1.25}/><span>DEPLOYMENT<br/>KNOWLEDGE BASE</span></div>
    </section>

    <div className="install-mode-tabs" role="tablist" aria-label="Installation center mode">
      <button type="button" role="tab" aria-selected={tab==='handbook'} className={tab==='handbook'?'selected':''} onClick={()=>setTab('handbook')}><BookOpen size={18}/> Step-by-step installation <span>{GUIDE_STEPS.length} chapters</span></button>
      <button type="button" role="tab" aria-selected={tab==='troubleshooting'} className={tab==='troubleshooting'?'selected':''} onClick={()=>setTab('troubleshooting')}><Wrench size={18}/> Common issues & solutions <span>{HELP_ITEMS.length} articles</span></button>
    </div>

    <section className="install-warning"><AlertTriangle size={20}/><div><strong>Operator handbook — not a remote auto-installer.</strong><p>Commands run only when an authorized admin copies them. Do not use Fresh VPS commands on running EU-01 / EU-02 / MENA-01. Keep CA/SSH private keys, `.ovpn`, passwords and credentials out of browser forms, chat and logs. Changes to a production VPN require backup, approval and maintenance window.</p></div></section>

    <section className="install-variables">
      <div className="install-variables-top"><div><span className="install-section-label">LOCAL PERSONALIZATION</span><h3><Settings2 size={20}/> Where to put your User ID, IP and SSH key path</h3><p>Non-secret fields stay in this browser so commands stay filled in. The PuTTY key path is kept only for this visit and is not written to storage.</p></div><button type="button" className="install-toggle" onClick={()=>setShowVars(s=>!s)} aria-expanded={showVars}>{showVars?'Hide fields':'Edit fields'} <ChevronRight className={showVars?'install-rotate':''} size={16}/></button></div>
      {showVars && <div className="install-variables-body">
        <div className="install-auth-switch"><strong><KeyRound size={16}/> Authentication choice:</strong><label><input type="radio" name="install-auth-mode" checked={variables.AUTH_MODE==='certificate'} onChange={()=>setVariables(s=>({...s,AUTH_MODE:'certificate'}))}/> Certificate only</label><label><input type="radio" name="install-auth-mode" checked={variables.AUTH_MODE==='pam'} onChange={()=>setVariables(s=>({...s,AUTH_MODE:'pam'}))}/> Certificate + PAM Username/Password</label></div>
        <div className="install-variable-grid">{VARIABLE_FIELDS.map(field=><label className="install-variable-field" key={field.name}><span>{field.label}</span><input type="text" autoComplete="off" spellCheck={false} value={variables[field.name]} onChange={e=>setVariables(v=>({...v,[field.name]:e.target.value}))} placeholder={field.help} aria-invalid={Boolean(variables[field.name])&&!valid(field.name,variables[field.name])}/><small>{field.help}</small></label>)}</div>
        <div className="install-vars-hint"><LockKeyhole size={16}/> No password fields. Command Copy is disabled when a required IP/Host/ID/Path is missing or invalid. Review every generated command before running.</div>
      </div>}
    </section>

    {tab==='handbook' ? <div className="install-layout">
      <aside className="install-side">
        <div className="install-side-top"><span>PROVISIONING ROADMAP</span><strong>{complete} / {GUIDE_STEPS.length} reviewed</strong></div>
        <div className="install-progress-track"><div style={{width:`${complete/GUIDE_STEPS.length*100}%`}}/></div>
        <nav className="install-steps" aria-label="OpenVPN installation chapters">
          {GUIDE_STEPS.map((item,index)=><button type="button" key={item.id} onClick={()=>chooseStep(index)} className={'install-step-link'+(index===active?' active':'')} aria-current={index===active?'step':undefined}>
            <span className="install-step-number">{reviewed[item.id]?<Check size={15}/>:String(index+1).padStart(2,'0')}</span>
            <span className="install-step-text"><strong>{item.title}</strong><small>{item.group}</small></span>
            <ChevronRight size={16}/>
          </button>)}
        </nav>
        <div className="install-side-hint"><LockKeyhole size={18}/><p>Reviewed chapters stay in this browser. A checkmark does not install or approve anything on a VPS.</p></div>
      </aside>
      <section className="install-main panel">
        <div className="install-current-heading"><div><span className="install-section-label">{step.group} · CHAPTER {active+1} OF {GUIDE_STEPS.length}</span><h3>{step.title}</h3><h4>{step.subtitle}</h4><p>{step.introduction}</p></div><span className="install-current-icon"><BookOpen size={25}/></span></div>
        <div className="install-command-list">{step.blocks.map((block,index)=><CommandCard key={`${step.id}-${index}`} block={block} variables={variables}/>)}</div>
        <div className="install-insights"><strong><ShieldCheck size={17}/> Important engineering notes</strong>{step.notes.map((note,i)=><p key={i}><span>•</span>{note}</p>)}</div>
        <div className="install-acceptance"><div><span className="install-section-label">OPERATOR CHECKPOINT</span><p>{step.checkpoint}</p></div><label><input type="checkbox" checked={Boolean(reviewed[step.id])} onChange={e=>setReviewed(prev=>({...prev,[step.id]:e.target.checked}))}/> Mark reviewed</label></div>
        <div className="install-step-actions"><button className="btn-secondary" disabled={active===0} onClick={()=>chooseStep(Math.max(active-1,0))}><ChevronLeft size={16}/> Previous</button><span>CHAPTER {active+1} / {GUIDE_STEPS.length}</span><button className="btn-primary" disabled={active===GUIDE_STEPS.length-1} onClick={()=>chooseStep(Math.min(active+1,GUIDE_STEPS.length-1))}>Next chapter <ChevronRight size={16}/></button></div>
      </section>
    </div> : <section className="install-faq-library">
      <div className="install-faq-intro"><div><span className="install-section-label">FIELD SUPPORT / TROUBLESHOOTING BLOG</span><h3><Wrench size={22}/> Common problems & copy-ready solutions</h3><p>সমস্যা, সম্ভাব্য কারণ, করণীয় ও Diagnostic Command—সব এক জায়গায়। Error Message দিয়ে Search করো; Linux/Windows পরিবেশ অনুসরণ করো।</p></div><span>{filteredHelp.length} / {HELP_ITEMS.length} articles</span></div>
      <div className="install-faq-filters"><label className="install-search"><Search size={18}/><input placeholder="Search: AUTH_FAILED, .ovpn, Permission, MTU, Oracle, DNS..." value={query} onChange={e=>setQuery(e.target.value)} />{query&&<button type="button" onClick={()=>setQuery('')} aria-label="Clear search"><X size={16}/></button>}</label><label className="install-category"><Filter size={16}/><select value={category} onChange={e=>setCategory(e.target.value)}>{allCategories.map(x=><option key={x} value={x}>{x}</option>)}</select></label></div>
      <div className="install-help-items">{filteredHelp.map((item,index)=>{
        const open=openedHelp===item.id
        return <article className={'install-help-article'+(open?' expanded':'')} key={item.id}>
          <button type="button" className="install-help-toggle" onClick={()=>setOpenedHelp(open?null:item.id)} aria-expanded={open}><span className="install-help-number">{String(index+1).padStart(2,'0')}</span><span className="install-help-title"><small>{item.area}</small><strong>{item.issue}</strong></span><ChevronRight className={open?'install-rotate':''} size={20}/></button>
          {open && <div className="install-help-content"><div><strong>সম্ভাব্য কারণ</strong><p>{item.cause}</p></div><div><strong>সমাধান / নির্দেশনা</strong><p>{item.fix}</p></div>{item.code && <CommandCard block={{title:'Diagnosis / recovery command',detail:'শুধু অনুমোদিত Environment-এ চালাবে। Output-এ Sensitive Information Redact করবে।',code:item.code,kind:item.kind,risk:item.risk}} variables={variables}/>}</div>}
        </article>
      })}{filteredHelp.length===0 && <div className="install-no-results"><CircleHelp size={26}/><strong>No matching topic</strong><p>অন্য Keyword দিয়ে Search করো অথবা Category = All topics রাখো।</p></div>}</div>
    </section>}
    <section className="install-bottom"><div><strong><MonitorDown size={18}/> Live onboarding is a separate page</strong><p>This handbook stays copy-ready guidance. Verify SSH, discover OpenVPN, and enroll the collector from Server Onboarding. This page does not change a server.</p></div><ArrowRight size={21}/></section>
    <div className="install-official"><KeyRound size={17}/><span>Official references</span>{OFFICIAL_LINKS.map(link=><a key={link.url} href={link.url} target="_blank" rel="noopener noreferrer">{link.name}<ExternalLink size={13}/></a>)}</div>
  </div>
}
