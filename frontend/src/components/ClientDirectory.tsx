import { useEffect, useState } from 'react'
import { Building2, Plus, RotateCcw, X, Save, ShieldCheck } from 'lucide-react'
import { createClient, fetchClients, updateClient } from '../api/clientDirectory'
import type { ClientDirectoryEntry } from '../api/clientDirectory'
import './ClientDirectory.css'

export default function ClientDirectory({isAdmin,onChange}: {isAdmin:boolean;onChange:()=>void}){
  const [clients,setClients]=useState<ClientDirectoryEntry[]>([])
  const [loading,setLoading]=useState(true)
  const [error,setError]=useState<string|null>(null)
  const [message,setMessage]=useState<string|null>(null)
  const [editing,setEditing]=useState<ClientDirectoryEntry|null|undefined>(undefined)
  const [name,setName]=useState('')
  const [email,setEmail]=useState('')
  const [saving,setSaving]=useState(false)
  const [revision,setRevision]=useState(0)
  useEffect(()=>{
    let cancelled=false
    setLoading(true)
    fetchClients().then(data=>{if(!cancelled){setClients(data.clients);setError(null)}})
      .catch(e=>{if(!cancelled)setError(e instanceof Error?e.message:'Client data unavailable')})
      .finally(()=>{if(!cancelled)setLoading(false)})
    return()=>{cancelled=true}
  },[revision])
  function open(item:ClientDirectoryEntry|null){setEditing(item);setName(item?.name||'');setEmail(item?.contact_email||'');setError(null);setMessage(null)}
  async function save(){
    if(!isAdmin||saving)return
    setSaving(true);setError(null);setMessage(null)
    try{
      if(editing){await updateClient(editing.id,{name,contact_email:email.trim()||null});setMessage('Client details updated.')}
      else{await createClient({name,contact_email:email.trim()||null});setMessage('Client created; ready to assign servers in Inventory.')}
      setEditing(undefined);setRevision(n=>n+1);onChange()
    }catch(e){setError(e instanceof Error?e.message:'Could not save client')}
    finally{setSaving(false)}
  }
  return <section className="sc-directory">
    <div className="sc-header"><div><span className="ml-eyebrow">STAG PRIME SENTINEL / CLIENT DIRECTORY</span><h2>Managed client organizations</h2><p>Live records from FastAPI. Client IDs and existing server ownership are preserved.</p></div><div className="sc-actions">
      <button className="btn-secondary" type="button" onClick={()=>setRevision(n=>n+1)}><RotateCcw size={16}/> Refresh</button>
      {isAdmin&&<button className="btn-primary" type="button" onClick={()=>open(null)}><Plus size={16}/> Add client</button>}
    </div></div>
    {error&&<p className="sc-error" role="alert">{error}</p>}
    {message&&<p className="sc-success" role="status">{message}</p>}
    {loading&&<p role="status">Loading client directory…</p>}
    <div className="sc-list">{clients.map(item=><article className="sc-item" key={item.id}>
      <Building2 size={22}/><div className="sc-detail"><strong>{item.name}</strong><small>{item.contact_email||'No contact email'} · {item.active_servers} active server(s)</small></div>
      {isAdmin&&<button type="button" className="btn-secondary" onClick={()=>open(item)}>Edit details</button>}
    </article>)}</div>
    {!loading&&!clients.length&&<p className="sc-empty">No client organizations are visible to your account.</p>}
    <p className="sc-note"><ShieldCheck size={16}/> Deletion is intentionally unavailable: client removal requires an audited transfer of servers, account grants and security records.</p>
    {editing!==undefined&&<div className="sc-backdrop" role="presentation" onClick={()=>!saving&&setEditing(undefined)}>
      <div className="sc-dialog" role="dialog" aria-modal="true" aria-label={editing?'Edit client':'Add client'} onClick={e=>e.stopPropagation()}>
        <div className="sc-dialog-head"><h3>{editing?'Edit client details':'Register new client'}</h3><button type="button" aria-label="Close" disabled={saving} onClick={()=>setEditing(undefined)}><X size={20}/></button></div>
        <label>Organization name<input value={name} maxLength={150} autoFocus onChange={e=>setName(e.target.value)}/></label>
        <label>Contact email (optional)<input value={email} maxLength={255} type="email" onChange={e=>setEmail(e.target.value)}/></label>
        <p>Server ownership and account permissions will not be changed by editing this organization.</p>
        <div className="sc-actions"><button className="btn-secondary" disabled={saving} onClick={()=>setEditing(undefined)}>Cancel</button><button className="btn-primary" disabled={saving||name.trim().length<2} onClick={()=>void save()}><Save size={15}/>{saving?'Saving…':'Save client'}</button></div>
        {error&&<p className="sc-error" role="alert">{error}</p>}
      </div>
    </div>}
  </section>
}
