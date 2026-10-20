import { useCallback, useEffect, useMemo, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import {
  Activity, ArrowRight, Building2, Check, CheckCircle2, CircleAlert,
  Eye, EyeOff, FileClock, KeyRound, LockKeyhole, Plus,
  RefreshCcw, Search, Shield, ShieldCheck, ShieldAlert, Trash2, UserCog,
  UserRoundCheck, UsersRound, X,
} from 'lucide-react';
import type { AuthUser, UserRole } from '../api/auth';
import {
  createManagedUser, fetchClientDirectory, fetchManagedUsers, permanentlyDeleteManagedUser,
  fetchSecurityAudit, replaceStaffClientGrants, resetManagedUserPassword,
  updateManagedUser,
} from '../api/users';
import type {
  ClientDirectoryEntry, CreateManagedUser, ManagedUser, SecurityAuditEvent,
} from '../api/users';
import './UserManagementCenter.css';

type Mode = 'directory' | 'audit';
type EditMode = 'create' | 'edit' | 'grants' | 'reset' | 'status' | 'delete' | null;
type FormDraft = {
  username: string;
  display_name: string;
  password: string;
  role: UserRole;
  client_id: string;
  client_ids: string[];
  confirm_admin_access: boolean;
};
const initialDraft = (): FormDraft => ({
  username: '', display_name: '', password: '', role: 'staff',
  client_id: '', client_ids: [], confirm_admin_access: false,
});

function dateText(utc: string): string {
  const date = new Date(utc);
  return Number.isNaN(date.getTime()) ? 'Unknown date' : date.toLocaleString();
}
function readableError(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed. Please try again.';
}
function roleTitle(role: UserRole): string {
  return role === 'admin' ? 'Administrator' : role === 'viewer' ? 'View' : role === 'staff' ? 'Staff' : 'Client';
}
function RoleBadge({ role }: { role: UserRole }) {
  return <span className={`um-role um-role-${role}`}>
    {role === 'admin' ? <ShieldCheck size={13}/> : role === 'viewer' ? <Eye size={13}/> : role === 'staff' ? <UserCog size={13}/> : <Building2 size={13}/>}
    {roleTitle(role)}
  </span>;
}
function Label({ children }: { children: ReactNode }) { return <span className="um-label">{children}</span>; }

export default function UserManagementCenter({ currentUser }: { currentUser: AuthUser }) {
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [clients, setClients] = useState<ClientDirectoryEntry[]>([]);
  const [events, setEvents] = useState<SecurityAuditEvent[]>([]);
  const [tab, setTab] = useState<Mode>('directory');
  const [loading, setLoading] = useState(true);
  const [auditLoading, setAuditLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [query, setQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | UserRole>('all');
  const [editMode, setEditMode] = useState<EditMode>(null);
  const [target, setTarget] = useState<ManagedUser | null>(null);
  const [draft, setDraft] = useState<FormDraft>(initialDraft());
  const [showPassword, setShowPassword] = useState(false);
  const [confirmStatus, setConfirmStatus] = useState(false);
  const [deleteUsername, setDeleteUsername] = useState('');
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteConfirmed, setDeleteConfirmed] = useState(false);

  const refreshDirectory = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [usersResult, clientsResult] = await Promise.all([fetchManagedUsers(), fetchClientDirectory()]);
      setUsers(usersResult.users);
      setClients(clientsResult.clients);
    } catch (err) {
      setError(readableError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshAudit = useCallback(async () => {
    setAuditLoading(true);
    try {
      const result = await fetchSecurityAudit(100);
      setEvents(result.events);
    } catch (err) {
      setError(readableError(err));
    } finally {
      setAuditLoading(false);
    }
  }, []);

  useEffect(() => { void refreshDirectory(); }, [refreshDirectory]);
  useEffect(() => { if (tab === 'audit') void refreshAudit(); }, [tab, refreshAudit]);
  const clientById = useMemo(() => new Map(clients.map(c => [c.id, c.name])), [clients]);
  const usersById = useMemo(() => new Map(users.map(u => [u.id, u])), [users]);
  const filtered = useMemo(() => users.filter(user => {
    if (roleFilter !== 'all' && user.role !== roleFilter) return false;
    const companies = user.role === 'staff'
      ? user.client_ids.map(id => clientById.get(id) ?? '').join(' ')
      : clientById.get(user.client_id ?? '') ?? '';
    return `${user.username} ${user.display_name} ${user.role} ${companies}`.toLowerCase().includes(query.toLowerCase().trim());
  }), [users, roleFilter, query, clientById]);
  const admins = users.filter(u => u.role === 'admin' && u.is_active).length;
  const active = users.filter(u => u.is_active).length;
  const staff = users.filter(u => u.role === 'staff').length;
  const viewers = users.filter(u => u.role === 'viewer').length;
  const clientUsers = users.filter(u => u.role === 'client').length;
  const readOnly = currentUser.role === 'viewer';

  function open(mode: Exclude<EditMode, null>, user: ManagedUser | null = null) {
    setMessage(''); setError(''); setShowPassword(false); setConfirmStatus(false);
    setDeleteUsername(''); setDeletePassword(''); setDeleteConfirmed(false);
    setTarget(user); setEditMode(mode);
    setDraft(user ? {
      username: user.username, display_name: user.display_name, password: '',
      role: user.role, client_id: user.client_id ?? '',
      client_ids: [...user.client_ids], confirm_admin_access: false,
    } : initialDraft());
  }
  function close() {
    if (busy) return;
    setDraft(initialDraft()); setTarget(null); setEditMode(null); setShowPassword(false);
    setConfirmStatus(false); setDeleteUsername(''); setDeletePassword(''); setDeleteConfirmed(false);
  }
  function toggleClient(id: string) {
    setDraft(prev => ({ ...prev, client_ids: prev.client_ids.includes(id)
      ? prev.client_ids.filter(value => value !== id)
      : [...prev.client_ids, id],
    }));
  }
  async function execute(task: () => Promise<unknown>, success: string) {
    setBusy(true); setError(''); setMessage('');
    try {
      await task();
      setDraft(initialDraft()); setTarget(null); setEditMode(null); setShowPassword(false);
      setDeletePassword(''); setDeleteUsername(''); setDeleteConfirmed(false);
      setMessage(success);
      await refreshDirectory();
      if (tab === 'audit') await refreshAudit();
    } catch (err) {
      setError(readableError(err));
    } finally {
      setBusy(false);
    }
  }
  function submitCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (draft.password.length < 14 || draft.password.length > 128) { setError('Password must be 14–128 characters.'); return; }
    if (draft.role === 'client' && !draft.client_id) { setError('Choose an organization for the client account.'); return; }
    if (draft.role === 'admin' && !draft.confirm_admin_access) { setError('Confirm administrator-level access explicitly.'); return; }
    const payload: CreateManagedUser = {
      username: draft.username.trim(), display_name: draft.display_name.trim(),
      password: draft.password, role: draft.role,
      ...(draft.role === 'client' ? { client_id: draft.client_id } : {}),
      ...(draft.role === 'staff' ? { client_ids: draft.client_ids } : {}),
      ...(draft.role === 'admin' ? { confirm_admin_access: true } : {}),
    };
    void execute(() => createManagedUser(payload), `${roleTitle(draft.role)} account created. Share the initial password securely, outside this dashboard.`);
  }
  function submitEdit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!target) return;
    if (draft.role === 'client' && !draft.client_id) { setError('Choose an organization for the client account.'); return; }
    if (draft.role === 'admin' && target.role !== 'admin' && !draft.confirm_admin_access) { setError('Confirm administrator promotion explicitly.'); return; }
    const roleChanged = draft.role !== target.role;
    const data = {
      display_name: draft.display_name.trim(),
      ...(roleChanged ? { role: draft.role } : {}),
      ...(draft.role === 'client' ? { client_id: draft.client_id } : {}),
      ...(roleChanged && draft.role === 'admin' ? { confirm_admin_access: true } : {}),
    };
    void execute(() => updateManagedUser(target.id, data), 'Account updated. Changed sessions were revoked by the backend.');
  }
  function submitGrants(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!target) return;
    void execute(() => replaceStaffClientGrants(target.id, draft.client_ids), 'Client grants updated. Previous staff sessions revoked.');
  }
  function submitReset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!target) return;
    if (draft.password.length < 14 || draft.password.length > 128) { setError('Password must be 14–128 characters.'); return; }
    void execute(() => resetManagedUserPassword(target.id, draft.password), 'Password reset complete. All previous sessions for that user revoked.');
  }
  function submitStatus(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!target || !confirmStatus) return;
    void execute(() => updateManagedUser(target.id, { is_active: !target.is_active }),
      `Account ${target.is_active ? 'disabled' : 'enabled'}.`);
  }

  function submitDelete(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!target || target.id === currentUser.id || target.is_active) return;
    if (deleteUsername !== target.username || !deletePassword || !deleteConfirmed) {
      setError('Exact username, administrator password and confirmation are required.');
      return;
    }
    void execute(() => permanentlyDeleteManagedUser(target.id, deleteUsername, deletePassword),
      'Account permanently deleted. Related sessions and client grants removed.');
  }

  function auditDetail(event: SecurityAuditEvent): string {
    const fields = event.details.fields;
    const role = event.details.role;
    const isActive = event.details.is_active;
    const changed: string[] = [];
    if (Array.isArray(fields)) changed.push('Changed: ' + fields.filter(v => typeof v === 'string').join(', '));
    if (typeof role === 'string') changed.push(`Role: ${role}`);
    if (typeof isActive === 'boolean') changed.push(isActive ? 'Account enabled' : 'Account disabled');
    if (event.action === 'staff_grants_replaced' && Array.isArray(event.details.client_ids)) {
      const ids = event.details.client_ids.filter((id): id is string => typeof id === 'string');
      changed.push(`Client grants: ${ids.length ? ids.map(id => clientById.get(id) ?? 'Unknown organization').join(', ') : 'none'}`);
    }
    return changed.join(' · ');
  }
  function accessDescription(user: ManagedUser) {
    if (user.role === 'admin') return 'All organizations';
    if (user.role === 'viewer') return 'View only · every area';
    if (user.role === 'client') return clientById.get(user.client_id ?? '') ?? 'Organization not found';
    if (user.client_ids.length === 0) return 'No client access';
    const names = user.client_ids.map(id => clientById.get(id) ?? 'Unknown client');
    return names.length > 2 ? `${names.slice(0, 2).join(', ')} +${names.length - 2}` : names.join(', ');
  }
  if (currentUser.role !== 'admin' && currentUser.role !== 'viewer') {
    return <div className="um-panel um-noaccess"><LockKeyhole size={25}/><h2>Administrator access required</h2><p>User Management is protected by the backend.</p></div>;
  }
  return <div className="um-page">
    <section className="um-hero">
      <div><div className="um-kicker"><ShieldCheck size={15}/> STAG PRIME SENTINEL / IDENTITY & ACCESS</div>
        <h2>People. Permissions. <span>Protected infrastructure.</span></h2>
        <p>Control who can sign in, which clients they can access, and review account changes from one secure workspace.</p>
        <div className="um-hero-chips"><span><Shield size={14}/> Backend-enforced access</span><span><LockKeyhole size={14}/> Passwords never displayed</span><span><FileClock size={14}/> Audited changes</span></div>
      </div><div className="um-hero-icon"><UsersRound size={42}/><small>IDENTITY CONTROL</small></div>
    </section>
    <div className="um-summary">
      <div><UsersRound size={19}/><small>Total users</small><strong>{users.length.toString().padStart(2, '0')}</strong><span>Registered accounts</span></div>
      <div><UserRoundCheck size={19}/><small>Active accounts</small><strong>{active.toString().padStart(2, '0')}</strong><span>Enabled for sign in</span></div>
      <div><ShieldCheck size={19}/><small>Active admins</small><strong>{admins.toString().padStart(2, '0')}</strong><span>Protected from lockout</span></div>
      <div><Building2 size={19}/><small>Staff / view / client</small><strong>{staff} / {viewers} / {clientUsers}</strong><span>{clients.length} organizations in registry</span></div>
    </div>
    <div className="um-panel">
      <div className="um-panel-head">
        <div><Label>SECURE ACCESS CONTROL</Label><h3>User directory</h3><p>Manage authorized accounts without exposing passwords, tokens or SSH credentials.</p></div>
        <div className="um-panel-actions">
          <button className="um-outline" type="button" onClick={() => { void refreshDirectory(); if (tab === 'audit') void refreshAudit(); }} disabled={loading || busy}><RefreshCcw size={16}/> Refresh</button>
          {!readOnly && <button className="um-primary" type="button" onClick={() => open('create')}><Plus size={17}/> Create user</button>}
        </div>
      </div>
      <div className="um-tabs" role="tablist" aria-label="User administration">
        <button type="button" role="tab" aria-selected={tab === 'directory'} className={tab === 'directory' ? 'selected' : ''} onClick={() => setTab('directory')}><UsersRound size={16}/> Accounts</button>
        <button type="button" role="tab" aria-selected={tab === 'audit'} className={tab === 'audit' ? 'selected' : ''} onClick={() => setTab('audit')}><FileClock size={16}/> Security audit</button>
      </div>
      {message && <div className="um-feedback success" role="status"><CheckCircle2 size={17}/>{message}<button aria-label="Dismiss success message" onClick={() => setMessage('')}><X size={16}/></button></div>}
      {error && <div className="um-feedback error" role="alert"><CircleAlert size={17}/>{error}<button aria-label="Dismiss error message" onClick={() => setError('')}><X size={16}/></button></div>}
      {tab === 'directory' ? <>
        <div className="um-toolbar">
          <div className="um-search"><Search size={17}/><input aria-label="Search users" placeholder="Search name, username or client..." value={query} onChange={e => setQuery(e.target.value)}/></div>
          <select aria-label="Filter account role" value={roleFilter} onChange={e => setRoleFilter(e.target.value as typeof roleFilter)}><option value="all">All roles</option><option value="admin">Administrators</option><option value="viewer">View</option><option value="staff">Staff</option><option value="client">Clients</option></select>
          <span className="um-results">{filtered.length} of {users.length} accounts</span>
        </div>
        <div className="um-table-wrap"><table className="um-table"><thead><tr><th>ACCOUNT</th><th>ROLE</th><th>ORGANIZATION ACCESS</th><th>STATUS</th><th>MANAGE</th></tr></thead><tbody>
          {!loading && filtered.map(user => <tr key={user.id}><td><div className="um-person"><div className="um-avatar">{(user.display_name || user.username).slice(0, 1).toUpperCase()}</div><div><strong>{user.display_name}</strong><small>@{user.username}{user.id === currentUser.id ? ' · You' : ''}</small></div></div></td>
            <td><RoleBadge role={user.role}/></td><td><div className="um-access" title={accessDescription(user)}>{accessDescription(user)}</div>{user.role === 'staff' && <small>{user.client_ids.length} explicit client grant{user.client_ids.length === 1 ? '' : 's'}</small>}</td>
            <td><span className={`um-status ${user.is_active ? 'on' : 'off'}`}><i/>{user.is_active ? 'Active' : 'Disabled'}</span></td>
            <td><div className="um-actions">{readOnly ? <span>View only</span> : <><button type="button" onClick={() => open('edit', user)} title={`Edit ${user.username}`}><UserCog size={15}/> Edit</button>
              {user.role === 'staff' && <button type="button" onClick={() => open('grants', user)} title="Assign client access"><Building2 size={15}/> Grants</button>}
              {user.id !== currentUser.id && <button type="button" onClick={() => open('reset', user)} title="Reset password"><KeyRound size={15}/> Reset</button>}
              {user.id !== currentUser.id && <button type="button" onClick={() => open('status', user)} title={user.is_active ? 'Disable account' : 'Enable account'}>{user.is_active ? <LockKeyhole size={15}/> : <Check size={15}/>} {user.is_active ? 'Disable' : 'Enable'}</button>}
              {user.id !== currentUser.id && !user.is_active && <button className="um-delete-button" type="button" onClick={() => open('delete', user)} title={`Permanently delete ${user.username}`}><Trash2 size={15}/> Delete</button>}
            </>}</div></td></tr>)}
          {!loading && filtered.length === 0 && <tr><td colSpan={5} className="um-empty">No accounts match the current filters.</td></tr>}
          {loading && <tr><td colSpan={5} className="um-empty">Loading accounts from the protected API…</td></tr>}
        </tbody></table></div>
        <p className="um-table-note"><ShieldCheck size={15}/> Account and grant changes revoke affected sessions. Staff have no client access unless explicitly granted.</p>
      </> : <div className="um-audit">
        <div className="um-audit-header"><div><strong>Security audit trail</strong><p>Latest 100 account-management events; metadata only, no passwords or tokens.</p></div><button type="button" className="um-outline" disabled={auditLoading} onClick={() => void refreshAudit()}><RefreshCcw size={15}/> Refresh events</button></div>
        {auditLoading ? <p className="um-empty">Loading audit events…</p> : events.length === 0 ? <p className="um-empty">No recorded account changes yet.</p> : <div className="um-audit-list">{events.map(event => <div key={event.id} className="um-audit-event"><div className="um-event-mark"><Activity size={17}/></div><div><strong>{event.action.replaceAll('_', ' ')}</strong><p>Actor: {usersById.get(event.actor_user_id)?.display_name || 'Account ID ' + event.actor_user_id.slice(0, 8)} · Target: {event.target_user_id ? (usersById.get(event.target_user_id)?.display_name || 'Account ID ' + event.target_user_id.slice(0, 8)) : 'Permanently deleted account'}</p>{auditDetail(event) && <p>{auditDetail(event)}</p>}<small>{dateText(event.created_at_utc)}</small></div></div>)}</div>}
      </div>}
    </div>
    <div className="um-bottom-note"><ShieldAlert size={19}/><div><strong>Security boundary</strong><p>User management is administrator-only and enforced server-side. This is a localhost development build. HTTPS, broader RBAC administration and production security review are required before public deployment.</p></div></div>

    {editMode && <div className="um-modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget) close(); }}>
      <div className="um-modal" role="dialog" aria-modal="true" aria-label={editMode === 'create' ? 'Create user' : `${editMode} user`}>
        <div className="um-modal-head"><div><Label>ADMIN / IDENTITY MANAGEMENT</Label><h3>{editMode === 'create' ? 'Create a new account' : editMode === 'edit' ? `Edit ${target?.username}` : editMode === 'grants' ? 'Assign client access' : editMode === 'reset' ? 'Reset account password' : editMode === 'delete' ? 'Permanently delete account' : target?.is_active ? 'Disable account' : 'Enable account'}</h3><p>{editMode === 'create' ? 'Create authorized login credentials with explicit role and organization scope.' : `Target: ${target?.display_name} (@${target?.username})`}</p></div><button type="button" className="um-close" disabled={busy} aria-label="Close dialog" onClick={close}><X size={20}/></button></div>
        <form onSubmit={editMode === 'create' ? submitCreate : editMode === 'edit' ? submitEdit : editMode === 'grants' ? submitGrants : editMode === 'reset' ? submitReset : editMode === 'delete' ? submitDelete : submitStatus}>
          <div className="um-modal-body">
            {(editMode === 'create' || editMode === 'edit') && <>
              {editMode === 'create' && <label className="um-field">Username<input required minLength={3} maxLength={80} autoComplete="off" placeholder="e.g. supportteam01" value={draft.username} onChange={e => setDraft({ ...draft, username: e.target.value })}/><small>Must be unique. Use lowercase letters and numbers.</small></label>}
              <label className="um-field">Display name<input required minLength={2} maxLength={120} value={draft.display_name} onChange={e => setDraft({ ...draft, display_name: e.target.value })}/></label>
              <label className="um-field">Account role<select value={draft.role} disabled={editMode === 'edit' && target?.id === currentUser.id} onChange={e => setDraft({ ...draft, role: e.target.value as UserRole, confirm_admin_access: false })}><option value="staff">Staff — explicitly granted clients only</option><option value="viewer">View — every area, cannot add or change</option><option value="client">Client — one organization only</option><option value="admin">Administrator — all organizations</option></select></label>
              {draft.role === 'client' && <label className="um-field">Assigned organization<select required value={draft.client_id} onChange={e => setDraft({ ...draft, client_id: e.target.value })}><option value="">Choose client organization</option>{clients.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>}
              {draft.role === 'staff' && editMode === 'create' && <div className="um-grants"><strong>Staff client access</strong><p>Select only the organizations this staff member is allowed to monitor. None selected means no client access.</p>{clients.length === 0 ? <small>No organizations available yet.</small> : clients.map(c => <label key={c.id}><input type="checkbox" checked={draft.client_ids.includes(c.id)} onChange={() => toggleClient(c.id)}/> {c.name}</label>)}</div>}
              {draft.role === 'staff' && editMode === 'edit' && <p className="um-hint">After changing this account to Staff, use the separate <strong>Grants</strong> action to assign clients. No automatic access is granted.</p>}
              {draft.role === 'viewer' && <p className="um-hint">This account can open every area and click through it. The server rejects every add, edit, delete, and SSH change.</p>}
              {draft.role === 'admin' && (editMode === 'create' || target?.role !== 'admin') && <label className="um-check-warning"><input type="checkbox" required checked={draft.confirm_admin_access} onChange={e => setDraft({ ...draft, confirm_admin_access: e.target.checked })}/> I explicitly approve administrator access to every client and server.</label>}
              {editMode === 'create' && <label className="um-field">Temporary initial password<div className="um-passfield"><input required minLength={14} maxLength={128} autoComplete="new-password" type={showPassword ? 'text' : 'password'} value={draft.password} onChange={e => setDraft({ ...draft, password: e.target.value })} placeholder="14–128 characters"/><button type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={() => setShowPassword(prev => !prev)}>{showPassword ? <EyeOff size={18}/> : <Eye size={18}/>}</button></div><small>Never share passwords in chat or screenshots. Use a secure channel.</small></label>}
            </>}
            {editMode === 'grants' && <><p className="um-hint">Staff only. Changes take effect server-side and invalidate existing sessions.</p><div className="um-grants"><strong>Accessible client organizations</strong>{clients.length === 0 ? <small>No clients available.</small> : clients.map(c => <label key={c.id}><input type="checkbox" checked={draft.client_ids.includes(c.id)} onChange={() => toggleClient(c.id)}/> {c.name}</label>)}</div><p className="um-hint">{draft.client_ids.length} organization{draft.client_ids.length === 1 ? '' : 's'} selected</p></>}
            {editMode === 'reset' && <><div className="um-hint"><KeyRound size={17}/> Resetting another user's password revokes their existing sessions. Admin passwords cannot be retrieved.</div><label className="um-field">New password<div className="um-passfield"><input required minLength={14} maxLength={128} autoComplete="new-password" type={showPassword ? 'text' : 'password'} value={draft.password} onChange={e => setDraft({ ...draft, password: e.target.value })} placeholder="14–128 characters"/><button type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={() => setShowPassword(v => !v)}>{showPassword ? <EyeOff size={18}/> : <Eye size={18}/>}</button></div></label></>}
            {editMode === 'delete' && <div className="um-delete-confirmation">
              <div className="um-delete-warning"><ShieldAlert size={20}/><div><strong>Irreversible deletion</strong><p>Account credentials, login sessions and client grants will be deleted. Audit entries involving this account will be removed because of the current database structure; an anonymized deletion event remains. Existing client organizations and VPS records will NOT be deleted. This action cannot be undone without restoring a database backup.</p></div></div>
              <label className="um-field">Type <strong>{target?.username}</strong> to confirm<input required autoComplete="off" spellCheck={false} value={deleteUsername} onChange={event => setDeleteUsername(event.target.value)} placeholder="Exact username"/></label>
              <label className="um-field">Your administrator password<input required type="password" autoComplete="current-password" value={deletePassword} onChange={event => setDeletePassword(event.target.value)} placeholder="Verify your admin password"/></label>
              <label className="um-check-warning"><input type="checkbox" required checked={deleteConfirmed} onChange={event => setDeleteConfirmed(event.target.checked)}/> I understand that this account and its login history will be permanently removed.</label>
            </div>}
            {editMode === 'status' && <><div className="um-hint"><ShieldAlert size={18}/> {target?.is_active ? 'Disabling this account prevents further sign-ins and revokes existing sessions.' : 'Enabling this account allows the user to sign in with their existing credentials.'}</div><label className="um-check-warning"><input type="checkbox" required checked={confirmStatus} onChange={e => setConfirmStatus(e.target.checked)}/> I confirm this account status change.</label></>}
            {error && <div className="um-feedback error" role="alert"><CircleAlert size={17}/>{error}</div>}
          </div>
          <div className="um-modal-footer"><button type="button" className="um-outline" disabled={busy} onClick={close}>Cancel</button><button type="submit" className={editMode === 'delete' ? 'um-primary um-primary-danger' : 'um-primary'} disabled={busy || (editMode === 'delete' && (deleteUsername !== target?.username || !deletePassword || !deleteConfirmed))}>{busy ? 'Saving…' : editMode === 'create' ? 'Create account' : editMode === 'edit' ? 'Save changes' : editMode === 'grants' ? 'Save client grants' : editMode === 'reset' ? 'Reset password' : editMode === 'delete' ? 'Delete permanently' : target?.is_active ? 'Disable account' : 'Enable account'} <ArrowRight size={16}/></button></div>
        </form>
      </div>
    </div>}
  </div>;
}
