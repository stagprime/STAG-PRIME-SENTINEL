import { csrfHeaders, signalAuthExpired } from './auth';
import type { UserRole } from './auth';

// Admin-only API. Credentials/token are not persisted or logged by this module.
export type ManagedUser = {
  id: string;
  username: string;
  display_name: string;
  role: UserRole;
  is_active: boolean;
  client_id: string | null;
  client_ids: string[];
  created_at_utc: string;
};
export type ClientDirectoryEntry = { id: string; name: string };
export type SecurityAuditEvent = {
  id: string;
  actor_user_id: string;
  target_user_id: string | null;
  action: string;
  details: Record<string, unknown>;
  created_at_utc: string;
};
export type CreateManagedUser = {
  username: string;
  display_name: string;
  password: string;
  role: UserRole;
  client_id?: string | null;
  client_ids?: string[];
  confirm_admin_access?: boolean;
};
export type EditManagedUser = {
  display_name?: string;
  role?: UserRole;
  client_id?: string | null;
  is_active?: boolean;
  confirm_admin_access?: boolean;
};

async function adminRequest<T>(url: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(url, {
    ...init,
    cache: 'no-store',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...csrfHeaders(init.method || 'GET'),
      ...init.headers,
    },
  });
  if (response.status === 401) {
    signalAuthExpired();
    throw new Error('Session expired. Please sign in again.');
  }
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    const detail = payload && typeof payload === 'object' && 'detail' in payload
      ? (payload as { detail: unknown }).detail : null;
    const readable = typeof detail === 'string' ? detail : `Request failed (HTTP ${response.status}).`;
    throw new Error(readable);
  }
  return (await response.json()) as T;
}

export const fetchManagedUsers = () => adminRequest<{ total: number; users: ManagedUser[] }>('/api/admin/users');
export const fetchClientDirectory = () => adminRequest<{ total: number; clients: ClientDirectoryEntry[] }>('/api/admin/clients');
export const fetchSecurityAudit = (limit = 50) => adminRequest<{ events: SecurityAuditEvent[] }>(`/api/admin/audit?limit=${limit}`);
export const createManagedUser = (data: CreateManagedUser) => adminRequest<ManagedUser>('/api/admin/users', {
  method: 'POST', body: JSON.stringify(data),
});
export const updateManagedUser = (id: string, data: EditManagedUser) => adminRequest<ManagedUser>(`/api/admin/users/${encodeURIComponent(id)}`, {
  method: 'PATCH', body: JSON.stringify(data),
});
export const replaceStaffClientGrants = (id: string, client_ids: string[]) => adminRequest<ManagedUser>(`/api/admin/users/${encodeURIComponent(id)}/grants`, {
  method: 'PUT', body: JSON.stringify({ client_ids }),
});
export const resetManagedUserPassword = (id: string, new_password: string) => adminRequest<{ message: string }>(`/api/admin/users/${encodeURIComponent(id)}/reset-password`, {
  method: 'POST', body: JSON.stringify({ new_password }),
});

export const permanentlyDeleteManagedUser = (id: string, confirm_username: string, admin_password: string) => adminRequest<{ message: string }>(`/api/admin/users/${encodeURIComponent(id)}`, {
  method: 'DELETE', body: JSON.stringify({ confirm_username, admin_password, confirm_permanent_delete: true }),
});
