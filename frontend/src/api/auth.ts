// Step 38.4.6 — HttpOnly cookie sessions, not localStorage/sessionStorage.
// CSRF token lives only in this JavaScript page's memory (refresh gets a fresh
// copy from /api/auth/session). Authentication cookie is invisible to JS.
let csrfToken: string | null = null;
export type UserRole = 'admin' | 'staff' | 'client';
export interface AuthUser {
  id: string;
  username: string;
  display_name: string;
  role: UserRole;
  client_id: string | null;
}
interface BrowserSession { user: AuthUser; csrf_token: string; expires_at_utc: string }
export function csrfHeaders(method = 'GET'): HeadersInit {
  return /^(POST|PUT|PATCH|DELETE)$/i.test(method) && csrfToken
    ? { 'X-Sentinel-CSRF': csrfToken } : {};
}
export function signalAuthExpired() {
  csrfToken = null;
  window.dispatchEvent(new Event('sentinel:auth-expired'));
}
export async function restoreSession(signal?: AbortSignal): Promise<AuthUser | null> {
  const response = await fetch('/api/auth/session', {
    credentials: 'same-origin', cache: 'no-store', signal,
  });
  if (response.status === 401) { csrfToken = null; return null; }
  if (!response.ok) throw new Error(`Unable to verify login (HTTP ${response.status}).`);
  const data = (await response.json()) as BrowserSession;
  if (!data.user || !data.csrf_token) throw new Error('Invalid session response.');
  if (!signal?.aborted) csrfToken = data.csrf_token;
  return data.user;
}
export async function signIn(username: string, password: string): Promise<AuthUser> {
  const response = await fetch('/api/auth/login-cookie', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }), cache: 'no-store',
  });
  if (!response.ok) throw new Error(response.status === 401
    ? 'Invalid credentials or account temporarily locked.'
    : `Sign in unavailable (HTTP ${response.status}).`);
  const data = (await response.json()) as BrowserSession;
  if (!data.user || !data.csrf_token) throw new Error('Unexpected login response.');
  csrfToken = data.csrf_token;
  return data.user;
}
export async function signOut(): Promise<void> {
  const response = await fetch('/api/auth/logout-cookie', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: { ...csrfHeaders('POST') },
  });
  if (!response.ok) throw new Error(`Unable to revoke session (HTTP ${response.status}).`);
  csrfToken = null;
}

/** Changes the signed-in user's password. Backend revokes all sessions; caller must sign in again. */
export async function changePassword(currentPassword: string, newPassword: string): Promise<string> {
  const response = await fetch('/api/auth/change-password', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
      ...csrfHeaders('POST'),
    },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
  if (response.status === 401) {
    signalAuthExpired();
    throw new Error('Session expired. Please sign in again.');
  }
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    const detail = payload && typeof payload === 'object' && 'detail' in payload
      ? (payload as { detail: unknown }).detail : null;
    throw new Error(typeof detail === 'string' ? detail : `Password change failed (HTTP ${response.status}).`);
  }
  const data = (await response.json()) as { message?: string };
  csrfToken = null;
  return data.message || 'Password updated. Sign in again.';
}
