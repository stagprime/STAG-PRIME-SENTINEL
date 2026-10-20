import { csrfHeaders, signalAuthExpired } from './auth';

export type WebhookStatus = {
  configured: boolean;
  masked: string | null;
  source: 'environment' | 'file' | null;
  locked_by_env: boolean;
};

export type AlertDelivery = {
  at_utc: string;
  server_id: string;
  server_name: string;
  code: string;
  state: string;
  detail: string;
};

export type IntegrationStatus = {
  webhook: WebhookStatus;
  channels: { in_app: boolean; webhook: boolean; email: boolean; telegram: boolean; slack: boolean };
  recent: AlertDelivery[];
  note: string;
};

export type OperationsAuditEvent = {
  id: number;
  server_id: string;
  server_name: string;
  actor_id: string;
  operation: string;
  result: string;
  happened_at_utc: string | null;
};

async function request<T>(url: string, init: RequestInit = {}): Promise<T> {
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
    throw new Error(typeof detail === 'string' ? detail : `Request failed (HTTP ${response.status}).`);
  }
  return (await response.json()) as T;
}

export const fetchIntegrationStatus = () => request<IntegrationStatus>('/api/integrations/alerts');
export const saveAlertWebhook = (url: string) => request<{ saved: boolean; cleared: boolean; webhook: WebhookStatus }>('/api/integrations/webhook', {
  method: 'POST', body: JSON.stringify({ url, clear: false }),
});
export const clearAlertWebhook = () => request<{ saved: boolean; cleared: boolean; webhook: WebhookStatus }>('/api/integrations/webhook', {
  method: 'POST', body: JSON.stringify({ url: null, clear: true }),
});
export const fetchOperationsAudit = (limit = 80) => request<{ events: OperationsAuditEvent[]; total: number }>(`/api/server-operations/operations-audit?limit=${limit}`);
