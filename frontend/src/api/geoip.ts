import { csrfHeaders, signalAuthExpired } from './auth'

export type GeoResult = {
  ip?: string | null
  country?: string | null
  country_code?: string | null
  region?: string | null
  city?: string | null
  label?: string
  cached?: boolean
}

export async function lookupGeoIps(ips: string[], signal?: AbortSignal): Promise<Record<string, GeoResult>> {
  const unique = [...new Set(ips.map((ip) => ip.trim()).filter(Boolean))].slice(0, 40)
  if (!unique.length) return {}
  const response = await fetch('/api/geoip/lookup', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    signal,
    headers: { 'Content-Type': 'application/json', ...csrfHeaders('POST') },
    body: JSON.stringify({ ips: unique }),
  })
  if (response.status === 401) signalAuthExpired()
  if (!response.ok) return {}
  const payload = await response.json() as { results?: Record<string, GeoResult> }
  return payload.results && typeof payload.results === 'object' ? payload.results : {}
}
