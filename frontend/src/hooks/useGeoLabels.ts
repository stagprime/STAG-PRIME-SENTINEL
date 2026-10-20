import { useEffect, useMemo, useState } from 'react'
import { lookupGeoIps, type GeoResult } from '../api/geoip'

/** Resolve public IPs → "City, Country" labels for live session tables. */
export function useGeoLabels(ips: Array<string | null | undefined>) {
  const key = useMemo(
    () => [...new Set(ips.map((ip) => (ip || '').trim()).filter(Boolean))].sort().join('|'),
    [ips],
  )
  const [map, setMap] = useState<Record<string, GeoResult>>({})

  useEffect(() => {
    if (!key) {
      setMap({})
      return
    }
    const list = key.split('|')
    const ctrl = new AbortController()
    lookupGeoIps(list, ctrl.signal)
      .then((results) => {
        if (!ctrl.signal.aborted) setMap(results)
      })
      .catch(() => {
        if (!ctrl.signal.aborted) setMap({})
      })
    return () => ctrl.abort()
  }, [key])

  return map
}

export function geoLabel(map: Record<string, GeoResult>, ip?: string | null): string {
  if (!ip) return '—'
  const hit = map[ip]
  return hit?.label || (hit ? 'Unknown' : '…')
}
