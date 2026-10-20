import {useEffect, useState} from 'react'
import {Activity, AlertTriangle, CheckCircle2, LockKeyhole, RefreshCw, ShieldCheck} from 'lucide-react'
import {enrollVerifiedMonitoring, disableVerifiedMonitoring, getAdminProfiles, verifyAdminSSH} from '../api/serverOperations'
import type {AdminProfileStatus} from '../api/serverOperations'

type Props = {
  serverId: string
  serverName: string
  monitored: boolean
  onChange: () => void
}

/**
 * Minimal operator control: verify SSH once, then auto-discover VPN unit and enroll.
 * No .ovpn upload — live sessions come from the server status file via SSH.
 */
export default function InventorySSHEnrollment({serverId, serverName, monitored, onChange}: Props) {
  const [profile, setProfile] = useState<AdminProfileStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [target, setTarget] = useState<{service: string; iface: string} | null>(null)

  useEffect(() => {
    const ctl = new AbortController()
    setProfile(null)
    setLoading(true)
    setError(null)
    getAdminProfiles(ctl.signal)
      .then((x) => {
        if (!ctl.signal.aborted) setProfile(x.profiles.find((p) => p.server_id === serverId) || null)
      })
      .catch(() => {
        if (!ctl.signal.aborted) setError('Unable to load administrative access status')
      })
      .finally(() => {
        if (!ctl.signal.aborted) setLoading(false)
      })
    return () => ctl.abort()
  }, [serverId, refresh])

  const verified =
    profile?.recent_verification?.state === 'success' && profile.recent_verification.ssh_verified === true
  const ready = profile?.verification_ready === true

  async function autoEnroll() {
    // Backend auto-discovers OpenVPN / WireGuard / IKEv2 and enrolls the best match.
    const result = await enrollVerifiedMonitoring(serverId, {
      consent: true,
      vpn_service: 'auto',
      vpn_interface: 'auto',
      network_interface: 'auto',
    })
    if (!result.monitoring_enabled) throw new Error('Backend did not confirm monitoring enrollment')
    const service = (result as {vpn_service?: string}).vpn_service || 'auto'
    const iface = (result as {vpn_interface?: string}).vpn_interface || 'auto'
    setTarget({service, iface})
    onChange()
    setMessage(`Live monitoring on ${service} / ${iface}. Worker keeps health & sessions updated.`)
  }

  async function verifyAndStart() {
    if (busy || !ready) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      if (!verified) {
        const result = await verifyAdminSSH(serverId)
        if (!result.ssh_verified || !result.host_key_verified) {
          throw new Error('SSH or host key could not be verified')
        }
      }
      await autoEnroll()
      setRefresh((n) => n + 1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'SSH verification or monitoring enrollment failed')
      setRefresh((n) => n + 1)
    } finally {
      setBusy(false)
    }
  }

  async function disable() {
    if (busy) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      await disableVerifiedMonitoring(serverId)
      setMessage('Monitoring disabled. Historical telemetry kept.')
      onChange()
      setRefresh((n) => n + 1)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not disable monitoring')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="sentinel-enroll" aria-label="SSH verification and monitoring enrollment">
      <div className="sentinel-enroll-head">
        <ShieldCheck size={18} />
        <strong>Live monitoring</strong>
      </div>
      <p className="sentinel-enroll-hint">
        Add SSH access once. Sentinel discovers the VPN service on the VPS and keeps health + connected users live — no .ovpn file needed.
      </p>
      {loading ? (
        <p>Checking protected server profile…</p>
      ) : (
        <>
          <p className="sentinel-enroll-stage">
            <span>{verified ? <CheckCircle2 size={16} /> : <LockKeyhole size={16} />}</span>
            {verified
              ? 'SSH identity verified'
              : ready
                ? 'SSH credentials ready — start live monitoring'
                : 'Configure encrypted SSH credentials first'}
          </p>
          {!monitored && (
            <button
              type="button"
              className="btn-primary"
              disabled={!ready || busy}
              onClick={() => void verifyAndStart()}
            >
              <ShieldCheck size={16} />
              {busy ? 'Connecting…' : verified ? 'Start live monitoring' : 'Verify SSH & start live monitoring'}
            </button>
          )}
          {monitored && (
            <div className="sentinel-enroll-settings">
              <p className="sentinel-enroll-stage">
                <Activity size={16} /> Monitoring active
                {target ? (
                  <>
                    {' '}
                    · <b>{target.service}</b> / <b>{target.iface}</b>
                  </>
                ) : null}
              </p>
              <div style={{display: 'flex', gap: 8, flexWrap: 'wrap'}}>
                <button type="button" className="btn-secondary" disabled={busy || !ready} onClick={() => void verifyAndStart()}>
                  <RefreshCw size={16} />
                  {busy ? 'Updating…' : 'Re-detect & refresh'}
                </button>
                <button type="button" className="btn-secondary" disabled={busy} onClick={() => void disable()}>
                  Disable monitoring
                </button>
              </div>
            </div>
          )}
        </>
      )}
      {error && (
        <p className="sentinel-enroll-error" role="alert">
          <AlertTriangle size={16} />
          {error}
        </p>
      )}
      {message && (
        <p className="sentinel-enroll-success" role="status">
          {message}
        </p>
      )}
      <p className="sentinel-enroll-hint" style={{marginTop: 8}}>
        For {serverName}: connected users are read from the OpenVPN status file over SSH — not from client .ovpn profiles.
      </p>
    </section>
  )
}
