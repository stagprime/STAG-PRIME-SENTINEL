# Stag Prime Sentinel — Operator Guide (VPN Company NOC)

**Stag Prime LLC** — add a server once; live monitoring + control runs 24/7 while `START_ALL` is up.

## What you get

| Capability | Status |
|------------|--------|
| Add server → SSH vault → verify → multi-VPN discover → enroll | Ready |
| SSH password **or** private key **or** key + login password | Ready |
| OpenVPN / WireGuard / IKEv2 sessions | Ready |
| Connected users + failed-auth signals | Ready |
| Kick / block / unblock VPN identity | Ready (Fleet Ops) |
| VPN service start / stop / restart | Ready |
| Issue → solution engine | Ready |
| Alerts when collector/VPN goes bad (local JSONL + optional webhook) | Ready |
| Fleet Ops + Dashboard NOC UI | Ready |

## Start (keep this window open)

```bat
START_ALL.bat
```

- UI: http://127.0.0.1:5173  
- API docs: http://127.0.0.1:8000/docs  

## Daily flow

1. **Add server** (Dashboard / Servers / Fleet Ops) with host + SSH key or password  
2. Sentinel auto-discovers which VPN is running and enrolls monitoring  
3. Worker polls **health ~60s** and **sessions ~30s**  
4. **Fleet Ops** → see connected users → **kick / block / unblock**  
5. Per-server **start / restart / stop** if VPN unit is down  

No `.ovpn` client upload is required for monitoring.

### Do I need to turn on monitoring permission on the VPS first?

**No separate Sentinel agent/permission package.** Just:

| Need | Why |
|------|-----|
| SSH reachable (port open to your PC) | Connect |
| Correct **lowercase** Linux username + working key/password | Login |
| User can read VPN status (OpenVPN status file / `wg` / swanctl) | Session counts |
| For kick/block/VPN restart: `sudo -n` for those units (or root) | Control actions |

If SSH works, add the server in Sentinel — discovery + 24/7 polling starts automatically while `START_ALL` is running. You do **not** install a Sentinel agent on the VPS.

**Tip:** Linux usernames are case-sensitive (`tariq` ≠ `Tariq`).

## Alerts (optional webhook)

Incidents write to `%LOCALAPPDATA%\StagPrimeSentinel\alerts\alerts-YYYYMMDD.jsonl`.

Optional Slack/Discord-style webhook:

```text
%LOCALAPPDATA%\StagPrimeSentinel\alert_webhook.url
```

Put one HTTPS URL in that file, or set env `SENTINEL_ALERT_WEBHOOK`.

## Vercel production

Emily sets these on the Vercel project `stag-prime-sentinel` (Production, and Preview if previews should use a database). Do not commit the values.

| Name | Value |
| --- | --- |
| `SENTINEL_DATABASE_URL` | Neon **pooled** Postgres URL. `postgres://` and `postgresql://` are both accepted. Prefer the host that contains `-pooler`. The app rewrites that host to the direct endpoint only while creating tables. |
| `SENTINEL_VAULT_MASTER_KEY` | Fernet key. On a trusted computer: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Losing this key makes saved SSH credentials unreadable. |

The hosted SQLite file is not durable. Leave `SENTINEL_DATABASE_URL` unset only for local SQLite.

### First administrator

`python -m backend.auth_cli bootstrap-admin` asks for the username and password in the terminal. A Vercel function cannot run that prompt, so there is no serverless bootstrap.

After the Neon URL is set, run the command once on a trusted computer with the same `SENTINEL_DATABASE_URL`. It creates the tables if they are missing, then the first admin, and it stops if an admin already exists. The password is not written to Vercel.

## Notes

- VPN user **block** (OpenVPN) writes CCD `disable` + best-effort disconnect.  
- WireGuard **block/kick** removes the peer (unblock needs peer re-add in config).  
- Host needs `sudo -n` for systemctl / CCD / wg actions.  
- Production later: Windows Service / always-on host, HTTPS, secret manager.

## Test checklist (you)

1. Run `START_ALL.bat` → open http://127.0.0.1:5173 and sign in as admin  
2. **Fleet Ops** → EU-01 shows connected users (auto-refresh ~15s)  
3. Try **kick** on a test session; confirm user drops then reconnects if allowed  
4. Try **block** then **unblock** on OpenVPN CN (CCD `disable`)  
5. Per-server **stop / start / restart** VPN unit; Fleet Ops issue strip + alerts update  
6. Optional: put webhook URL in `%LOCALAPPDATA%\StagPrimeSentinel\alert_webhook.url`  
7. **Add server (SSH)** with another VPS key/password → discovery + enroll → same board
