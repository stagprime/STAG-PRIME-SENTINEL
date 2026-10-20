"""Historical, client-scoped reports from recorded snapshots (never invokes SSH).

Only bounded observed data is reported. No unverified/unknown VPN sample is
represented as zero users, and no stale value is labeled live.
"""
from __future__ import annotations

import csv
from datetime import timedelta
from io import StringIO

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select

from backend.auth_api import require_current_session
from backend.auth_security import can_access_client
from backend.database import Server, SessionLocal
from backend.monitoring_engine import (TelemetrySample, MonitorIncident, as_utc,
                                       initialize_monitor_tables, utcnow)

router = APIRouter(prefix='/api/monitoring/reports', tags=['Monitoring reports'])


def reporting_rows(db, user, *, hours: int = 24, now=None):
    """Aggregate historical observations, scoped by client permission.

    Snapshot history is intentionally bounded by the collector retention policy;
    this endpoint makes no claim to reconstruct every intervening connection.
    """
    if hours not in (1, 6, 24):
        raise ValueError('Unsupported report period')
    now = now or utcnow()
    cutoff = now - timedelta(hours=hours)
    servers = db.scalars(select(Server).where(Server.archived_at.is_(None)).order_by(Server.name, Server.id)).all()
    visible = [s for s in servers if can_access_client(db, user, s.client_id)]
    if not visible:
        return {'period_hours': hours, 'generated_at_utc': as_utc(now).isoformat(),
                'scope': 'visible_active_servers', 'source': 'stored_ssh_snapshots',
                'note': 'Observed samples only. Unknown VPN counts remain null. Peaks are not certified server capacity.',
                'servers': []}

    # Grouped aggregation avoids four queries per server at growing fleet sizes.
    # Chunk IDs to stay safely below even older SQLite variable-count limits.
    sessions = {}
    health = {}
    incidents = {}
    for offset in range(0, len(visible), 350):
        ids = [s.id for s in visible[offset:offset + 350]]
        for sid, sample_count, peak, avg, last_seen in db.execute(select(
            TelemetrySample.server_id,
            func.count(TelemetrySample.id),
            func.max(func.json_extract(TelemetrySample.data_json, '$.total')),
            func.avg(func.json_extract(TelemetrySample.data_json, '$.total')),
            func.max(TelemetrySample.collected_at),
        ).where(TelemetrySample.server_id.in_(ids),
                TelemetrySample.kind == 'sessions',
                TelemetrySample.state == 'available',
                TelemetrySample.collected_at >= cutoff).group_by(TelemetrySample.server_id)):
            sessions[sid] = (int(sample_count), int(peak) if peak is not None else None,
                             round(float(avg), 2) if avg is not None else None, last_seen)

        for sid, count, avg_cpu, avg_ram, avg_disk in db.execute(select(
            TelemetrySample.server_id,
            func.count(TelemetrySample.id),
            func.avg(func.json_extract(TelemetrySample.data_json, '$.cpu_percent')),
            func.avg(func.json_extract(TelemetrySample.data_json, '$.memory_used_percent')),
            func.avg(func.json_extract(TelemetrySample.data_json, '$.disk_used_percent')),
        ).where(TelemetrySample.server_id.in_(ids),
                TelemetrySample.kind == 'health',
                TelemetrySample.state == 'connected',
                TelemetrySample.collected_at >= cutoff).group_by(TelemetrySample.server_id)):
            health[sid] = (int(count), *(round(float(x), 2) if x is not None else None
                                          for x in (avg_cpu, avg_ram, avg_disk)))

        for sid, count in db.execute(select(MonitorIncident.server_id,
                                          func.count(MonitorIncident.id)).where(
                MonitorIncident.server_id.in_(ids),
                MonitorIncident.opened_at >= cutoff).group_by(MonitorIncident.server_id)):
            incidents[sid] = int(count)

    rows = []
    for s in visible:
        count, peak, average, last = sessions.get(s.id, (0, None, None, None))
        h_count, cpu, ram, disk = health.get(s.id, (0, None, None, None))
        rows.append({
            'server_id': s.id, 'server_name': s.name, 'client_id': s.client_id,
            'session_samples': count,
            'peak_observed_connections': peak,
            'average_observed_connections': average,
            'health_samples': h_count,
            'average_cpu_percent': cpu,
            'average_ram_percent': ram,
            'average_disk_percent': disk,
            'incidents_opened': incidents.get(s.id, 0),
            'last_session_sample_utc': as_utc(last).isoformat() if last else None,
        })
    return {'period_hours': hours, 'generated_at_utc': as_utc(now).isoformat(),
            'scope': 'visible_active_servers', 'source': 'stored_ssh_snapshots',
            'note': 'Observed samples only. Unknown VPN counts remain null. Peaks are not certified server capacity.',
            'servers': rows}


def _report(hours, current):
    user, _ = current
    initialize_monitor_tables()
    with SessionLocal() as db:
        return reporting_rows(db, user, hours=hours)


@router.get('/summary')
def report_summary(hours: int = Query(24, ge=1, le=24),
                   current=Depends(require_current_session)):
    if hours not in (1, 6, 24):
        raise HTTPException(422, detail='Available report windows: 1, 6 or 24 hours')
    return _report(hours, current)


def _csv_field(value):
    if value is None:
        return ''
    txt = str(value)
    # Prevent spreadsheet formula execution on exported untrusted inventory names.
    if txt.lstrip().startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
        return "'" + txt
    return txt


@router.get('/summary.csv')
def report_csv(hours: int = Query(24, ge=1, le=24),
               current=Depends(require_current_session)):
    if hours not in (1, 6, 24):
        raise HTTPException(422, detail='Available report windows: 1, 6 or 24 hours')
    data = _report(hours, current)
    keys = ('server_name', 'server_id', 'session_samples', 'peak_observed_connections',
            'average_observed_connections', 'health_samples', 'average_cpu_percent',
            'average_ram_percent', 'average_disk_percent', 'incidents_opened', 'last_session_sample_utc')
    out = StringIO()
    writer = csv.writer(out)
    writer.writerow(keys)
    for row in data['servers']:
        writer.writerow([_csv_field(row.get(field)) for field in keys])
    return Response(content='\ufeff' + out.getvalue(), media_type='text/csv; charset=utf-8',
                    headers={'Content-Disposition': 'attachment; filename="sentinel-monitoring-report.csv"',
                             'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
