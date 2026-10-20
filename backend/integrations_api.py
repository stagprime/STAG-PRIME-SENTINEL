"""Admin alert-webhook status. Never returns the full webhook URL."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from backend.admin_access import _require_admin, _require_reader
from backend.alert_notify import recent_alerts, set_webhook_url, validate_webhook_url, webhook_locked_by_env, webhook_status

router = APIRouter(prefix='/api/integrations', tags=['Integrations'])


class WebhookBody(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    url: str | None = None
    clear: bool = False


@router.get('/alerts')
def integration_alerts(admin=Depends(_require_reader)):
    status = webhook_status()
    recent = []
    for row in recent_alerts(40):
        if not isinstance(row, dict):
            continue
        recent.append({
            'at_utc': str(row.get('at_utc') or ''),
            'server_id': str(row.get('server_id') or ''),
            'server_name': str(row.get('server_name') or ''),
            'code': str(row.get('code') or ''),
            'state': str(row.get('state') or ''),
            'detail': str(row.get('detail') or '')[:500],
        })
    return {
        'webhook': status,
        'channels': {
            'in_app': True,
            'webhook': status['configured'],
            'email': False,
            'telegram': False,
            'slack': False,
        },
        'recent': recent,
        'note': 'Open incidents are written locally and POSTed to the https webhook when configured. The full URL is never returned.',
    }


@router.post('/webhook')
def save_webhook(body: WebhookBody, admin=Depends(_require_admin)):
    if webhook_locked_by_env() and not body.clear:
        raise HTTPException(409, detail='SENTINEL_ALERT_WEBHOOK is set in the environment and overrides the saved URL')
    if body.clear or not (body.url or '').strip():
        set_webhook_url(None)
        return {'saved': True, 'cleared': True, 'webhook': webhook_status()}
    try:
        set_webhook_url(validate_webhook_url(body.url or ''))
    except ValueError as exc:
        raise HTTPException(422, detail=str(exc)) from exc
    return {'saved': True, 'cleared': False, 'webhook': webhook_status()}
