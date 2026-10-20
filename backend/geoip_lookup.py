"""Best-effort public-IP → country/city lookup with local disk cache.

Used only to enrich VPN client public IPs for operator display.
Never blocks monitoring; failures return unknown fields.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field

from backend.auth_api import require_current_session

router = APIRouter(prefix='/api/geoip', tags=['GeoIP enrichment'])

_CACHE_TTL_SECONDS = 7 * 24 * 3600
_MAX_BATCH = 40


def _cache_path() -> Path:
    home = os.environ.get('LOCALAPPDATA') or os.environ.get('HOME') or '.'
    path = Path(home) / 'StagPrimeSentinel' / 'geoip_cache.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _load_cache() -> dict[str, Any]:
    path = _cache_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding='utf-8'))
        return raw if isinstance(raw, dict) else {}
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    try:
        _cache_path().write_text(json.dumps(cache, separators=(',', ':')), encoding='utf-8')
    except OSError:
        pass


def _is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_multicast or addr.is_reserved or addr.is_unspecified
    )


def _fetch_one(ip: str) -> dict[str, str | None]:
    """Query ipwho.is (HTTPS, no API key). Soft-fail to unknowns."""
    url = f'https://ipwho.is/{ip}'
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'StagPrimeSentinel/1.0', 'Accept': 'application/json'},
            method='GET',
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            payload = json.loads(resp.read(8192).decode('utf-8', errors='replace'))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError):
        return {'country': None, 'country_code': None, 'region': None, 'city': None, 'source': 'unavailable'}
    if not isinstance(payload, dict) or payload.get('success') is False:
        return {'country': None, 'country_code': None, 'region': None, 'city': None, 'source': 'unavailable'}
    country = payload.get('country')
    code = payload.get('country_code')
    region = payload.get('region')
    city = payload.get('city')
    return {
        'country': country if isinstance(country, str) and country.strip() else None,
        'country_code': code if isinstance(code, str) and code.strip() else None,
        'region': region if isinstance(region, str) and region.strip() else None,
        'city': city if isinstance(city, str) and city.strip() else None,
        'source': 'ipwho.is',
    }


def lookup_ip(ip: str, *, cache: dict[str, Any] | None = None, persist: bool = True) -> dict[str, Any]:
    cleaned = (ip or '').strip()
    empty = {
        'ip': cleaned or None,
        'country': None,
        'country_code': None,
        'region': None,
        'city': None,
        'label': '—',
        'cached': False,
    }
    if not cleaned or not _is_public_ip(cleaned):
        empty['label'] = 'Private / invalid'
        return empty

    store = cache if cache is not None else _load_cache()
    now = time.time()
    hit = store.get(cleaned)
    if isinstance(hit, dict) and isinstance(hit.get('at'), (int, float)) and now - float(hit['at']) < _CACHE_TTL_SECONDS:
        country = hit.get('country')
        city = hit.get('city')
        region = hit.get('region')
        label = _label(city if isinstance(city, str) else None,
                       region if isinstance(region, str) else None,
                       country if isinstance(country, str) else None)
        return {
            'ip': cleaned,
            'country': country if isinstance(country, str) else None,
            'country_code': hit.get('country_code') if isinstance(hit.get('country_code'), str) else None,
            'region': region if isinstance(region, str) else None,
            'city': city if isinstance(city, str) else None,
            'label': label,
            'cached': True,
        }

    fetched = _fetch_one(cleaned)
    store[cleaned] = {'at': now, **fetched}
    if persist and cache is None:
        _save_cache(store)
    label = _label(
        fetched.get('city') if isinstance(fetched.get('city'), str) else None,
        fetched.get('region') if isinstance(fetched.get('region'), str) else None,
        fetched.get('country') if isinstance(fetched.get('country'), str) else None,
    )
    return {
        'ip': cleaned,
        'country': fetched.get('country'),
        'country_code': fetched.get('country_code'),
        'region': fetched.get('region'),
        'city': fetched.get('city'),
        'label': label,
        'cached': False,
    }


def _label(city: str | None, region: str | None, country: str | None) -> str:
    parts = [p for p in (city, region, country) if p]
    if not parts:
        return 'Unknown'
    # Prefer city, country — drop duplicate region if same as city
    if city and country:
        return f'{city}, {country}'
    return ', '.join(parts)


def lookup_many(ips: list[str]) -> dict[str, dict[str, Any]]:
    unique: list[str] = []
    seen: set[str] = set()
    for raw in ips:
        value = (raw or '').strip()
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
        if len(unique) >= _MAX_BATCH:
            break
    cache = _load_cache()
    out: dict[str, dict[str, Any]] = {}
    dirty = False
    for ip in unique:
        before = len(cache)
        result = lookup_ip(ip, cache=cache, persist=False)
        out[ip] = result
        if len(cache) != before or not result.get('cached'):
            dirty = True
        # Be polite to free API when resolving many uncached IPs.
        if not result.get('cached') and result.get('country'):
            time.sleep(0.15)
    if dirty:
        _save_cache(cache)
    return out


class GeoLookupRequest(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    ips: list[str] = Field(default_factory=list, max_length=_MAX_BATCH)


@router.post('/lookup')
def geoip_lookup(body: GeoLookupRequest, _current=Depends(require_current_session)):
    cleaned = [ip.strip() for ip in body.ips if isinstance(ip, str) and ip.strip()][:_MAX_BATCH]
    return {'results': lookup_many(cleaned), 'count': len(cleaned)}
