"""Tenant-aware client directory. No remote commands, secret access or client deletion.

Retains client UUIDs so VPN inventory, login grants and audit trails are stable.
"""
from __future__ import annotations

import re
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from backend.auth_api import require_current_session
from backend.auth_models import AuthClientGrant
from backend.database import Client, Server, SessionLocal
from backend.user_management import require_admin_session

router = APIRouter(prefix='/api/clients', tags=['Client directory'])


class ClientCreate(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    name: str = Field(min_length=2,max_length=150)
    contact_email: str | None = Field(default=None,max_length=255)


class ClientUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid',strict=True)
    name: str | None = Field(default=None,min_length=2,max_length=150)
    contact_email: str | None = Field(default=None,max_length=255)


def normalized_name(name):
    cleaned=' '.join(name.split())
    if len(cleaned)<2 or len(cleaned)>150:raise HTTPException(422,detail='Client name must be 2–150 characters')
    return cleaned


def normalized_email(email):
    if email is None or not email.strip():return None
    cleaned=email.strip()
    if len(cleaned)>255 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',cleaned):
        raise HTTPException(422,detail='Valid contact email required')
    return cleaned


def _visible(db,user):
    if not user.is_active:return []
    query=select(Client).order_by(Client.name,Client.id)
    if user.role=='client':
        query=query.where(Client.id==user.client_id)
    elif user.role=='staff':
        ids=list(db.scalars(select(AuthClientGrant.client_id).where(AuthClientGrant.user_id==user.id)))
        query=query.where(Client.id.in_(ids))
    elif user.role!='admin':return []
    servers=dict(db.execute(select(Server.client_id,func.count(Server.id)).where(
        Server.archived_at.is_(None)).group_by(Server.client_id)).all())
    return [{'id':c.id,'name':c.name,'contact_email':c.contact_email,
             'active_servers':int(servers.get(c.id,0))} for c in db.scalars(query)]


@router.get('')
def list_clients(current=Depends(require_current_session)):
    user,_=current
    with SessionLocal() as db:
        results=_visible(db,user)
        return {'clients':results,'total':len(results)}


@router.post('',status_code=201)
def add_client(payload:ClientCreate, actor=Depends(require_admin_session)):
    name=normalized_name(payload.name)
    email=normalized_email(payload.contact_email)
    with SessionLocal.begin() as db:
        if db.scalar(select(Client.id).where(func.lower(Client.name)==name.lower())):
            raise HTTPException(409,detail='Client name already exists')
        c=Client(name=name,contact_email=email)
        db.add(c);db.flush()
        return {'id':c.id,'name':c.name,'contact_email':c.contact_email,'active_servers':0}


@router.patch('/{client_id}')
def edit_client(client_id:str,payload:ClientUpdate,actor=Depends(require_admin_session)):
    changes=payload.model_dump(exclude_unset=True)
    if not changes:raise HTTPException(422,detail='No changes requested')
    with SessionLocal.begin() as db:
        c=db.get(Client,client_id)
        if c is None:raise HTTPException(404,detail='Client not found')
        if 'name' in changes:
            if changes['name'] is None:raise HTTPException(422,detail='Client name cannot be null')
            name=normalized_name(changes['name'])
            exists=db.scalar(select(Client.id).where(func.lower(Client.name)==name.lower(),Client.id!=client_id))
            if exists:raise HTTPException(409,detail='Client name already exists')
            c.name=name
        if 'contact_email' in changes:c.contact_email=normalized_email(changes['contact_email'])
        return {'id':c.id,'name':c.name,'contact_email':c.contact_email}
