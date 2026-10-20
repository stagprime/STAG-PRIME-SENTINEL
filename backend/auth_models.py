"""Step 38: additive authentication tables; never modifies legacy inventory data."""
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.database import Base, engine


def utcnow() -> datetime:
    # SQLite stores naive UTC timestamps, so standardize all auth timestamps to UTC.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AuthUser(Base):
    __tablename__ = "auth_users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(10), nullable=False)  # admin, staff, client
    client_id: Mapped[str | None] = mapped_column(ForeignKey("clients.id"), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until_utc: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("auth_users.id"), nullable=False, index=True)
    created_at_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)
    expires_at_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    revoked_at_utc: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuthClientGrant(Base):
    """Explicit staff -> client grants. Absence of a grant means DENY."""
    __tablename__ = "auth_client_grants"

    user_id: Mapped[str] = mapped_column(ForeignKey("auth_users.id"), primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), primary_key=True)
    granted_at_utc: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=utcnow)


def create_auth_tables(bind=None) -> None:
    """Create only new auth tables. Never migrate or reset existing clients/servers."""
    Base.metadata.create_all(bind=bind or engine, tables=[
        AuthUser.__table__, AuthSession.__table__, AuthClientGrant.__table__,
    ])
