
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import NullPool

BASE_DIR = Path(__file__).resolve().parent.parent


def _resolve_data_dir() -> Path:
    """Local installs keep SQLite beside the repo. Vercel functions can only write /tmp."""
    override = os.environ.get("SENTINEL_DATA_DIR", "").strip()
    if override:
        path = Path(override)
    elif os.environ.get("VERCEL") == "1":
        path = Path("/tmp/stag-prime-sentinel")
    else:
        path = BASE_DIR / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


DATA_DIR = _resolve_data_dir()


def _with_neon_ssl(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if "neon.tech" not in host:
        return url
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if "sslmode" in query:
        return url
    query["sslmode"] = "require"
    return urlunsplit(parts._replace(query="&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in query.items())))


def normalize_database_url(raw: str, *, data_dir: Path | None = None) -> str:
    """SQLite stays local. postgres/postgresql URLs use the psycopg driver."""
    value = (raw or "").strip()
    folder = data_dir or DATA_DIR
    if not value:
        return f"sqlite:///{(folder / 'sentinel.db').as_posix()}"
    lower = value.lower()
    if lower.startswith("sqlite:"):
        return value
    if lower.startswith("postgres://"):
        value = "postgresql://" + value[len("postgres://"):]
        lower = value.lower()
    if lower.startswith("postgresql+psycopg2://"):
        value = "postgresql+psycopg://" + value[len("postgresql+psycopg2://"):]
    elif lower.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value[len("postgresql://"):]
    elif lower.startswith("postgresql+psycopg://"):
        pass
    elif lower.startswith("postgresql+"):
        value = "postgresql+psycopg://" + value.split("://", 1)[1]
    else:
        raise RuntimeError("SENTINEL_DATABASE_URL must be a sqlite URL or a postgres/postgresql URL")
    return _with_neon_ssl(value)


def direct_postgres_url(url: str) -> str:
    """Neon pooled hosts are for app traffic. DDL uses the direct host when one is obvious."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if "-pooler." not in host:
        return url
    direct_host = host.replace("-pooler.", ".", 1)
    userinfo = ""
    if parts.username is not None:
        userinfo = quote(parts.username, safe="")
        if parts.password is not None:
            userinfo += ":" + quote(parts.password, safe="")
        userinfo += "@"
    port = f":{parts.port}" if parts.port else ""
    return urlunsplit(parts._replace(netloc=f"{userinfo}{direct_host}{port}"))


def is_postgres_url(url: str) -> bool:
    return url.startswith("postgresql")


def build_engine(url: str):
    if is_postgres_url(url):
        # NullPool plus prepare_threshold=None suits Neon PgBouncer on Fluid Compute.
        return create_engine(
            url,
            poolclass=NullPool,
            pool_pre_ping=True,
            connect_args={"prepare_threshold": None},
        )
    return create_engine(url, connect_args={"check_same_thread": False})


def schema_engine():
    """Engine used for create_all. Pooled Neon URLs are rewritten to the direct host."""
    if not is_postgres_url(DATABASE_URL):
        return engine, False
    direct = direct_postgres_url(DATABASE_URL)
    if direct == DATABASE_URL:
        return engine, False
    return build_engine(direct), True


DATABASE_URL = normalize_database_url(os.environ.get("SENTINEL_DATABASE_URL", ""))
engine = build_engine(DATABASE_URL)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    contact_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    servers: Mapped[list["Server"]] = relationship(back_populates="client")


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    location: Mapped[str | None] = mapped_column(String(150), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(150), nullable=True)
    monitoring_status: Mapped[str] = mapped_column(String(30), default="not_connected")
    archived_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    client: Mapped["Client"] = relationship(back_populates="servers")
    monitoring_config: Mapped["ServerMonitoringConfig | None"] = relationship(
        back_populates="server", uselist=False
    )


class ServerMonitoringConfig(Base):
    """Per-server monitoring authorization and non-secret connection settings.

    Each row is bound to an existing inventory UUID and approved SSH endpoint.
    Keys remain separate files on the local backend, not inside this database.
    The primary-key relationship supports arbitrarily many clients/servers.
    """

    __tablename__ = "server_monitoring_configs"

    server_id: Mapped[str] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Pinned host and account: edits to inventory cannot redirect SSH to a new
    # destination without explicit re-approval on the local backend computer.
    approved_host: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_ssh_username: Mapped[str] = mapped_column(String(100), nullable=False)
    approved_ssh_port: Mapped[int] = mapped_column(Integer, nullable=False)

    # Paths only (never private-key bytes, SSH passphrases, VPN passwords).
    ssh_key_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    known_hosts_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    vpn_service: Mapped[str] = mapped_column(String(80), nullable=False)
    vpn_interface: Mapped[str] = mapped_column(String(80), nullable=False)
    network_interface: Mapped[str] = mapped_column(String(80), nullable=False)

    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    server: Mapped["Server"] = relationship(back_populates="monitoring_config")
