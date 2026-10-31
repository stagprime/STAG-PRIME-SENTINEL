
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

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
# Optional sqlite URL only. A hosted Postgres URL needs a driver that is not installed yet.
_database_override = os.environ.get("SENTINEL_DATABASE_URL", "").strip()
if _database_override.startswith("sqlite:"):
    DATABASE_URL = _database_override
else:
    DATABASE_URL = f"sqlite:///{(DATA_DIR / 'sentinel.db').as_posix()}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

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
