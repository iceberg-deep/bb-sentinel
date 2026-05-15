from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Program(Base):
    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    domains: Mapped[list] = mapped_column(JSON, default=list)
    inscope_config: Mapped[str | None] = mapped_column(Text, nullable=True)
    scan_frequency: Mapped[str] = mapped_column(String(16), default="1h")
    webhooks: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="program", cascade="all, delete-orphan")
    runs: Mapped[list["ScanRun"]] = relationship(back_populates="program", cascade="all, delete-orphan")


class Asset(Base):
    """A hostname seen for a program — represents the baseline state of attack surface."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("program_id", "hostname", name="uq_asset_program_host"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    inscope: Mapped[bool] = mapped_column(Boolean, default=True)
    alive: Mapped[bool] = mapped_column(Boolean, default=False)

    program: Mapped[Program] = relationship(back_populates="assets")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Finding(Base):
    """A probed URL/endpoint observation tied to an asset."""

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "url", name="uq_finding_asset_url"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    technologies: Mapped[list] = mapped_column(JSON, default=list)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    priority_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    inscope_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    alerted: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    asset: Mapped[Asset] = relationship(back_populates="findings")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id", ondelete="CASCADE"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="running")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)

    program: Mapped[Program] = relationship(back_populates="runs")


class Database:
    """Thin async wrapper over the SQLAlchemy engine + session factory."""

    def __init__(self, url: str, echo: bool = False) -> None:
        self.url = _to_async_url(url)
        self.engine = create_async_engine(self.url, echo=echo, pool_pre_ping=True)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)

    async def create_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()

    def session(self) -> AsyncSession:
        return self.session_factory()

    async def get_program(self, name: str) -> Program | None:
        async with self.session() as s:
            res = await s.execute(select(Program).where(Program.name == name))
            return res.scalar_one_or_none()

    async def list_programs(self, only_enabled: bool = True) -> list[Program]:
        async with self.session() as s:
            stmt = select(Program)
            if only_enabled:
                stmt = stmt.where(Program.enabled == True)  # noqa: E712
            res = await s.execute(stmt)
            return list(res.scalars().all())

    async def upsert_program(self, **fields) -> Program:
        async with self.session() as s:
            res = await s.execute(select(Program).where(Program.name == fields["name"]))
            prog = res.scalar_one_or_none()
            if prog is None:
                prog = Program(**fields)
                s.add(prog)
            else:
                for k, v in fields.items():
                    setattr(prog, k, v)
            await s.commit()
            await s.refresh(prog)
            return prog

    async def known_hostnames(self, program_id: int) -> set[str]:
        async with self.session() as s:
            res = await s.execute(select(Asset.hostname).where(Asset.program_id == program_id))
            return {row[0] for row in res.all()}

    async def add_assets(
        self, program_id: int, hostnames: Iterable[str], source: str | None = None
    ) -> list[Asset]:
        """Insert hostnames not already known; bump last_seen on the rest. Returns the new ones."""
        new_assets: list[Asset] = []
        async with self.session() as s:
            existing_res = await s.execute(
                select(Asset).where(Asset.program_id == program_id, Asset.hostname.in_(list(hostnames)))
            )
            existing = {a.hostname: a for a in existing_res.scalars().all()}
            now = utcnow()
            for h in hostnames:
                if h in existing:
                    existing[h].last_seen = now
                else:
                    a = Asset(program_id=program_id, hostname=h, source=source, first_seen=now, last_seen=now)
                    s.add(a)
                    new_assets.append(a)
            await s.commit()
            for a in new_assets:
                await s.refresh(a)
            return new_assets


def _to_async_url(url: str) -> str:
    """Translate sync URLs to their async equivalents where possible."""
    if url.startswith("postgresql+asyncpg://") or url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
    return url
