from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import re
import sys
from datetime import timedelta
from pathlib import Path

import click
import structlog
import yaml
from sqlalchemy import desc, select

from .config import AppConfig
from .database import Asset, Database, Finding, Program, ScanRun, utcnow
from .monitor import MonitorLoop, ProgramScanner


def _configure_cli_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=level.upper(), format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper(), logging.INFO)),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)


def _parse_duration(value: str) -> timedelta:
    m = _DURATION_RE.match(value)
    if not m:
        raise click.BadParameter(f"invalid duration: {value!r}")
    n, unit = int(m.group(1)), m.group(2).lower()
    field = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]
    return timedelta(**{field: n})


def _load_app(programs_path: str, global_path: str) -> AppConfig:
    return AppConfig.load(programs_path, global_path)


def _coro(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return asyncio.run(fn(*args, **kwargs))
    return wrapper


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--programs", "programs_path", default=lambda: os.environ.get("BB_PROGRAMS_CONFIG", "config/programs.yaml"), show_default=True)
@click.option("--global", "global_path", default=lambda: os.environ.get("BB_GLOBAL_CONFIG", "config/global.yaml"), show_default=True)
@click.option("--log-level", default="INFO")
@click.pass_context
def cli(ctx: click.Context, programs_path: str, global_path: str, log_level: str) -> None:
    """bb-sentinel — bug bounty asset monitoring."""
    _configure_cli_logging(log_level)
    ctx.ensure_object(dict)
    ctx.obj["programs_path"] = programs_path
    ctx.obj["global_path"] = global_path


@cli.group()
def program() -> None:
    """Manage program definitions."""


@program.command("add")
@click.argument("name")
@click.option("--domains", required=True, help="Comma-separated root domains")
@click.option("--frequency", default="1h", show_default=True)
@click.option("--inscope-config", default=None)
@click.option("--webhook", "webhooks", multiple=True, help="webhook URL; may repeat")
@click.option("--threshold", default=7.0, show_default=True, type=float)
@click.pass_context
def program_add(
    ctx: click.Context,
    name: str,
    domains: str,
    frequency: str,
    inscope_config: str | None,
    webhooks: tuple[str, ...],
    threshold: float,
) -> None:
    """Add or update a program in the YAML config."""
    path = Path(ctx.obj["programs_path"])
    doc: dict = {}
    if path.exists():
        doc = yaml.safe_load(path.read_text()) or {}
    doc.setdefault("programs", {})
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    body: dict = {
        "domains": domain_list,
        "scan_frequency": frequency,
    }
    if inscope_config:
        body["inscope_config"] = inscope_config
    if webhooks:
        body["webhooks"] = [{"url": u, "priority_threshold": threshold} for u in webhooks]
    doc["programs"][name] = body
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False))
    click.echo(f"wrote program {name!r} → {path}")


@program.command("list")
@click.pass_context
def program_list(ctx: click.Context) -> None:
    app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
    if not app.programs:
        click.echo("(no programs configured)")
        return
    for name, cfg in app.programs.items():
        click.echo(f"{name:20} domains={','.join(cfg.domains)} freq={cfg.scan_frequency} enabled={cfg.enabled}")


@cli.command()
@click.argument("program_name")
@click.option("--force", is_flag=True, help="Run immediately regardless of schedule")
@click.pass_context
@_coro
async def scan(ctx: click.Context, program_name: str, force: bool) -> None:
    """Run a one-off scan for a single program."""
    app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
    cfg = app.programs.get(program_name)
    if not cfg:
        raise click.ClickException(f"unknown program: {program_name}")
    db = Database(app.global_.database_url)
    await db.create_all()
    try:
        scanner = ProgramScanner(app, db)
        stats = await scanner.scan(cfg, force=force)
        click.echo(json.dumps(stats.to_dict(), indent=2))
    finally:
        await db.dispose()


@cli.command()
@click.argument("program_name")
@click.option("--since", default="24h", show_default=True)
@click.option("--limit", default=50, show_default=True, type=int)
@click.option("--min-score", default=0.0, show_default=True, type=float)
@click.pass_context
@_coro
async def findings(ctx: click.Context, program_name: str, since: str, limit: int, min_score: float) -> None:
    """List recent findings for a program."""
    app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
    db = Database(app.global_.database_url)
    try:
        prog = await db.get_program(program_name)
        if not prog:
            raise click.ClickException(f"program {program_name!r} not yet in DB — run a scan first")
        delta = _parse_duration(since)
        cutoff = utcnow() - delta
        async with db.session() as s:
            stmt = (
                select(Finding, Asset)
                .join(Asset, Finding.asset_id == Asset.id)
                .where(Asset.program_id == prog.id, Finding.discovered_at >= cutoff, Finding.priority_score >= min_score)
                .order_by(desc(Finding.priority_score), desc(Finding.discovered_at))
                .limit(limit)
            )
            res = await s.execute(stmt)
            rows = res.all()
        if not rows:
            click.echo("(no findings)")
            return
        for f, a in rows:
            techs = ",".join(f.technologies or []) or "-"
            click.echo(
                f"{f.discovered_at.isoformat()}  score={f.priority_score:5.2f}  "
                f"{'IS' if f.inscope_verified else '  '}  {f.url}  [{techs}]"
            )
    finally:
        await db.dispose()


@cli.command()
@click.pass_context
@_coro
async def status(ctx: click.Context) -> None:
    """Show per-program scan status and counts."""
    app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
    db = Database(app.global_.database_url)
    try:
        await db.create_all()
        async with db.session() as s:
            programs = (await s.execute(select(Program))).scalars().all()
            for p in programs:
                asset_count = (await s.execute(select(Asset).where(Asset.program_id == p.id))).scalars().all()
                last_run = (
                    await s.execute(
                        select(ScanRun).where(ScanRun.program_id == p.id).order_by(desc(ScanRun.started_at)).limit(1)
                    )
                ).scalar_one_or_none()
                last_info = f"{last_run.status}@{last_run.started_at.isoformat()}" if last_run else "-"
                click.echo(
                    f"{p.name:20} enabled={p.enabled}  assets={len(asset_count):5d}  "
                    f"next={p.next_scan_at.isoformat() if p.next_scan_at else '-'}  last={last_info}"
                )
        if not programs:
            click.echo("(no programs)")
    finally:
        await db.dispose()


@cli.command()
@click.option("--tick", default=30, show_default=True, type=int)
@click.pass_context
@_coro
async def run(ctx: click.Context, tick: int) -> None:
    """Run the monitor loop in the foreground (same as `python -m src.main`)."""
    app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
    db = Database(app.global_.database_url)
    await db.create_all()
    loop = MonitorLoop(app, db)
    try:
        await loop.run_forever(tick_seconds=tick)
    finally:
        await db.dispose()


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
    sys.exit(0)
