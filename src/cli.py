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

from .compliance import ComplianceCheck, check_file as compliance_check_file, check_url as compliance_check_url
from .config import AppConfig
from .database import Asset, Database, Finding, Program, ScanRun, utcnow
from .rocks import DeepScanner, SEVERITY_ORDER
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
@click.option("-v", "verbose", count=True,
              help="Increase verbosity: -v adds per-step detail, -vv adds raw structlog/JSON")
@click.option("-q", "--quiet", is_flag=True, help="Errors and final summary only")
@click.pass_context
def cli(ctx: click.Context, programs_path: str, global_path: str, log_level: str,
        verbose: int, quiet: bool) -> None:
    """bb-sentinel — bug bounty asset monitoring."""
    # Verbosity → progress level mapping (used by the human-readable
    # `Progress` reporter) and underlying log level (structlog).
    if quiet:
        progress_level = "quiet"
        effective_log = "ERROR"
    elif verbose >= 2:
        progress_level = "debug"
        effective_log = "DEBUG"
    elif verbose == 1:
        progress_level = "verbose"
        effective_log = log_level
    else:
        progress_level = "normal"
        # Suppress structlog INFO chatter in normal mode; the human Progress
        # reporter narrates the same phases more cleanly. Keep WARN/ERROR.
        effective_log = "WARNING"
    _configure_cli_logging(effective_log)
    ctx.ensure_object(dict)
    ctx.obj["programs_path"] = programs_path
    ctx.obj["global_path"] = global_path
    ctx.obj["progress_level"] = progress_level
    from .progress import make_progress
    ctx.obj["progress"] = make_progress(progress_level)


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


async def _preflight_compliance(cfg, ignore: bool, assume_yes: bool) -> None:
    """Pre-flight check: read program rules + decide whether automation is OK.

    Reads `rules_url` and/or `rules_text` from the program config. If neither is
    set, we cannot assess — emits an UNCLEAR warning and (unless --yes) prompts.
    """
    if ignore:
        click.echo("[compliance] override flag set — skipping pre-flight (you own this)")
        return
    if getattr(cfg, "compliance_override", False):
        click.echo("[compliance] program has compliance_override=true in config — skipping")
        return
    rules_url = getattr(cfg, "rules_url", None)
    rules_text_path = getattr(cfg, "rules_text", None)
    check: ComplianceCheck | None = None
    if rules_text_path:
        try:
            check = compliance_check_file(rules_text_path)
        except Exception as e:
            click.echo(f"[compliance] failed to read rules_text {rules_text_path}: {e}", err=True)
    elif rules_url:
        click.echo(f"[compliance] fetching rules from {rules_url} ...")
        check = await compliance_check_url(rules_url)
    else:
        click.echo("[compliance] no rules_url or rules_text configured — UNCLEAR")
        check = ComplianceCheck(source="<no source>", verdict="UNCLEAR",
                                fetch_error="program config has neither rules_url nor rules_text")
    if check is None:
        return
    click.echo("─" * 60)
    click.echo(check.render())
    click.echo("─" * 60)
    if check.is_blocking():
        raise click.ClickException(
            "Compliance pre-flight: BLOCK. Refusing to run automated probes against "
            "a program with explicit anti-automation language. Override with "
            "--ignore-compliance only after manual review."
        )
    if check.needs_confirmation() and not assume_yes:
        click.confirm(f"Compliance verdict is {check.verdict}. Proceed anyway?", abort=True)


@cli.command()
@click.argument("program_name")
@click.option("--force", is_flag=True, help="Run immediately regardless of schedule")
@click.option("--ignore-compliance", is_flag=True,
              help="Skip the compliance pre-flight (you take responsibility)")
@click.option("--yes", "-y", is_flag=True, help="Auto-confirm WARN/UNCLEAR verdicts")
@click.pass_context
@_coro
async def scan(ctx: click.Context, program_name: str, force: bool,
               ignore_compliance: bool, yes: bool) -> None:
    """Run a one-off scan for a single program."""
    progress = ctx.obj.get("progress")
    app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
    cfg = app.programs.get(program_name)
    if not cfg:
        raise click.ClickException(f"unknown program: {program_name}")
    if progress:
        progress.info(f"[{program_name}] starting scan")
        progress.detail(f"roots: {','.join(cfg.domains)}")
        if cfg.rate_limit_rps:
            progress.detail(f"rate limit: {cfg.rate_limit_rps} RPS")
        if cfg.auth_headers:
            progress.detail(f"auth headers: {sorted(cfg.auth_headers.keys())}")
    await _preflight_compliance(cfg, ignore_compliance, yes)
    db = Database(app.global_.database_url)
    await db.create_all()
    try:
        scanner = ProgramScanner(app, db, progress=progress)
        stats = await scanner.scan(cfg, force=force)
        if progress:
            progress.summary(lines=[
                f"  discovered_hosts: {stats.discovered_hosts}",
                f"  new_hosts:        {stats.new_hosts}",
                f"  live_probes:      {stats.live_probes}",
                f"  new_findings:     {stats.new_findings}",
                f"  alerts_sent:      {stats.alerts_sent}",
                *([f"  errors:           {len(stats.errors)}"] if stats.errors else []),
            ])
        else:
            click.echo(json.dumps(stats.to_dict(), indent=2))
    finally:
        await db.dispose()


@cli.command()
@click.option("--url", "url", default=None, help="Fetch and assess a rules URL")
@click.option("--file", "path", default=None, type=click.Path(exists=True, dir_okay=False),
              help="Assess a pasted rules-text file (skips network fetch)")
@click.option("--program", "program_name", default=None,
              help="Pull rules_url / rules_text from this program's config")
@click.option("--force-headless", is_flag=True,
              help="Skip the httpx attempt and go straight to headless chromium")
@click.option("--no-headless", is_flag=True,
              help="Disable the headless fallback (UNCLEAR if httpx returns too-short text)")
@click.pass_context
@_coro
async def compliance(ctx: click.Context, url: str | None, path: str | None,
                     program_name: str | None,
                     force_headless: bool, no_headless: bool) -> None:
    """Standalone compliance check — read program rules and decide if automation is OK.

    Auto-renders JS-heavy SPA pages (Bugcrowd / H1 / Intigriti briefs) via
    headless chromium when the plain HTTP fetch returns too-short text.
    """
    if program_name:
        app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
        cfg = app.programs.get(program_name)
        if not cfg: raise click.ClickException(f"unknown program: {program_name}")
        url = getattr(cfg, "rules_url", None) or url
        path = getattr(cfg, "rules_text", None) or path
    if not url and not path:
        raise click.UsageError("supply --url URL, --file PATH, or --program NAME")
    if path:
        check = compliance_check_file(path)
    else:
        check = await compliance_check_url(url, force_headless=force_headless,
                                            no_headless=no_headless)  # type: ignore[arg-type]
    click.echo(check.render())
    if check.is_blocking():
        raise SystemExit(2)
    if check.needs_confirmation():
        raise SystemExit(1)


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


@cli.command()
@click.option("--from-jsonl", "from_jsonl", type=click.Path(exists=True, dir_okay=False),
              help="Read live URLs from an httpx-style JSONL file (one probe per line).")
@click.option("--program", "program_name", default=None,
              help="Pull live URLs for this program from the DB instead of a JSONL file.")
@click.option("--concurrency", default=8, show_default=True, type=int)
@click.option("--timeout", default=8.0, show_default=True, type=float)
@click.option("--min-severity", default="info", show_default=True,
              type=click.Choice(list(SEVERITY_ORDER)))
@click.option("--limit", default=80, show_default=True, type=int,
              help="Cap number of findings to print (file output is uncapped).")
@click.option("--out", "out_path", default="data/rocks.jsonl", show_default=True,
              help="JSONL file to write all findings to.")
@click.option("--ignore-compliance", is_flag=True,
              help="Skip the compliance pre-flight (you take responsibility)")
@click.option("--yes", "-y", is_flag=True, help="Auto-confirm WARN/UNCLEAR verdicts")
@click.pass_context
@_coro
async def rocks(ctx: click.Context, from_jsonl: str | None, program_name: str | None,
                concurrency: int, timeout: float, min_severity: str, limit: int,
                out_path: str, ignore_compliance: bool, yes: bool) -> None:
    """Turn over every rock — impact-focused probes (paths/bypass/CORS/Tomcat-CVE/wayback/js-mine) against live URLs."""
    import json as _json
    import pathlib

    # Pre-flight compliance check when running against a configured program
    if program_name:
        app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
        cfg = app.programs.get(program_name)
        if cfg is None:
            raise click.ClickException(f"unknown program: {program_name}")
        await _preflight_compliance(cfg, ignore_compliance, yes)

    probes: list[dict] = []
    if from_jsonl:
        for line in pathlib.Path(from_jsonl).read_text().splitlines():
            if line.strip():
                probes.append(_json.loads(line))
    elif program_name:
        app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
        db = Database(app.global_.database_url)
        try:
            prog = await db.get_program(program_name)
            if not prog:
                raise click.ClickException(f"program {program_name!r} not in DB")
            async with db.session() as s:
                stmt = (select(Finding, Asset)
                        .join(Asset, Finding.asset_id == Asset.id)
                        .where(Asset.program_id == prog.id))
                res = await s.execute(stmt)
                for f, a in res.all():
                    probes.append({
                        "url": f.url, "host": a.hostname,
                        "port": (f.ports or [None])[0],
                        "status_code": f.status_code,
                        "title": f.title, "technologies": f.technologies or [],
                    })
        finally:
            await db.dispose()
    else:
        raise click.UsageError("supply --from-jsonl FILE or --program NAME")

    # Honor per-program rate limit + auth when running via --program.
    program_rate_limit = None
    program_auth: dict[str, str] = {}
    program_in_scope: list[str] = []
    if program_name:
        app = _load_app(ctx.obj["programs_path"], ctx.obj["global_path"])
        cfg = app.programs.get(program_name)
        if cfg:
            if cfg.rate_limit_rps:
                program_rate_limit = cfg.rate_limit_rps
                click.echo(f"[rate-limit] honoring program cap: {program_rate_limit} RPS")
            if cfg.auth_headers:
                program_auth = cfg.auth_headers
                click.echo(f"[auth] propagating headers: {sorted(program_auth.keys())}")
            # Use domain roots as the scope-restriction list. Python rocks
            # probes only send auth headers to hosts ending in one of these.
            program_in_scope = list(cfg.domains)
    progress = ctx.obj.get("progress")
    if progress:
        progress.info(f"[rocks] {len(probes)} probe records loaded")
    else:
        click.echo(f"loaded {len(probes)} probe records → turning rocks")

    scanner = DeepScanner(
        concurrency=concurrency, timeout=timeout,
        rate_limit_rps=program_rate_limit,
        auth_headers=program_auth, in_scope_hosts=program_in_scope,
        progress=progress,
    )
    if progress:
        with progress.phase("rocks (10 probes)"):
            findings = await scanner.scan(probes)
    else:
        findings = await scanner.scan(probes)
    if not progress:
        click.echo(f"rocks produced {len(findings)} findings")

    min_idx = SEVERITY_ORDER.index(min_severity)
    filtered = [f for f in findings if SEVERITY_ORDER.index(f.severity) <= min_idx]
    filtered.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))

    # Write full output to disk
    pathlib.Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as fh:
        for f in findings:
            fh.write(_json.dumps({
                "url": f.url, "probe": f.probe, "signal": f.signal,
                "severity": f.severity, "title": f.title,
                "evidence": f.evidence[:500], "extra": f.extra,
            }) + "\n")
    click.echo(f"wrote {out_path}")

    # Print top N to stdout for the operator
    for f in filtered[:limit]:
        click.echo(f"  [{f.severity.upper():>8}] {f.signal:<28}  {f.url}")
        if f.title and f.title != f.signal:
            click.echo(f"             title: {f.title}")
    if len(filtered) > limit:
        click.echo(f"  ... +{len(filtered) - limit} more (see {out_path})")


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
    sys.exit(0)
