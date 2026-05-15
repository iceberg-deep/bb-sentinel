from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable

import structlog
from sqlalchemy import select

from .config import AppConfig, ProgramConfig, WebhookConfig, parse_frequency
from .database import Asset, Database, Finding, Program, ScanRun, utcnow
from .discovery import Assetfinder, CrtSh, DiscoveryResult, HttpxProbe, NucleiTech, Subfinder
from .scope import InscopeFilter
from .scoring import score_finding
from .webhooks import AssetPayload, WebhookSender

log = structlog.get_logger(__name__)


@dataclass
class ScanStats:
    discovered_hosts: int = 0
    new_hosts: int = 0
    live_probes: int = 0
    new_findings: int = 0
    alerts_sent: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "discovered_hosts": self.discovered_hosts,
            "new_hosts": self.new_hosts,
            "live_probes": self.live_probes,
            "new_findings": self.new_findings,
            "alerts_sent": self.alerts_sent,
            "errors": self.errors[:10],
        }


class ProgramScanner:
    """Runs one end-to-end scan for a single program."""

    def __init__(self, app: AppConfig, db: Database, sender: WebhookSender | None = None) -> None:
        self.app = app
        self.db = db
        self.sender = sender or WebhookSender(timeout=app.global_.webhook_timeout)
        g = app.global_
        self.subfinder = Subfinder(binary_path=g.tool("subfinder"))
        self.assetfinder = Assetfinder(binary_path=g.tool("assetfinder"))
        self.crtsh = CrtSh(timeout=g.crtsh_timeout, user_agent=g.user_agent)
        self.httpx = HttpxProbe(binary_path=g.tool("httpx"), threads=g.httpx_threads)
        self.nuclei = NucleiTech(binary_path=g.tool("nuclei"), concurrency=g.nuclei_concurrency)

    async def scan(self, program_cfg: ProgramConfig, *, force: bool = False) -> ScanStats:
        stats = ScanStats()
        log.info("scan starting", program=program_cfg.name, domains=program_cfg.domains, force=force)
        program = await self._ensure_program_row(program_cfg)
        run = await self._start_run(program.id)

        try:
            scope = InscopeFilter(
                binary_path=self.app.global_.tool("inscope"),
                scope_file=program_cfg.inscope_config,
            )

            # 1) Subdomain discovery (run sources in parallel)
            disc = await self._gather_subdomains(program_cfg.domains)
            stats.errors.extend(disc.errors)
            unique_hosts = sorted({h.hostname for h in disc.hosts if h.hostname})
            stats.discovered_hosts = len(unique_hosts)

            # 2) Scope filter
            kept, _ = await scope.filter(unique_hosts)

            # 3) Persist hostnames — get the new ones
            new_assets = await self.db.add_assets(program.id, kept, source="discovery")
            stats.new_hosts = len(new_assets)

            # 4) Probe with httpx — limit to new hosts + a refresh of known live hosts
            to_probe = sorted({a.hostname for a in new_assets} | await self._refresh_targets(program.id))
            probes = await self.httpx.probe(to_probe) if to_probe else []
            stats.live_probes = len(probes)

            # 5) Optional nuclei tech enrichment for new/interesting probes
            new_host_set = {a.hostname for a in new_assets}
            urls_to_enrich = [p.url for p in probes if p.host in new_host_set and p.url]
            tech_map = await self.nuclei.detect(urls_to_enrich) if urls_to_enrich else {}

            # 6) Persist findings + score + collect alerts
            alerts = await self._record_findings(program.id, probes, tech_map, scope_kept=set(kept))
            stats.new_findings = len(alerts)

            # 7) Dispatch webhooks
            hook_cfgs = _hooks_from_cfg(program_cfg.webhooks)
            if alerts and hook_cfgs:
                results = await self.sender.send_program(program_cfg.name, alerts, hook_cfgs)
                stats.alerts_sent = sum(1 for _, ok, _ in results if ok)
                if not stats.alerts_sent:
                    stats.errors.extend(msg for _, ok, msg in results if not ok)
                else:
                    await self._mark_alerted(program.id, [a.url for a in alerts])

            await self._finish_run(run.id, "ok", stats)
            await self._touch_program(program.id, program_cfg.scan_interval_seconds)
            log.info("scan finished", program=program_cfg.name, **stats.to_dict())
            return stats
        except Exception as e:
            log.exception("scan failed", program=program_cfg.name, error=str(e))
            stats.errors.append(str(e))
            await self._finish_run(run.id, "error", stats, error=str(e))
            await self._touch_program(program.id, program_cfg.scan_interval_seconds)
            return stats

    async def _gather_subdomains(self, domains: list[str]) -> DiscoveryResult:
        tasks = [
            self.subfinder.discover(domains),
            self.assetfinder.discover(domains),
            self.crtsh.discover(domains),
        ]
        combined = DiscoveryResult()
        for res in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(res, Exception):
                combined.errors.append(str(res))
                continue
            combined.extend(res)
        return combined

    async def _refresh_targets(self, program_id: int) -> set[str]:
        """Optionally probe a sample of known hosts so findings stay fresh.

        For now: nothing extra — keep scans focused on new surface.
        """
        return set()

    async def _record_findings(
        self,
        program_id: int,
        probes: list,
        tech_map: dict,
        scope_kept: set[str],
    ) -> list[AssetPayload]:
        alerts: list[AssetPayload] = []
        if not probes:
            return alerts
        async with self.db.session() as s:
            res = await s.execute(select(Asset).where(Asset.program_id == program_id))
            host_to_asset = {a.hostname: a for a in res.scalars().all()}

            now = utcnow()
            for p in probes:
                asset = host_to_asset.get(p.host)
                if asset is None:
                    asset = Asset(program_id=program_id, hostname=p.host, first_seen=now, last_seen=now)
                    s.add(asset)
                    await s.flush()
                    host_to_asset[p.host] = asset
                asset.alive = True
                asset.last_seen = now
                asset.inscope = (p.host in scope_kept) if scope_kept else True

                tech = list(dict.fromkeys((p.technologies or []) + (tech_map.get(p.url).technologies if tech_map.get(p.url) else [])))
                breakdown = score_finding(
                    url=p.url,
                    technologies=tech,
                    port=p.port,
                    discovered_at=now,
                    status_code=p.status_code,
                )

                f_res = await s.execute(select(Finding).where(Finding.asset_id == asset.id, Finding.url == p.url))
                existing = f_res.scalar_one_or_none()
                if existing is None:
                    finding = Finding(
                        asset_id=asset.id,
                        url=p.url,
                        status_code=p.status_code,
                        title=p.title,
                        technologies=tech,
                        ports=[p.port] if p.port else [],
                        priority_score=breakdown.score,
                        inscope_verified=asset.inscope,
                        discovered_at=now,
                        last_seen_at=now,
                        alerted=False,
                        raw=p.raw,
                    )
                    s.add(finding)
                    alerts.append(
                        AssetPayload(
                            url=p.url,
                            technologies=tech,
                            priority_score=breakdown.score,
                            inscope_verified=asset.inscope,
                            status_code=p.status_code,
                            title=p.title,
                            port=p.port,
                        )
                    )
                else:
                    existing.last_seen_at = now
                    existing.technologies = tech or existing.technologies
                    existing.priority_score = max(existing.priority_score, breakdown.score)
            await s.commit()
        return alerts

    async def _mark_alerted(self, program_id: int, urls: Iterable[str]) -> None:
        urls_list = list(urls)
        if not urls_list:
            return
        async with self.db.session() as s:
            res = await s.execute(
                select(Finding).join(Asset).where(Asset.program_id == program_id, Finding.url.in_(urls_list))
            )
            for f in res.scalars().all():
                f.alerted = True
            await s.commit()

    async def _ensure_program_row(self, cfg: ProgramConfig) -> Program:
        return await self.db.upsert_program(
            name=cfg.name,
            domains=cfg.domains,
            inscope_config=cfg.inscope_config,
            scan_frequency=cfg.scan_frequency,
            webhooks=[w.model_dump() for w in cfg.webhooks],
            enabled=cfg.enabled,
        )

    async def _start_run(self, program_id: int) -> ScanRun:
        async with self.db.session() as s:
            run = ScanRun(program_id=program_id, status="running")
            s.add(run)
            await s.commit()
            await s.refresh(run)
            return run

    async def _finish_run(self, run_id: int, status: str, stats: ScanStats, error: str | None = None) -> None:
        async with self.db.session() as s:
            res = await s.execute(select(ScanRun).where(ScanRun.id == run_id))
            run = res.scalar_one()
            run.status = status
            run.error = error
            run.stats = stats.to_dict()
            run.finished_at = utcnow()
            await s.commit()

    async def _touch_program(self, program_id: int, interval_seconds: int) -> None:
        async with self.db.session() as s:
            res = await s.execute(select(Program).where(Program.id == program_id))
            p = res.scalar_one()
            now = utcnow()
            p.last_scan_at = now
            p.next_scan_at = now + timedelta(seconds=interval_seconds)
            await s.commit()


def _hooks_from_cfg(hooks: list[WebhookConfig]) -> list[WebhookConfig]:
    return list(hooks or [])


class MonitorLoop:
    """Continuously dispatch scans across programs with bounded concurrency."""

    def __init__(self, app: AppConfig, db: Database) -> None:
        self.app = app
        self.db = db
        self.scanner = ProgramScanner(app, db)
        self.semaphore = asyncio.Semaphore(app.global_.concurrency)
        self._stop = asyncio.Event()

    def request_stop(self) -> None:
        self._stop.set()

    async def run_forever(self, tick_seconds: int = 30) -> None:
        log.info(
            "monitor loop starting",
            programs=list(self.app.programs.keys()),
            concurrency=self.app.global_.concurrency,
        )
        # Ensure all configured programs exist in the DB up front.
        for cfg in self.app.programs.values():
            await self.scanner._ensure_program_row(cfg)

        running: set[asyncio.Task] = set()
        while not self._stop.is_set():
            now = utcnow()
            for cfg in list(self.app.programs.values()):
                if not cfg.enabled:
                    continue
                if any(t.get_name() == cfg.name for t in running):
                    continue
                prog = await self.db.get_program(cfg.name)
                if prog and prog.next_scan_at and prog.next_scan_at > now:
                    continue
                task = asyncio.create_task(self._guarded_scan(cfg), name=cfg.name)
                running.add(task)
                task.add_done_callback(running.discard)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=tick_seconds)
            except asyncio.TimeoutError:
                pass

        if running:
            log.info("waiting for in-flight scans", count=len(running))
            await asyncio.gather(*running, return_exceptions=True)

    async def _guarded_scan(self, cfg: ProgramConfig) -> None:
        async with self.semaphore:
            try:
                await self.scanner.scan(cfg)
            except Exception:
                log.exception("scan crashed", program=cfg.name)


__all__ = ["MonitorLoop", "ProgramScanner", "ScanStats", "parse_frequency"]
