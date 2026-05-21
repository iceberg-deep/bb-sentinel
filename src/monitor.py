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
from .discovery.tls_san import TLSSan, extract_registrable_domain
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

    def __init__(self, app: AppConfig, db: Database, sender: WebhookSender | None = None,
                 progress=None) -> None:
        self.app = app
        self.db = db
        self.sender = sender or WebhookSender(timeout=app.global_.webhook_timeout)
        # Optional human-readable progress reporter (see src/progress.py).
        # When None, the scanner stays silent on stdout/stderr — same
        # behavior as before this flag existed.
        self.progress = progress
        g = app.global_
        self.subfinder = Subfinder(binary_path=g.tool("subfinder"))
        self.assetfinder = Assetfinder(binary_path=g.tool("assetfinder"))
        self.crtsh = CrtSh(timeout=g.crtsh_timeout, user_agent=g.user_agent)
        # TLSSan reuses the httpx binary with -tls-grab; SAN extraction
        # from the cert chain. Per-program rate-limit + auth_headers are
        # applied in scan() before invoking discovery (see below).
        self.tls_san = TLSSan(binary_path=g.tool("httpx"))
        self.httpx = HttpxProbe(binary_path=g.tool("httpx"), threads=g.httpx_threads)
        self.nuclei = NucleiTech(binary_path=g.tool("nuclei"), concurrency=g.nuclei_concurrency)

    async def scan(self, program_cfg: ProgramConfig, *, force: bool = False) -> ScanStats:
        stats = ScanStats()
        log.info("scan starting", program=program_cfg.name, domains=program_cfg.domains, force=force)
        program = await self._ensure_program_row(program_cfg)
        run = await self._start_run(program.id)

        # Rebuild active-probe wrappers per-program when there's any
        # program-specific config (rate limit, auth headers) so we don't
        # leak credentials across scans of different programs.
        g = self.app.global_
        if program_cfg.rate_limit_rps is not None or program_cfg.auth_headers:
            if program_cfg.rate_limit_rps is not None:
                log.info("rate-limit applied", program=program_cfg.name,
                         rps=program_cfg.rate_limit_rps)
            if program_cfg.auth_headers:
                log.info("auth-aware probing enabled",
                         program=program_cfg.name,
                         header_names=sorted(program_cfg.auth_headers.keys()))
            self.httpx = HttpxProbe(
                binary_path=g.tool("httpx"), threads=g.httpx_threads,
                rate_limit_rps=program_cfg.rate_limit_rps,
                auth_headers=program_cfg.auth_headers,
            )
            # Apply per-program rate + auth to the SAN-discovery httpx call
            self.tls_san = TLSSan(
                binary_path=g.tool("httpx"),
                rate_limit_rps=program_cfg.rate_limit_rps,
                auth_headers=program_cfg.auth_headers,
            )
            self.nuclei = NucleiTech(
                binary_path=g.tool("nuclei"), concurrency=g.nuclei_concurrency,
                rate_limit_rps=program_cfg.rate_limit_rps,
                auth_headers=program_cfg.auth_headers,
            )

        prog = self.progress
        try:
            scope = InscopeFilter(
                binary_path=self.app.global_.tool("inscope"),
                scope_file=program_cfg.inscope_config,
            )

            # 1) Subdomain discovery (run sources in parallel)
            if prog:
                with prog.phase(f"discovery — {program_cfg.name}"):
                    prog.step("subfinder", "enumerating subdomains…")
                    prog.step("assetfinder", "querying passive sources…")
                    prog.step("crt.sh", "mining CT logs…")
                    disc = await self._gather_subdomains(program_cfg.domains)
                    stats.errors.extend(disc.errors)
                    unique_hosts = sorted({h.hostname for h in disc.hosts if h.hostname})
                    stats.discovered_hosts = len(unique_hosts)
                    prog.metric("unique hostnames", len(unique_hosts))
                    if disc.errors:
                        prog.warn(f"{len(disc.errors)} non-fatal discovery error(s)")
            else:
                disc = await self._gather_subdomains(program_cfg.domains)
                stats.errors.extend(disc.errors)
                unique_hosts = sorted({h.hostname for h in disc.hosts if h.hostname})
                stats.discovered_hosts = len(unique_hosts)

            # 2) Scope filter
            if prog:
                with prog.phase("scope filter"):
                    kept, _ = await scope.filter(unique_hosts)
                    dropped = len(unique_hosts) - len(kept)
                    prog.metric("in-scope", f"{len(kept)} / {len(unique_hosts)}")
                    if dropped:
                        prog.metric("dropped", dropped)
            else:
                kept, _ = await scope.filter(unique_hosts)

            # 3) Persist hostnames — get the new ones
            new_assets = await self.db.add_assets(program.id, kept, source="discovery")
            stats.new_hosts = len(new_assets)

            # 4) Probe with httpx — limit to new hosts + a refresh of known live hosts
            to_probe = sorted({a.hostname for a in new_assets} | await self._refresh_targets(program.id))
            if prog:
                with prog.phase("active probing"):
                    if to_probe:
                        rps_note = f" at {program_cfg.rate_limit_rps} RPS" if program_cfg.rate_limit_rps else ""
                        prog.step("httpx", f"probing {len(to_probe)} hosts{rps_note}…")
                        import time as _t
                        _t0 = _t.monotonic()
                        probes = await self.httpx.probe(to_probe)
                        prog.step("httpx", f"{len(probes)} live hosts responded",
                                  ok=True, duration=_t.monotonic()-_t0)
                        prog.metric("live", len(probes))
                    else:
                        probes = []
                        prog.info("    no hosts to probe (everything already baseline)")
            else:
                probes = await self.httpx.probe(to_probe) if to_probe else []
            stats.live_probes = len(probes)

            # 5) Optional nuclei tech enrichment for new/interesting probes.
            # nuclei timeouts / failures must NOT kill the scan — losing the
            # httpx probes because the *enrichment* step failed is the worst
            # possible outcome. Catch broadly here and fall through with an
            # empty tech map; the scan still records findings from httpx.
            new_host_set = {a.hostname for a in new_assets}
            urls_to_enrich = [p.url for p in probes if p.host in new_host_set and p.url]
            tech_map = {}
            if urls_to_enrich:
                if prog:
                    with prog.phase(f"[{program_cfg.name}] tech enrichment"):
                        prog.step("nuclei", f"detecting tech across {len(urls_to_enrich)} URLs…")
                        try:
                            tech_map = await self.nuclei.detect(urls_to_enrich)
                            hits = sum(1 for v in tech_map.values() if v.technologies)
                            prog.step("nuclei", f"{hits} URLs matched tech templates", ok=True)
                        except Exception as e:
                            prog.warn(f"nuclei timed out / failed — continuing: {str(e)[:120]}")
                            stats.errors.append(f"nuclei enrichment failed: {str(e)[:200]}")
                else:
                    try:
                        tech_map = await self.nuclei.detect(urls_to_enrich)
                    except Exception as e:
                        log.warning("nuclei tech-detect failed — continuing without enrichment",
                                    error=str(e)[:200])
                        stats.errors.append(f"nuclei enrichment failed: {str(e)[:200]}")

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
        # Two-stage discovery:
        #
        # Stage 1: tls-san FIRST (sequential, blocking the others).
        # TLS-SAN is higher-yield than CT-log enumeration on
        # CDN-fronted assets — a single cert commonly carries 50–200
        # SANs, and operational testing shows SANs are 100% reachable
        # vs. ~1-of-3 for typical subfinder-derived internal-named
        # hosts. Running first lets us harvest the SAN list before
        # spending time on slower enumerators.
        #
        # Stage 2: extract registrable-domain (eTLD+1) roots from the
        # SAN set. Any root NOT in the original seed list is novel —
        # the SAN list revealed a registered domain we didn't know to
        # enumerate. Add it to the seed set for subfinder/assetfinder/
        # crt.sh so they enumerate it too.
        #
        # Stage 3: subfinder + assetfinder + crt.sh in parallel against
        # the augmented seed list.
        combined = DiscoveryResult()
        original_roots = {extract_registrable_domain(d) for d in domains}

        san_result = await self.tls_san.discover(domains)
        if isinstance(san_result, Exception):
            combined.errors.append(str(san_result))
        else:
            combined.extend(san_result)

        # Extract novel registrable roots from the SAN set
        novel_roots: set[str] = set()
        for h in combined.hostnames:
            r = extract_registrable_domain(h)
            if r and r not in original_roots:
                novel_roots.add(r)

        # Pre-filter novel roots through the program's scope rules.
        # Without this, a SAN-listed IdP redirect (e.g.,
        # microsoftonline.com on an SSO chain) becomes a novel root
        # and subfinder/crt.sh burn time enumerating someone else's
        # entire surface. Downstream scope filter would drop the
        # results anyway, but pre-filtering at the SEED level saves
        # the enumeration cost.
        in_scope_novel: set[str] = set()
        try:
            from .scope import InscopeFilter
            inscope_path = None
            # Best-effort: find the scope file from any of the loaded programs
            # whose seed roots overlap with these novel roots' parents.
            # Falls back to no-filter if we can't determine.
            for p in self.app.programs.values():
                if p.inscope_config and any(
                        extract_registrable_domain(d) in original_roots
                        for d in p.domains):
                    inscope_path = p.inscope_config
                    break
            if inscope_path:
                sf = InscopeFilter(scope_file=inscope_path)
                kept_novel, _ = await sf.filter(sorted(novel_roots))
                in_scope_novel = set(kept_novel)
            else:
                in_scope_novel = novel_roots
        except Exception as e:
            log.warning("novel-root scope pre-filter failed; using all",
                        error=str(e))
            in_scope_novel = novel_roots

        if novel_roots:
            log.info("novel roots discovered via tls-san",
                     total=len(novel_roots),
                     in_scope=len(in_scope_novel),
                     out_of_scope=len(novel_roots) - len(in_scope_novel),
                     sample=sorted(in_scope_novel)[:10])

        augmented_seeds = sorted(original_roots | in_scope_novel)
        tasks = [
            self.subfinder.discover(augmented_seeds),
            self.assetfinder.discover(augmented_seeds),
            self.crtsh.discover(augmented_seeds),
        ]
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
