from __future__ import annotations

import json
from dataclasses import dataclass, field

import structlog

from .base import Discoverer, DiscoveryResult, HostResult

log = structlog.get_logger(__name__)


@dataclass
class TechResult:
    url: str
    technologies: list[str] = field(default_factory=list)
    raw: list[dict] = field(default_factory=list)


class NucleiTech(Discoverer):
    """Wrapper for nuclei's technology-detection templates (-t http/technologies)."""

    name = "nuclei"
    binary = "nuclei"

    def __init__(
        self,
        binary_path: str | None = None,
        concurrency: int = 25,
        templates: str = "http/technologies",
        timeout: int = 1200,
    ) -> None:
        super().__init__(binary_path=binary_path, timeout=timeout)
        self.concurrency = concurrency
        self.templates = templates

    async def detect(self, urls: list[str]) -> dict[str, TechResult]:
        out: dict[str, TechResult] = {u: TechResult(url=u) for u in urls}
        if not urls:
            return out
        if not self.is_available():
            log.warning("nuclei binary not available", binary=self.binary_path)
            return out

        cmd = [
            self.binary_path,
            "-silent",
            "-jsonl",
            "-no-color",
            "-disable-update-check",
            "-t",
            self.templates,
            "-c",
            str(self.concurrency),
        ]
        rc, stdout, stderr = await self._run_cmd(cmd, stdin="\n".join(urls).encode())
        if rc != 0 and not stdout:
            err = stderr.decode(errors="replace")
            if "no templates" in err.lower() or "no templates provided" in err.lower():
                log.warning(
                    "nuclei templates not installed — skipping tech enrichment. "
                    "Run `nuclei -update-templates` to enable.",
                )
            else:
                log.error("nuclei failed", rc=rc, stderr=err[:300])
            return out

        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            matched_at = obj.get("matched-at") or obj.get("host") or obj.get("matched") or ""
            tech = obj.get("info", {}).get("name") or obj.get("template-id") or "unknown"
            entry = out.setdefault(matched_at, TechResult(url=matched_at))
            if tech and tech not in entry.technologies:
                entry.technologies.append(tech)
            entry.raw.append(obj)
        log.info("nuclei done", urls=len(urls))
        return out

    async def discover(self, domains: list[str]) -> DiscoveryResult:
        result = DiscoveryResult()
        detections = await self.detect(domains)
        for url, tech in detections.items():
            if tech.technologies:
                result.hosts.append(HostResult(hostname=url, source=self.name))
                result.raw.setdefault("tech", {})[url] = tech.technologies
        return result
