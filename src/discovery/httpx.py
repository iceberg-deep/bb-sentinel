from __future__ import annotations

import json
from dataclasses import dataclass, field

import structlog

from .base import Discoverer, DiscoveryResult, HostResult

log = structlog.get_logger(__name__)


@dataclass
class ProbeResult:
    url: str
    host: str
    status_code: int | None = None
    title: str | None = None
    technologies: list[str] = field(default_factory=list)
    port: int | None = None
    raw: dict = field(default_factory=dict)


class HttpxProbe(Discoverer):
    """Wraps projectdiscovery `httpx` to probe live hosts and return enriched results."""

    name = "httpx"
    binary = "httpx"

    def __init__(self, binary_path: str | None = None, threads: int = 50, timeout: int = 600) -> None:
        super().__init__(binary_path=binary_path, timeout=timeout)
        self.threads = threads

    async def probe(self, hostnames: list[str]) -> list[ProbeResult]:
        if not hostnames:
            return []
        if not self.is_available():
            log.warning("httpx binary not available", binary=self.binary_path)
            return []

        cmd = [
            self.binary_path,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-no-color",
            "-threads",
            str(self.threads),
        ]
        rc, stdout, stderr = await self._run_cmd(cmd, stdin="\n".join(hostnames).encode())
        if rc != 0 and not stdout:
            log.error("httpx failed", rc=rc, stderr=stderr.decode(errors="replace")[:300])
            return []

        results: list[ProbeResult] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = obj.get("url") or ""
            host = obj.get("host") or obj.get("input") or ""
            port_str = obj.get("port")
            try:
                port = int(port_str) if port_str else None
            except (TypeError, ValueError):
                port = None
            results.append(
                ProbeResult(
                    url=url,
                    host=host,
                    status_code=obj.get("status_code") or obj.get("status-code"),
                    title=obj.get("title"),
                    technologies=list(obj.get("tech") or obj.get("technologies") or []),
                    port=port,
                    raw=obj,
                )
            )
        log.info("httpx done", probed=len(results))
        return results

    async def discover(self, domains: list[str]) -> DiscoveryResult:
        """When asked to discover, treat input as candidate hosts and return only the live ones."""
        result = DiscoveryResult()
        probes = await self.probe(domains)
        for p in probes:
            if p.host:
                result.hosts.append(HostResult(hostname=p.host, source=self.name))
            result.raw.setdefault("probes", []).append(p.raw)
        return result
