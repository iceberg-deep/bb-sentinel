from __future__ import annotations

import structlog

from .base import Discoverer, DiscoveryResult, HostResult

log = structlog.get_logger(__name__)


class Assetfinder(Discoverer):
    name = "assetfinder"
    binary = "assetfinder"

    async def discover(self, domains: list[str]) -> DiscoveryResult:
        result = DiscoveryResult()
        if not domains:
            return result
        if not self.is_available():
            result.errors.append(f"{self.binary_path} not found on PATH")
            return result

        for domain in domains:
            cmd = [self.binary_path, "-subs-only", domain]
            rc, stdout, stderr = await self._run_cmd(cmd)
            if rc != 0:
                result.errors.append(
                    f"assetfinder {domain} rc={rc}: {stderr.decode(errors='replace').strip()[:200]}"
                )
                continue
            for line in stdout.decode(errors="replace").splitlines():
                host = line.strip().lower()
                if host:
                    result.hosts.append(HostResult(hostname=host, source=self.name))
        log.info("assetfinder done", count=len(result.hosts))
        return result
