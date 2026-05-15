from __future__ import annotations

import structlog

from .base import Discoverer, DiscoveryResult, HostResult

log = structlog.get_logger(__name__)


class Subfinder(Discoverer):
    name = "subfinder"
    binary = "subfinder"

    async def discover(self, domains: list[str]) -> DiscoveryResult:
        result = DiscoveryResult()
        if not domains:
            return result
        if not self.is_available():
            result.errors.append(f"{self.binary_path} not found on PATH")
            return result

        cmd = [self.binary_path, "-silent", "-all", "-nW", "-dL", "-"]
        rc, stdout, stderr = await self._run_cmd(cmd, stdin="\n".join(domains).encode())
        if rc != 0:
            result.errors.append(f"subfinder rc={rc}: {stderr.decode(errors='replace').strip()[:300]}")
            return result

        for line in stdout.decode(errors="replace").splitlines():
            host = line.strip().lower()
            if host:
                result.hosts.append(HostResult(hostname=host, source=self.name))
        log.info("subfinder done", count=len(result.hosts))
        return result
