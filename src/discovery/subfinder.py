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

        # subfinder takes `-d a,b,c` for inline domains (no stdin support — `-dL`
        # expects a file path, not `-`). -nW drops wildcard DNS noise. We avoid
        # `-all` since it queries 30+ sources (many slow or key-gated) and blows
        # past sane scan budgets; the default ~6 sources cover most of the value.
        cmd = [self.binary_path, "-silent", "-nW", "-duc", "-timeout", "20", "-d", ",".join(domains)]
        rc, stdout, stderr = await self._run_cmd(cmd)
        if rc != 0:
            result.errors.append(f"subfinder rc={rc}: {stderr.decode(errors='replace').strip()[:300]}")
            return result

        for line in stdout.decode(errors="replace").splitlines():
            host = line.strip().lower()
            if host:
                result.hosts.append(HostResult(hostname=host, source=self.name))
        log.info("subfinder done", count=len(result.hosts))
        return result
