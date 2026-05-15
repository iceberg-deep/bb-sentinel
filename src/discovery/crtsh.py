from __future__ import annotations

import httpx
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import Discoverer, DiscoveryResult, HostResult

log = structlog.get_logger(__name__)


class CrtSh(Discoverer):
    """crt.sh certificate transparency client. Does not require a binary."""

    name = "crtsh"
    binary = None

    def __init__(self, timeout: int = 30, user_agent: str = "bb-sentinel/0.1") -> None:
        super().__init__(binary_path="-", timeout=timeout)
        self.user_agent = user_agent

    def is_available(self) -> bool:
        return True

    async def discover(self, domains: list[str]) -> DiscoveryResult:
        result = DiscoveryResult()
        if not domains:
            return result
        async with httpx.AsyncClient(
            timeout=self.timeout, headers={"User-Agent": self.user_agent}
        ) as client:
            for domain in domains:
                try:
                    hosts = await self._query(client, domain)
                except Exception as e:
                    result.errors.append(f"crtsh {domain}: {e}")
                    continue
                for h in hosts:
                    result.hosts.append(HostResult(hostname=h, source=self.name))
        log.info("crtsh done", count=len(result.hosts))
        return result

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10), reraise=True)
    async def _query(self, client: httpx.AsyncClient, domain: str) -> set[str]:
        url = "https://crt.sh/"
        r = await client.get(url, params={"q": f"%.{domain}", "output": "json"})
        r.raise_for_status()
        try:
            data = r.json()
        except Exception:
            return set()
        out: set[str] = set()
        for entry in data or []:
            name_value = entry.get("name_value") or ""
            for line in name_value.splitlines():
                h = line.strip().lower().lstrip("*.")
                if h and "*" not in h and (h == domain or h.endswith("." + domain)):
                    out.add(h)
        return out
