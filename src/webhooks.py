from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

import httpx
import structlog
from tenacity import AsyncRetrying, stop_after_attempt, wait_exponential

from .config import WebhookConfig

log = structlog.get_logger(__name__)


@dataclass
class AssetPayload:
    url: str
    technologies: list[str] = field(default_factory=list)
    priority_score: float = 0.0
    inscope_verified: bool = False
    status_code: int | None = None
    title: str | None = None
    port: int | None = None

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "technologies": self.technologies,
            "priority_score": self.priority_score,
            "inscope_verified": self.inscope_verified,
            "status_code": self.status_code,
            "title": self.title,
            "port": self.port,
        }


def build_payload(program: str, assets: Iterable[AssetPayload]) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "program": program,
        "assets": [a.to_dict() for a in assets],
    }


class WebhookSender:
    def __init__(self, timeout: int = 15) -> None:
        self.timeout = timeout

    async def send_program(
        self,
        program: str,
        assets: list[AssetPayload],
        webhooks: list[WebhookConfig],
    ) -> list[tuple[WebhookConfig, bool, str]]:
        """Send the payload to every webhook whose threshold is met. Returns per-hook results."""
        results: list[tuple[WebhookConfig, bool, str]] = []
        if not assets or not webhooks:
            return results
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            tasks = []
            relevant: list[WebhookConfig] = []
            for hook in webhooks:
                filtered = [a for a in assets if a.priority_score >= hook.priority_threshold]
                if not filtered:
                    continue
                payload = build_payload(program, filtered)
                tasks.append(self._send_one(client, hook, payload))
                relevant.append(hook)
            if not tasks:
                return results
            sent = await asyncio.gather(*tasks, return_exceptions=True)
            for hook, outcome in zip(relevant, sent):
                if isinstance(outcome, Exception):
                    results.append((hook, False, str(outcome)))
                else:
                    results.append((hook, True, outcome))
        return results

    async def _send_one(self, client: httpx.AsyncClient, hook: WebhookConfig, payload: dict) -> str:
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(3),
            wait=wait_exponential(min=1, max=10),
            reraise=True,
        ):
            with attempt:
                r = await client.post(hook.url, json=payload, headers=hook.headers or None)
                r.raise_for_status()
                log.info(
                    "webhook sent",
                    hook=hook.name or hook.url,
                    status=r.status_code,
                    assets=len(payload.get("assets") or []),
                )
                return f"{r.status_code}"
        return "unknown"
