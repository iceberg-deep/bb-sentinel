from __future__ import annotations

import asyncio
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)


@dataclass
class HostResult:
    hostname: str
    source: str


@dataclass
class DiscoveryResult:
    hosts: list[HostResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def hostnames(self) -> list[str]:
        return [h.hostname for h in self.hosts]

    def extend(self, other: "DiscoveryResult") -> None:
        self.hosts.extend(other.hosts)
        self.errors.extend(other.errors)


class Discoverer(ABC):
    """Abstract base for any discovery component (subdomain enum, probing, tech detection)."""

    name: str = "discoverer"
    binary: str | None = None

    def __init__(self, binary_path: str | None = None, timeout: int = 600) -> None:
        self.binary_path = binary_path or self.binary or self.name
        self.timeout = timeout

    def is_available(self) -> bool:
        return shutil.which(self.binary_path) is not None

    @abstractmethod
    async def discover(self, domains: list[str]) -> DiscoveryResult:
        """Discover hostnames for the given root domains."""

    async def _run_cmd(self, cmd: list[str], stdin: bytes | None = None) -> tuple[int, bytes, bytes]:
        """Run a subprocess, capturing stdout/stderr. Returns (rc, stdout, stderr)."""
        log.debug("running command", cmd=cmd)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(input=stdin), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(f"command timed out after {self.timeout}s: {cmd[0]}")
        return proc.returncode or 0, stdout, stderr
