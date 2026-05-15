from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)


class InscopeFilter:
    """Wrap the `inscope` CLI to filter a stream of hostnames/URLs against a scope file.

    tomnomnom's `inscope` reads a literal `.scope` file from cwd (no CLI flags), so we
    stage the configured scope file as `.scope` in a temp dir and run with that as cwd.
    When the binary is missing or no scope file is configured, the filter is pass-through.
    """

    def __init__(self, binary_path: str = "inscope", scope_file: str | None = None, timeout: int = 60) -> None:
        self.binary_path = binary_path
        self.scope_file = scope_file
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.scope_file) and Path(self.scope_file).exists() and shutil.which(self.binary_path) is not None

    async def filter(self, items: list[str]) -> tuple[list[str], set[str]]:
        """Return (kept, kept_set). If unavailable, everything is kept."""
        if not items:
            return [], set()
        if not self.available():
            log.debug("inscope unavailable — passthrough", configured=bool(self.scope_file))
            return list(items), set(items)

        scope_content = Path(self.scope_file).read_text()  # type: ignore[arg-type]
        with tempfile.TemporaryDirectory(prefix="bb-inscope-") as tmpdir:
            (Path(tmpdir) / ".scope").write_text(scope_content)
            proc = await asyncio.create_subprocess_exec(
                self.binary_path,
                cwd=tmpdir,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input="\n".join(items).encode()), timeout=self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                log.error("inscope timed out — failing open", count=len(items))
                return list(items), set(items)
            if proc.returncode != 0:
                log.error(
                    "inscope failed — failing open",
                    rc=proc.returncode,
                    stderr=stderr.decode(errors="replace")[:200],
                )
                return list(items), set(items)
            kept = [line.strip() for line in stdout.decode(errors="replace").splitlines() if line.strip()]
            kept_set = set(kept)
            log.info("inscope filter applied", input=len(items), kept=len(kept))
            return kept, kept_set
