from __future__ import annotations

import re
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)


class InscopeFilter:
    """Filter hostnames against a tomnomnom-style `.scope` regex file.

    Scope file format (tomnomnom/inscope-compatible):
      * One regex per line
      * Lines starting with `!` are excludes (drop on match)
      * Lines starting with `#` or blank lines are ignored

    Semantics:
      * If any exclude regex matches the host → DROPPED
      * If at least one include regex matches → KEPT
      * If includes list is non-empty and no include matches → DROPPED
      * If includes list is empty (only excludes defined) → KEPT-unless-excluded

    Earlier versions shelled out to an external `inscope` binary. That
    flow turned out to be fragile across the two incompatible CLIs that
    ship under the `inscope` name:
      * tomnomnom/inscope (Go) — reads `.scope` from cwd, no flags
      * iceberg-deep/inscope (Python) — `inscope filter --scope PATH`,
        but parses *wildcard-glob* scope files, NOT regex

    Native Python regex matching avoids the format-mismatch foot-gun
    (silent zero-match passthrough when a regex `.scope` is fed to the
    wildcard-only inscope), removes a subprocess per filter call, and
    keeps semantics 100% under bb-sentinel's control.

    The `binary_path` / `timeout` constructor args are retained for
    backwards compatibility with callers but are now unused.
    """

    def __init__(self, binary_path: str | None = None,
                 scope_file: str | None = None,
                 timeout: int = 60) -> None:
        self.binary_path = binary_path  # retained for compat; unused
        self.scope_file = scope_file
        self.timeout = timeout            # retained for compat; unused
        self._includes: list[re.Pattern] = []
        self._excludes: list[re.Pattern] = []
        self._compile()

    def _compile(self) -> None:
        if not self.scope_file or not Path(self.scope_file).exists():
            return
        for ln, raw in enumerate(Path(self.scope_file).read_text().splitlines(), 1):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            try:
                if s.startswith("!"):
                    self._excludes.append(re.compile(s[1:]))
                else:
                    self._includes.append(re.compile(s))
            except re.error as e:
                log.warning("scope file: invalid regex; skipping",
                            file=self.scope_file, line=ln, raw=s, error=str(e))
        log.info("scope rules compiled",
                 file=self.scope_file,
                 includes=len(self._includes),
                 excludes=len(self._excludes))

    def available(self) -> bool:
        return bool(self._includes or self._excludes)

    async def filter(self, items: list[str]) -> tuple[list[str], set[str]]:
        """Return (kept_list, kept_set). If no rules compiled, passthrough."""
        if not items:
            return [], set()
        if not self.available():
            log.debug("scope filter passthrough — no rules",
                      configured=bool(self.scope_file))
            return list(items), set(items)

        kept: list[str] = []
        for h in items:
            if any(e.search(h) for e in self._excludes):
                continue
            # If includes are defined, require at least one to match.
            # If only excludes are defined, any non-excluded host passes.
            if not self._includes or any(i.search(h) for i in self._includes):
                kept.append(h)
        log.info("scope filter applied", input=len(items), kept=len(kept))
        return kept, set(kept)
