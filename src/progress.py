"""
Human-readable progress reporting — the layer between bb-sentinel's
internal structlog (great for debugging, hostile to humans) and the
operator watching a scan run.

Modeled on Claude Code's narration: brief active statements per phase,
counters when work fans out, durations on completion, errors inline
without aborting the report.

Verbosity levels (chosen by CLI flag, plumbed through ctx.obj):

    QUIET    only errors and the final summary line
    NORMAL   one line per phase boundary + final summary (default)
    VERBOSE  + per-step counts, per-tool subprocess statuses
    DEBUG    + raw structlog JSON underneath (configure separately)

The Progress instance is stateless across runs; create one per command
invocation, pass through to the layer doing work. Calls are synchronous
and write to stderr so stdout stays clean for piping/redirect.
"""
from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import IO, Iterator, Literal

Level = Literal["quiet", "normal", "verbose", "debug"]
_LEVEL_RANK = {"quiet": 0, "normal": 1, "verbose": 2, "debug": 3}


@dataclass
class Progress:
    level: Level = "normal"
    stream: IO = field(default_factory=lambda: sys.stderr)
    _t0: float = field(default_factory=time.monotonic)
    _phase_t0: float = 0.0
    _phase_label: str = ""
    _use_color: bool = field(default_factory=lambda: sys.stderr.isatty())

    # -- visibility helpers ------------------------------------------------

    def _at(self, lvl: Level) -> bool:
        return _LEVEL_RANK[self.level] >= _LEVEL_RANK[lvl]

    def _c(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self._use_color else text

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        if seconds < 1:    return f"{seconds*1000:.0f}ms"
        if seconds < 60:   return f"{seconds:.1f}s"
        m, s = divmod(seconds, 60)
        return f"{int(m)}m {s:.0f}s"

    def _emit(self, line: str) -> None:
        self.stream.write(line + "\n")
        self.stream.flush()

    # -- phase API ---------------------------------------------------------

    @contextmanager
    def phase(self, label: str) -> Iterator["Progress"]:
        """Bracket a major phase. Emits header at open, summary at close."""
        if self._at("normal"):
            self._phase_label = label
            self._phase_t0 = time.monotonic()
            self._emit(self._c("36;1", f"⠿ {label}"))
        try:
            yield self
        except Exception as e:
            self.fail(f"{label}: {type(e).__name__}: {e}")
            raise
        else:
            if self._at("normal"):
                dur = time.monotonic() - self._phase_t0
                self._emit(self._c("32", f"  ✓ done in {self._fmt_duration(dur)}"))

    def step(self, name: str, status: str = "starting...", *, ok: bool | None = None,
              detail: str = "") -> None:
        """One step inside a phase. ``ok=True`` adds ✓, ``ok=False`` adds ✗.
        Only emits at NORMAL+ for ok=True/None, always emits errors."""
        if ok is False:
            mark = self._c("31", "✗")
            self._emit(f"  {mark} {name}: {status} {detail}".rstrip())
            return
        if not self._at("normal"):
            return
        mark = self._c("32", "✓") if ok is True else self._c("90", "·")
        line = f"  {mark} {name:<18} {status}"
        if detail and self._at("verbose"):
            line += f"  {self._c('90', detail)}"
        self._emit(line)

    def detail(self, text: str) -> None:
        """Verbose-level subordinate detail (counts, sub-step status)."""
        if not self._at("verbose"):
            return
        self._emit(f"    {self._c('90', text)}")

    def info(self, text: str) -> None:
        """Plain info line — emits at NORMAL+ without indent decoration."""
        if not self._at("normal"):
            return
        self._emit(text)

    def fail(self, reason: str) -> None:
        """Hard error. Always emits regardless of level."""
        self._emit(self._c("31;1", f"  ✗ ERROR: {reason}"))

    def warn(self, reason: str) -> None:
        """Soft warning (something didn't go as planned but scan continues)."""
        if not self._at("normal"):
            return
        self._emit(self._c("33", f"  ⚠ {reason}"))

    def summary(self, *, lines: list[str]) -> None:
        """Final block at the end of a command — emitted in every mode
        except quiet (quiet still shows the final summary)."""
        total = self._fmt_duration(time.monotonic() - self._t0)
        if self._at("normal"):
            self._emit("")
        # Always print summary header
        self._emit(self._c("36;1", f"━━━ summary  ({total}) ━━━"))
        for line in lines:
            self._emit(line)


# Module-level helpers so callers don't have to thread the instance
# manually when they just want a single phase block. For the main scan
# pipeline, prefer explicit instances stored on the scanner.

def make_progress(level: Level = "normal") -> Progress:
    return Progress(level=level)
