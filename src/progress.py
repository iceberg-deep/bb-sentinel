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

Color palette (256-color where possible, with ANSI fallback):

    headers           bright cyan, bold
    phase marker      ▸  cyan
    step name         white
    running indicator ·  dim gray
    ✓ success         bright green
    ⚠ warning         bright yellow
    ✗ error           bright red, bold
    counts            bright cyan
    durations         dim gray, right-aligned
    rules             dim gray

Auto-disables color when stderr is not a TTY (so log files / pipes are
plain text).
"""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import IO, Iterator, Literal

Level = Literal["quiet", "normal", "verbose", "debug"]
_LEVEL_RANK = {"quiet": 0, "normal": 1, "verbose": 2, "debug": 3}

# ANSI escape sequences. Using bright variants (90+ for fg, 100+ for bg)
# so output reads well on both light and dark terminal themes.
_C = {
    "reset":   "\x1b[0m",
    "bold":    "\x1b[1m",
    "dim":     "\x1b[2m",
    "italic":  "\x1b[3m",
    "rule":    "\x1b[38;5;240m",   # 256-color dim gray
    "header":  "\x1b[38;5;51;1m",  # bright cyan bold
    "phase":   "\x1b[38;5;87m",    # cyan
    "step":    "\x1b[38;5;253m",   # near-white
    "running": "\x1b[38;5;244m",   # mid gray
    "ok":      "\x1b[38;5;120m",   # bright green
    "warn":    "\x1b[38;5;221m",   # bright yellow
    "err":     "\x1b[38;5;203;1m", # bright red bold
    "count":   "\x1b[38;5;117m",   # cyan emphasis
    "duration":"\x1b[38;5;240m",   # dim gray
    "label":   "\x1b[38;5;110m",   # soft blue label
}

# Symbols (chosen to render in most terminals; ASCII fallbacks where unicode
# fails would be a nice-to-have but unicode is the default these days).
_SYM = {
    "rule":      "━",
    "phase":     "▸",
    "running":   "·",
    "ok":        "✓",
    "warn":      "▲",
    "err":       "✗",
    "indent":    "  ",
    "double_in": "    ",
    "arrow":     "↳",
}


@dataclass
class Progress:
    level: Level = "normal"
    stream: IO = field(default_factory=lambda: sys.stderr)
    _t0: float = field(default_factory=time.monotonic)
    _phase_t0: float = 0.0
    _phase_label: str = ""
    _use_color: bool = field(default_factory=lambda: sys.stderr.isatty() and
                                                   not os.environ.get("NO_COLOR"))
    _step_width: int = 16   # left-align name column for clean scanning
    _ruler_width: int = 60  # how wide the ━ rules are

    # -- helpers -----------------------------------------------------------

    def _at(self, lvl: Level) -> bool:
        return _LEVEL_RANK[self.level] >= _LEVEL_RANK[lvl]

    def _c(self, key: str, text: str) -> str:
        if not self._use_color or key not in _C:
            return text
        return f"{_C[key]}{text}{_C['reset']}"

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        if seconds < 1:    return f"{seconds*1000:.0f}ms"
        if seconds < 10:   return f"{seconds:.1f}s"
        if seconds < 60:   return f"{seconds:.0f}s"
        m, s = divmod(seconds, 60)
        if m < 60:         return f"{int(m)}m {s:.0f}s"
        h, m = divmod(m, 60)
        return f"{int(h)}h {int(m)}m"

    def _emit(self, line: str = "") -> None:
        self.stream.write(line + "\n")
        self.stream.flush()

    def _rule(self) -> str:
        return self._c("rule", _SYM["rule"] * self._ruler_width)

    # -- top-level banner --------------------------------------------------

    def banner(self, command: str) -> None:
        """Optional top-of-run header. Most commands won't call this."""
        if not self._at("normal"):
            return
        self._emit()
        self._emit(self._rule())
        self._emit(f"  {self._c('header', 'bb-sentinel')} {self._c('rule', '·')} "
                   f"{self._c('phase', command)}")
        self._emit(self._rule())
        self._emit()

    # -- phase API ---------------------------------------------------------

    @contextmanager
    def phase(self, label: str) -> Iterator["Progress"]:
        """Bracket a major phase. Emits header at open, summary at close."""
        if self._at("normal"):
            self._phase_label = label
            self._phase_t0 = time.monotonic()
            self._emit(f"{self._c('phase', _SYM['phase'])} "
                       f"{self._c('header', label)}")
        try:
            yield self
        except Exception as e:
            self.fail(f"{label}: {type(e).__name__}: {e}")
            raise
        else:
            if self._at("normal"):
                dur = self._fmt_duration(time.monotonic() - self._phase_t0)
                self._emit(f"{_SYM['indent']}{self._c('ok', _SYM['ok'])} "
                           f"{self._c('duration', dur)}")
                self._emit()

    def step(self, name: str, status: str = "starting...", *, ok: bool | None = None,
              detail: str = "", duration: float | None = None) -> None:
        """One step inside a phase.

        ``ok=True``  → ✓ green
        ``ok=False`` → ✗ red (always emitted regardless of level)
        ``ok=None``  → · running (gray, only at NORMAL+)
        """
        if ok is False:
            mark = self._c("err", _SYM["err"])
            line = f"{_SYM['indent']}{mark}  {self._c('step', name):<{self._step_width}}  {status}"
            if detail:
                line += f"  {self._c('err', detail)}"
            self._emit(line)
            return
        if not self._at("normal"):
            return
        if ok is True:
            mark = self._c("ok", _SYM["ok"])
        else:
            mark = self._c("running", _SYM["running"])
        name_col = f"{name:<{self._step_width}}"
        line = (f"{_SYM['indent']}{mark}  "
                f"{self._c('step' if ok else 'running', name_col)}  "
                f"{self._c('step' if ok else 'running', status)}")
        if duration is not None:
            line += f"  {self._c('duration', f'({self._fmt_duration(duration)})')}"
        if detail and self._at("verbose"):
            line += f"  {self._c('duration', detail)}"
        self._emit(line)

    def metric(self, label: str, value: str | int) -> None:
        """Phase result line: highlighted count, label, indented under phase.

        Use after a step completes to summarize. e.g. metric("hostnames", 4084).
        """
        if not self._at("normal"):
            return
        val = self._c("count", str(value))
        lab = self._c("label", label)
        self._emit(f"{_SYM['indent']}{self._c('rule', _SYM['arrow'])}  {lab}: {val}")

    def detail(self, text: str) -> None:
        """Verbose-level subordinate detail (counts, sub-step status)."""
        if not self._at("verbose"):
            return
        self._emit(f"{_SYM['double_in']}{self._c('duration', text)}")

    def info(self, text: str) -> None:
        """Plain info line — emits at NORMAL+ without indent decoration."""
        if not self._at("normal"):
            return
        self._emit(text)

    def fail(self, reason: str) -> None:
        """Hard error. Always emits regardless of level."""
        self._emit(f"{_SYM['indent']}{self._c('err', _SYM['err'])}  "
                   f"{self._c('err', 'ERROR:')} {reason}")

    def warn(self, reason: str) -> None:
        """Soft warning (something didn't go as planned but scan continues)."""
        if not self._at("normal"):
            return
        self._emit(f"{_SYM['indent']}{self._c('warn', _SYM['warn'])}  "
                   f"{self._c('warn', reason)}")

    def summary(self, *, lines: list[str]) -> None:
        """Final block at the end of a command — emitted in every mode
        except quiet-without-error (quiet still shows the final summary).
        """
        total = self._fmt_duration(time.monotonic() - self._t0)
        if self._at("normal"):
            self._emit()
        self._emit(self._rule())
        head = f"  {self._c('header', 'summary')} {self._c('rule', '·')} "
        head += f"{self._c('label', 'total')} {self._c('count', total)}"
        self._emit(head)
        self._emit(self._rule())
        for line in lines:
            # Auto-colorize "key: value" lines for visual scanning
            if ":" in line:
                # Preserve leading whitespace, then split on first colon
                lead_len = len(line) - len(line.lstrip())
                lead = line[:lead_len]
                rest = line[lead_len:]
                key, _, val = rest.partition(":")
                self._emit(f"{lead}{self._c('label', key)}:"
                           f"{self._c('count', val.rstrip())}")
            else:
                self._emit(line)
        self._emit(self._rule())


def make_progress(level: Level = "normal") -> Progress:
    return Progress(level=level)
