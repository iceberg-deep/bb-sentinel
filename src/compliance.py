"""
Compliance pre-flight — read a program's rules/policy text and decide whether
bb-sentinel's automated probes are likely to violate the program's posted
terms BEFORE running them.

Why this exists: bug bounty programs typically have strong anti-bot /
automation legal language. Running subfinder + httpx + nuclei + rocks against
a program that prohibits automated scanning can get the researcher's account
banned from the platform — and in the worst case generates a TOS / CFAA
exposure. This module is the cheapest possible insurance: read the rules
text once, grep for prohibition patterns, emit a verdict and exit-1 if it's
clearly forbidden.

The check is intentionally conservative. The patterns are tuned to favor
false positives (flagging OK programs as WARN) over false negatives
(missing a real prohibition). The operator can override with
`compliance_override: true` in programs.yaml for cases they've manually
reviewed.

Verdict ladder (worst → best):
  BLOCK    explicit prohibition with no carveout. Don't run.
  WARN     ambiguous, restricted, or requires prior approval. Confirm
           before running.
  UNCLEAR  no language found either way — could mean policy is silent,
           could mean we couldn't fetch the page (JS-rendered, gated).
           Treat as WARN in practice.
  OK       explicit allowance for automated tooling.

This is a *tooling pre-flight*, not legal advice. The operator is still
responsible for reading the actual program terms.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import httpx
import structlog

log = structlog.get_logger(__name__)


# -- Pattern tables ---------------------------------------------------------

# (regex, signal-name). Regex are matched case-insensitively against the
# rules text body. Patterns chosen from rules pages observed across H1,
# Bugcrowd, Intigriti, YWH. The list is intentionally conservative —
# borderline phrases trigger WARN, not BLOCK.

PROHIBITED_PATTERNS: list[tuple[str, str]] = [
    # Explicit no-automation language
    (r"\bno\s+automated\s+(?:scanning|scanners?|tools?|testing)\b",
     "explicit-no-automation"),
    (r"\bmanual\s+testing\s+only\b",
     "manual-testing-only"),
    (r"\bautomated\s+(?:scanning\s+)?(?:scanners?|tools?|testing)\b\s+(?:are\s+)?(?:strictly\s+)?prohibited\b",
     "automated-prohibited"),
    # "Do not use/run/perform ... automated" — allow filler words between the
    # verb and 'automated' to catch phrasings like
    # "Do not use or report findings from automated scanning tools."
    (r"\bdo\s+not\s+(?:run|use|perform|report\s+(?:findings\s+)?from)\b[^.]{0,80}\bautomated\b",
     "do-not-automated"),
    # Standalone catch — "automated scanning tools" anywhere in a Rules section
    (r"\bautomated\s+(?:scanning|vulnerability)\s+(?:tool|scanner)s?\b",
     "automated-scanning-tools-mentioned"),
    (r"\bautomated\s+vulnerability\s+scanners?\b\s+(?:are\s+)?(?:not\s+)?(?:allowed|permitted)?(?:\s+prohibited)?",
     "vuln-scanner-mention"),
    # Prior approval required
    (r"\bprior\s+(?:written\s+)?(?:consent|approval|authorization)\b",
     "requires-prior-approval"),
    (r"\bnotify\s+(?:us\s+)?before\s+(?:running\s+|using\s+)?(?:any\s+)?(?:automated|scanning)\b",
     "notify-before-scanning"),
    # Specific tool bans
    (r"\b(?:nuclei|nikto|nessus|qualys|acunetix|burp\s+scanner|owasp\s+zap)\b\s+(?:is\s+)?(?:not\s+)?(?:allowed|prohibited|forbidden)",
     "specific-tool-named"),
    # DoS / volume
    (r"\bDoS\b|\bdenial[\s-]of[\s-]service\b|\bDDoS\b",
     "no-dos"),
    (r"\bvolumetric\b|\bexcessive\s+(?:requests|traffic|use)\b",
     "no-volumetric"),
    (r"\bbrute[\s-]?force\b\s+(?:attacks?|attempts?|testing)",
     "no-bruteforce"),
    # Fuzzing
    (r"\bno\s+fuzzing\b|\bfuzzing\s+(?:is\s+)?(?:not\s+)?(?:allowed|permitted|prohibited)\b",
     "no-fuzzing"),
    # Generic "no scanning"
    (r"\b(?:do\s+not|please\s+do\s+not)\s+(?:scan|attack|probe)\b",
     "no-scan"),
]

PERMITTED_PATTERNS: list[tuple[str, str]] = [
    (r"\bautomated\s+(?:scanning|testing|tools?)\s+(?:is\s+|are\s+)?(?:allowed|permitted|welcome|encouraged)\b",
     "auto-allowed"),
    (r"\bnuclei\s+(?:templates?\s+)?(?:welcome|accepted|allowed|permitted)\b",
     "nuclei-explicitly-allowed"),
    (r"\bautomated\s+scanners?\s+(?:are\s+)?(?:allowed|permitted)\b",
     "scanners-allowed"),
]

RATE_LIMIT_PATTERNS: list[tuple[str, str]] = [
    (r"\brate[\s-]*limit(?:ing|s)?\b",
     "rate-limit-mentioned"),
    (r"\b(\d+)\s*(?:requests?|rps|reqs?)\s*(?:per\s*)?(?:second|sec|s)\b",
     "explicit-rps"),
    (r"\bthrottle\b",
     "throttle"),
    (r"\b(?:respect|observe|honor)\s+(?:our\s+|the\s+)?(?:rate\s+)?(?:limits?|throttling)\b",
     "respect-limits"),
    (r"\breasonable\s+(?:use|throttling|pace)\b",
     "reasonable-use"),
]

# Public-disclosure policy. Critical for signal-build strategy — researchers
# who plan to puvendor-bh writeups need this to be permitted. The bounty-targets-
# data dump's `allows_disclosure` field has been observed to misreport, so we
# verify against the rules text.
DISCLOSURE_FORBIDDEN_PATTERNS: list[tuple[str, str]] = [
    (r"\bdoes\s+not\s+allow\s+disclosure\b",         "explicit-no-disclosure"),
    (r"\bnon[\s-]?disclosure\b\s*[:.]",              "nondisclosure-header"),
    (r"\bmay\s+not\s+release\s+information\b",       "no-release-info"),
    (r"\bdisclosure\s+is\s+not\s+permitted\b",       "no-disclosure-permitted"),
    (r"\bwithout\s+written\s+(?:authorization|approval|consent)\s+from\s+(?:us|the\s+company|the\s+team)\s+(?:to\s+)?disclos",
     "no-disclosure-without-approval"),
]
DISCLOSURE_ALLOWED_PATTERNS: list[tuple[str, str]] = [
    (r"\b(?:public\s+)?disclosure\s+is\s+(?:allowed|permitted|encouraged)\b",
     "disclosure-allowed"),
    (r"\bcoordinated\s+disclosure\b",
     "coordinated-disclosure"),
    (r"\bafter\s+(?:\d+|ninety|sixty)\s+days?\s+(?:you\s+may|public\s+disclosure)",
     "time-based-disclosure"),
]


# Verdict precedence: any BLOCK > any WARN > UNCLEAR > OK
# - any PROHIBITED match without a covering PERMITTED match → BLOCK
# - any "requires-prior-approval" → WARN
# - any PERMITTED match and no PROHIBITED → OK
# - no matches → UNCLEAR
VERDICT_LADDER = ("OK", "UNCLEAR", "WARN", "BLOCK")


@dataclass
class ComplianceMatch:
    signal: str          # signal name from the pattern table
    quoted_context: str  # ~140 chars of surrounding text


@dataclass
class ComplianceCheck:
    source: str                # URL or "file:..."
    verdict: str               # "OK" | "UNCLEAR" | "WARN" | "BLOCK"
    prohibitions: list[ComplianceMatch] = field(default_factory=list)
    allowances:   list[ComplianceMatch] = field(default_factory=list)
    rate_limits:  list[ComplianceMatch] = field(default_factory=list)
    # Disclosure policy is detected separately — doesn't change BLOCK/WARN
    # verdict but is critical strategy info that platform metadata may misreport.
    disclosure_status: str = "UNKNOWN"   # "FORBIDDEN" | "ALLOWED" | "UNKNOWN"
    disclosure_matches: list[ComplianceMatch] = field(default_factory=list)
    fetch_error:  str | None = None
    text_length:  int = 0

    def is_blocking(self) -> bool:
        return self.verdict == "BLOCK"

    def needs_confirmation(self) -> bool:
        return self.verdict in ("WARN", "UNCLEAR")

    def render(self) -> str:
        lines = [f"Compliance verdict: {self.verdict}", f"Source: {self.source}"]
        if self.fetch_error:
            lines.append(f"Fetch error: {self.fetch_error}")
        else:
            lines.append(f"Text length: {self.text_length} chars")
        lines.append(f"Disclosure: {self.disclosure_status}")
        if self.prohibitions:
            lines.append("\nProhibitions found:")
            for m in self.prohibitions:
                lines.append(f"  [{m.signal}] {m.quoted_context!r}")
        if self.allowances:
            lines.append("\nAllowances found:")
            for m in self.allowances:
                lines.append(f"  [{m.signal}] {m.quoted_context!r}")
        if self.disclosure_matches:
            lines.append("\nDisclosure-policy matches:")
            for m in self.disclosure_matches:
                lines.append(f"  [{m.signal}] {m.quoted_context!r}")
        if self.rate_limits:
            lines.append("\nRate-limit guidance:")
            for m in self.rate_limits:
                lines.append(f"  [{m.signal}] {m.quoted_context!r}")
        return "\n".join(lines)


# -- Core check -------------------------------------------------------------

def _scan_patterns(text: str, patterns: list[tuple[str, str]]) -> list[ComplianceMatch]:
    out: list[ComplianceMatch] = []
    seen_signals: set[str] = set()
    for pattern, signal in patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            start = max(0, m.start() - 60)
            end = min(len(text), m.end() + 80)
            context = re.sub(r"\s+", " ", text[start:end]).strip()
            # Cap one match per signal to keep output tight
            if signal in seen_signals: break
            seen_signals.add(signal)
            out.append(ComplianceMatch(signal=signal, quoted_context=context))
            break
    return out


# Signals that actually block our automated pipeline. Every other prohibition
# is either universal program-rule boilerplate (no-DoS, no-bruteforce) or
# requires-approval gating (WARN-level, not block-level).
HARD_BLOCK_SIGNALS = frozenset({
    "explicit-no-automation",
    "manual-testing-only",
    "automated-prohibited",
    "do-not-automated",
    "automated-scanning-tools-mentioned",
    "vuln-scanner-mention",
    "specific-tool-named",
    "no-fuzzing",
    "no-scan",
})
# These are noted (printed in render()) but don't change verdict on their own
# — every bounty program forbids DoS, that's universal not a tool-killer.
WARN_LEVEL_SIGNALS = frozenset({
    "no-dos",
    "no-volumetric",
    "no-bruteforce",
    "requires-prior-approval",
    "notify-before-scanning",
})


def assess_text(text: str, source: str = "<text>") -> ComplianceCheck:
    """Apply the pattern tables to a rules-text blob and produce a verdict.

    Signal classification:
      HARD_BLOCK_SIGNALS  → BLOCK (or WARN if an explicit allowance contradicts)
      WARN_LEVEL_SIGNALS  → WARN (rules to follow, but don't kill the pipeline)
      Anything else       → just surfaced, doesn't change verdict
    """
    text_lower = text.lower()
    prohibitions = _scan_patterns(text_lower, PROHIBITED_PATTERNS)
    allowances   = _scan_patterns(text_lower, PERMITTED_PATTERNS)
    rate_limits  = _scan_patterns(text_lower, RATE_LIMIT_PATTERNS)
    disc_forbid  = _scan_patterns(text_lower, DISCLOSURE_FORBIDDEN_PATTERNS)
    disc_allow   = _scan_patterns(text_lower, DISCLOSURE_ALLOWED_PATTERNS)

    # Disclosure status — forbidden wins over allowed if both match
    if disc_forbid:
        disclosure_status = "FORBIDDEN"
    elif disc_allow:
        disclosure_status = "ALLOWED"
    else:
        disclosure_status = "UNKNOWN"
    disclosure_matches = disc_forbid + disc_allow

    has_hard_block = any(p.signal in HARD_BLOCK_SIGNALS for p in prohibitions)
    has_warn = any(p.signal in WARN_LEVEL_SIGNALS for p in prohibitions)
    has_allowance = bool(allowances)

    if has_hard_block and not has_allowance:
        verdict = "BLOCK"
    elif has_hard_block and has_allowance:
        # explicit allowance contradicts the prohibition — operator must read
        verdict = "WARN"
    elif has_warn:
        verdict = "WARN"
    elif has_allowance:
        verdict = "OK"
    elif not text.strip():
        verdict = "UNCLEAR"
    else:
        verdict = "UNCLEAR"

    return ComplianceCheck(
        source=source,
        verdict=verdict,
        prohibitions=prohibitions,
        allowances=allowances,
        rate_limits=rate_limits,
        disclosure_status=disclosure_status,
        disclosure_matches=disclosure_matches,
        text_length=len(text),
    )


CHROMIUM_BINARY_CANDIDATES = ("chromium", "chromium-browser",
                              "google-chrome", "google-chrome-stable", "chrome")
DEFAULT_BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def find_chromium() -> str | None:
    """Locate a chromium-family binary on PATH. Returns None if absent."""
    for candidate in CHROMIUM_BINARY_CANDIDATES:
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _strip_html(body: str) -> str:
    """Roughly strip HTML tags / scripts / styles. Sufficient for keyword
    matching against the compliance pattern tables, not for layout."""
    body = re.sub(r"<script[^>]*>.*?</script>", " ", body,
                  flags=re.IGNORECASE | re.DOTALL)
    body = re.sub(r"<style[^>]*>.*?</style>", " ", body,
                  flags=re.IGNORECASE | re.DOTALL)
    body = re.sub(r"<[^>]+>", " ", body)
    body = re.sub(r"\s+", " ", body).strip()
    return body


async def fetch_rules(url: str, *, timeout: float = 20.0,
                      user_agent: str = "bb-sentinel-compliance/0.1") -> tuple[str, str | None]:
    """Fetch a rules page with httpx (fast, no JS). Returns (text, error)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                      headers={"User-Agent": user_agent}) as client:
            r = await client.get(url)
        if r.status_code != 200:
            return "", f"HTTP {r.status_code}"
        return _strip_html(r.text or ""), None
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"


async def fetch_rules_headless(url: str, *, timeout: float = 45.0,
                                user_agent: str = DEFAULT_BROWSER_UA,
                                virtual_time_ms: int = 10000) -> tuple[str, str | None]:
    """Render a page in headless chromium, dump the DOM, strip HTML.

    Used as a fallback when ``fetch_rules`` returns suspiciously little text
    (the page is a JS-rendered SPA — Bugcrowd / HackerOne / Intigriti briefs
    all behave this way). The ``--virtual-time-budget`` flag fast-forwards
    chromium's internal clock so SPA content has time to render before the
    DOM is dumped; without it the dump captures only the loader shell.

    No Python deps beyond stdlib — calls the system chromium binary via
    subprocess so this stays a portable bb-sentinel concern, not a
    Playwright/Selenium pin.
    """
    binary = find_chromium()
    if not binary:
        return "", ("no chromium-family binary found on PATH — "
                    "install chromium / chromium-browser / google-chrome")
    cmd = [
        binary,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        f"--virtual-time-budget={virtual_time_ms}",
        "--run-all-compositor-stages-before-draw",
        "--dump-dom",
        f"--user-agent={user_agent}",
        url,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "", f"chromium headless timed out after {timeout}s"
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"
    if not stdout:
        return "", "chromium returned no output"
    return _strip_html(stdout.decode("utf-8", errors="replace")), None


async def check_url(url: str, *, force_headless: bool = False,
                    no_headless: bool = False) -> ComplianceCheck:
    """Fetch a rules URL + assess. Auto-falls-back to headless chromium when
    plain httpx returns a too-short body (the signature of a JS-rendered SPA).

    Set ``force_headless=True`` to skip the httpx attempt entirely.
    Set ``no_headless=True`` to keep the httpx-only behavior (useful when the
    operator wants UNCLEAR rather than running a local browser).
    """
    text, err, source_note = "", None, url
    if not force_headless:
        text, err = await fetch_rules(url)

    # Decide whether to escalate to headless
    needs_headless = (
        force_headless
        or (err is not None)
        or (len(text) < 500)   # SPA shells are typically <500 chars after stripping
    )
    if needs_headless and not no_headless:
        log.info("compliance: escalating to headless chromium",
                 url=url, plain_text_len=len(text), plain_err=err)
        h_text, h_err = await fetch_rules_headless(url)
        if not h_err and len(h_text) >= 500:
            text, err = h_text, None
            source_note = url + " (headless-rendered)"
        elif h_err:
            # Headless failed; surface what we have. err prefers original message.
            err = err or h_err

    if err and len(text) < 200:
        return ComplianceCheck(
            source=url, verdict="UNCLEAR",
            fetch_error=err, text_length=len(text),
        )
    if len(text) < 200:
        return ComplianceCheck(
            source=url, verdict="UNCLEAR",
            fetch_error=f"text too short ({len(text)} chars) — JS-rendered and headless unavailable",
            text_length=len(text),
        )
    return assess_text(text, source=source_note)


def check_file(path: str | Path) -> ComplianceCheck:
    """Assess a pasted rules text file (avoids JS-rendered fetch problems)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    return assess_text(text, source=f"file:{p}")


__all__ = [
    "ComplianceCheck", "ComplianceMatch",
    "assess_text", "fetch_rules", "check_url", "check_file",
    "PROHIBITED_PATTERNS", "PERMITTED_PATTERNS", "RATE_LIMIT_PATTERNS",
    "VERDICT_LADDER",
]
