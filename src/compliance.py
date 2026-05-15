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

import re
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
    (r"\bautomated\s+(?:scanners?|tools?|testing)\s+(?:are\s+)?(?:strictly\s+)?prohibited\b",
     "automated-prohibited"),
    (r"\bdo\s+not\s+(?:run|use|perform)\s+(?:any\s+)?automated\b",
     "do-not-automated"),
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
        if self.prohibitions:
            lines.append("\nProhibitions found:")
            for m in self.prohibitions:
                lines.append(f"  [{m.signal}] {m.quoted_context!r}")
        if self.allowances:
            lines.append("\nAllowances found:")
            for m in self.allowances:
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


def assess_text(text: str, source: str = "<text>") -> ComplianceCheck:
    """Apply the pattern tables to a rules-text blob and produce a verdict."""
    text_lower = text.lower()
    prohibitions = _scan_patterns(text_lower, PROHIBITED_PATTERNS)
    allowances   = _scan_patterns(text_lower, PERMITTED_PATTERNS)
    rate_limits  = _scan_patterns(text_lower, RATE_LIMIT_PATTERNS)

    # Verdict computation
    has_block = any(p.signal != "requires-prior-approval" for p in prohibitions)
    has_approval_req = any(p.signal == "requires-prior-approval" for p in prohibitions)
    has_allowance = bool(allowances)

    if has_block and not has_allowance:
        verdict = "BLOCK"
    elif has_block and has_allowance:
        # contradiction — operator must read
        verdict = "WARN"
    elif has_approval_req:
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
        text_length=len(text),
    )


async def fetch_rules(url: str, *, timeout: float = 20.0,
                      user_agent: str = "bb-sentinel-compliance/0.1") -> tuple[str, str | None]:
    """Fetch a rules page and return (text-content, error). HTML is roughly
    stripped via regex — sufficient for keyword matching, not for layout."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                      headers={"User-Agent": user_agent}) as client:
            r = await client.get(url)
        if r.status_code != 200:
            return "", f"HTTP {r.status_code}"
        # Strip scripts + tags; collapse whitespace
        body = r.text or ""
        body = re.sub(r"<script[^>]*>.*?</script>", " ", body,
                      flags=re.IGNORECASE | re.DOTALL)
        body = re.sub(r"<style[^>]*>.*?</style>", " ", body,
                      flags=re.IGNORECASE | re.DOTALL)
        body = re.sub(r"<[^>]+>", " ", body)
        body = re.sub(r"\s+", " ", body).strip()
        return body, None
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"


async def check_url(url: str) -> ComplianceCheck:
    """Fetch + assess in one call."""
    text, err = await fetch_rules(url)
    if err:
        return ComplianceCheck(
            source=url, verdict="UNCLEAR",
            fetch_error=err, text_length=len(text),
        )
    if len(text) < 200:
        # JS-rendered page or extremely short — can't trust the assessment
        result = ComplianceCheck(
            source=url, verdict="UNCLEAR",
            fetch_error=f"text too short ({len(text)} chars) — likely JS-rendered",
            text_length=len(text),
        )
        return result
    result = assess_text(text, source=url)
    return result


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
