from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


KEYWORD_TOKENS: tuple[str, ...] = (
    "admin", "api", "staging", "stage", "test", "dev", "qa", "internal",
    "preprod", "uat", "sandbox", "console", "portal", "manage", "manager",
    "grafana", "kibana", "jenkins", "gitlab", "phpmyadmin",
)
TECH_TOKENS: tuple[str, ...] = (
    "spring boot", "spring", "laravel", "django", "rails", "ruby on rails",
    "express", "flask", "fastapi", "tomcat", "jboss", "wildfly", "weblogic",
)
INTERESTING_PORTS: frozenset[int] = frozenset({8080, 9090, 3000, 4000, 5000, 8443, 8081, 8000, 8888, 9000})
KEYWORD_MULTIPLIER = 3.0
TECH_MULTIPLIER = 2.0
PORT_MULTIPLIER = 2.5
RECENCY_MULTIPLIER = 2.0
RECENCY_WINDOW_HOURS = 6.0
BASE_SCORE = 0.7
MAX_SCORE = 25.0


@dataclass
class ScoreBreakdown:
    score: float
    base: float
    matched_keywords: list[str] = field(default_factory=list)
    matched_tech: list[str] = field(default_factory=list)
    matched_ports: list[int] = field(default_factory=list)
    recent: bool = False

    def reasons(self) -> list[str]:
        out: list[str] = []
        if self.matched_keywords:
            out.append(f"keywords={','.join(self.matched_keywords)} (x{KEYWORD_MULTIPLIER})")
        if self.matched_tech:
            out.append(f"tech={','.join(self.matched_tech)} (x{TECH_MULTIPLIER})")
        if self.matched_ports:
            out.append(f"ports={','.join(map(str, self.matched_ports))} (x{PORT_MULTIPLIER})")
        if self.recent:
            out.append(f"recent (<{RECENCY_WINDOW_HOURS:g}h) (x{RECENCY_MULTIPLIER})")
        return out


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def score_finding(
    *,
    url: str,
    technologies: list[str] | None = None,
    port: int | None = None,
    discovered_at: datetime | None = None,
    status_code: int | None = None,
) -> ScoreBreakdown:
    """Compute a priority score for a discovered finding.

    Multipliers compound on top of BASE_SCORE — each qualifying signal multiplies once.
    """
    technologies = technologies or []
    url_lc = (url or "").lower()
    tech_lc = [t.lower() for t in technologies]

    score = BASE_SCORE
    if status_code and 200 <= status_code < 400:
        score += 0.3

    breakdown = ScoreBreakdown(score=score, base=score)

    matched_keywords = [k for k in KEYWORD_TOKENS if k in url_lc]
    if matched_keywords:
        breakdown.matched_keywords = matched_keywords
        score *= KEYWORD_MULTIPLIER

    matched_tech: list[str] = []
    for token in TECH_TOKENS:
        for t in tech_lc:
            if token in t and token not in matched_tech:
                matched_tech.append(token)
    if matched_tech:
        breakdown.matched_tech = matched_tech
        score *= TECH_MULTIPLIER

    if port is not None and port in INTERESTING_PORTS:
        breakdown.matched_ports = [port]
        score *= PORT_MULTIPLIER

    if discovered_at is not None:
        age_h = (_utcnow() - _ensure_aware(discovered_at)).total_seconds() / 3600.0
        if age_h < RECENCY_WINDOW_HOURS:
            breakdown.recent = True
            score *= RECENCY_MULTIPLIER

    breakdown.score = round(min(score, MAX_SCORE), 2)
    return breakdown
