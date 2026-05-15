from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


# URL tokens that signal "non-production / admin / management" surface.
KEYWORD_TOKENS: tuple[str, ...] = (
    "admin", "api", "staging", "stage", "test", "dev", "qa", "qat", "internal",
    "preprod", "ppd", "nonprod", "uat", "sandbox", "console", "portal",
    "manage", "manager", "grafana", "kibana", "jenkins", "gitlab", "phpmyadmin",
    "swagger", "graphql", "actuator", "metrics", "debug",
)

# Auth / identity surface — auth bypass on these is usually high-impact.
AUTH_TOKENS: tuple[str, ...] = (
    "account", "auth", "sso", "oauth", "openid", "login", "signin", "signon",
    "logon", "idp", "identity", "okta", "ping", "duo", "saml", "register",
    "password", "reset", "mfa", "2fa",
)

# Tech fingerprints worth a bonus — frameworks + ops tooling that hint at "real
# app, not marketing page." CDN / TLS / analytics deliberately excluded.
TECH_TOKENS: tuple[str, ...] = (
    # web frameworks
    "spring boot", "spring", "laravel", "django", "rails", "ruby on rails",
    "express", "flask", "fastapi", "tomcat", "jboss", "wildfly", "weblogic",
    "struts", "play", "phoenix", "asp.net",
    # platforms / infra signal
    "appdynamics", "kubernetes", "openshift", "consul", "vault", "rancher",
    "elasticsearch", "kibana", "jenkins", "gitlab", "jira", "confluence",
    "sonarqube", "nexus", "artifactory", "splunk", "prometheus",
    "grafana", "harbor", "argocd", "drone", "wordpress", "drupal", "joomla",
)

# "Boring" fingerprints — CDN, TLS, analytics. Stripped out before counting
# "interesting tech" stack depth.
NOISE_TECH: frozenset[str] = frozenset({
    "akamai", "akamai bot manager", "cloudflare", "cloudfront", "fastly",
    "google cdn", "hsts", "http/2", "http/3", "google tag manager",
    "google analytics", "google font api", "lodash", "modernizr", "alpine.js",
    "dc.js", "moment.js", "jquery", "react", "vue",
})

INTERESTING_PORTS: frozenset[int] = frozenset(
    {8080, 9090, 3000, 4000, 5000, 8443, 8081, 8000, 8888, 9000, 7001, 9200, 5601}
)

KEYWORD_MULTIPLIER = 3.0
AUTH_MULTIPLIER = 2.5
TECH_MULTIPLIER = 2.0
PORT_MULTIPLIER = 2.5
RECENCY_MULTIPLIER = 2.0
UNIQUE_TECH_MULTIPLIER = 1.3  # applied when ≥2 interesting (non-noise) techs present
UNIQUE_TECH_THRESHOLD = 2

RECENCY_WINDOW_HOURS = 6.0
BASE_SCORE = 0.7
MAX_SCORE = 50.0


@dataclass
class ScoreBreakdown:
    score: float
    base: float
    matched_keywords: list[str] = field(default_factory=list)
    matched_auth: list[str] = field(default_factory=list)
    matched_tech: list[str] = field(default_factory=list)
    matched_ports: list[int] = field(default_factory=list)
    unique_tech: list[str] = field(default_factory=list)
    recent: bool = False

    def reasons(self) -> list[str]:
        out: list[str] = []
        if self.matched_keywords:
            out.append(f"keywords={','.join(self.matched_keywords)} (x{KEYWORD_MULTIPLIER})")
        if self.matched_auth:
            out.append(f"auth={','.join(self.matched_auth)} (x{AUTH_MULTIPLIER})")
        if self.matched_tech:
            out.append(f"tech={','.join(self.matched_tech)} (x{TECH_MULTIPLIER})")
        if self.unique_tech:
            out.append(f"stack-depth={len(self.unique_tech)} (x{UNIQUE_TECH_MULTIPLIER})")
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

    matched_auth = [k for k in AUTH_TOKENS if k in url_lc]
    if matched_auth:
        breakdown.matched_auth = matched_auth
        score *= AUTH_MULTIPLIER

    matched_tech: list[str] = []
    for token in TECH_TOKENS:
        for t in tech_lc:
            if token in t and token not in matched_tech:
                matched_tech.append(token)
    if matched_tech:
        breakdown.matched_tech = matched_tech
        score *= TECH_MULTIPLIER

    # Stack-depth bonus: 2+ "real app" technologies (excluding CDN/TLS/analytics)
    interesting = [t for t in tech_lc if t and t not in NOISE_TECH]
    if len(interesting) >= UNIQUE_TECH_THRESHOLD:
        breakdown.unique_tech = interesting
        score *= UNIQUE_TECH_MULTIPLIER

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
