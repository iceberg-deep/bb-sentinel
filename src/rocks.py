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
                 in_scope_hosts: frozenset[str] | None = None) -> None:
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

        # 2) For confirmed-Tomcat hosts, also check PUT
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
        for t in self.TEMPLATE_TREES:
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
    accidents where the original file was puvendor-bhed next to a saved-by-editor
    copy. Cheap (a handful of GETs per 200) and high-leverage when there's a
    leak."""
    name = "backup-file"

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
            return DeepScanFinding(
                url=target, probe=self.name,
                signal=f"exposed-backup{suffix}",
                severity="high",
                title=f"Backup-suffix variant returned {r.status_code} ({len(body)} bytes)",
                evidence=body[:300].decode("utf-8", errors="replace"),
                extra={"content-type": ctype, "length": len(body),
                       "suffix": suffix, "original-url": url},
            )

        findings: list[DeepScanFinding] = []
        tasks = [check(u, s) for u in candidates[:120] for s in BACKUP_SUFFIXES]
        for f in await asyncio.gather(*tasks):
            if f is not None: findings.append(f)
        return findings


class MethodEnumProbe(DeepScanProbe):
    """Enumerate uncommon HTTP methods against each live URL. Surfaces:
      - PUT / DELETE returning 200/201/204 = unauth write (critical)
      - TRACE returning 200 = XST (low/info)
      - PROPFIND returning 207 = WebDAV exposed (medium-high)
      - Custom methods returning non-error = misconfigured proxy
    Sends one request per (URL, method); ~8 extra requests per host."""
    name = "method-enum"
    METHODS = ("OPTIONS", "PUT", "DELETE", "PATCH", "TRACE", "PROPFIND", "CONNECT", "DEBUG")
    # Methods we care about IF they return success. OPTIONS is informational
    # (always 200 + Allow header) — surface only the Allow contents.
    INTERESTING_STATUS = {"PUT": (200, 201, 204),
                          "DELETE": (200, 204),
                          "PATCH": (200, 201, 204),
                          "TRACE": (200,),
                          "PROPFIND": (207, 200),
                          "DEBUG": (200,),
                          "CONNECT": (200, 405)}  # 405 = method known, could still be probed

    async def run(self, probes: list[dict]) -> list[DeepScanFinding]:
        bases = sorted({p["url"] for p in probes
                        if p.get("status_code") and 200 <= p["status_code"] < 400})
        log.info("method-enum probe", urls=len(bases), methods=len(self.METHODS))
        findings: list[DeepScanFinding] = []

        async def try_method(url: str, method: str):
            async with self.sem:
                try:
                    r = await self.client.request(method, url, timeout=self.timeout)
                except Exception:
                    return None
            # OPTIONS: surface Allow header content only if it includes write methods
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
            # Other methods: flag if status matches the interesting set
            interesting = self.INTERESTING_STATUS.get(method, ())
            if r.status_code not in interesting:
                return None
            sev = "high" if method in ("PUT", "DELETE", "PATCH") else "medium"
            if method == "TRACE": sev = "low"
            return DeepScanFinding(
                url=url, probe=self.name,
                signal=f"method-{method.lower()}-accepted",
                severity=sev,
                title=f"{method} returned {r.status_code}",
                evidence=(r.text or "")[:300],
                extra={"method": method, "status": r.status_code,
                       "length": len(r.content)},
            )

        tasks = [try_method(u, m) for u in bases for m in self.METHODS]
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
                body_l = (r.content[:512] or b"").lower()
                if b"<title>404" in body_l or b"page not found" in body_l:
                    return None
                # Skip empty bodies — fallback or just gone
                if len(r.content) < 32 and r.status_code != 401:
                    return None
                # Skip very small redirects-as-200 (some servers do this)
                sev = "low"
                if "/admin" in p.lower() or "/api" in p.lower():
                    sev = "medium"
                if "/.git" in p.lower() or "/.env" in p.lower() or "/dump" in p.lower():
                    sev = "high"
                return DeepScanFinding(
                    url=full, probe=self.name,
                    signal="historical-url-still-live",
                    severity=sev,
                    title=f"Wayback-historical path {p} still serves content",
                    evidence=(r.text or "")[:300],
                    extra={"status": r.status_code, "length": len(r.content),
                           "historical-source": u,
                           "content-type": r.headers.get("content-type","")},
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
        ("aws-access-key",   "high",     r"AKIA[0-9A-Z]{16}"),
        ("aws-secret-key",   "high",     r'(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])'),  # very high FP; off by default
        ("github-pat",       "high",     r"ghp_[A-Za-z0-9]{36}"),
        ("github-oauth",     "high",     r"gho_[A-Za-z0-9]{36}"),
        ("slack-token",      "high",     r"xox[bpoas]-[A-Za-z0-9-]{10,48}"),
        ("private-key",      "critical", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        ("google-api-key",   "medium",   r"AIza[0-9A-Za-z\-_]{35}"),
        ("jwt-token",        "medium",   r"eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}"),
        ("password-literal", "medium",   r'(?i)["\']?password["\']?\s*[:=]\s*["\'][^"\']{6,80}["\']'),
        ("api-key-literal",  "medium",   r'(?i)["\']?api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}["\']'),
    )
    # aws-secret-key is too FP-prone — keep it off by default
    DISABLED = {"aws-secret-key"}

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

    def _scan_body(self, url: str, body: str, out: list, *,
                    source_kind: str, from_page: str | None = None) -> None:
        for signal, severity, pattern in self.SECRET_PATTERNS:
            if signal in self.DISABLED: continue
            for m in re.findall(pattern, body):
                if isinstance(m, tuple): m = m[0]
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

DEFAULT_PROBES = (PathSweep, BackupFileProbe, MethodEnumProbe,
                  Bypass403, CorsProbe, TomcatFingerprint,
                  WaybackHistorical, JsSecretMine,
                  OriginCandidateProbe, OwaspVulnsProbe)


class DeepScanner:
    """Run a fixed set of probes concurrently against a list of probe-results."""

    def __init__(self, *, concurrency: int = 8, timeout: float = 8.0,
                 user_agent: str = "bb-sentinel-deepscan/0.1",
                 probes: Iterable[type[DeepScanProbe]] = DEFAULT_PROBES,
                 rate_limit_rps: int | None = None,
                 auth_headers: dict[str, str] | None = None,
                 in_scope_hosts: Iterable[str] | None = None,
                 progress=None) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent
        self.probe_classes = list(probes)
        # Honor program-puvendor-bhed rate caps (e.g., Plusgrade's ≤6 RPS clause).
        # Probes that shell out to nuclei pass this to nuclei's -rate-limit;
        # internal-httpx probes use it as a token-bucket budget hint.
        self.rate_limit_rps = rate_limit_rps
        # Per-program auth — propagated to all probes. Python-side probes
        # use in_scope_hosts to scope-restrict the headers (don't leak to
        # CDNs); subprocess tools (nuclei) send globally.
        self.auth_headers = auth_headers or {}
        self.in_scope_hosts = frozenset((h or "").lower() for h in (in_scope_hosts or []))
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
                )
                t_start = time.monotonic()
                if self.progress:
                    self.progress.step(cls.name, "running…")
                try:
                    fs = await probe.run(probes)
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
    "WaybackHistorical", "JsSecretMine",
    "OriginCandidateProbe", "OwaspVulnsProbe",
    "HIGH_VALUE_PATHS", "BACKUP_SUFFIXES", "BYPASS_HEADERS", "TOMCAT9_CVE_BANDS",
    "SEVERITY_ORDER", "SEVERITY_WEIGHT",
]
