from __future__ import annotations

import json

import structlog

from .base import Discoverer, DiscoveryResult, HostResult

log = structlog.get_logger(__name__)


# A small hand-curated list of multi-part eTLDs. Covers the common cases
# without pulling in tldextract's full PSL bundle (~250 KB compressed).
# Wrong on uncommon ccTLDs; swap to tldextract if engagements start
# touching e.g. nigerian or japanese registry shapes regularly.
_MULTI_PART_TLDS = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "com.br", "co.in", "com.mx", "com.tr",
    "com.cn", "net.cn", "co.kr", "com.tw",
    "co.za", "co.il", "com.sg", "com.hk",
})


def extract_registrable_domain(host: str) -> str:
    """Return the registrable (eTLD+1) domain for a hostname.

    `api.staging.example.co.uk` → `example.co.uk`
    `subdomain.example.com`      → `example.com`
    `*.example.com`              → `example.com`

    Heuristic: take the last 2 labels, or last 3 if the last 2 match a
    known multi-part eTLD. Wildcards stripped before extraction.
    """
    parts = host.lower().strip().lstrip("*").lstrip(".").split(".")
    if len(parts) < 2:
        return host.lower().strip()
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


class TLSSan(Discoverer):
    """Mine SubjectAltName entries from TLS certificates to expand the
    discovered host set, optionally following the redirect chain.

    Single-layer mode (`max_depth=0`): probe the seeds, return their
    SANs. A typical CDN-fronted shared cert carries 50–200 SANs, so
    even a single layer is a significant expansion.

    Transitive mode (`max_depth>=1`): on each layer, additionally
    capture HTTP redirect destinations (`Location` header from each
    probed host's response). At the next layer, probe THOSE
    destinations and accumulate their SANs. SANs are collected from
    every layer; only redirect destinations form the next frontier.
    This surfaces hosts visible on the L-N cert but not on the L-0
    cert (e.g., the original CDN edge has one SAN list; the redirected
    portal app behind it has a different SAN list).

    `max_per_layer` caps the per-layer probe count to keep transitive
    runs from fanning out catastrophically when intermediate hosts
    redirect across multiple distinct cert chains.

    Implementation:
      * Wraps `httpx -tls-grab -json`. No new dependencies.
      * Per-program `rate_limit_rps` + `auth_headers` propagated.
      * Wildcard SANs (`*.example.com`) are stripped of the `*.` prefix
        — downstream can decide whether to expand via subfinder or
        treat as scope-defining metadata.
      * `-tls-grab` adds 5–10× per-host latency vs. plain probes (TLS
        handshake must complete before close); intrinsic to the
        technique.
      * SANs are public information once the cert is presented — no
        per-host auth-scope restriction applies to this layer.
    """

    name = "tls-san"
    binary = "httpx"

    def __init__(
        self,
        binary_path: str | None = None,
        timeout: int = 600,
        rate_limit_rps: int | None = None,
        auth_headers: dict[str, str] | None = None,
        max_depth: int = 1,
        max_per_layer: int = 25,
    ) -> None:
        super().__init__(binary_path=binary_path, timeout=timeout)
        self.rate_limit_rps = rate_limit_rps
        self.auth_headers = auth_headers or {}
        self.max_depth = max(0, int(max_depth))
        self.max_per_layer = max(1, int(max_per_layer))

    async def discover(self, domains: list[str]) -> DiscoveryResult:
        result = DiscoveryResult()
        if not domains:
            return result
        if not self.is_available():
            result.errors.append(f"{self.binary_path} not found on PATH")
            return result

        seen_sans: set[str] = set()
        visited_probes: set[str] = set()
        frontier: list[str] = list({d.lower().strip() for d in domains if d})

        for depth in range(self.max_depth + 1):
            if not frontier:
                break
            # Cap per-layer probe count and dedupe against already-probed
            to_probe = [h for h in frontier
                        if h not in visited_probes][:self.max_per_layer]
            if not to_probe:
                break
            visited_probes.update(to_probe)
            log.info("tls-san layer",
                     depth=depth, probing=len(to_probe), so_far=len(seen_sans))

            sans, redirects = await self._probe_one_layer(to_probe, result)
            new_sans = sans - seen_sans
            for s in sorted(new_sans):
                result.hosts.append(
                    HostResult(hostname=s, source=f"{self.name}-d{depth}")
                )
            seen_sans.update(new_sans)
            # Next frontier = redirect destinations not yet probed
            frontier = sorted(redirects - visited_probes)

        log.info("tls-san done",
                 input=len(domains), discovered=len(seen_sans),
                 layers_traversed=min(self.max_depth + 1, max(1, depth + 1)))
        return result

    async def _probe_one_layer(
        self, hosts: list[str], parent_result: DiscoveryResult,
    ) -> tuple[set[str], set[str]]:
        """Run httpx -tls-grab against `hosts`. Returns (sans, redirect-destinations)."""
        cmd = [
            self.binary_path,
            "-silent", "-json", "-no-color",
            "-tls-grab",
            "-timeout", "10",
            "-threads", "3",
        ]
        if self.rate_limit_rps is not None:
            cmd += ["-rl", str(self.rate_limit_rps)]
        for k, v in self.auth_headers.items():
            cmd += ["-H", f"{k}: {v}"]

        try:
            rc, stdout, stderr = await self._run_cmd(
                cmd, stdin="\n".join(hosts).encode()
            )
        except RuntimeError as e:
            parent_result.errors.append(f"tls-san layer timed out: {e}")
            return set(), set()
        if rc != 0 and not stdout:
            parent_result.errors.append(
                f"tls-san httpx rc={rc}: "
                f"{stderr.decode(errors='replace').strip()[:200]}"
            )
            return set(), set()

        sans: set[str] = set()
        redirects: set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # SAN extraction
            for san in (obj.get("tls") or {}).get("subject_an") or []:
                s = str(san).strip().lower().lstrip("*").lstrip(".")
                if s:
                    sans.add(s)
            # Redirect destination — only the host portion (drop path)
            loc = obj.get("location")
            if loc:
                from urllib.parse import urlparse
                pu = urlparse(loc)
                if pu.netloc:
                    redirects.add(pu.netloc.split(":")[0].lower())
                elif pu.path and "/" not in pu.path:
                    # Relative-host redirect (rare); skip
                    pass

        return sans, redirects
