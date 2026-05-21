from __future__ import annotations

import json

import structlog

from .base import Discoverer, DiscoveryResult, HostResult

log = structlog.get_logger(__name__)


class TLSSan(Discoverer):
    """Mine SubjectAltName entries from TLS certificates to expand the
    discovered host set.

    A single shared cert on a CDN-fronted origin commonly carries 50–200
    SANs covering the customer's owned hosts. Pulling those SANs back
    into the discovery loop typically 2–4× the host count vs. subfinder
    + crt.sh alone — and surfaces hosts that don't appear in CT logs
    (private/non-CT-logged certs) or in passive DNS dumps.

    Runs `httpx -tls-grab -json` against the input host set, parses each
    response's `tls.subject_an` array, and emits one HostResult per
    SAN. Downstream scope filtering trims to in-scope.

    Implementation notes:
      * Reuses httpx with its existing CLI; no separate TLS lib.
      * `httpx -tls-grab` adds ~5–10× latency vs. a plain probe because
        the TLS handshake must complete before TCP is closed. That's
        intrinsic to certificate inspection.
      * Wildcard SANs (`*.example.com`) emit the literal `*.example.com`
        hostname — downstream consumers must decide whether to expand
        them into specific hosts via subfinder/crt.sh or treat them as
        scope-defining metadata.
      * Auth headers are propagated so this can run against authenticated
        endpoints whose certs you have permission to inspect, but the
        SANs themselves are public information once the cert is
        presented — no per-host scope restriction applies here.
    """

    name = "tls-san"
    binary = "httpx"

    def __init__(
        self,
        binary_path: str | None = None,
        timeout: int = 600,
        rate_limit_rps: int | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(binary_path=binary_path, timeout=timeout)
        self.rate_limit_rps = rate_limit_rps
        self.auth_headers = auth_headers or {}

    async def discover(self, domains: list[str]) -> DiscoveryResult:
        result = DiscoveryResult()
        if not domains:
            return result
        if not self.is_available():
            result.errors.append(f"{self.binary_path} not found on PATH")
            return result

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

        stdin_blob = "\n".join(domains).encode()
        rc, stdout, stderr = await self._run_cmd(cmd, stdin=stdin_blob)
        if rc != 0 and not stdout:
            result.errors.append(
                f"tls-san httpx rc={rc}: "
                f"{stderr.decode(errors='replace').strip()[:200]}"
            )
            return result

        seen: set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            tls = obj.get("tls") or {}
            sans = tls.get("subject_an") or []
            for san in sans:
                san_l = str(san).strip().lower().lstrip(".")
                if not san_l or san_l in seen:
                    continue
                seen.add(san_l)
                result.hosts.append(HostResult(hostname=san_l, source=self.name))

        log.info("tls-san done", input=len(domains), discovered=len(result.hosts))
        return result
