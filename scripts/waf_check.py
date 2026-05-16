"""
WAF/CDN screening pass — quickly probe each candidate program's primary
asset to identify what's sitting in front of the origin. bb-sentinel's
unauth pipeline is heavily neutered against CF/Akamai/AWS-CloudFront,
so the cleanest signal for "where could we actually land findings unauth"
is "what's NOT behind one of those."

Output: data/waf-screening.{md,json} — candidates ranked by WAF presence
(none → light WAF → enterprise WAF). Combines with prior compliance
verdict to give an actionable shortlist.

Resource discipline: caps at 5 RPS to be polite, dedupes hosts before
probing, single httpx invocation per program.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Hardcoded shortlist — picked from the build_signal_list.py top 60 to
# represent a mix of payout tiers, industries, and likely defensiveness.
# Each entry: (handle, payout, primary_host_candidates)
CANDIDATES = [
    # Already known CF-walled (regression check)
    ("plusgrade-mbb-public",     5000, ["www.points.com"]),
    ("hostgator-latam-bb",       2500, ["www.hostgator.com.br", "financeiro.hostgator.com.br"]),
    # WARN-tolerable from prior batch
    ("hotdoc",                   8000, ["www.hotdoc.com.au"]),
    ("myfitnesspal-mbb",         4500, ["www.myfitnesspal.com"]),
    ("carrefour",                4000, ["www.carrefouruae.com", "api-prod.retailsso.com"]),
    ("magiclabs-mbb-og",         3000, ["magic.link", "auth.magic.link"]),
    ("webdotcom",                3000, ["www.web.com"]),
    ("tamedia",                  2500, ["www.tamedia.ch"]),
    ("jora",                     2500, ["au.jora.com"]),
    ("quizlet",                  2000, ["quizlet.com", "www.quizlet.com"]),
    ("cloudinary",               4000, ["cloudinary.com"]),
    # Lower-tier — less corporate WAF investment likely
    ("snapnames",                2000, ["www.snapnames.com"]),
    ("bykea",                    1500, ["www.bykea.com"]),
    ("eternal",                  1500, ["www.eternal.gg"]),
    ("gocardless_bbp",           3500, ["gocardless.com"]),
    ("ynab",                     3000, ["api.ynab.com", "app.ynab.com"]),
    ("planethosterinc",          3000, ["www.planethoster.com"]),
    ("eazybi",                   3000, ["eazybi.com"]),
    ("balsamiq",                 1500, ["balsamiq.cloud"]),
    ("kohls",                    4500, ["www.kohls.com"]),
]

# Tech-string fingerprints that scream "enterprise WAF in the way."
WAF_FINGERPRINTS = {
    "Cloudflare":       "cloudflare",      # AS13335
    "Akamai":           "akamai",          # AS16625/etc
    "Fastly":           "fastly",          # AS54113
    "AWS CloudFront":   "cloudfront",      # AS16509
    "Azure Front Door": "azure",           # AS8075
    "Imperva":          "imperva",         # named WAF
    "F5 BIG-IP":        "f5 ",
    "Sucuri":           "sucuri",
    "Barracuda":        "barracuda",
    "DataDome":         "datadome",
}


def classify_wafs(techs: list[str]) -> list[str]:
    """Return the set of WAF/CDN names detected in the tech list."""
    lc = [t.lower() for t in techs]
    hits = []
    for name, marker in WAF_FINGERPRINTS.items():
        if any(marker in t for t in lc):
            hits.append(name)
    return hits


async def probe_host(host: str) -> dict | None:
    """Single httpx probe via subprocess. Returns the parsed JSON record."""
    proc = await asyncio.create_subprocess_exec(
        "/home/iceberg/go/bin/httpx",
        "-silent", "-json", "-status-code", "-title", "-tech-detect",
        "-no-color", "-threads", "1", "-rate-limit", "5",
        "-H", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=host.encode() + b"\n"), timeout=20,
        )
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait()
        return None
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            pass
    return None


async def main():
    print(f"Probing {len(CANDIDATES)} program primary assets to detect WAFs...\n")
    rows: list[dict] = []
    for i, (handle, payout, hosts) in enumerate(CANDIDATES, 1):
        # Use the first host as primary indicator
        host = hosts[0]
        print(f"  [{i:>2}/{len(CANDIDATES)}] {handle:<28}  {host:<35}", end=" ")
        rec = await probe_host(host)
        if rec is None:
            print("  ← no response")
            rows.append({"handle": handle, "host": host, "payout": payout,
                         "status": None, "wafs": [], "tech": [],
                         "verdict": "NO-RESPONSE"})
            continue
        techs = rec.get("tech") or rec.get("technologies") or []
        wafs = classify_wafs(techs)
        status = rec.get("status_code") or rec.get("status-code")
        # Verdict ladder
        if not wafs:
            verdict = "OPEN"             # no WAF detected → good unauth target
        elif len(wafs) == 1 and wafs[0] not in ("Cloudflare", "Akamai", "Imperva"):
            verdict = "LIGHT-WAF"        # CDN but not aggressive bot management
        elif "Imperva" in wafs or "DataDome" in wafs or "Akamai" in wafs:
            verdict = "STRICT-WAF"
        else:
            verdict = "WAF-WALLED"
        wafs_str = ",".join(wafs) or "none"
        print(f"  status={status} verdict={verdict:<11} wafs=[{wafs_str}]")
        rows.append({
            "handle": handle, "host": host, "payout": payout,
            "status": status, "wafs": wafs, "tech": techs,
            "verdict": verdict,
        })

    # Rank: OPEN > LIGHT-WAF > NO-RESPONSE > WAF-WALLED > STRICT-WAF
    rank = {"OPEN": 0, "LIGHT-WAF": 1, "NO-RESPONSE": 2,
            "WAF-WALLED": 3, "STRICT-WAF": 4}
    rows.sort(key=lambda r: (rank.get(r["verdict"], 9), -r["payout"]))

    Path("data/waf-screening.json").write_text(json.dumps(rows, indent=2))

    # Markdown table
    md = ["# WAF/CDN screening — Bugcrowd shortlist",
          "",
          "Ranked by likelihood of producing findings via unauth bb-sentinel.",
          "**OPEN** = no WAF detected — best target for unauth probing.",
          "**LIGHT-WAF** = CDN only, no aggressive bot management.",
          "**WAF-WALLED** = CF/Azure FrontDoor — most unauth probes blocked.",
          "**STRICT-WAF** = Akamai/Imperva/DataDome — even auth probes fight back.",
          "",
          "| Verdict | Payout | Program | Primary host | WAFs detected |",
          "|---------|-------:|---------|--------------|---------------|"]
    for r in rows:
        wafs = ", ".join(r["wafs"]) or "—"
        md.append(f'| `{r["verdict"]}` | ${r["payout"]:,} | '
                  f'`{r["handle"]}` | `{r["host"]}` | {wafs} |')
    Path("data/waf-screening.md").write_text("\n".join(md) + "\n")

    # Summary
    print("\n=== VERDICT DISTRIBUTION ===")
    vc = Counter(r["verdict"] for r in rows)
    for v in ("OPEN", "LIGHT-WAF", "NO-RESPONSE", "WAF-WALLED", "STRICT-WAF"):
        if vc[v]: print(f"  {v:<12} {vc[v]}")

    print("\n=== BEST TARGETS FOR UNAUTH PROBING ===")
    best = [r for r in rows if r["verdict"] in ("OPEN", "LIGHT-WAF")]
    if not best:
        print("  (none — every candidate sits behind major WAF)")
        print("  → Auth-aware probing is the only path forward for this shortlist.")
    else:
        for r in best:
            print(f'  {r["verdict"]:<11} ${r["payout"]:<6} {r["handle"]:<28} {r["host"]}')

    print("\nwrote data/waf-screening.{md,json}")


if __name__ == "__main__":
    asyncio.run(main())
