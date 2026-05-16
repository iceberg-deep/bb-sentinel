"""
Batch compliance check — run the headless-rendered pre-flight across a
shortlist of programs and produce a side-by-side comparison.

This is the operator's "which program should I actually point bb-sentinel at"
ground-truth check. Each row of the output shows the verdict + disclosure
status pulled from the rendered program brief — these are the two facts
that the bounty-targets-data dump's metadata cannot be trusted on.

Run from repo root:
    python3 scripts/batch_compliance.py
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.compliance import check_url


# Top webable-scope Bugcrowd candidates from build_signal_list.py.
# Format: (display-name, max-payout, in-scope-summary, url)
CANDIDATES = [
    ("HotDoc",                   8000, "3 webable",                  "https://bugcrowd.com/engagements/hotdoc"),
    ("Plusgrade Loyalty",        5000, "*.points.com",               "https://bugcrowd.com/engagements/plusgrade-mbb-public"),
    ("MyFitnessPal Managed",     4500, "3 webable",                  "https://bugcrowd.com/engagements/myfitnesspal-mbb"),
    ("Majid Al Futtaim Retail",  4000, "carrefouruae.com + api",     "https://bugcrowd.com/engagements/carrefour"),
    ("Cloudinary",               4000, "5 webable",                  "https://bugcrowd.com/engagements/cloudinary"),
    ("Directly",                 3000, "3 webable",                  "https://bugcrowd.com/engagements/directly"),
    ("Magic Labs",               3000, "3 webable",                  "https://bugcrowd.com/engagements/magiclabs-mbb-og"),
    ("Web.com",                  3000, "3 webable",                  "https://bugcrowd.com/engagements/webdotcom"),
    ("HostGator LATAM",          2500, "2 webable",                  "https://bugcrowd.com/engagements/hostgator-latam-bb"),
    ("Tamedia",                  2500, "2 webable",                  "https://bugcrowd.com/engagements/tamedia"),
    ("Jora",                     2500, "2 webable",                  "https://bugcrowd.com/engagements/jora"),
    ("Quizlet",                  2000, "4 webable",                  "https://bugcrowd.com/engagements/quizlet"),
]


def short_prohibitions(check) -> str:
    if not check.prohibitions:
        return "—"
    sigs = []
    seen = set()
    for p in check.prohibitions:
        if p.signal in seen: continue
        seen.add(p.signal)
        sigs.append(p.signal)
        if len(sigs) >= 3: break
    return ", ".join(sigs)


async def check_one(name: str, url: str) -> dict:
    try:
        check = await check_url(url)
    except Exception as e:
        return {"name": name, "url": url, "verdict": "ERROR",
                "disclosure": "UNKNOWN", "prohibitions": [],
                "text_len": 0, "error": f"{type(e).__name__}: {e}"}
    return {
        "name": name, "url": url,
        "verdict": check.verdict,
        "disclosure": check.disclosure_status,
        "prohibitions": [m.signal for m in check.prohibitions],
        "allowances":   [m.signal for m in check.allowances],
        "text_len": check.text_length,
        "error": check.fetch_error,
    }


async def main():
    print(f"Batch-checking compliance for {len(CANDIDATES)} candidates")
    print(f"(sequential to avoid stampeding chromium; ~15-30s each)\n")
    results = []
    for i, (name, pay, scope, url) in enumerate(CANDIDATES, 1):
        print(f"  [{i:>2}/{len(CANDIDATES)}] {name:<28}  fetching ...", flush=True)
        r = await check_one(name, url)
        r["max_payout"] = pay
        r["scope_summary"] = scope
        results.append(r)
        # Live one-line summary
        v = r["verdict"]; d = r["disclosure"]
        prohibs_str = ", ".join(r["prohibitions"][:3]) if r["prohibitions"] else "—"
        print(f"          → {v:<8}  disclosure={d:<9}  {prohibs_str}", flush=True)

    # Sort: OK first (with ALLOWED disclosure), then WARN, then UNCLEAR, then BLOCK
    rank = {"OK":0, "WARN":1, "UNCLEAR":2, "BLOCK":3, "ERROR":4}
    disc_rank = {"ALLOWED":0, "UNKNOWN":1, "FORBIDDEN":2}
    results.sort(key=lambda r: (rank.get(r["verdict"], 9),
                                  disc_rank.get(r["disclosure"], 9),
                                  -r["max_payout"]))

    out = Path("/home/iceberg/bb-sentinel/data/batch-compliance.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))

    # MD table
    md = ["# Batch compliance check — Bugcrowd webable shortlist", "",
          f"Generated: {len(results)} candidates rendered via headless chromium.",
          "Ranked by verdict (OK > WARN > UNCLEAR > BLOCK), then disclosure status, then payout.",
          "",
          "| Verdict | Disclosure | Max  | Name | Scope | Prohibitions | URL |",
          "|---------|------------|-----:|------|-------|--------------|-----|"]
    for r in results:
        prohibs = ", ".join(r["prohibitions"][:3]) or "—"
        md.append(f"| `{r['verdict']}` | `{r['disclosure']}` | ${r['max_payout']:,} | "
                  f"{r['name']} | {r['scope_summary']} | {prohibs} | <{r['url']}> |")
    Path("/home/iceberg/bb-sentinel/data/batch-compliance.md").write_text("\n".join(md) + "\n")
    print(f"\nwrote data/batch-compliance.{{md,json}}")
    print(f"\n=== SUMMARY ===")
    from collections import Counter
    vc = Counter(r["verdict"] for r in results)
    dc = Counter(r["disclosure"] for r in results)
    print(f"verdicts:     {dict(vc)}")
    print(f"disclosures:  {dict(dc)}")
    print(f"\n=== BEST PICKS (verdict + disclosure both green) ===")
    best = [r for r in results
            if r["verdict"] in ("OK", "WARN")
            and r["disclosure"] in ("ALLOWED", "UNKNOWN")]
    if not best:
        print("  (none — every shortlist program either BLOCKS automation or FORBIDS disclosure)")
    for r in best[:10]:
        print(f"  {r['verdict']:<6} {r['disclosure']:<9} ${r['max_payout']:>5} {r['name']:<28} {r['url']}")


if __name__ == "__main__":
    asyncio.run(main())
