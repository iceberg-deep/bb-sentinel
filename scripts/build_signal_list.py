"""
Build a unified curated signal-building target list across Bugcrowd, Intigriti,
and YesWeHack — filtered for the criteria stated by the user:

  * Low / no signal requirement (excludes HackerOne — separate trial-report
    block in effect, see [[user-bb-strategy]] memory)
  * Pays cash (max_payout > 0)
  * New / less-researched (proxy: smaller in-scope count, mid-tier payout)
  * USD preferred (Bugcrowd is mostly USD; Intigriti/YWH are EUR; we keep
    EUR programs but flag the conversion)
  * Allows public disclosure when possible (writeups build platform-
    independent signal)

Output: data/signal-build-targets.md (human-readable) and
        data/signal-build-targets.json (machine).
"""
import json
from pathlib import Path

BC  = json.load(open("/tmp/bc_data.json"))
INT = json.load(open("/tmp/intigriti_data.json"))
YWH = json.load(open("/tmp/ywh_data.json"))

# Approximate EUR→USD; programs published in EUR get noted, value compared
# against USD-equivalent for sorting only.
EUR_USD = 1.07


def normalize_bc(p):
    mp = p.get("max_payout") or 0
    n = len(p.get("targets", {}).get("in_scope", []) or [])
    return {
        "platform": "Bugcrowd",
        "name": p.get("name", "?"),
        "url": p.get("url", ""),
        "max_payout_usd": mp,            # BC is USD by default
        "currency": "USD",
        "in_scope_count": n,
        "allows_disclosure": bool(p.get("allows_disclosure")),
        "managed": bool(p.get("managed_by_bugcrowd")),
        "safe_harbor": p.get("safe_harbor", ""),
    }


def normalize_int(p):
    mb = p.get("max_bounty") or {}
    val = mb.get("value", 0) or 0
    cur = mb.get("currency", "EUR") or "EUR"
    usd = round(val * (EUR_USD if cur == "EUR" else 1))
    n = len(p.get("targets", {}).get("in_scope", []) or [])
    return {
        "platform": "Intigriti",
        "name": p.get("name", "?"),
        "url": p.get("url", ""),
        "max_payout_usd": usd,
        "currency": cur,
        "in_scope_count": n,
        # Intigriti dump doesn't expose disclosure policy; treat as unknown
        "allows_disclosure": None,
        "managed": None,
        "safe_harbor": "",
        "max_payout_native": val,
    }


def normalize_ywh(p):
    mp = p.get("max_bounty") or 0       # YWH dump appears to be EUR by convention
    usd = round(mp * EUR_USD)
    n = len(p.get("targets", {}).get("in_scope", []) or [])
    return {
        "platform": "YesWeHack",
        "name": p.get("name", "?"),
        "url": f"https://yeswehack.com/programs/{p.get('id','')}",
        "max_payout_usd": usd,
        "currency": "EUR",
        "in_scope_count": n,
        "allows_disclosure": None,
        "managed": p.get("managed"),
        "safe_harbor": "",
        "max_payout_native": mp,
    }


# Filter each platform: paying + public + reasonable-scope size
def usable(p, np):
    return (np["max_payout_usd"] >= 500
            and 2 <= np["in_scope_count"] <= 25)


pool = []
for p in BC:
    if p.get("max_payout") and p.get("max_payout") > 0:
        np = normalize_bc(p)
        if usable(p, np): pool.append(np)
for p in INT:
    if p.get("confidentiality_level") == "public" and p.get("status") == "open":
        np = normalize_int(p)
        if np["max_payout_usd"] > 0 and usable(p, np): pool.append(np)
for p in YWH:
    if p.get("public") and not p.get("disabled") and (p.get("max_bounty") or 0) > 0:
        np = normalize_ywh(p)
        if usable(p, np): pool.append(np)

# Score for signal-building suitability
def score(np):
    s = 0.0
    # Disclosure-allowed is the strongest signal-building signal
    if np["allows_disclosure"] is True: s += 30
    elif np["allows_disclosure"] is None: s += 10  # unknown — don't punish, don't reward
    # Payout band — prefer $1k-$8k (real money but not whale-tier prestige)
    pay = np["max_payout_usd"]
    if 1000 <= pay <= 8000: s += 25
    elif 500 <= pay < 1000: s += 10
    elif pay > 8000: s += 5
    # Smaller scope = less competition (but not too small)
    n = np["in_scope_count"]
    if 2 <= n <= 6: s += 20
    elif 7 <= n <= 12: s += 15
    elif 13 <= n <= 25: s += 8
    # USD bonus — user is US-based
    if np["currency"] == "USD": s += 10
    # Safe harbor (Bugcrowd only) — explicit legal coverage
    if np.get("safe_harbor") in ("full",): s += 5
    return round(s, 1)

for np in pool: np["signal_build_score"] = score(np)
pool.sort(key=lambda p: (-p["signal_build_score"], p["in_scope_count"]))

# Write outputs
out_dir = Path("/home/iceberg/bb-sentinel/data")
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / "signal-build-targets.json").write_text(json.dumps(pool, indent=2))

# Markdown
md = [
    "# Signal-building target list",
    "",
    "Cross-platform paying public programs filtered for the user's stated",
    "criteria (low signal req, good payout, less-researched, USD preferred,",
    "disclosure-allowed when known). Sorted by signal-build score:",
    "  +30 disclosure allowed · +10 unknown · 0 forbidden",
    "  +25 payout $1k-$8k · +10 $500-$1k · +5 >$8k (whale-tier, more competition)",
    "  +20 scope 2-6 · +15 7-12 · +8 13-25",
    "  +10 USD · +5 full safe-harbor",
    "",
    "**H1 is excluded** — trial-report exhaustion locks the account across the",
    "entire platform regardless of program signal requirement.",
    "",
    "| # | Score | Platform | Name | Max | Cur | Assets | Disc | URL |",
    "|---|------:|----------|------|----:|:---:|------:|:----:|-----|",
]
for i, np in enumerate(pool[:60], 1):
    disc = {True: "✓", False: "✗", None: "?"}.get(np["allows_disclosure"], "?")
    md.append(
        f'| {i} | {np["signal_build_score"]:.0f} | {np["platform"]:<9} | '
        f'{np["name"][:42]} | {np["max_payout_usd"]:,} | {np["currency"]} | '
        f'{np["in_scope_count"]:>3} | {disc} | [link]({np["url"]}) |'
    )
(out_dir / "signal-build-targets.md").write_text("\n".join(md) + "\n")
print(f"\npool size: {len(pool)}")
print(f"wrote data/signal-build-targets.{{md,json}}")
print()
# Show top 25 to console
print("=== TOP 25 SIGNAL-BUILD TARGETS ===")
print(f"{'#':>2} {'Score':>5}  {'Plat':<9}  {'Max':>6}{'Cur':<4}  {'Scope':>5}  {'Disc':>4}  Name")
for i, np in enumerate(pool[:25], 1):
    disc = {True: "Y", False: "N", None: "?"}.get(np["allows_disclosure"])
    print(f"{i:>2} {np['signal_build_score']:>5.0f}  {np['platform']:<9}  "
          f"${np['max_payout_usd']:>5}{np['currency']:<4}  {np['in_scope_count']:>5}  "
          f"{disc:>4}  {np['name'][:55]}")
