#!/usr/bin/env bash
#
# manual-test.sh — turnkey wrappers for manual bb-sentinel testing
#
# Every mode that touches the target enforces the engagement's
# attribution header + rate cap. Output is timestamped to /tmp/bbs-out/.
#
# Usage:
#   ./scripts/manual-test.sh <mode> [args]
#
# Modes (cheapest → most active):
#   help                           Show this message
#   config [program]               Show effective config for the program
#   targets                        List current discovery output (if any)
#   discover <seed-host>           TLS-SAN transitive (no ExampleCorp HTTP needed)
#                                  Falls back to https://… cert read only.
#   probe <host>                   Single-host httpx live check (auth + rate)
#   probe-list <file>              Multi-host httpx live check (confirms first)
#   scan [program]                 Full bb-sentinel scan (discovery + httpx)
#   rocks [program]                rocks deep-scan probes
#
# Environment overrides:
#   BB_PROGRAM       default program (default: example-program-internal)
#   BB_RATE          rate-limit r/s (default: 3)
#   BB_BC_USERNAME   Bugcrowd username for X-Bug-Bounty (default: <your-handle>)
#   BB_OOB_HOST      enable SSRF OOB mode for rocks (sets BBSENTINEL_OOB_HOST)
#   BB_PIVOT_URLS    enable SSRF internal-pivot (sets BBSENTINEL_PIVOT_URLS)
#
# Examples:
#   ./scripts/manual-test.sh discover passwordreset.internal.example.com
#   ./scripts/manual-test.sh probe papi.example.com
#   ./scripts/manual-test.sh probe-list /tmp/some-targets.txt
#   ./scripts/manual-test.sh scan example-program-internal
#   BB_PROGRAM=example-program-core ./scripts/manual-test.sh rocks
#

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROGRAM="${BB_PROGRAM:-example-program-internal}"
RATE="${BB_RATE:-3}"
BC_USER="${BB_BC_USERNAME:-<your-handle>}"
HEADER="X-Bug-Bounty: BugCrowd-${BC_USER}"
OUTDIR="/tmp/bbs-out/$(date +%Y%m%d-%H%M%S)"

# Resolve absolute tool paths so we don't depend on PATH manipulation
HTTPX="${BB_HTTPX:-/root/.local/bin/httpx}"
NUCLEI="${BB_NUCLEI:-/root/.local/bin/nuclei}"
SUBFINDER="${BB_SUBFINDER:-/root/.local/bin/subfinder}"

cd "$REPO"

# Activate the venv (or fail loudly if missing)
if [[ ! -f .venv/bin/python ]]; then
    echo "FATAL: $REPO/.venv not found. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
    exit 1
fi
PY=".venv/bin/python"

mkdir -p "$OUTDIR"

# ── helpers ──────────────────────────────────────────────────────────

show_help() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
}

show_config() {
    local prog="${1:-$PROGRAM}"
    "$PY" -c "
from src.config import AppConfig
c = AppConfig.load('config/programs.yaml', 'config/global.yaml')
p = c.programs.get('$prog')
if not p:
    print(f'unknown program: $prog')
    print(f'available: {sorted(c.programs)}')
    exit(1)
print(f'PROGRAM:           $prog')
print(f'  domains:          {p.domains}')
print(f'  rate_limit_rps:   {p.rate_limit_rps}')
print(f'  auth_headers:     {list(p.auth_headers)}')
print(f'  no_write_methods: {p.no_write_methods}')
print(f'  rocks_enabled:    {p.rocks_enabled}')
print(f'  inscope_config:   {p.inscope_config}')
print(f'  exclude_finding_signals: {len(p.exclude_finding_signals)} patterns')
print(f'  nuclei_exclude_trees:    {p.nuclei_exclude_trees}')
print()
print(f'GLOBAL:')
print(f'  database_url:     {c.global_.database_url}')
print(f'  httpx_threads:    {c.global_.httpx_threads}')
print(f'  nuclei_conc:      {c.global_.nuclei_concurrency}')
"
}

confirm() {
    local prompt="$1"
    read -rp "[?] $prompt (y/N) " -n 1 ans
    echo
    [[ "$ans" =~ ^[Yy]$ ]]
}

# ── mode dispatch ────────────────────────────────────────────────────

MODE="${1:-help}"
shift || true

case "$MODE" in

    help|--help|-h)
        show_help
        ;;

    config)
        show_config "${1:-$PROGRAM}"
        ;;

    targets)
        if [[ -f /tmp/internal-zones.txt ]]; then
            echo "[*] /tmp/internal-zones.txt: $(wc -l < /tmp/internal-zones.txt) hosts"
            head -20 /tmp/internal-zones.txt
            echo "    ..."
        else
            echo "(no discovery output cached at /tmp/internal-zones.txt — run discover first)"
        fi
        ;;

    discover)
        host="${1:?host required: $0 discover <host>}"
        echo "[*] TLS-SAN transitive discovery on $host"
        echo "    rate: $RATE r/s | header: $HEADER | out: $OUTDIR"
        "$PY" - <<PYEOF | tee "$OUTDIR/discover.txt"
import asyncio
from src.discovery.tls_san import TLSSan, extract_registrable_domain

async def main():
    d = TLSSan(binary_path='$HTTPX', rate_limit_rps=$RATE,
               auth_headers={'X-Bug-Bounty': 'BugCrowd-$BC_USER'},
               max_depth=1, max_per_layer=10)
    res = await d.discover(['$host'])
    for h in res.hosts:
        print(h.hostname)
    import sys
    print(f'--- {len(res.hosts)} hosts ---', file=sys.stderr)
    roots = sorted({extract_registrable_domain(h.hostname) for h in res.hosts})
    print(f'--- {len(roots)} registrable roots: {roots[:8]}{"..." if len(roots) > 8 else ""} ---',
          file=sys.stderr)

asyncio.run(main())
PYEOF
        echo "[*] $OUTDIR/discover.txt"
        ;;

    probe)
        host="${1:?host required: $0 probe <host>}"
        echo "[*] httpx live probe → $host"
        echo "    rate: $RATE r/s | header: $HEADER"
        printf '%s\n' "$host" | "$HTTPX" \
            -rate-limit "$RATE" -timeout 10 \
            -H "$HEADER" \
            -title -status-code -tech-detect -tls-grab \
            -json -silent 2>/dev/null > "$OUTDIR/probe.json"
        "$PY" - "$OUTDIR/probe.json" <<'PYEOF'
import json, sys
for line in open(sys.argv[1]):
    if not line.strip(): continue
    try: r = json.loads(line)
    except json.JSONDecodeError: continue
    print(f'{r.get("status_code", "?"):>4}  {r.get("url")}')
    if r.get("title"):    print(f'      title: {r["title"][:60]!r}')
    if r.get("tech"):     print(f'      tech:  {r["tech"]}')
    if r.get("location"): print(f'      → {r["location"]}')
    cn = (r.get("tls") or {}).get("subject_cn")
    if cn: print(f'      tls-cn: {cn}')
PYEOF
        echo "[*] $OUTDIR/probe.json"
        ;;

    probe-list)
        file="${1:?file required: $0 probe-list <file>}"
        [[ -f "$file" ]] || { echo "FATAL: file not found: $file" >&2; exit 1; }
        n=$(grep -cv '^$' "$file")
        echo "[*] probe-list against $n hosts from $file"
        echo "    rate: $RATE r/s ($(echo "scale=1; $n / $RATE" | bc)s estimated)"
        echo "    header: $HEADER"
        confirm "proceed?" || { echo "aborted"; exit 0; }
        "$HTTPX" -l "$file" \
            -rate-limit "$RATE" -timeout 10 \
            -H "$HEADER" \
            -title -status-code -tech-detect -tls-grab \
            -json -silent 2>/dev/null > "$OUTDIR/probe-list.json"
        live=$(wc -l < "$OUTDIR/probe-list.json")
        echo "[*] $live / $n live → $OUTDIR/probe-list.json"
        "$PY" - "$OUTDIR/probe-list.json" <<'PYEOF'
import json, sys
hits = []
for line in open(sys.argv[1]):
    if not line.strip(): continue
    try: hits.append(json.loads(line))
    except json.JSONDecodeError: pass
for r in hits[:30]:
    sc = r.get('status_code', '?')
    print(f'{sc:>4}  {r.get("url", "?"):<55s}  {(r.get("title") or "")[:40]!r}')
if len(hits) > 30: print(f'  … {len(hits)-30} more in JSON')
PYEOF
        ;;

    scan)
        prog="${1:-$PROGRAM}"
        echo "[*] bb-sentinel scan — $prog"
        echo "[*] config:"
        show_config "$prog" | sed 's/^/    /'
        confirm "fire scan?" || { echo "aborted"; exit 0; }
        "$PY" -m src.cli scan "$prog" --force --ignore-compliance 2>&1 |
            tee "$OUTDIR/scan.log"
        echo "[*] $OUTDIR/scan.log"
        ;;

    rocks)
        prog="${1:-$PROGRAM}"
        # Honor OOB env vars if set in the user's shell — bb-sentinel
        # already reads BBSENTINEL_* directly, but reflect them here so
        # the user sees the active mode before launching.
        ssrf_mode="heuristic"
        [[ -n "${BB_OOB_HOST:-}" ]] && { export BBSENTINEL_OOB_HOST="$BB_OOB_HOST"; ssrf_mode="oob-active"; }
        [[ -n "${BB_PIVOT_URLS:-}" ]] && { export BBSENTINEL_PIVOT_URLS="$BB_PIVOT_URLS"; ssrf_mode="internal-pivot"; }
        echo "[*] rocks deep-scan — $prog"
        echo "    ssrf-oob mode: $ssrf_mode"
        confirm "fire rocks?" || { echo "aborted"; exit 0; }
        "$PY" -m src.cli rocks --program "$prog" --min-severity medium 2>&1 |
            tee "$OUTDIR/rocks.log"
        echo "[*] $OUTDIR/rocks.log"
        ;;

    *)
        echo "unknown mode: $MODE" >&2
        echo
        show_help
        exit 2
        ;;
esac
