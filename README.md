# bb-sentinel

Continuous attack-surface monitoring for bug-bounty programs. bb-sentinel runs
discovery (`subfinder`, `assetfinder`, `crt.sh`, `httpx`, `nuclei`) on a
schedule, diffs results against a PostgreSQL baseline, scores new findings, and
dispatches webhook alerts for anything above a configurable priority threshold.

## Status

Skeleton ready. Database models, discovery wrappers, scoring, webhooks,
monitor loop, and CLI are wired end-to-end. The external binaries
(`subfinder`, `assetfinder`, `httpx`, `nuclei`, `inscope`) need to be on
PATH at runtime — the provided Dockerfile installs them.

## Layout

```
bb-sentinel/
├── src/
│   ├── main.py          entry point — runs the monitor loop
│   ├── monitor.py       per-program scanner + scheduler
│   ├── config.py        YAML loader with env-var expansion
│   ├── database.py      SQLAlchemy 2.0 async models (Program/Asset/Finding/ScanRun)
│   ├── scope.py         wrapper around the `inscope` CLI (fails-open if missing)
│   ├── scoring.py       priority-score model
│   ├── webhooks.py      async webhook dispatch with retries
│   ├── cli.py           management CLI
│   └── discovery/       per-tool wrappers behind a common `Discoverer` interface
├── config/
│   ├── programs.example.yaml
│   └── global.example.yaml
├── docker-compose.yml   postgres + redis + sentinel
├── Dockerfile
├── deploy.sh
└── requirements.txt
```

## Quick start (Docker)

```bash
cp config/programs.example.yaml config/programs.yaml
cp config/global.example.yaml   config/global.yaml
# edit programs.yaml with your target programs, then:
./deploy.sh
```

## Configuration

`config/programs.yaml`:

```yaml
programs:
  evilcorp:
    domains: [evilcorp.com, evilcorp.io]
    inscope_config: /app/config/evilcorp.inscope
    scan_frequency: 1h
    webhooks:
      - url: https://hooks.slack.com/services/...
        priority_threshold: 10.0
```

`config/global.yaml` controls the database URL, log level, concurrency, and
tool paths. Both files support `${VAR}` and `${VAR:-default}` env-var
expansion.

## Priority scoring

`score = base × multipliers`, capped at **50**. Each signal contributes at most
one multiplier; multipliers stack on the base score in fixed order. See
[src/scoring.py](src/scoring.py) for the complete token sets.

| Signal                                                                                       | Multiplier |
|----------------------------------------------------------------------------------------------|------------|
| **URL keyword** — `admin`, `api`, `staging`, `dev`, `qa`, `qat`, `uat`, `preprod`, `internal`, `swagger`, `graphql`, `actuator`, `metrics`, `debug`, `jenkins`, `gitlab`, etc. | **×3.0** |
| **Auth surface** — `account`, `auth`, `sso`, `oauth`, `login`, `signin`, `idp`, `identity`, `okta`, `saml`, `mfa`, `2fa`, etc. | **×2.5** |
| **Real-app tech** — Spring/Django/Rails/Laravel/Express/Tomcat or ops tooling (Kubernetes, AppDynamics, Jenkins, GitLab, Elasticsearch, Vault, Consul, …) | **×2.0** |
| **Stack depth** — ≥2 interesting techs after stripping CDN/TLS/jQuery/analytics noise        | **×1.3**   |
| **Interesting port** — `{8080, 9090, 3000, 4000, 5000, 8443, 8081, 8000, 8888, 9000, 7001, 9200, 5601}` | **×2.5** |
| **Recency** — discovered in the last 6 hours                                                 | **×2.0**   |

Base score: `0.7`, +0.3 if the probe returned a 2xx/3xx. Worked example —
`api-staging.evilcorp.com` running Spring Boot + MySQL, just discovered,
returns 200:

```
base 1.0  × 3.0 (keyword: api, staging)  × 2.0 (tech: spring)
          × 1.3 (stack-depth: spring + mysql)  × 2.0 (recent <6h)
        = 15.60
```

An auth-context dev env scores higher — `account-dev.evilcorp.com` returning
200 with no detected tech: `1.0 × 3.0 (dev) × 2.5 (account) × 2.0 (recent) = 15.00`.

Set per-webhook `priority_threshold` to gate alert noise. Threshold `10.0`
catches dev/staging on auth surface; `15.0` catches only when stack tech or
multiple signals also stack.

## Rock-turning (deep scanning)

Heuristic scoring tells you *where to look*. Rock-turning tells you *what to
report*. [src/rocks.py](src/rocks.py) runs six focused probes against the
live URLs found by the monitor and emits `DeepScanFinding` records with
severity + copy-pasteable evidence — the kind triagers can't argue down to
"input validation issue." Inspired by the Armitage Hail-Mary philosophy:
throw every reasonable check at every live target, surface the hits, move on.

| Probe | What it catches |
|-------|-----------------|
| **path-sweep** | `.git/HEAD`, `.env`, `/actuator/heapdump`, `/actuator/env`, `/h2-console`, exposed Swagger/OpenAPI, `/examples/` (Tomcat), `/server-status`, etc. Compares each response against a learned **404-sentinel fingerprint** so 200-instead-of-404 vhost wrappers don't false-positive. Strict per-signal Content-Type checks reject empty-body and HTML-wrapper matches. |
| **bypass-403** | Header tricks against every URL that responded 403: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /`, `X-HTTP-Method-Override: GET`, etc. Status-change → finding. |
| **cors-reflect** | Sends `Origin: https://evil.example.com` and `Origin: null` to every 2xx; flags credentialed reflection (high) and wildcard-with-creds (medium). |
| **tomcat-fingerprint** | Detects Tomcat via `/docs/`, extracts the version, cross-references the 9.x CVE band table (CVE-2025-24813 down through GhostCat). Also tests **PUT writability** non-destructively (PUT a sentinel file, GET-verify, DELETE if accepted) — when writable on Tomcat ≤ 9.0.98 that satisfies the CVE-2025-24813 RCE precondition. |
| **wayback-historical** | Pulls historical URLs from `web.archive.org/cdx` for each base's host (zero traffic to the target), then re-probes a sample of interesting paths (`/admin`, `/api`, `/.git`, `/dump`, etc.) against the live host. Surfaces *forgotten endpoints* — retired admin panels, legacy API consoles — that normal recon misses because they're not linked anywhere. |
| **js-secret-mine** | Fetches each 200 HTML page, follows `<script src=>` references, greps the JS bundles for hardcoded credentials (AWS keys, GitHub PATs, JWT tokens, Google API keys, private-key blocks, `password=`/`api_key=` literals) and internal-hostname/RFC1918-IP disclosures. Capped at 60 JS bundles to bound traffic. |

Each finding carries a `severity` from the standard ladder (`critical/high/
medium/low/info`) and an `evidence` field with the raw HTTP excerpt. Use it
from the CLI:

```bash
# Run against a program's live findings already in the DB
bb-sentinel rocks --program evilcorp --min-severity medium

# Or against any httpx-style JSONL of probe results (from a one-off scan)
bb-sentinel rocks --from-jsonl data/evilcorp-live.jsonl --min-severity high \
  --out data/evilcorp-rocks.jsonl --limit 50
```

Severity weights (`critical=50, high=25, medium=10, low=4, info=1`) are
exposed for any external scoring layer that wants to combine these with the
heuristic priority above.

## Compliance pre-flight — don't get your account banned

Most bug-bounty programs include explicit anti-automation language in their
rules (Bugcrowd's VRT flags "Excessive Use of Automated Tools," many H1
program briefs list named scanners as out-of-scope, etc.). Running bb-sentinel
against a program that prohibits automated scanning gets the researcher's
account banned and can create TOS/CFAA exposure. [src/compliance.py](src/compliance.py)
is a pre-flight check that reads the program's posted rules text and decides
whether automation is likely allowed **before** the scan runs.

| Verdict | Meaning |
|---------|---------|
| `BLOCK` | Explicit prohibition without a covering allowance. `scan` / `rocks` refuse to start. |
| `WARN`  | Ambiguous, contradictory, or "prior written consent" language. Prompts the operator. |
| `UNCLEAR` | Rules page silent, or couldn't be fetched (JS-rendered, etc.). Prompts the operator. Paste the rules to a file and use `rules_text` to get a real verdict. |
| `OK` | Explicit allowance for automated tooling. |

What the checker greps for (case-insensitive, multi-pattern):

```
PROHIBITED → "no automated scanning/tools/testing"
             "manual testing only"
             "automated vulnerability scanners are prohibited"
             "do not run automated"
             "prior written consent/approval/authorization"
             named scanners (nuclei, nikto, nessus, qualys, acunetix, burp, zap)
             "DoS / denial-of-service / DDoS"
             "volumetric / excessive requests"
             "brute-force testing"
             "no fuzzing"

PERMITTED  → "automated scanning is allowed/permitted/welcome"
             "nuclei templates welcome/accepted"
             "automated scanners are allowed"

RATE-LIMIT → "rate limit", explicit RPS values, "throttle",
             "respect/observe/honor our limits", "reasonable use"
```

Configure per program in `programs.yaml`:

```yaml
programs:
  evilcorp:
    domains: [evilcorp.com]
    inscope_config: /app/config/evilcorp.scope
    # Compliance pre-flight inputs — either url OR text file
    rules_url: https://bugcrowd.com/engagements/evilcorp
    # Or paste the rules text into a file when the policy page is JS-rendered
    # rules_text: /app/config/evilcorp.rules.txt
    # Override AFTER you've read the rules yourself
    # compliance_override: true
```

Use the standalone command for a one-off check:

```bash
bb-sentinel compliance --url https://bugcrowd.com/engagements/something
bb-sentinel compliance --file path/to/pasted-rules.txt
bb-sentinel compliance --program evilcorp        # pulls from programs.yaml
bb-sentinel compliance --url URL --force-headless   # skip httpx, render directly
bb-sentinel compliance --url URL --no-headless      # disable the JS fallback
```

### How it fetches JS-rendered policy pages

Bugcrowd / HackerOne / Intigriti program briefs are SPAs — a plain `httpx`
GET returns just the loader shell with no rules text in it. Manually pasting
the policy each time defeats the point of an automated pre-flight, so the
fetcher does this:

1. First tries `httpx` (fast, no JS).
2. If the response is shorter than 500 chars of stripped text (signature of
   an unrendered SPA), or returns an error, auto-escalates to a headless
   chromium fetch via `subprocess`.
3. Headless chromium runs with `--virtual-time-budget=10000` so the SPA's
   internal JS has 10 seconds of virtual time to populate the DOM before
   it gets dumped with `--dump-dom`. Without that flag the dump captures
   only the loader.
4. The rendered HTML is stripped (scripts / styles / tags removed) and fed
   to the same compliance pattern matcher used for pasted rules text.

The headless fetch path adds no Python deps — it shells out to whichever
chromium-family binary is on `$PATH` (`chromium`, `chromium-browser`,
`google-chrome`, `google-chrome-stable`, or `chrome`). If none is present,
the fetch falls back to UNCLEAR with an install hint in the error message.

**Why this matters operationally:** the `bounty-targets-data` dumps that
power [target curation](#target-curation--picking-what-to-point-bb-sentinel-at)
*lie* about disclosure policy in observed cases (Bolt Technology, May 2026:
dump said `allows_disclosure: True`, program brief actually said "This
engagement does not allow disclosure"). The compliance check is now the
single source of truth — it reads the rendered policy text directly, runs
the disclosure-detection patterns alongside the automation patterns, and
surfaces `Disclosure: ALLOWED / FORBIDDEN / UNKNOWN` in every check.

The pre-flight runs automatically before `bb-sentinel scan <program>` and
`bb-sentinel rocks --program <name>`. To skip after manual review:

```bash
bb-sentinel scan evilcorp --ignore-compliance     # one-off
bb-sentinel scan evilcorp --yes                   # auto-confirm WARN/UNCLEAR
```

This is *tooling* — not legal advice. The operator is still responsible for
reading the actual program terms.

## Authenticated probing

The big unlock beyond unauth recon. Most paid bug-bounty findings live
behind a login — IDOR / privilege-escalation / cross-tenant data leaks
are invisible to anon probes. bb-sentinel can carry per-program auth
through every active-probe layer.

### Config

`auth_headers` is a bag of HTTP headers in `programs.yaml`. Values
support `${ENV_VAR}` expansion so secrets stay out of YAML:

```yaml
programs:
  evilcorp:
    domains: [evilcorp.com, evilcorp.io]
    inscope_config: /app/config/evilcorp.scope
    rate_limit_rps: 5
    auth_headers:
      Authorization: "Bearer ${EVILCORP_API_TOKEN}"
      Cookie: "session=${EVILCORP_SESSION}; csrf=${EVILCORP_CSRF}"
      X-API-Key: "${EVILCORP_API_KEY}"
```

`programs.yaml` is gitignored, so even literal values stay local — but
env-var expansion is the recommended pattern. Export the secrets in
your shell before running `bb-sentinel`:

```bash
export EVILCORP_API_TOKEN="eyJhbGc..."
export EVILCORP_SESSION="abc123..."
bb-sentinel scan evilcorp --force
```

### Propagation

`auth_headers` flows through:

| Layer | Mechanism | Scope behavior |
|-------|-----------|----------------|
| `httpx` subprocess (discovery probe) | `-H "Key: Value"` flags | **Global** — sent to every target the subprocess hits |
| `nuclei` subprocess (tech-detect + OWASP vulns) | `-H "Key: Value"` flags | **Global** — same caveat |
| Python `rocks` probes (path-sweep / cors / js-mine / etc.) | `httpx.AsyncClient` per-request header merge | **Scope-restricted** — only sent on requests whose host matches one of `domains:` (or a subdomain thereof). Third-party CDN / JS-bundle fetches do NOT carry auth — prevents token leakage during js-mine. |

### Security notes

- The subprocess tools (httpx, nuclei) send auth headers globally and
  do not strip on cross-domain redirect. If an in-scope host redirects
  to a third-party, your token follows. Mitigate by scoping
  `domains:` tightly per program.
- Python-side probes scope-restrict via the host-suffix match on
  `domains:`. This covers `*.evilcorp.com` style wildcards correctly.
- Never put real auth values into the example YAML or anywhere that
  could be committed. Always go through environment variables.
- Auth tokens rotate — bb-sentinel does no auto-refresh. When a scan
  starts returning 401s, re-export and re-run.

### Why this matters

bb-sentinel's recon + rocks layer found mostly unauth surface
(exposed `.git`/`.env`/admin panels) in the SIX engagement and would
have surfaced more on Plusgrade. The bigger payouts —
cross-tenant IDOR, account-takeover via stale session, server-side
template injection in authenticated app — only become visible once
the auth header rides every probe. This commit lights up that surface
without forcing the operator to manually re-run each tool with the
cookie attached.

## Target curation — picking what to point bb-sentinel at

Half the battle is **choosing a program where your reports will actually be
accepted**, not just finding bugs. [scripts/build_signal_list.py](scripts/build_signal_list.py)
pulls the latest public-program dumps from `arkadiyt/bounty-targets-data` for
Bugcrowd, Intigriti, and YesWeHack, applies a signal-build heuristic, and
emits a ranked target list:

```bash
python3 scripts/build_signal_list.py
# → data/signal-build-targets.md  (human-readable, 60 rows)
# → data/signal-build-targets.json (machine-readable, 287+ programs)
```

The heuristic weights what actually matters when grinding rep from zero:

| Signal | Weight | Why |
|--------|-------:|-----|
| Allows public disclosure | **+30** | Writeups build portfolio-level signal independent of any platform's reputation score |
| Payout band **$1k-$8k** | +25 | Real money but not whale-tier prestige where the strongest hunters camp |
| Scope **2-6 in-scope assets** | +20 | Smaller surface = less competition + room for deep focus |
| Payout band **$500-$1k** | +10 | Smaller checks but valid ROI |
| USD currency | +10 | (Configurable; US-based default) |
| Scope **7-12** assets | +15 | Bigger surface still tractable |
| Full safe-harbor (Bugcrowd) | +5  | Explicit legal coverage |

### HackerOne is deliberately excluded

H1 has a **trial-report mechanism** that locks accounts across the entire
platform when:

1. You've used your ~5 trial submissions
2. Your existing reports haven't been *Resolved* yet (signal stays "Still
   being determined")

In that state, every H1 program rejects new submissions — **even
`Signal Required: 0` VDPs**. This isn't a per-program gate; it's an
account-level gate that no program-side setting can bypass. The H1
Signal score also gets pushed *negative* when triage closes reports as
Informative or N/A, so the loop hardens against you.

Until existing trial reports clear, H1 is dead surface and bb-sentinel
should be pointed at Bugcrowd / Intigriti / YesWeHack instead. The
curation script reflects this and skips H1 entirely.

## CLI

```
bb-sentinel program add <name> --domains a.com,b.com --frequency 2h
bb-sentinel program list
bb-sentinel scan <program> [--force]
bb-sentinel findings <program> --since 24h [--min-score 7]
bb-sentinel status
bb-sentinel run                # foreground monitor loop
bb-sentinel rocks --program <name> [--min-severity medium]
bb-sentinel rocks --from-jsonl <file.jsonl> [--min-severity high]
bb-sentinel compliance --url <rules-url>
bb-sentinel compliance --program <name>
```

Invoke as `python -m src.cli ...` (or install the package and use the
`bb-sentinel` console script when you add one to `pyproject.toml`).

## Webhook payload

```json
{
  "timestamp": "2026-05-14T22:30:00Z",
  "program": "evilcorp",
  "assets": [
    {
      "url": "https://api-staging.evilcorp.com/v2/users",
      "technologies": ["Spring Boot", "MySQL"],
      "priority_score": 15.6,
      "inscope_verified": true,
      "status_code": 200,
      "title": null,
      "port": 443
    }
  ]
}
```

## Scope enforcement

If `inscope_config` is set on a program and the `inscope` binary is on PATH,
discovered hosts are piped through it before being stored. Misconfiguration
fails **open** with an error log line — review logs after first scan.

## Operational notes

- The monitor loop reads `next_scan_at` from the DB, so restarts don't reset
  the schedule.
- Nuclei templates are warmed at image build time; mount `/root/nuclei-templates`
  as a volume to persist template updates across restarts.
- Webhooks retry with exponential backoff (3 attempts). Failures are recorded
  in the `scan_runs.stats` JSON, not retried on subsequent scans.
- Only run this against programs you are authorized to test. Keep
  `inscope_config` accurate; it is the only thing protecting you from
  scope drift.
