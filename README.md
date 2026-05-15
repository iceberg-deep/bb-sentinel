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

## Deep scan

Heuristic scoring tells you *where to look*. Deep-scan tells you *what to
report*. [src/deepscan.py](src/deepscan.py) runs four focused probes against
the live URLs found by the monitor and emits `DeepScanFinding` records with
severity + copy-pasteable evidence — the kind triagers can't argue down to
"input validation issue."

| Probe | What it catches |
|-------|-----------------|
| **path-sweep** | `.git/HEAD`, `.env`, `/actuator/heapdump`, `/actuator/env`, `/h2-console`, exposed Swagger/OpenAPI, `/examples/` (Tomcat), `/server-status`, etc. Compares each response against a learned 404-sentinel fingerprint so 200-instead-of-404 vhost wrappers don't false-positive. Strict per-signal Content-Type checks reject empty-body and HTML-wrapper matches. |
| **bypass-403** | Header tricks against every URL that responded 403: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /`, `X-HTTP-Method-Override: GET`, etc. Status-change → finding. |
| **cors-reflect** | Sends `Origin: https://evil.example.com` and `Origin: null` to every 2xx; flags credentialed reflection (high) and wildcard-with-creds (medium). |
| **tomcat-fingerprint** | Detects Tomcat via `/docs/`, extracts the version, cross-references the 9.x CVE band table (CVE-2025-24813 down through GhostCat). Also tests **PUT writability** non-destructively (PUT a sentinel file, GET-verify, DELETE if accepted) — when writable on Tomcat ≤ 9.0.98 that satisfies the CVE-2025-24813 RCE precondition. |

Each finding carries a `severity` from the standard ladder (`critical/high/
medium/low/info`) and an `evidence` field with the raw HTTP excerpt. Use it
from the CLI:

```bash
# Run against a program's live findings already in the DB
bb-sentinel deepscan --program evilcorp --min-severity medium

# Or against any httpx-style JSONL of probe results (from a one-off scan)
bb-sentinel deepscan --from-jsonl data/evilcorp-live.jsonl --min-severity high \
  --out data/evilcorp-deep.jsonl --limit 50
```

Severity weights (`critical=50, high=25, medium=10, low=4, info=1`) are
exposed for any external scoring layer that wants to combine these with the
heuristic priority above.

## CLI

```
bb-sentinel program add <name> --domains a.com,b.com --frequency 2h
bb-sentinel program list
bb-sentinel scan <program> [--force]
bb-sentinel findings <program> --since 24h [--min-score 7]
bb-sentinel status
bb-sentinel run                # foreground monitor loop
bb-sentinel deepscan --program <name> [--min-severity medium]
bb-sentinel deepscan --from-jsonl <file.jsonl> [--min-severity high]
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
