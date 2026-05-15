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
  tmobile:
    domains: [t-mobile.com, tmobile.com, sprint.com]
    inscope_config: /app/config/tmobile.inscope
    scan_frequency: 1h
    webhooks:
      - url: https://hooks.slack.com/services/...
        priority_threshold: 7.0
```

`config/global.yaml` controls the database URL, log level, concurrency, and
tool paths. Both files support `${VAR}` and `${VAR:-default}` env-var
expansion.

## Priority scoring

`score = base × multipliers`, capped at 25. Multipliers stack:

| Signal                                              | Multiplier |
|-----------------------------------------------------|------------|
| URL contains admin/api/staging/test/dev/etc.        | ×3         |
| Tech stack includes Spring Boot/Laravel/Django/Rails | ×2         |
| Port in {8080, 9090, 3000, 4000, 5000, 8443, …}     | ×2.5       |
| Discovered in the last 6 hours                      | ×2         |

Set per-webhook `priority_threshold` to gate alert noise.

## CLI

```
bb-sentinel program add <name> --domains a.com,b.com --frequency 2h
bb-sentinel program list
bb-sentinel scan <program> [--force]
bb-sentinel findings <program> --since 24h [--min-score 7]
bb-sentinel status
bb-sentinel run                # foreground monitor loop
```

Invoke as `python -m src.cli ...` (or install the package and use the
`bb-sentinel` console script when you add one to `pyproject.toml`).

## Webhook payload

```json
{
  "timestamp": "2026-05-14T22:30:00Z",
  "program": "tmobile",
  "assets": [
    {
      "url": "https://api-staging.tmobile.com/v2/users",
      "technologies": ["Spring Boot", "MySQL"],
      "priority_score": 8.5,
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
