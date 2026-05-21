# bb-sentinel

Continuous attack-surface monitoring for bug-bounty programs. bb-sentinel
discovers new subdomains and live hosts on your tracked programs, scores
them by priority, and runs impact-focused probes against the high-value
ones — surfacing report-ready findings while you sleep.

## Table of contents

- [What it does](#what-it-does)
- [Pipeline](#pipeline)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Priority scoring](#priority-scoring)
- [Rock-turning (deep scanning)](#rock-turning-deep-scanning)
- [Report writing](#report-writing)
- [Authenticated probing](#authenticated-probing)
- [Compliance pre-flight](#compliance-pre-flight)
- [Target curation](#target-curation)
- [CLI reference](#cli-reference)
- [Webhook payload](#webhook-payload)
- [Operational notes](#operational-notes)
- [Legal & ethical use](#legal--ethical-use)

## What it does

- **Discovers attack surface** — `subfinder`, `assetfinder`, `crt.sh`,
  `httpx`, `nuclei` orchestrated against your program domains
- **Diffs against a baseline** — PostgreSQL/SQLite state tracks every
  asset, surfaces new appearances
- **Scores findings** — multi-tier multiplier model (URL keywords, auth
  context, tech stack, ports, recency) so high-value surface bubbles up
- **Hunts for impact** — `rocks` runs nine focused probes against live
  URLs to find exposed `.git`/`.env`/actuator/swagger, SQLi/LFI/RCE/SSRF
  via curated nuclei templates, subdomain takeovers, default creds,
  Tomcat-version CVE matches, CORS misconfigs, and more
- **Writes the report** — `bb-sentinel report` turns scan output into
  a submission-ready Markdown + PDF document. Per-class Jinja templates
  frame impact, list triage-validation steps, and flag the common
  downgrade traps that cause programs to close findings as informational
- **Respects program rules** — compliance pre-flight reads each
  program's policy (with headless-rendered fallback for JS pages) and
  refuses to scan programs that prohibit automation; per-program rate
  limits are honored across every probe
- **Carries credentials when authorized** — auth headers propagate
  through every active layer, scope-restricted so tokens don't leak to
  third-party CDNs during JS mining
- **Alerts on impact** — webhook delivery with severity filtering;
  thresholds gate alert noise

## Companion documentation

[`docs/manual-workflows.md`](docs/manual-workflows.md) — playbooks for
the categories bb-sentinel doesn't automate: cellular auth-bypass
testing, mobile-app dynamic analysis (Frida / Objection), IdP
self-registration, and the manual-exploitation cheatsheets for each
detection probe's output (ysoserial chains by gadget library,
ysoserial.net for ViewState, SSTI engine-to-RCE map, file-upload
bypass catalog, SAML claim swap, SSRF gadget catalog including
cloud-metadata endpoints). Read alongside the [Rock-turning](#rock-turning-deep-scanning)
section — `rocks.py` finds the lead, `manual-workflows.md` is the
follow-up.

## Pipeline

```
┌─────────────────┐    ┌────────────────┐    ┌────────────────┐
│  Target         │    │  Compliance    │    │   Discovery    │
│  curation       │───▶│  pre-flight    │───▶│  (subfinder,   │
│  (bounty-data)  │    │  (rules text)  │    │   crt.sh, …)   │
└─────────────────┘    └────────────────┘    └────────┬───────┘
                                                       │
       ┌──────────────────┐    ┌────────────────┐    ┌▼───────────────┐
       │  Webhook alerts  │◀───│  Priority      │◀───│  Scope filter  │
       │  (severity-gated)│    │  scoring       │    │  (inscope)     │
       └──────────────────┘    └────────▲───────┘    └────────┬───────┘
                                        │                     │
                                        │            ┌────────▼───────┐
                                        │            │  httpx + nuclei│
                                        │            │  (live probes) │
                                        │            └────────┬───────┘
                                        │                     │
                                        │            ┌────────▼───────┐
                                        └────────────│  rocks         │
                                                     │  (9 probes,    │
                                                     │  OWASP class)  │
                                                     └────────┬───────┘
                                                              │
                                                     ┌────────▼───────┐
                                                     │  report writer │
                                                     │  (Markdown/PDF │
                                                     │  Jinja per     │
                                                     │  finding class)│
                                                     └────────────────┘
```

## Installation

### Docker (recommended for VPS)

```bash
git clone https://github.com/<your-handle>/bb-sentinel.git
cd bb-sentinel
cp config/programs.example.yaml config/programs.yaml
cp config/global.example.yaml   config/global.yaml
./deploy.sh                     # builds image, brings up Postgres + Redis + sentinel
```

### Local development

```bash
git clone https://github.com/<your-handle>/bb-sentinel.git
cd bb-sentinel
pip install -r requirements.txt
# external tools needed on PATH: subfinder, assetfinder, httpx, nuclei, inscope
```

### Project layout

```
bb-sentinel/
├── src/
│   ├── main.py          monitor-loop entry point
│   ├── monitor.py       per-program scanner + scheduler
│   ├── config.py        YAML loader with env-var expansion
│   ├── database.py      SQLAlchemy 2.0 async models
│   ├── compliance.py    rules-text pre-flight (headless-rendered)
│   ├── scope.py         wrapper around tomnomnom/inscope
│   ├── scoring.py       priority-score multiplier model
│   ├── rocks.py         9-probe deep-scan toolkit
│   ├── report.py        Markdown + PDF report generator (Jinja2)
│   ├── webhooks.py      async webhook dispatch
│   ├── cli.py           management CLI
│   └── discovery/       per-tool wrappers (subfinder, httpx, nuclei, …)
├── scripts/
│   ├── build_signal_list.py    cross-platform target curation
│   └── batch_compliance.py     bulk pre-flight checker
├── templates/
│   └── findings/               per-class Jinja2 report templates
├── config/                     user config (gitignored)
├── data/                       cache, dumps, baselines (gitignored)
└── docker-compose.yml          postgres + redis + sentinel
```

## Quick start

```bash
# 1. Curate targets — pulls Bugcrowd/Intigriti/YesWeHack dumps, ranks
python3 scripts/build_signal_list.py
# → data/signal-build-targets.md  (top 60 ranked)

# 2. Add the program to programs.yaml (see Configuration below)

# 3. Compliance pre-flight — auto-renders JS pages
bb-sentinel compliance --program <name>

# 4. Scan — runs discovery + scope-filter + httpx + nuclei tech-detect
bb-sentinel scan <name> --force

# 5. Deep probe — runs the 9-probe rocks toolkit against live URLs
bb-sentinel rocks --program <name> --min-severity medium

# 6. Write the report — turns rocks JSONL into a Markdown + PDF document
bb-sentinel report --program <name>
# → data/<name>-report.md  (paste into H1/Bugcrowd submission form)
# → data/<name>-report.pdf (for programs that accept PDF deliverables)

# 7. Continuous monitoring
bb-sentinel run     # background loop, alerts via webhook on new findings
```

## Configuration

### `config/programs.yaml`

```yaml
programs:
  evilcorp:
    enabled: true
    domains:
      - evilcorp.com
      - evilcorp.io

    # Scope filter (regex per line; ! prefix = exclude)
    inscope_config: /app/config/evilcorp.scope

    # Compliance pre-flight — either url OR pasted-rules file
    rules_url: https://bugcrowd.com/engagements/evilcorp
    # rules_text: /app/config/evilcorp.rules.txt

    # Per-program outbound rate cap (matches program-puvendor-bhed limits)
    rate_limit_rps: 5

    # Authenticated probing (env-expanded so secrets stay out of YAML)
    auth_headers:
      Authorization: "Bearer ${EVILCORP_API_TOKEN}"
      Cookie: "session=${EVILCORP_SESSION}"

    # Engagement guardrails — see below
    no_write_methods: false   # disable PUT/POST/DELETE/PATCH probes
    rocks_enabled: true       # set false for discovery-only profiles

    # Out-of-scope finding suppression (regex match on finding.signal)
    exclude_finding_signals:
      - "^xss.*"              # if program closes XSS as N/A
      - "^open-redirect.*"

    # Skip these nuclei template trees entirely (pre-filter; saves rate budget)
    nuclei_exclude_trees:
      - "http/vulnerabilities/redirect"

    scan_frequency: 1h

    webhooks:
      - url: https://hooks.slack.com/services/...
        priority_threshold: 10.0
```

#### Engagement guardrails

Two flags gate the more invasive parts of the pipeline. Both default to
the most-permissive value, but several programs *require* the stricter
setting and silent compliance is on the operator.

**`no_write_methods: true`** — disables every probe that sends a
state-modifying HTTP method. Today that's TomcatFingerprint's PUT-probe
(it writes `/bb-sentinel-write-probe-DELETE-ME.txt` to test
CVE-2025-24813's precondition, then DELETEs it); the FileUploadDiscovery
probe's active upload step; and any future write-method probe is
required to honor the flag. Use on programs whose terms ban data
modification — e.g. ExampleCorp's VendorA/VendorB clause: *"do not modify any
data within customer accounts; modification will result in a ban from
the platform."* Even a transient write that you immediately delete is a
violation under that wording.

**`rocks_enabled: false`** — skip the deep-scan stage entirely.
Discovery + httpx live-host check + nuclei still run; the
9-probe `rocks` stage is bypassed. Use for discovery-only profiles
where you want a host inventory to manually triage before any active
probing. Examples: freshly-discovered scopes, internal-named zones,
programs in a quiet observation phase, or staging an engagement where
you don't yet have approval to run deep probes.

Both flags log a `[guardrail]` line at scan start so it's obvious from
the run output which mode you're in.

#### Out-of-scope finding suppression

Two complementary filters keep findings the program won't accept out of
the submission pipeline:

**`exclude_finding_signals: list[str]`** — regex patterns matched
against `DeepScanFinding.signal`. Findings whose signal starts with any
of these are dropped *after* the probe runs but *before* the report
writer sees them. The probe still does its work — only the report is
filtered. Logged at INFO so you can see how much was filtered per
probe. Use for vulnerability classes the program explicitly excludes
from rewards (XSS, open-redirect, cache poisoning, missing headers,
OPTIONS/TRACE, non-sensitive cookie flags, outdated libs without PoC).

**`nuclei_exclude_trees: list[str]`** — nuclei template-tree subpaths
removed from `OwaspVulnsProbe`'s scan set *before* nuclei runs. Pure
pre-filter — these never get sent to the target, saving rate-limit
budget. Pattern is the same as nuclei's standard layout (e.g.
`http/vulnerabilities/redirect` to skip the entire open-redirect
template tree).

Use both: `nuclei_exclude_trees` for nuclei-class output you can predict
upfront; `exclude_finding_signals` for the broader set of signals
emitted across all rocks probes.

### `config/global.yaml`

Controls database URL, log level, concurrency, tool paths. Supports
`${VAR}` and `${VAR:-default}` env-var expansion.

## Priority scoring

`score = base × multipliers`, capped at **50**. Each signal contributes
at most one multiplier; multipliers stack on the base score in fixed
order. Token sets are in [`src/scoring.py`](src/scoring.py).

| Signal                                                       | Multiplier |
|--------------------------------------------------------------|-----------:|
| **URL keyword** (`admin`/`api`/`staging`/`dev`/`actuator`/…) | ×3.0       |
| **Auth surface** (`account`/`auth`/`sso`/`oauth`/`login`/…)  | ×2.5       |
| **Real-app tech** (Spring/Django/Rails/Tomcat/Jenkins/…)     | ×2.0       |
| **Stack depth** (≥2 non-noise techs detected)                | ×1.3       |
| **Interesting port** (`8080`/`9090`/`3000`/`5000`/`8443`/…)  | ×2.5       |
| **Recency** (discovered in the last 6 hours)                 | ×2.0       |

Base score is `0.7`, +0.3 if the probe returned a 2xx/3xx.

**Worked example:** `api-staging.evilcorp.com` running Spring Boot +
MySQL, just discovered, returns 200:

```
base 1.0  × 3.0 (api, staging)  × 2.0 (spring)
          × 1.3 (stack-depth)   × 2.0 (recent)
        = 15.60
```

Set per-webhook `priority_threshold` to gate alert noise. Threshold
`10.0` catches dev/staging on auth surface; `15.0` catches only when
stack tech or multiple signals also stack.

## Rock-turning (deep scanning)

Where heuristic scoring tells you *where to look*, rocks tells you *what
to report*. [`src/rocks.py`](src/rocks.py) runs eighteen focused probes
against the live URLs found by the monitor and emits
`DeepScanFinding` records with severity + copy-pasteable evidence.

| Probe | Catches |
|-------|---------|
| **`path-sweep`** | 126 high-value paths: `.git/HEAD`, `.env*`, `/actuator/heapdump`, `/actuator/env`, `/h2-console`, exposed Swagger/OpenAPI/GraphQL, `/examples/` (Tomcat), source-control directories, CMS admin paths, cloud IaC artifacts. Compares each response to a learned 404-sentinel fingerprint so SPA wrappers don't false-positive. |
| **`backup-file`** | For every live 200 URL, probes `.bak` / `.old` / `~` / `.swp` / `.orig` / `.tmp` / `.backup` / `.save` / `.zip` / `.gz` variants. Catches editor-save and naive backup leaks. |
| **`method-enum`** | `OPTIONS` / `PUT` / `DELETE` / `PATCH` / `TRACE` / `PROPFIND` / `CONNECT` / `DEBUG` against each base. Flags `OPTIONS` advertising write methods, unauth PUT/DELETE writes, WebDAV exposed, TRACE-XST. |
| **`bypass-403`** | Header tricks against every 403: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /`, `X-HTTP-Method-Override: GET`. Status-change → finding. |
| **`cors-reflect`** | Sends `Origin: https://evil.example.com` and `Origin: null` to every 2xx; flags credentialed reflection (high) and wildcard-with-creds (medium). |
| **`tomcat-fingerprint`** | Detects Tomcat via `/docs/`, extracts version, cross-references the 9.x CVE band table (CVE-2025-24813 through GhostCat). Tests PUT writability non-destructively (sentinel-file PUT → GET-verify → DELETE) — writable + ≤9.0.98 satisfies the CVE-2025-24813 RCE precondition. Honors `no_write_methods` — skips the PUT step entirely on programs that ban data modification. |
| **`spring-actuator`** | Beyond PathSweep's single-path hits, walks the full Spring Boot Actuator surface (`/actuator/*` + Boot-1.x legacy paths). For `/env` parses JSON and flags **unmasked** secret values (`password`/`token`/`api-key`/etc.). For `/jolokia` follows `/list` to enumerate MBeans and flags dangerous ones (scriptEngineFactories, DiagnosticCommand, Realm) — detection only, never invokes exec. For `/heapdump` flags presence + Content-Length without downloading (heap files are 50–500 MB). Extracts Spring version from `/info` for downstream n-day CVE matching. |
| **`ssti-fingerprint`** | Math-only template-injection fingerprint. Tests seven payloads (`{{7*7}}` / `${7*7}` / `<%=7*7%>` / `#{7*7}` / `{{= 7*7 }}` / `[[${7*7}]]` / `{7*7}`) across the four most commonly-reflected GET params per base. Confirms only when (a) `49` appears in the response, (b) the raw payload does not, and (c) the result count exceeds the baseline page's count of `49`. Identifies engine (Jinja2/Twig, FreeMarker/SpEL, ERB/JSP, Thymeleaf, etc.); RCE escalation is the operator's manual step with engine-specific gadgets. |
| **`lfi-flag`** | LFI canary reads via two confirmation paths: (a) `/etc/passwd` traversal (with `..%2f`, `....//`, double-encoded, and `php://filter` variants) confirmed only when the response contains `root:x:0:0`; (b) direct `/flag.txt` / `/flag` / `/flag.html` reads for flag-capture targets where the file lives at root without traversal. Twelve highest-yield param names (`file`, `path`, `template`, `page`, `include`, …). Per-base budget capped at 30 requests so a 100-host run stays within typical rate caps. |
| **`ssrf-oob`** | SSRF candidate identification + optional out-of-band confirmation. Three modes auto-selected from env vars: **heuristic** (default, no env) — emits info findings flagging SSRF-prone params (`url`, `callback`, `redirect_uri`, `image_url`, …) for manual Burp testing; **oob-active** (`BBSENTINEL_OOB_HOST` set) — injects the OOB host as each candidate param's value and emits high findings, operator confirms via their OOB listener (Burp Collaborator / interactsh); **internal-pivot** (`BBSENTINEL_OOB_HOST` + `BBSENTINEL_PIVOT_URLS=<csv>` + `BBSENTINEL_PIVOT_CANARY=<substr>`) — additionally injects each pivot URL and flags critical when the canary substring appears in the response. Pivot URLs and canary stay in env vars, not source — probe is a generic SSRF tool, engagement-specific targets supplied at runtime. |
| **`file-upload-discovery`** | Surfaces file-upload endpoints by parsing HTML for `<form enctype="multipart/form-data">` containing `<input type="file">`. Resolves each form's action URL and emits a finding with method + field names + a Burp follow-up checklist (mis-declared MIME, double extensions, null-byte truncation, SVG XSS, polyglots, traversal-in-filename). Discovery only — never POSTs uploads, so safe to run on programs that ban data modification. |
| **`deserialization-markers`** | Passive detection of insecure-deserialization indicators in responses, cookies, and bodies. Catches Java serialized streams (`AC ED 00 05` magic / `rO0AB` base64), ASP.NET `__VIEWSTATE` parameter (flags critical when `__VIEWSTATEGENERATOR` MAC validator is absent), Python pickle protocol-4 magic (`\x80\x04`) on `octet-stream` responses, and PHP serialization syntax. Each finding includes a one-line ysoserial / ysoserial.net / phpggc / pickle-gadget cheatsheet for the operator's local follow-up. Never sends gadget payloads. |
| **`object-storage`** | Cloud-bucket misconfig hunt. Extracts S3 / GCS / Azure Blob / Alibaba OSS / DigitalOcean Spaces / Cloudflare R2 / Wasabi URIs from every page's HTML and inline `<script>` references, deduplicates, then tests each bucket for anonymous read (HIGH if 200 listing) and anonymous read-only (MEDIUM if root GET 200 but listing closed). Read-only — never PUTs or DELETEs; operator does write-takeover testing manually if warranted. |
| **`saml-oidc`** | Federation endpoint discovery + sanity checks. Hits `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/saml/metadata`, the AD FS federation metadata path, plus Keycloak / Okta variants. Parses each: emits CRITICAL when `alg=none` is in `id_token_signing_alg_values_supported`; HIGH when `HS256` mixes with RSA (algorithm-confusion risk); HIGH when SAML metadata declares `AssertionConsumerService` without a signature requirement. IdP identification only — claim-swap / sig-strip / KID-injection exploits stay manual. |
| **`internal-service`** | Service-fingerprint sweep for 20 commonly internal-only systems that occasionally leak to the public internet: Jenkins (login/`/api/json`), GitLab (`/api/v4/version`), Grafana (including critical-flag for unauth `/api/datasources`), Kibana, Consul (`/v1/agent/self`), Docker Registry v2 (`/v2/_catalog` flags HIGH), Splunk, Nexus, SonarQube, Jupyter (`/api/contents` = code-exec lead), Airflow, Vault (`/v1/sys/health`), Elasticsearch / OpenSearch (`/_cluster/health` flags CRITICAL). Each entry pairs a path with a unique-token regex to avoid generic-200 false positives. Read-only — no logins, no API writes. |
| **`wayback-historical`** | Pulls historical URLs from `web.archive.org/cdx` (zero traffic to the target during lookup), re-probes interesting paths (`/admin`, `/api`, `/.git`, `/dump`, …) against the live host. Surfaces forgotten endpoints normal recon misses. |
| **`js-secret-mine`** | Fetches each 200 HTML page, follows `<script src=>`, greps JS bundles for AWS keys, GitHub PATs, JWT tokens, Google API keys, private-key blocks, `password=` / `api_key=` literals, internal-hostname / RFC1918-IP disclosures. Capped at 60 JS bundles. |
| **`owasp-vulns`** | Runs nuclei against the live URLs with curated vuln-class template trees: SQLi, LFI, RCE, SSRF, XXE, SSTI, open-redirect, file-upload, subdomain takeover, default-logins, recent CVEs (2024-2025). Severity filter: `medium,high,critical`. |

Each finding carries a severity (`critical/high/medium/low/info`) and
an evidence excerpt of the raw response. Severity weights
(`critical=50, high=25, medium=10, low=4, info=1`) are exposed for any
external scoring layer.

```bash
# Against a program in the DB
bb-sentinel rocks --program evilcorp --min-severity medium

# Against any httpx-style JSONL of probe results
bb-sentinel rocks --from-jsonl data/evilcorp-live.jsonl --min-severity high
```

## Report writing

The scan is only half the work — the report is what determines whether
a program pays out, downgrades, or closes informational. `bb-sentinel
report` turns rocks JSONL output into a submission-ready Markdown +
PDF document with per-class impact framing.

```bash
# From program config (pulls domains, auth status, rate-limit into header)
bb-sentinel report --program evilcorp
# → data/evilcorp-report.md
# → data/evilcorp-report.pdf

# From a standalone JSONL (no program config needed)
bb-sentinel report --from-jsonl data/scan.jsonl --out report.md --no-pdf

# Tune the main/appendix split
bb-sentinel report --program evilcorp --min-severity-main high
# (medium findings move to Appendix A)
```

### What's in the output

- **Executive summary** — severity histogram, host counts, compliance
  and disclosure verdict
- **Report-class findings** (medium+) — each with class-specific
  impact paragraph, copy-pasteable curl reproduction, response-excerpt
  evidence, triage-validation steps, and downgrade-trap notes
- **Appendix A** — info-tier findings the operator can skip
- **Appendix B** — scan methodology (tools, rate limit, auth status)

### Program-format submission template

`templates/findings/bugcrowd-submission.md.j2` is a standalone
per-finding template that wraps a `ReportFinding` in the
Bugcrowd-style submission shape (Vulnerability Title → Severity →
Affected URL → Steps to Reproduce → Proof of Concept → Impact →
Remediation → Researcher attestation). It's a *structural placeholder*
— programs that puvendor-bh their own `submission-template.md` in the
brief's Resources tab will have slightly different section ordering,
wording, or required fields (e.g., Bugcrowd's VRT category, CVSS
vector). Copy the program-specific headers in to make it byte-accurate.

Render outside the main report pipeline (one finding at a time, for
direct paste into the submission form):

```python
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader("templates/findings"))
tmpl = env.get_template("bugcrowd-submission.md.j2")
print(tmpl.render(finding=f, repro_curl=f.reproduction_curl(),
                  bugcrowd_username="your-name",
                  rate_limit_rps=5))
```

The attestation block at the bottom captures the common program
requirements (rate limit honored, custom header sent, no customer
data accessed); update the placeholders if the program's brief
demands different wording.

### Per-class templates

Each finding signal dispatches to a Jinja2 template in
[`templates/findings/`](templates/findings/). Templates carry the
class-specific impact language, validation checks, and submission
strategy notes — so the report writes itself once the evidence is
captured.

| Template | Catches |
|----------|---------|
| `exposed-config.md.j2` | `.npmrc`, `.env`, `.git/config`, dotfiles |
| `exposed-info.md.j2` | `robots.txt`, `sitemap.xml`, `security.txt` (appendix-tier) |
| `internal-disclosure.md.j2` | Internal hostnames / IPs leaked in JS bundles |
| `origin-candidate.md.j2` | WAF-bypass via direct origin-IP reachability |
| `tomcat-vuln.md.j2` | Tomcat version-CVE, examples/, snoop/, docs/ |
| `method-misconfig.md.j2` | PUT/DELETE/CONNECT accepted by the server |
| `bypass-403.md.j2` | 403/401 bypass via path-segment or header tricks |
| `cors-misconfig.md.j2` | Credentialed CORS reflection or null-origin |
| `backup-file.md.j2` | `.bak` / `.zip` / `.swp` source/archive exposure |
| `owasp-vuln.md.j2` | SQLi / XSS / LFI / SSRF / SSTI / RCE / IDOR / XXE |
| `secret-leak.md.j2` | Hard-coded API keys / tokens in client bundles |
| `historical-url.md.j2` | Wayback-archived URLs still live (forgotten endpoints) |
| `generic.md.j2` | Fallback for unmapped signals |

Adding a new class is one file: drop `templates/findings/<class>.md.j2`
and add one entry to `_SIGNAL_TEMPLATE_MAP` in
[`src/report.py`](src/report.py).

PDF rendering uses [WeasyPrint](https://weasyprint.org/) (Letter page,
severity badges, monospace evidence blocks). Disable with `--no-pdf`
if you only need the Markdown for paste-into-form workflows.

## Authenticated probing

Most paid bug-bounty findings live behind a login — IDOR, privilege
escalation, cross-tenant data leaks. bb-sentinel carries per-program
auth through every active-probe layer.

### Configuration

```yaml
programs:
  evilcorp:
    auth_headers:
      Authorization: "Bearer ${EVILCORP_API_TOKEN}"
      Cookie: "session=${EVILCORP_SESSION}"
      X-API-Key: "${EVILCORP_API_KEY}"
```

Values support `${ENV_VAR}` expansion so secrets stay out of YAML.
Export the variables in your shell before running:

```bash
export EVILCORP_API_TOKEN="eyJhbGc..."
export EVILCORP_SESSION="abc123..."
bb-sentinel scan evilcorp --force
```

### Propagation and scope

| Layer | Mechanism | Scope behavior |
|-------|-----------|----------------|
| `httpx` subprocess | `-H "Key: Value"` flags | **Global** — sent to every host the subprocess hits |
| `nuclei` subprocess | `-H "Key: Value"` flags | **Global** — same caveat |
| Python rocks probes | `httpx.AsyncClient` per-request merge | **Scope-restricted** — only sent when the request host matches a `domains:` entry (or subdomain). CDN / external JS fetches do NOT carry auth. |

### Security notes

- Subprocess tools (httpx, nuclei) do not strip auth on cross-domain
  redirect — if an in-scope host redirects to a third-party, the token
  follows. Mitigate by scoping `domains:` tightly per program.
- Auth tokens rotate. bb-sentinel does no auto-refresh. When scans
  start returning 401s, re-export and re-run.
- Never put real auth values into `programs.example.yaml` or anywhere
  that could be committed. Always go through environment variables.

## Compliance pre-flight

Most bug-bounty programs include explicit anti-automation language in
their rules. Running bb-sentinel against a program that prohibits it
gets the researcher's account banned. [`src/compliance.py`](src/compliance.py)
is a pre-flight check that reads each program's rules text and decides
whether automated probing is likely allowed **before** the scan starts.

### Verdicts

| Verdict | Behavior |
|---------|----------|
| `BLOCK` | Explicit hard-block signal (no-automation / named-scanner ban / manual-only). `scan` / `rocks` refuse to start. |
| `WARN` | Universal program rules detected (no-DoS / no-bruteforce / prior-approval) — automation still allowed but the operator must read. Prompts to confirm. |
| `UNCLEAR` | Rules page silent or unfetchable. Prompts. Paste rules to a file and re-run for a real verdict. |
| `OK` | Explicit allowance for automated tooling found. |

### Patterns

| Class | Examples |
|-------|----------|
| **Hard block (BLOCK)** | `no automated scanning/tools/testing`, `manual testing only`, named scanners (`nuclei`/`nikto`/`nessus`/`qualys`/`acunetix`/`burp`/`zap`), `do not run automated`, `no fuzzing`, `do not scan` |
| **Warn-only** | `no DoS / DDoS / denial-of-service`, `no volumetric / excessive traffic`, `no brute-force`, `prior written consent/approval`, `notify before scanning` |
| **Allowance** | `automated scanning is allowed/permitted/welcome`, `nuclei templates welcome/accepted`, `automated scanners are allowed` |
| **Rate-limit guidance** | `rate limit`, explicit RPS values, `throttle`, `respect our limits`, `reasonable use` |

### Disclosure detection

bb-sentinel also detects whether the program permits public disclosure
of findings — critical for signal-build strategy that depends on
public writeups. The `bounty-targets-data` `allows_disclosure` field
is **unreliable** (observed at multiple programs lying both directions).
The pre-flight reads the rendered policy text directly and emits
`Disclosure: ALLOWED / FORBIDDEN / UNKNOWN` in every check.

### Headless fetch for JS-rendered pages

Bugcrowd / HackerOne / Intigriti program briefs are SPAs — plain
`httpx` returns the loader shell with no rules text. The fetcher:

1. Tries `httpx` first (fast, no JS).
2. If the response is short (<500 chars stripped) or errors, escalates
   to headless `chromium` via subprocess.
3. Renders with `--virtual-time-budget=10000` so SPA JS populates the
   DOM, then `--dump-dom`.
4. Strips HTML and feeds to the compliance pattern matcher.

No Python deps for the fallback — shells out to whichever
chromium-family binary is on `$PATH`. Graceful UNCLEAR if none present.

```bash
bb-sentinel compliance --url https://bugcrowd.com/engagements/foo
bb-sentinel compliance --file path/to/pasted-rules.txt
bb-sentinel compliance --program evilcorp
bb-sentinel compliance --url URL --force-headless    # skip httpx
bb-sentinel compliance --url URL --no-headless       # disable fallback
```

## Target curation

Half the battle is choosing a program where reports will actually be
accepted. [`scripts/build_signal_list.py`](scripts/build_signal_list.py)
pulls the latest dumps from `arkadiyt/bounty-targets-data` for
Bugcrowd, Intigriti, and YesWeHack, applies a signal-build heuristic,
and emits a ranked target list.

```bash
python3 scripts/build_signal_list.py
# → data/signal-build-targets.md  (human-readable, top 60)
# → data/signal-build-targets.json (machine-readable, 287+ programs)
```

### Heuristic weights

| Signal | Weight | Rationale |
|--------|-------:|-----------|
| Allows public disclosure | **+30** | Writeups build portfolio signal independent of platform score |
| Payout band `$1k-$8k` | +25 | Real money, not whale-tier prestige where the strongest hunters camp |
| Scope **2-6** assets | +20 | Smaller surface = less competition |
| Scope **7-12** assets | +15 | Bigger surface, still tractable |
| Payout band `$500-$1k` | +10 | Smaller checks but valid ROI |
| USD currency | +10 | US-based default |
| Full safe-harbor (Bugcrowd) | +5 | Explicit legal coverage |

### HackerOne deliberately excluded

HackerOne enforces a trial-report mechanism that locks the account
across the entire platform once trial reports are exhausted but not yet
*Resolved* — including programs that show `Signal Required: 0`. This
is an account-level gate no per-program setting can bypass, so no H1
program is a viable signal-build target until trial reports clear.
The curation script reflects this and skips H1 entirely.

## CLI reference

```
bb-sentinel program add <name> --domains a.com,b.com --frequency 2h
bb-sentinel program list
bb-sentinel scan <program> [--force] [--yes] [--ignore-compliance]
bb-sentinel findings <program> --since 24h [--min-score 7]
bb-sentinel status
bb-sentinel run                                       # foreground monitor loop
bb-sentinel rocks --program <name> [--min-severity medium]
bb-sentinel rocks --from-jsonl <file.jsonl> [--min-severity high]
bb-sentinel report --program <name> [--no-pdf] [--out PATH] [--min-severity-main S]
bb-sentinel report --from-jsonl <rocks.jsonl> [--out PATH] [--no-pdf]
bb-sentinel compliance --url <rules-url>
bb-sentinel compliance --program <name>
bb-sentinel compliance --file <pasted-rules.txt>
```

Invoke as `python -m src.cli ...` (or install the package and use the
`bb-sentinel` console script when added to `pyproject.toml`).

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

Webhooks retry with exponential backoff (3 attempts). Failures are
recorded in the `scan_runs.stats` JSON; not retried on subsequent
scans.

## Operational notes

- The monitor loop reads `next_scan_at` from the database, so restarts
  don't reset the schedule.
- Scope enforcement: if `inscope_config` is set and the `inscope`
  binary is on `$PATH`, discovered hosts are filtered before storage.
  Misconfiguration **fails open** with an error log line — review logs
  after first scan.
- Nuclei templates are warmed at image build time; mount
  `/root/nuclei-templates` as a volume to persist updates across
  container restarts.
- The `bounty-targets-data` dumps are cached in
  `data/bounty-targets-cache/` with a 24-hour TTL. Re-derivable, not
  committed.
- `/tmp` discipline: headless chromium uses managed `tempfile.
  TemporaryDirectory` for `--user-data-dir`. No accumulation.

## Legal & ethical use

Only run bb-sentinel against programs you are authorized to test. Keep
`inscope_config` accurate — it is the only thing protecting you from
scope drift.

The compliance pre-flight is *tooling*, not legal advice. The operator
is still responsible for reading the actual program terms. A `BLOCK`
verdict means "the rules text reads forbidding and you should
manually review"; an `OK` verdict means "no anti-automation language
found" — neither is a substitute for understanding the program.

bb-sentinel does no automatic credential rotation, no automatic
network-layer testing, no exploitation. It surfaces evidence; the
human decides what to file and how to scope the manual deep-test.
