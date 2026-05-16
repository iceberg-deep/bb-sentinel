"""
Report generator — turn a rocks/scan findings dump into a professional
PDF (or Markdown) report.

The output is structured for **bug-bounty submission workflows**, not a
generic pentest. Per [[bb-hunting-impact-first]] memory:
  - Each report-class finding is its own section with copy-pasteable
    reproduction (curl one-liner from the URL + auth headers)
  - Severity badge sits next to the title; CWE/CVSS framing is footer-tier
  - Findings filtered to medium+ by default — info-level noise lives in
    an appendix the operator can skip
  - Final page is the scan metadata: tools used, rate limits, compliance
    verdict, host counts

Renderer choice:
  - Markdown is always produced first (it's the source of truth + can be
    copy-pasted into Bugcrowd / HackerOne form fields directly).
  - PDF rendering is opt-in via --pdf flag; uses weasyprint if installed.
    Falls back gracefully to markdown-only when the lib is missing.

CLI: ``bb-sentinel report --program X [--from-jsonl F] [--pdf] --out <path>``
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


# Where the per-class Jinja templates live. Resolved relative to the repo
# root, not CWD — the CLI may be invoked from any directory.
_TEMPLATES_ROOT = Path(__file__).resolve().parent.parent / "templates" / "findings"

# Map finding `signal` (or signal prefix) → template filename. The dispatch
# is checked exact-match first, then prefix. Anything unmatched falls through
# to `generic.md.j2`. Adding a new class = drop a new `.md.j2` file in
# `templates/findings/` and add one line here.
_SIGNAL_TEMPLATE_MAP: dict[str, str] = {
    # exact matches
    "exposed-npmrc":              "exposed-config.md.j2",
    "exposed-env":                "exposed-config.md.j2",
    "exposed-git-config":         "exposed-config.md.j2",
    "exposed-git-head":           "exposed-config.md.j2",
    "exposed-DS_Store":           "exposed-config.md.j2",
    "exposed-htaccess":           "exposed-config.md.j2",
    "exposed-htpasswd":           "exposed-config.md.j2",
    "exposed-robots":             "exposed-info.md.j2",
    "exposed-sitemap":            "exposed-info.md.j2",
    "well-known-security":        "exposed-info.md.j2",
    "internal-hostname-disclosed": "internal-disclosure.md.j2",
    "internal-ip-disclosed":      "internal-disclosure.md.j2",
    "origin-candidate":           "origin-candidate.md.j2",
    "historical-url-still-live":  "historical-url.md.j2",
}
# Prefix dispatch (checked in order, first match wins). Keep most specific first.
_SIGNAL_PREFIX_MAP: list[tuple[str, str]] = [
    ("tomcat-",  "tomcat-vuln.md.j2"),
    ("method-",  "method-misconfig.md.j2"),
    ("bypass-",  "bypass-403.md.j2"),
    ("cors-",    "cors-misconfig.md.j2"),
    ("backup-",  "backup-file.md.j2"),
    ("owasp-",   "owasp-vuln.md.j2"),
    ("secret-",  "secret-leak.md.j2"),
]


def _template_for_signal(signal: str) -> str:
    if signal in _SIGNAL_TEMPLATE_MAP:
        return _SIGNAL_TEMPLATE_MAP[signal]
    for prefix, tmpl in _SIGNAL_PREFIX_MAP:
        if signal.startswith(prefix):
            return tmpl
    return "generic.md.j2"


# Severity → display name, color, CSS class (for PDF styling).
SEVERITY_STYLE = {
    "critical": {"label": "Critical", "color": "#a31515", "weight": 50},
    "high":     {"label": "High",     "color": "#cc4400", "weight": 25},
    "medium":   {"label": "Medium",   "color": "#aa8800", "weight": 10},
    "low":      {"label": "Low",      "color": "#446699", "weight": 4},
    "info":     {"label": "Info",     "color": "#666666", "weight": 1},
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class ReportFinding:
    """Normalized finding for report rendering. Built from rocks JSONL or
    DB Finding rows."""
    url: str
    severity: str
    signal: str
    title: str
    evidence: str = ""
    probe: str = ""
    extra: dict = field(default_factory=dict)

    def reproduction_curl(self, auth_headers: dict[str, str] | None = None) -> str:
        """Produce a copy-pasteable curl command for the finding's URL."""
        parts = ["curl -ksSi"]
        for k, v in (auth_headers or {}).items():
            parts.append(f"-H '{k}: {v[:20]}...'" if "Bearer" in v or "Cookie" in k.lower()
                         else f"-H '{k}: {v}'")
        parts.append(f"'{self.url}'")
        return " ".join(parts)


@dataclass
class ReportMetadata:
    program_name: str
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scope_summary: str = ""
    domains: list[str] = field(default_factory=list)
    rate_limit_rps: int | None = None
    auth_used: bool = False
    compliance_verdict: str = "UNKNOWN"
    disclosure_status: str = "UNKNOWN"
    discovered_hosts: int = 0
    in_scope_hosts: int = 0
    live_probes: int = 0
    tools_run: list[str] = field(default_factory=list)


# -- Markdown rendering ----------------------------------------------------

_MD_TEMPLATE = """\
# Bug Bounty Findings Report — {program}

**Scan completed:** {scan_time}
**Program domains:** {domains}
**Compliance verdict:** {compliance}
**Disclosure policy:** {disclosure}

---

## Executive summary

| Severity | Count |
|----------|------:|
{severity_table}
| **Total** | **{total}** |

**Discovered hostnames:** {discovered}
**In-scope after filter:** {in_scope}
**Live probes:** {live}

{report_class_count} of the {total} findings are at medium+ severity and warrant report consideration. The rest (info-level) are listed in the appendix as supporting context.

---

## Report-class findings

{report_findings}

---

## Appendix A — Informational findings

These are below the reporting threshold. Useful as supporting context but not standalone payout-class.

{info_findings}

---

## Appendix B — Scan methodology

**Tools run:** {tools}
**Rate limit:** {rate_limit}
**Authentication:** {auth_status}

Findings produced by bb-sentinel `rocks` pipeline ({probe_count} probes total).
Each finding's `evidence` field contains the raw HTTP response excerpt that
triggered the detection — sufficient for triage to verify.

---

*Report generated by bb-sentinel · {gen_time}*
"""


def _render_severity_table(findings: list[ReportFinding]) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines = []
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0) == 0:
            continue
        style = SEVERITY_STYLE[sev]
        lines.append(f"| {style['label']} | {counts[sev]} |")
    return "\n".join(lines) or "| (none) | 0 |"


_jinja_env = None


def _get_jinja_env():
    """Lazy-load the Jinja2 environment so report.py imports cheaply when
    rendering isn't actually invoked."""
    global _jinja_env
    if _jinja_env is None:
        from jinja2 import Environment, FileSystemLoader, StrictUndefined
        _jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_ROOT)),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=False,
            # StrictUndefined would crash on missing extra fields, which is
            # the wrong default for an exploratory tool. Default is fine.
        )
    return _jinja_env


def _render_finding_md(idx: int, f: ReportFinding,
                        auth_headers: dict | None = None) -> str:
    """Render one finding section via the per-class Jinja template, with a
    generic fallback. The dispatch is keyed on `f.signal`."""
    style = SEVERITY_STYLE.get(f.severity, SEVERITY_STYLE["info"])
    env = _get_jinja_env()
    tmpl_name = _template_for_signal(f.signal)
    try:
        tmpl = env.get_template(tmpl_name)
    except Exception:
        tmpl = env.get_template("generic.md.j2")
    return tmpl.render(
        idx=idx,
        finding=f,
        severity_label=style["label"],
        repro_curl=f.reproduction_curl(auth_headers),
    )


def render_markdown(findings: list[ReportFinding], meta: ReportMetadata,
                     auth_headers: dict | None = None,
                     min_severity_in_main: str = "medium") -> str:
    """Render the report as markdown."""
    cutoff = SEVERITY_ORDER.index(min_severity_in_main)
    main = [f for f in findings if SEVERITY_ORDER.index(f.severity) <= cutoff]
    info = [f for f in findings if SEVERITY_ORDER.index(f.severity) > cutoff]
    # Sort by severity within each group
    main.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    info.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))

    main_md = "\n".join(_render_finding_md(i + 1, f, auth_headers)
                         for i, f in enumerate(main)) or \
              "*No report-class findings at the configured threshold.*"
    info_md = "\n".join(f"- **{SEVERITY_STYLE[f.severity]['label']}** · `{f.signal}` "
                         f"on `{f.url}` — {f.title[:80]}"
                         for f in info[:50]) or "*(none)*"
    if len(info) > 50:
        info_md += f"\n- *…and {len(info) - 50} more (see raw JSONL output)*"

    return _MD_TEMPLATE.format(
        program=meta.program_name,
        scan_time=meta.scan_time.strftime("%Y-%m-%d %H:%M UTC"),
        domains=", ".join(meta.domains) or "(none specified)",
        compliance=meta.compliance_verdict,
        disclosure=meta.disclosure_status,
        severity_table=_render_severity_table(findings),
        total=len(findings),
        discovered=meta.discovered_hosts,
        in_scope=meta.in_scope_hosts,
        live=meta.live_probes,
        report_class_count=len(main),
        report_findings=main_md,
        info_findings=info_md,
        tools=", ".join(meta.tools_run) or "subfinder, assetfinder, crt.sh, httpx, nuclei, rocks",
        rate_limit=f"{meta.rate_limit_rps} RPS (program-published)" if meta.rate_limit_rps else "global default",
        auth_status="enabled (per-program auth headers)" if meta.auth_used else "anonymous probing only",
        probe_count=10,
        gen_time=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


# -- HTML / PDF rendering --------------------------------------------------

_PDF_CSS = """
@page {
  size: Letter;
  margin: 0.9in 0.8in 1in 0.8in;
  @bottom-center { content: "bb-sentinel report — page " counter(page) " of " counter(pages); font-family: sans-serif; font-size: 9pt; color: #888; }
}
body {
  font-family: -apple-system, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  font-size: 10.5pt;
  line-height: 1.5;
  color: #1a1a1a;
}
h1 {
  font-size: 22pt;
  color: #16365c;
  border-bottom: 3px solid #16365c;
  padding-bottom: 6pt;
  margin-bottom: 12pt;
}
h2 {
  font-size: 15pt;
  color: #2c3e50;
  border-bottom: 1px solid #ddd;
  padding-bottom: 4pt;
  margin-top: 22pt;
}
h3 {
  font-size: 12.5pt;
  color: #2c3e50;
  margin-top: 18pt;
  padding-left: 8pt;
  border-left: 4px solid #16365c;
}
h3 .sev-critical { color: #a31515; }
h3 .sev-high     { color: #cc4400; }
h3 .sev-medium   { color: #aa8800; }
h3 .sev-low      { color: #446699; }
h3 .sev-info     { color: #666666; }
table {
  border-collapse: collapse;
  margin: 8pt 0;
  width: 100%;
}
th, td {
  border: 1px solid #ddd;
  padding: 6pt 10pt;
  text-align: left;
}
th { background: #f3f6fa; font-weight: 600; }
td:last-child { text-align: right; }
code, pre {
  font-family: "SF Mono", Menlo, Consolas, monospace;
  font-size: 9.5pt;
  background: #f6f8fa;
  border-radius: 3px;
}
code { padding: 1pt 4pt; }
pre {
  padding: 8pt 10pt;
  border: 1px solid #e1e4e8;
  border-left: 3px solid #16365c;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-x: auto;
  max-height: 240pt;
}
.severity-badge {
  display: inline-block;
  padding: 2pt 8pt;
  border-radius: 3px;
  font-size: 8.5pt;
  font-weight: 600;
  letter-spacing: 0.5pt;
  text-transform: uppercase;
  color: white;
}
.sev-bg-critical { background: #a31515; }
.sev-bg-high     { background: #cc4400; }
.sev-bg-medium   { background: #aa8800; }
.sev-bg-low      { background: #446699; }
.sev-bg-info     { background: #666666; }
hr {
  border: 0;
  border-top: 1px solid #ddd;
  margin: 18pt 0;
}
.meta-row { color: #555; }
.appendix h3 {
  font-size: 11pt;
  border-left: none;
  padding-left: 0;
}
em { color: #888; }
"""


def _md_to_html(md: str) -> str:
    """Minimal Markdown → HTML conversion for the report. Supports the
    subset we actually use: headers, paragraphs, tables, code blocks,
    bold/italic, inline code, lists. Keeps deps minimal."""
    import re
    out: list[str] = []
    lines = md.split("\n")
    i = 0
    in_code = False
    in_table = False
    in_list = False

    def close_table():
        nonlocal in_table
        if in_table:
            out.append("</tbody></table>")
            in_table = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            if in_code:
                out.append("</pre>")
                in_code = False
            else:
                close_table(); close_list()
                out.append("<pre>")
                in_code = True
            i += 1; continue
        if in_code:
            out.append(_escape_html(line))
            i += 1; continue

        # Tables
        if "|" in line and i + 1 < len(lines) and re.match(r'^\s*\|?\s*[-:|]+\s*\|', lines[i + 1]):
            close_list()
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            out.append("<table><thead><tr>" +
                       "".join(f"<th>{_inline(c)}</th>" for c in cells) +
                       "</tr></thead><tbody>")
            in_table = True
            i += 2; continue
        if in_table and "|" in line:
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
            i += 1; continue
        if in_table:
            close_table()

        # Headers
        m = re.match(r'^(#{1,6})\s+(.+)$', line)
        if m:
            close_list()
            lvl = len(m.group(1))
            text = _inline(m.group(2))
            # Severity badge injection in h3 titles like "### 1. <title> [SEV]"
            out.append(f"<h{lvl}>{text}</h{lvl}>")
            i += 1; continue

        # Lists
        m = re.match(r'^[-*]\s+(.+)$', line)
        if m:
            if not in_list:
                close_table()
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(m.group(1))}</li>")
            i += 1; continue
        if in_list and line.strip() == "":
            close_list()

        # Horizontal rule
        if re.match(r'^[-_*]{3,}\s*$', line):
            close_list(); close_table()
            out.append("<hr>")
            i += 1; continue

        # Bold-text-only paragraph (e.g. **Severity:** Low)
        if line.strip():
            close_list()
            out.append(f"<p>{_inline(line)}</p>")
        else:
            out.append("")
        i += 1

    close_list(); close_table()
    if in_code: out.append("</pre>")
    return "\n".join(out)


def _escape_html(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _inline(text: str) -> str:
    """Inline markdown → HTML: **bold**, *italic*, `code`."""
    import re
    text = _escape_html(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    return text


def render_pdf(md: str, out_path: str | Path) -> str | None:
    """Render the markdown report as a PDF via weasyprint. Returns the
    output path on success, None on failure (with a console hint)."""
    try:
        from weasyprint import HTML, CSS
    except ImportError:
        return None
    body_html = _md_to_html(md)
    full_html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>bb-sentinel report</title></head>
<body>{body_html}</body></html>"""
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    HTML(string=full_html).write_pdf(str(out_path), stylesheets=[CSS(string=_PDF_CSS)])
    return str(out_path)


# -- Data ingest -----------------------------------------------------------

def load_findings_from_jsonl(path: str | Path) -> list[ReportFinding]:
    """Read rocks --out JSONL output and produce ReportFinding records."""
    findings: list[ReportFinding] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line: continue
        try: obj = json.loads(line)
        except json.JSONDecodeError: continue
        findings.append(ReportFinding(
            url=obj.get("url", ""),
            severity=(obj.get("severity") or "info").lower(),
            signal=obj.get("signal", "?"),
            title=obj.get("title", obj.get("signal", "?")),
            evidence=str(obj.get("evidence") or ""),
            probe=obj.get("probe", ""),
            extra=obj.get("extra") or {},
        ))
    return findings


__all__ = [
    "ReportFinding", "ReportMetadata",
    "render_markdown", "render_pdf",
    "load_findings_from_jsonl",
    "SEVERITY_STYLE", "SEVERITY_ORDER",
]
