"""Output formatters: terminal (Rich), JSON, and self-contained HTML."""

from __future__ import annotations

import json
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .models import FileResult, ScanReport, Severity


# ---------------------------------------------------------------------------
# Terminal reporter (Rich)
# ---------------------------------------------------------------------------

_SEVERITY_STYLE: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold yellow",
    "MEDIUM": "blue",
    "LOW": "green",
    "INFO": "dim",
}

_SEVERITY_ICON: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "⚪",
}


def _severity_text(sev: str) -> Text:
    t = Text(sev, style=_SEVERITY_STYLE.get(sev, ""))
    return t


def print_report(report: ScanReport, console: Optional[Console] = None) -> None:
    c = console or Console()

    c.rule("[bold]Security Scan Results[/bold]")

    for file_result in report.files:
        _print_file_result(file_result, c)

    _print_summary(report, c)


def _print_file_result(result: FileResult, c: Console) -> None:
    cache_tag = " [dim](cached)[/dim]" if result.from_cache else ""
    duration = f"{result.scan_duration_ms:.0f}ms"

    title = f"[bold]{result.file_path}[/bold]{cache_tag}  [dim]{result.language} · {duration}[/dim]"

    if result.error:
        c.print(Panel(f"[red]Error: {result.error}[/red]", title=title, border_style="red"))
        return

    if not result.vulnerabilities:
        c.print(Panel("[green]No vulnerabilities found.[/green]", title=title, border_style="green"))
        return

    table = Table(box=box.SIMPLE_HEAVY, expand=True, show_lines=True)
    table.add_column("Sev", style="bold", width=10)
    table.add_column("Type", style="bold white", min_width=24)
    table.add_column("Line", width=6)
    table.add_column("Description", min_width=40)
    table.add_column("OWASP", style="dim", min_width=16)
    table.add_column("Src", width=6)

    for v in result.vulnerabilities:
        icon = _SEVERITY_ICON.get(v.severity.value, "")
        sev_cell = Text(f"{icon} {v.severity.value}", style=_SEVERITY_STYLE.get(v.severity.value, ""))
        line_str = str(v.line_number) if v.line_number else "—"
        owasp_short = v.owasp.split("–")[0].strip() if v.owasp else "—"
        src_icon = "🔬" if v.source == "static" else "🤖"
        table.add_row(
            sev_cell,
            v.type,
            line_str,
            textwrap.shorten(v.description, width=80),
            owasp_short,
            src_icon,
        )

    vuln_count = len(result.vulnerabilities)
    counts = result.severity_counts
    border = "red" if counts.get("CRITICAL", 0) else ("yellow" if counts.get("HIGH", 0) else "blue")

    c.print(Panel(table, title=title, border_style=border,
                  subtitle=f"[dim]{vuln_count} finding(s) · risk score {result.risk_score}[/dim]"))

    # Detail pane per finding
    for i, v in enumerate(result.vulnerabilities, 1):
        sev_style = _SEVERITY_STYLE.get(v.severity.value, "")
        header = Text(f"[{i}] {v.type}", style=sev_style)
        body = (
            f"[bold]Description:[/bold] {v.description}\n"
            f"[bold]Impact:[/bold] {v.impact}\n"
            f"[bold]OWASP:[/bold] {v.owasp or 'N/A'}\n"
            f"[bold]Confidence:[/bold] {v.confidence:.0%}\n\n"
            f"[bold green]Fix:[/bold green]\n{v.fix}"
        )
        c.print(Panel(body, title=header, border_style=sev_style or "white", padding=(0, 1)))


def _print_summary(report: ScanReport, c: Console) -> None:
    c.rule()
    counts = report.severity_counts
    total = report.total_vulnerabilities

    summary = Table(box=box.ROUNDED, show_header=False)
    summary.add_column("Key", style="bold")
    summary.add_column("Value")
    summary.add_row("Files scanned", str(len(report.files)))
    summary.add_row("Cache hits", str(report.cache_hits))
    summary.add_row("Total findings", str(total))
    for sev in Severity:
        cnt = counts.get(sev.value, 0)
        if cnt:
            summary.add_row(
                Text(sev.value, style=_SEVERITY_STYLE.get(sev.value, "")),
                str(cnt),
            )
    summary.add_row("Scan time", f"{report.total_duration_ms:.0f}ms")
    if report.riskiest_file:
        summary.add_row("Riskiest file", report.riskiest_file.file_path)

    c.print(Panel(summary, title="[bold]Summary[/bold]", border_style="white"))


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

def write_json(report: ScanReport, output_path: Path) -> None:
    data = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "files_scanned": len(report.files),
            "total_vulnerabilities": report.total_vulnerabilities,
            "severity_counts": report.severity_counts,
            "cache_hits": report.cache_hits,
            "total_duration_ms": report.total_duration_ms,
        },
        "files": [
            {
                "file_path": f.file_path,
                "language": f.language,
                "file_hash": f.file_hash[:12] + "…",
                "from_cache": f.from_cache,
                "scan_duration_ms": f.scan_duration_ms,
                "risk_score": f.risk_score,
                "severity_counts": f.severity_counts,
                "error": f.error,
                "vulnerabilities": [
                    v.model_dump() for v in f.vulnerabilities
                ],
            }
            for f in report.files
        ],
    }
    output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


# ---------------------------------------------------------------------------
# HTML reporter
# ---------------------------------------------------------------------------

_SEV_COLORS: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#d97706",
    "MEDIUM": "#2563eb",
    "LOW": "#16a34a",
    "INFO": "#6b7280",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Security Scan Report</title>
<style>
  :root {{--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#f1f5f9;--muted:#94a3b8}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem}}
  h1{{font-size:1.75rem;margin-bottom:.25rem}}
  .subtitle{{color:var(--muted);font-size:.875rem;margin-bottom:2rem}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:2rem}}
  .stat{{background:var(--surface);border:1px solid var(--border);border-radius:.5rem;padding:1rem;text-align:center}}
  .stat .num{{font-size:2rem;font-weight:700;line-height:1}}
  .stat .label{{font-size:.75rem;color:var(--muted);margin-top:.25rem}}
  .file-card{{background:var(--surface);border:1px solid var(--border);border-radius:.5rem;margin-bottom:1.5rem;overflow:hidden}}
  .file-header{{padding:.75rem 1rem;background:#0f172a;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}}
  .file-path{{font-weight:600;font-size:.95rem;word-break:break-all}}
  .file-meta{{font-size:.75rem;color:var(--muted);white-space:nowrap;margin-left:1rem}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th{{padding:.6rem 1rem;text-align:left;font-weight:600;color:var(--muted);border-bottom:1px solid var(--border)}}
  td{{padding:.6rem 1rem;border-bottom:1px solid var(--border);vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  .badge{{display:inline-block;padding:.15rem .5rem;border-radius:.25rem;font-size:.75rem;font-weight:700;color:#fff}}
  .fix-cell{{font-family:monospace;font-size:.8rem;white-space:pre-wrap;color:#86efac}}
  details summary{{cursor:pointer;padding:.75rem 1rem;color:var(--muted);font-size:.85rem}}
  .no-findings{{padding:1rem;color:#16a34a;font-style:italic}}
  .owasp{{font-size:.72rem;color:var(--muted)}}
  .src-badge{{font-size:.7rem;padding:.1rem .3rem;border-radius:.2rem;background:#334155}}
</style>
</head>
<body>
<h1>Security Scan Report</h1>
<div class="subtitle">Generated {generated_at} · {file_count} file(s) · {total_vulns} finding(s)</div>

<div class="summary-grid">
{summary_cards}
</div>

{file_sections}

</body>
</html>
"""


def _sev_badge(sev: str) -> str:
    color = _SEV_COLORS.get(sev, "#6b7280")
    return f'<span class="badge" style="background:{color}">{sev}</span>'


def _stat_card(num: str, label: str, color: str = "#f1f5f9") -> str:
    return (
        f'<div class="stat">'
        f'<div class="num" style="color:{color}">{num}</div>'
        f'<div class="label">{label}</div>'
        f'</div>'
    )


def write_html(report: ScanReport, output_path: Path) -> None:
    counts = report.severity_counts
    summary_cards = "\n".join([
        _stat_card(str(len(report.files)), "Files Scanned"),
        _stat_card(str(report.total_vulnerabilities), "Total Findings"),
        _stat_card(str(counts.get("CRITICAL", 0)), "Critical", _SEV_COLORS["CRITICAL"]),
        _stat_card(str(counts.get("HIGH", 0)), "High", _SEV_COLORS["HIGH"]),
        _stat_card(str(counts.get("MEDIUM", 0)), "Medium", _SEV_COLORS["MEDIUM"]),
        _stat_card(str(counts.get("LOW", 0)), "Low", _SEV_COLORS["LOW"]),
        _stat_card(f"{report.total_duration_ms:.0f}ms", "Scan Time"),
    ])

    file_sections = "\n".join(_file_section(f) for f in report.files)

    html = _HTML_TEMPLATE.format(
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        file_count=len(report.files),
        total_vulns=report.total_vulnerabilities,
        summary_cards=summary_cards,
        file_sections=file_sections,
    )
    output_path.write_text(html, encoding="utf-8")


def _file_section(result: FileResult) -> str:
    cache_tag = " (cached)" if result.from_cache else ""
    meta = f"{result.language} · {result.scan_duration_ms:.0f}ms · risk {result.risk_score}{cache_tag}"

    if result.error:
        body = f'<div class="no-findings" style="color:#dc2626">Error: {result.error}</div>'
    elif not result.vulnerabilities:
        body = '<div class="no-findings">No vulnerabilities found.</div>'
    else:
        rows = "\n".join(_vuln_row(v) for v in result.vulnerabilities)
        body = f"""<table>
<thead><tr>
  <th>Severity</th><th>Type</th><th>Line</th><th>Description</th><th>OWASP</th><th>Fix</th><th>Src</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>"""

    return f"""<div class="file-card">
  <div class="file-header">
    <span class="file-path">{result.file_path}</span>
    <span class="file-meta">{meta}</span>
  </div>
  {body}
</div>"""


def _vuln_row(v) -> str:
    line = str(v.line_number) if v.line_number else "—"
    owasp = f'<div class="owasp">{v.owasp}</div>' if v.owasp else ""
    src = "🔬" if v.source == "static" else "🤖"
    fix_escaped = v.fix.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    desc_escaped = v.description.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        f"<tr>"
        f"<td>{_sev_badge(v.severity.value)}</td>"
        f"<td><strong>{v.type}</strong></td>"
        f"<td>{line}</td>"
        f"<td>{desc_escaped}</td>"
        f"<td>{owasp}</td>"
        f'<td><details><summary>Show fix</summary><div class="fix-cell">{fix_escaped}</div></details></td>'
        f"<td><span class='src-badge'>{src}</span></td>"
        f"</tr>"
    )


# ---------------------------------------------------------------------------
# SARIF reporter (GitHub Security tab / Code Scanning Alerts)
# ---------------------------------------------------------------------------

_SARIF_LEVEL: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "none",
}

# GitHub uses CVSS-like float for security-severity filtering
_SARIF_CVSS: dict[str, str] = {
    "CRITICAL": "9.5",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.0",
    "INFO": "0.0",
}


def _type_to_rule_id(vuln_type: str) -> str:
    """Stable, slug-friendly rule ID derived from vulnerability type."""
    return "SS-" + vuln_type.upper().replace(" ", "-").replace("(", "").replace(")", "")[:40]


def write_sarif(report: ScanReport, output_path: Path) -> None:
    """Write a SARIF 2.1.0 file consumable by github/codeql-action/upload-sarif."""
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for file_result in report.files:
        if file_result.error:
            continue
        for v in file_result.vulnerabilities:
            rule_id = _type_to_rule_id(v.type)

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": v.type.replace(" ", ""),
                    "shortDescription": {"text": v.type},
                    "fullDescription": {"text": v.description},
                    "helpUri": "https://owasp.org/www-project-top-ten/",
                    "help": {
                        "text": f"Fix: {v.fix}",
                        "markdown": f"**Fix:** `{v.fix}`",
                    },
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL[v.severity.value],
                    },
                    "properties": {
                        "tags": ["security", v.source],
                        "precision": "high" if v.confidence >= 0.90 else "medium",
                        "problem.severity": _SARIF_LEVEL[v.severity.value],
                        "security-severity": _SARIF_CVSS[v.severity.value],
                    },
                }

            results.append({
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[v.severity.value],
                "message": {
                    "text": f"{v.description} — {v.impact}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_result.file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": v.line_number or 1,
                            },
                        },
                    }
                ],
                "properties": {
                    "owasp": v.owasp or "",
                    "confidence": v.confidence,
                    "source": v.source,
                },
            })

    sarif = {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecurityScanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/anthropics/claude-code",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": f"security-scan/{datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}",
                },
            }
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
