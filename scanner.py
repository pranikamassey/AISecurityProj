#!/usr/bin/env python3
"""
Security Scanner — multi-file, multi-analyzer CLI.

Usage:
  python scanner.py <path> [<path>...]           scan files/directories
  python scanner.py vulnerable.py -f html -o r.html
  python scanner.py src/ --severity HIGH -w 8
  python scanner.py --clear-cache
  python scanner.py --cache-stats
"""

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv
import os

import google.genai as genai
from rich.console import Console

from scanner_core.cache import ScanCache
from scanner_core.engine import ScanEngine
from scanner_core.llm_analyzer import LLMAnalyzer
from scanner_core.models import FileResult, Severity
from scanner_core.reporters import print_report, write_json, write_html, write_sarif
from scanner_core.utils import get_git_changed_files

console = Console()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner",
        description="AI-powered security scanner with static + LLM analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("paths", nargs="*", metavar="PATH",
                   help="Files or directories to scan")

    p.add_argument("-f", "--format", choices=["terminal", "json", "html", "sarif"],
                   default="terminal", help="Output format (default: terminal)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write report to FILE (required for json/html/sarif)")

    p.add_argument("-s", "--severity",
                   choices=[s.value for s in Severity],
                   default="LOW",
                   help="Minimum severity to report (default: LOW)")
    p.add_argument("-w", "--workers", type=int, default=4,
                   help="Parallel worker threads (default: 4)")

    p.add_argument("--model", default="gemini-2.5-flash",
                   help="Gemini model to use (default: gemini-2.5-flash)")
    p.add_argument("--no-cache", action="store_true",
                   help="Disable result caching")
    p.add_argument("--no-static", action="store_true",
                   help="Skip AST static analysis (LLM only)")

    p.add_argument("--git-diff", action="store_true",
                   help="Scan only files changed vs the base branch (PR) or HEAD~1 (push)")
    p.add_argument("--fail-on",
                   choices=[s.value for s in Severity],
                   default="HIGH",
                   help="Exit 1 when any finding reaches this severity or above (default: HIGH)")

    p.add_argument("--clear-cache", action="store_true",
                   help="Delete all cached scan results and exit")
    p.add_argument("--cache-stats", action="store_true",
                   help="Show cache statistics and exit")

    return p


# ---------------------------------------------------------------------------
# Progress callback (live updates while scanning)
# ---------------------------------------------------------------------------

def _make_progress_cb(fmt: str):
    def cb(result: FileResult) -> None:
        if fmt != "terminal":
            return
        status = "cached" if result.from_cache else f"{len(result.vulnerabilities)} finding(s)"
        if result.error:
            console.print(f"  [red]✗[/red] {result.file_path} — [red]{result.error}[/red]")
        elif result.vulnerabilities:
            worst = result.vulnerabilities[0].severity.value
            style = result.vulnerabilities[0].severity.rich_color
            console.print(
                f"  [yellow]![/yellow] {result.file_path} — "
                f"[{style}]{worst}[/{style}] · {status}"
            )
        else:
            console.print(f"  [green]✓[/green] {result.file_path} — clean ({status})")
    return cb


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    # ---- Cache-only sub-commands -------------------------------------------
    if args.clear_cache:
        n = ScanCache().clear()
        console.print(f"[green]Cache cleared — {n} entries removed.[/green]")
        return 0

    if args.cache_stats:
        stats = ScanCache().stats()
        console.print(f"[bold]Cache stats:[/bold] {stats}")
        return 0

    # ---- Resolve target paths ----------------------------------------------
    if args.git_diff:
        changed = get_git_changed_files()
        if not changed:
            console.print("[yellow]No scannable files changed — nothing to do.[/yellow]")
            return 0
        console.print(f"[dim]--git-diff: {len(changed)} changed file(s)[/dim]")
        target_paths = changed
    else:
        target_paths = args.paths

    if not target_paths:
        parser.print_help()
        return 1

    missing = [p for p in target_paths if not Path(p).exists()]
    if missing:
        console.print(f"[red]Path(s) not found: {', '.join(missing)}[/red]")
        return 1

    if args.format in ("json", "html", "sarif") and not args.output:
        console.print(f"[red]--output FILE is required when --format={args.format}[/red]")
        return 1

    # ---- API key -----------------------------------------------------------
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        console.print("[red]GOOGLE_API_KEY not set. Add it to .env or export it.[/red]")
        return 1

    # ---- Build components --------------------------------------------------
    client = genai.Client(api_key=api_key)
    llm = LLMAnalyzer(client, model=args.model)
    engine = ScanEngine(
        llm=llm,
        use_cache=not args.no_cache,
        use_static=not args.no_static,
        min_severity=Severity(args.severity),
        max_workers=args.workers,
    )

    # ---- Run scan ----------------------------------------------------------
    console.rule("[bold]Scanning[/bold]")
    console.print(
        f"  Targets : {', '.join(target_paths)}\n"
        f"  Model   : {args.model}\n"
        f"  Static  : {'off' if args.no_static else 'on'}\n"
        f"  Cache   : {'off' if args.no_cache else 'on'}\n"
        f"  Workers : {args.workers}\n"
        f"  Min sev : {args.severity}  Fail on : {args.fail_on}\n"
    )

    report = engine.scan(target_paths, on_file_done=_make_progress_cb(args.format))

    # ---- Output ------------------------------------------------------------
    if args.format == "terminal":
        print_report(report, console)
    elif args.format == "json":
        out = Path(args.output)
        write_json(report, out)
        console.print(f"[green]JSON report written → {out}[/green]")
    elif args.format == "html":
        out = Path(args.output)
        write_html(report, out)
        console.print(f"[green]HTML report written → {out}[/green]")
    elif args.format == "sarif":
        out = Path(args.output)
        write_sarif(report, out)
        console.print(f"[green]SARIF report written → {out}[/green]")

    # ---- Exit code (CI gate) -----------------------------------------------
    fail_score = Severity(args.fail_on).score
    breached = any(
        v.severity.score >= fail_score
        for f in report.files
        for v in f.vulnerabilities
    )
    if breached:
        console.print(
            f"[red bold]Build failed:[/red bold] findings at or above "
            f"[bold]{args.fail_on}[/bold] severity detected."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
