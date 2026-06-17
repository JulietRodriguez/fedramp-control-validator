"""Rich-powered command line interface for fedramp-control-validator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .gap import build_gaps
from .models import FAIL, NOT_ASSESSED, PARTIAL, PASS, ValidationReport
from .oscal import to_oscal
from .parsers import ParseError, load_findings
from .validator import validate

console = Console()

BANNER = r"""
 ___        _ ___    _   __  __ ___
| __|__ __| | _ \  /_\ |  \/  | _ \
| _|/ -_) _` |   / / _ \| |\/| |  _/
|_| \___\__,_|_|_\/_/ \_\_|  |_|_|
   Control Validator · FedRAMP Moderate
"""

_STATUS_STYLE = {
    PASS: "bold green",
    FAIL: "bold red",
    PARTIAL: "bold yellow",
    NOT_ASSESSED: "dim",
}

_STATUS_LABEL = {
    PASS: "PASS",
    FAIL: "FAIL",
    PARTIAL: "PARTIAL",
    NOT_ASSESSED: "not assessed",
}


def _status_text(status: str) -> Text:
    return Text(_STATUS_LABEL[status], style=_STATUS_STYLE[status])


def _print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print(
        f"[dim]NIST 800-53 Rev 5 · OSCAL 1.1.2 · v{__version__}[/dim]\n"
    )


def _score_color(score: float) -> str:
    if score >= 90:
        return "green"
    if score >= 70:
        return "yellow"
    return "red"


def _render_overview(report: ValidationReport) -> None:
    counts = report.counts()
    score = round(report.overall_score * 100, 1)
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold")
    grid.add_column()
    grid.add_row("AWS Account:", f"[cyan]{report.account_id}[/cyan]")
    grid.add_row("Region:", report.region)
    grid.add_row("Findings source:", report.source)
    grid.add_row("Findings evaluated:", str(report.findings_evaluated))
    grid.add_row(
        "Overall score:",
        f"[{_score_color(score)}]{score}%[/{_score_color(score)}]",
    )
    grid.add_row(
        "Controls:",
        f"[green]{counts[PASS]} pass[/green]  "
        f"[yellow]{counts[PARTIAL]} partial[/yellow]  "
        f"[red]{counts[FAIL]} fail[/red]  "
        f"[dim]{counts[NOT_ASSESSED]} n/a[/dim]",
    )
    console.print(
        Panel(grid, title="FedRAMP Moderate Assessment", border_style="cyan")
    )


def _render_families(report: ValidationReport) -> None:
    table = Table(
        title="Control Family Scores",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Family", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("P / Pt / F", justify="center", style="dim")
    for family in report.families:
        if family.status == NOT_ASSESSED:
            continue
        score = round(family.score * 100, 1)
        table.add_row(
            family.family,
            family.title,
            _status_text(family.status),
            f"[{_score_color(score)}]{score}%[/{_score_color(score)}]",
            f"{family.passing} / {family.partial} / {family.failing}",
        )
    console.print(table)


def _render_gaps(report: ValidationReport) -> None:
    gaps = build_gaps(report)
    if not gaps:
        console.print(
            Panel(
                "[green]No failing or partially-satisfied controls. "
                "All assessed controls pass.[/green]",
                title="Gap Analysis",
                border_style="green",
            )
        )
        return

    table = Table(
        title=f"Gap Analysis · {len(gaps)} control(s) need attention",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("Control", style="cyan", no_wrap=True)
    table.add_column("Title", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Failing", justify="right")
    table.add_column("Why", style="dim")
    for gap in gaps:
        reason = gap.reasons[0] if gap.reasons else "—"
        if len(gap.reasons) > 1:
            reason += f"  (+{len(gap.reasons) - 1} more)"
        table.add_row(
            gap.control_id,
            gap.title,
            _status_text(gap.status),
            f"{gap.failing_resources}/{gap.total_resources}",
            reason,
        )
    console.print(table)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fedramp-control-validator",
        description=(
            "Validate an AWS environment against the FedRAMP Moderate baseline "
            "(NIST 800-53 Rev 5) from AWS Config findings."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Path to an AWS Config findings JSON file.",
    )
    parser.add_argument(
        "-o",
        "--oscal",
        metavar="PATH",
        help="Write OSCAL 1.1.2 Assessment Results JSON to this path.",
    )
    parser.add_argument(
        "-g",
        "--gap-report",
        metavar="PATH",
        help="Write the gap analysis JSON to this path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the OSCAL Assessment Results to stdout instead of tables.",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        metavar="PCT",
        help="Exit non-zero if the overall score is below this percentage.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"fedramp-control-validator {__version__}",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.input:
        parser.print_help()
        return 1

    try:
        finding_set = load_findings(args.input)
    except ParseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    report = validate(finding_set)

    if args.oscal:
        Path(args.oscal).write_text(
            json.dumps(to_oscal(report), indent=2), encoding="utf-8"
        )
    if args.gap_report:
        from .gap import gap_summary

        Path(args.gap_report).write_text(
            json.dumps(gap_summary(report), indent=2), encoding="utf-8"
        )

    if args.json:
        console.print_json(json.dumps(to_oscal(report)))
    else:
        if not args.no_banner:
            _print_banner()
        _render_overview(report)
        _render_families(report)
        _render_gaps(report)
        if args.oscal:
            console.print(
                f"\n[green]✓[/green] OSCAL 1.1.2 Assessment Results written to "
                f"[cyan]{args.oscal}[/cyan]."
            )
        if args.gap_report:
            console.print(
                f"[green]✓[/green] Gap analysis written to "
                f"[cyan]{args.gap_report}[/cyan]."
            )

    if args.fail_under is not None:
        score = report.overall_score * 100
        if score < args.fail_under:
            console.print(
                f"\n[bold red]Score {round(score, 1)}% is below the required "
                f"{args.fail_under}% threshold.[/bold red]"
            )
            return 3
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
