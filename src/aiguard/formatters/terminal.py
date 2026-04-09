"""Rich-based terminal formatter for AIGuard."""

from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aiguard.formatters.base import BaseFormatter
from aiguard.models import ScanReport, Severity


SEVERITY_STYLES = {
    Severity.ERROR: ("bold red", "E"),
    Severity.WARNING: ("yellow", "W"),
    Severity.INFO: ("blue", "I"),
}


class TerminalFormatter(BaseFormatter):
    """Colored terminal output using Rich."""

    def format(self, report: ScanReport) -> str:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)

        if report.total_findings == 0:
            console.print()
            console.print(
                Panel(
                    "[bold green]No issues found! Your code looks clean.[/]",
                    title="AIGuard",
                    border_style="green",
                )
            )
            self._print_score(console, report.score)
            return buf.getvalue()

        console.print()
        console.print(
            f"[bold]AIGuard[/] found [bold]{report.total_findings}[/] "
            f"issue(s) in [bold]{report.files_scanned}[/] file(s)\n"
        )

        # Group findings by file
        for file_report in report.file_reports:
            if not file_report.has_findings:
                continue

            # File header
            rel_path = self._relative_path(file_report.file_path)
            console.print(f"[bold underline]{rel_path}[/]")

            for finding in file_report.findings:
                style, icon = SEVERITY_STYLES.get(
                    finding.severity, ("white", "?")
                )

                # Main finding line
                location = f"  {finding.line}"
                if finding.end_line and finding.end_line != finding.line:
                    location += f"-{finding.end_line}"

                rule_tag = f"[dim]{finding.rule_id}[/]"
                console.print(
                    f"  [{style}]{icon}[/] "
                    f"[dim]{location:>8}[/]  "
                    f"{finding.message}  {rule_tag}"
                )

                # Suggestion
                if finding.suggestion:
                    console.print(
                        f"           [dim italic]-> {finding.suggestion}[/]"
                    )

            console.print()

        # Summary table
        self._print_summary(console, report)

        # Score
        self._print_score(console, report.score)

        return buf.getvalue()

    def _print_summary(self, console: Console, report: ScanReport) -> None:
        """Print a summary table of findings by rule."""
        table = Table(title="Summary", show_header=True, header_style="bold")
        table.add_column("Rule", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Severity")

        # We need to get rule names — aggregate from file reports
        rule_info: dict[str, tuple[str, str]] = {}  # rule_id -> (rule_name, severity)
        for fr in report.file_reports:
            for f in fr.findings:
                if f.rule_id not in rule_info:
                    rule_info[f.rule_id] = (f.rule_name, f.severity.value)

        for rule_id, count in sorted(report.findings_by_rule.items()):
            name, severity = rule_info.get(rule_id, (rule_id, "unknown"))
            style = {
                "error": "red",
                "warning": "yellow",
                "info": "blue",
            }.get(severity, "white")

            table.add_row(
                f"{rule_id} ({name})",
                str(count),
                f"[{style}]{severity}[/]",
            )

        console.print(table)
        console.print()

    def _print_score(self, console: Console, score: int) -> None:
        """Print the health score as a visual bar."""
        if score >= 80:
            color = "green"
            emoji = "+"
        elif score >= 60:
            color = "yellow"
            emoji = "~"
        else:
            color = "red"
            emoji = "!"

        bar_width = 40
        filled = round(score / 100 * bar_width)
        empty = bar_width - filled
        bar = f"[{color}]{'█' * filled}[/][dim]{'░' * empty}[/]"

        console.print(
            Panel(
                f"  {bar}  [{color} bold]{score}/100[/]  {emoji}",
                title="AI Code Health Score",
                border_style=color,
            )
        )
        console.print()

    def _relative_path(self, file_path: str) -> str:
        """Try to make a path relative to cwd."""
        try:
            return str(Path(file_path).relative_to(Path.cwd()))
        except ValueError:
            return file_path
