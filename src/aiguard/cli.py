"""CLI interface for AIGuard."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from aiguard.config import Config
from aiguard.formatters import get_formatter
from aiguard.scanner import Scanner


@click.group()
@click.version_option(package_name="aiguard")
def cli():
    """AIGuard — AI Code Quality Guard.

    Detect common failure patterns in AI-generated code.
    """
    pass


@cli.command()
@click.argument("path", default=".")
@click.option(
    "--format", "-f",
    "output_format",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    help="Output format.",
)
@click.option(
    "--config", "-c",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to .aiguard.yml config file.",
)
@click.option(
    "--fail-under",
    type=int,
    default=None,
    help="Exit with code 1 if score is below this threshold (0-100).",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write output to a file instead of stdout.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Only output the score (for CI).",
)
@click.option(
    "--diff",
    "diff_target",
    type=str,
    default=None,
    help="Only scan changed lines vs a git ref (e.g. HEAD, main, HEAD~3).",
)
@click.option(
    "--staged",
    is_flag=True,
    default=False,
    help="Only scan staged changes (for pre-commit hooks).",
)
@click.option(
    "--fix",
    is_flag=True,
    default=False,
    help="Automatically fix issues where possible.",
)
def scan(path: str, output_format: str, config_path: str | None,
         fail_under: int | None, output: str | None, quiet: bool,
         diff_target: str | None, staged: bool, fix: bool):
    """Scan files for AI-generated code quality issues.

    PATH can be a file or directory (default: current directory).

    \b
    Examples:
      aiguard scan ./src                    # Scan everything
      aiguard scan --diff HEAD              # Only new issues since last commit
      aiguard scan --diff main              # Only new issues vs main branch
      aiguard scan --staged                 # Only staged changes (pre-commit)
    """
    # Load config
    config = Config.load(config_path)

    # Override fail threshold if provided via CLI
    if fail_under is not None:
        config.score_fail_threshold = fail_under

    # Run scan
    scanner = Scanner(config)
    report = scanner.scan(
        path, diff_target=diff_target, diff_staged=staged, fix=fix
    )

    if quiet:
        click.echo(report.score)
    else:
        # Format output
        formatter = get_formatter(output_format)
        result = formatter.format(report)

        if output:
            Path(output).write_text(result, encoding="utf-8")
            click.echo(f"Results written to {output}")
        else:
            click.echo(result)

    # Exit with failure if score is below threshold
    if report.score < config.score_fail_threshold:
        sys.exit(1)


@cli.command("list-rules")
def list_rules():
    """List all available detection rules."""
    from aiguard.detectors import get_all_detectors, load_builtin_detectors

    load_builtin_detectors()
    detectors = get_all_detectors()

    click.echo()
    click.echo("Available AIGuard Rules:")
    click.echo("=" * 70)

    for rule_id in sorted(detectors.keys()):
        det = detectors[rule_id]
        severity_color = {
            "error": "red",
            "warning": "yellow",
            "info": "blue",
        }.get(det.severity.value, "white")

        click.echo(
            f"  {click.style(rule_id, bold=True)}  "
            f"{click.style(det.severity.value.upper(), fg=severity_color):>10s}  "
            f"{det.description}"
        )
        langs = ", ".join(lang.value for lang in det.languages)
        click.echo(f"           Languages: {langs}")
        click.echo()


@cli.command()
def init():
    """Generate a default .aiguard.yml configuration file."""
    target = Path.cwd() / ".aiguard.yml"

    if target.exists():
        click.confirm(
            f"{target} already exists. Overwrite?",
            abort=True,
        )

    config = Config.default()
    target.write_text(config.generate_default_yaml(), encoding="utf-8")
    click.echo(f"Created {target}")
    click.echo("Customize the rules and ignore patterns for your project.")


if __name__ == "__main__":
    cli()
