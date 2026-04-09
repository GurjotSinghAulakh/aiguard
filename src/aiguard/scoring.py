"""Scoring system for AIGuard scan results."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiguard.models import Finding, ScanReport


def compute_score(
    findings: list[Finding],
    files_scanned: int,
    total_lines: int,
    weights: dict[str, int] | None = None,
) -> int:
    """Compute an AI code health score from 0-100.

    The score starts at 100 and deducts points based on findings,
    weighted by severity. A normalization factor prevents large
    codebases from always scoring 0.

    Args:
        findings: All findings across the scan.
        files_scanned: Number of files scanned.
        total_lines: Total lines scanned across all files.
        weights: Severity -> point deduction per finding.

    Returns:
        Score from 0 (worst) to 100 (perfect).
    """
    if not findings:
        return 100

    if weights is None:
        weights = {"error": 10, "warning": 3, "info": 1}

    # Sum weighted deductions
    total_deduction = sum(weights.get(f.severity.value, 3) for f in findings)

    # Normalize: scale deductions relative to codebase size
    # This prevents large codebases from always scoring 0
    normalization = max(1.0, total_lines / 200)

    raw_score = 100 - (total_deduction / normalization) * 5

    return max(0, min(100, round(raw_score)))


def compute_breakdown(findings: list[Finding]) -> dict[str, dict]:
    """Compute a per-category breakdown of findings.

    Returns:
        Dict mapping rule_name -> {count, severity, rule_id}
    """
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_name, []).append(f)

    breakdown = {}
    for rule_name, rule_findings in sorted(by_rule.items()):
        breakdown[rule_name] = {
            "count": len(rule_findings),
            "rule_id": rule_findings[0].rule_id,
            "severity": rule_findings[0].severity.value,
        }

    return breakdown


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity."""
    counter = Counter(f.severity.value for f in findings)
    return dict(counter)
