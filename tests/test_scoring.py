"""Tests for the scoring system."""

import pytest

from aiguard.models import Finding, Severity
from aiguard.scoring import compute_score, severity_counts


def make_finding(severity: Severity = Severity.WARNING) -> Finding:
    return Finding(
        rule_id="TEST001",
        rule_name="test-rule",
        message="Test finding",
        file_path="test.py",
        line=1,
        severity=severity,
    )


class TestComputeScore:
    def test_no_findings_perfect_score(self):
        assert compute_score([], 5, 500) == 100

    def test_many_errors_low_score(self):
        findings = [make_finding(Severity.ERROR) for _ in range(20)]
        score = compute_score(findings, 1, 100)
        assert score < 50

    def test_score_never_negative(self):
        findings = [make_finding(Severity.ERROR) for _ in range(1000)]
        score = compute_score(findings, 1, 10)
        assert score >= 0

    def test_score_never_above_100(self):
        score = compute_score([], 100, 10000)
        assert score <= 100

    def test_info_findings_low_impact(self):
        findings = [make_finding(Severity.INFO) for _ in range(5)]
        score = compute_score(findings, 5, 500)
        assert score >= 80


class TestSeverityCounts:
    def test_counts(self):
        findings = [
            make_finding(Severity.ERROR),
            make_finding(Severity.ERROR),
            make_finding(Severity.WARNING),
            make_finding(Severity.INFO),
        ]
        counts = severity_counts(findings)
        assert counts["error"] == 2
        assert counts["warning"] == 1
        assert counts["info"] == 1

    def test_empty(self):
        assert severity_counts([]) == {}
