"""Tests for output formatters."""

import json
import pytest

from aiguard.formatters import get_formatter
from aiguard.models import FileReport, Finding, Language, ScanReport, Severity


@pytest.fixture
def sample_report():
    finding = Finding(
        rule_id="AIG001",
        rule_name="shallow-error-handling",
        message="Bare except clause",
        file_path="/test/example.py",
        line=10,
        severity=Severity.ERROR,
        suggestion="Catch a specific exception",
    )
    file_report = FileReport(
        file_path="/test/example.py",
        language=Language.PYTHON,
        findings=[finding],
        lines_scanned=50,
    )
    return ScanReport(
        file_reports=[file_report],
        score=75,
        files_scanned=1,
        total_findings=1,
        findings_by_severity={"error": 1},
        findings_by_rule={"AIG001": 1},
    )


class TestTerminalFormatter:
    def test_output_contains_finding(self, sample_report):
        formatter = get_formatter("terminal")
        output = formatter.format(sample_report)
        assert "AIG001" in output
        assert "75" in output

    def test_clean_report(self):
        report = ScanReport(score=100)
        formatter = get_formatter("terminal")
        output = formatter.format(report)
        assert "clean" in output.lower() or "No issues" in output


class TestJsonFormatter:
    def test_valid_json(self, sample_report):
        formatter = get_formatter("json")
        output = formatter.format(sample_report)
        data = json.loads(output)
        assert data["score"] == 75
        assert data["total_findings"] == 1

    def test_findings_in_output(self, sample_report):
        formatter = get_formatter("json")
        output = formatter.format(sample_report)
        data = json.loads(output)
        assert len(data["file_reports"]) == 1
        assert data["file_reports"][0]["findings"][0]["rule_id"] == "AIG001"


class TestSarifFormatter:
    def test_valid_sarif(self, sample_report):
        formatter = get_formatter("sarif")
        output = formatter.format(sample_report)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

    def test_sarif_has_rules(self, sample_report):
        formatter = get_formatter("sarif")
        output = formatter.format(sample_report)
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert any(r["id"] == "AIG001" for r in rules)

    def test_sarif_has_results(self, sample_report):
        formatter = get_formatter("sarif")
        output = formatter.format(sample_report)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "AIG001"
