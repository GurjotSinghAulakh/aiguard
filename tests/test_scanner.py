"""Tests for the Scanner orchestrator."""

import pytest
from pathlib import Path

from aiguard.config import Config
from aiguard.scanner import Scanner


@pytest.fixture
def scanner():
    config = Config.default()
    config.ignore_patterns.append("**/node_modules/**")
    return Scanner(config)


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"


class TestScanner:
    def test_scan_single_file(self, scanner, fixtures_dir):
        report = scanner.scan(str(fixtures_dir / "shallow_error.py"))
        assert report.files_scanned == 1
        assert report.total_findings > 0

    def test_scan_directory(self, scanner, fixtures_dir):
        report = scanner.scan(str(fixtures_dir))
        assert report.files_scanned > 1
        assert report.total_findings > 0

    def test_scan_nonexistent_path(self, scanner):
        report = scanner.scan("/nonexistent/path")
        assert report.files_scanned == 0

    def test_score_computed(self, scanner, fixtures_dir):
        report = scanner.scan(str(fixtures_dir))
        assert 0 <= report.score <= 100

    def test_findings_by_severity(self, scanner, fixtures_dir):
        report = scanner.scan(str(fixtures_dir / "shallow_error.py"))
        assert isinstance(report.findings_by_severity, dict)

    def test_clean_code_high_score(self, scanner, tmp_path):
        clean_file = tmp_path / "clean.py"
        clean_file.write_text('''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b
''')
        report = scanner.scan(str(clean_file))
        assert report.score >= 80


class TestScannerConfig:
    def test_disabled_rule_not_run(self, fixtures_dir):
        config = Config.default()
        config.rules = {}
        from aiguard.config import RuleConfig
        config.rules["AIG001"] = RuleConfig(enabled=False)

        scanner = Scanner(config)
        report = scanner.scan(str(fixtures_dir / "shallow_error.py"))

        # Should not have any AIG001 findings
        for fr in report.file_reports:
            for f in fr.findings:
                assert f.rule_id != "AIG001"
