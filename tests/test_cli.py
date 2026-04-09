"""Tests for the CLI interface."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from aiguard.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def fixtures_dir():
    return Path(__file__).parent / "fixtures"


class TestScanCommand:
    def test_scan_directory(self, runner, fixtures_dir):
        result = runner.invoke(cli, ["scan", str(fixtures_dir)])
        assert result.exit_code in (0, 1)  # May fail threshold
        assert "AIGuard" in result.output or "issue" in result.output

    def test_scan_single_file(self, runner, fixtures_dir):
        result = runner.invoke(cli, ["scan", str(fixtures_dir / "shallow_error.py")])
        assert result.exit_code in (0, 1)

    def test_scan_json_format(self, runner, fixtures_dir):
        result = runner.invoke(
            cli, ["scan", str(fixtures_dir / "shallow_error.py"), "-f", "json"]
        )
        assert result.exit_code in (0, 1)
        assert '"score"' in result.output

    def test_scan_sarif_format(self, runner, fixtures_dir):
        result = runner.invoke(
            cli, ["scan", str(fixtures_dir / "shallow_error.py"), "-f", "sarif"]
        )
        assert result.exit_code in (0, 1)
        assert '"version": "2.1.0"' in result.output

    def test_scan_quiet_mode(self, runner, fixtures_dir):
        result = runner.invoke(
            cli, ["scan", str(fixtures_dir / "shallow_error.py"), "-q"]
        )
        output = result.output.strip()
        assert output.isdigit()

    def test_scan_output_to_file(self, runner, fixtures_dir, tmp_path):
        outfile = tmp_path / "results.json"
        runner.invoke(
            cli,
            ["scan", str(fixtures_dir / "shallow_error.py"), "-f", "json", "-o", str(outfile)],
        )
        assert outfile.exists()

    def test_scan_fail_under(self, runner, fixtures_dir):
        result = runner.invoke(
            cli, ["scan", str(fixtures_dir / "shallow_error.py"), "--fail-under", "100"]
        )
        # Score will be below 100 because fixtures have issues
        assert result.exit_code == 1


class TestListRulesCommand:
    def test_list_rules(self, runner):
        result = runner.invoke(cli, ["list-rules"])
        assert result.exit_code == 0
        assert "AIG001" in result.output
        assert "AIG010" in result.output


class TestInitCommand:
    def test_init_creates_config(self, runner, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli, ["init"])
        assert result.exit_code == 0
        assert (tmp_path / ".aiguard.yml").exists()
