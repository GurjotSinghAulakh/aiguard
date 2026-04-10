"""Tests for inline suppression comments."""

from aiguard.suppression import is_suppressed, parse_suppressions


class TestParseSuppressions:
    """Test parsing of suppression comments."""

    def test_python_ignore_all(self):
        source = "x = 1  # aiguard: ignore\n"
        result = parse_suppressions(source)
        assert result == {1: None}

    def test_python_ignore_specific_rule(self):
        source = "x = 1  # aiguard: ignore AIG001\n"
        result = parse_suppressions(source)
        assert result == {1: {"AIG001"}}

    def test_python_ignore_multiple_rules(self):
        source = "x = 1  # aiguard: ignore AIG001, AIG002\n"
        result = parse_suppressions(source)
        assert result == {1: {"AIG001", "AIG002"}}

    def test_markdown_ignore_all(self):
        source = "<!-- aiguard: ignore -->\n"
        result = parse_suppressions(source)
        assert result == {1: None}

    def test_markdown_ignore_specific_rule(self):
        source = "<!-- aiguard: ignore AIG011 -->\n"
        result = parse_suppressions(source)
        assert result == {1: {"AIG011"}}

    def test_case_insensitive(self):
        source = "x = 1  # AIGUARD: IGNORE AIG001\n"
        result = parse_suppressions(source)
        assert result == {1: {"AIG001"}}

    def test_multiple_lines(self):
        source = (
            "line1\n"
            "x = 1  # aiguard: ignore AIG001\n"
            "line3\n"
            "y = 2  # aiguard: ignore\n"
        )
        result = parse_suppressions(source)
        assert result == {2: {"AIG001"}, 4: None}

    def test_no_suppressions(self):
        source = "x = 1\ny = 2\n"
        result = parse_suppressions(source)
        assert result == {}


class TestIsSuppressed:
    """Test the is_suppressed helper."""

    def test_not_suppressed_when_no_entry(self):
        assert not is_suppressed(1, "AIG001", {})

    def test_suppressed_all_rules(self):
        suppressions = {5: None}
        assert is_suppressed(5, "AIG001", suppressions)
        assert is_suppressed(5, "AIG099", suppressions)

    def test_suppressed_specific_rule(self):
        suppressions = {5: {"AIG001", "AIG002"}}
        assert is_suppressed(5, "AIG001", suppressions)
        assert is_suppressed(5, "AIG002", suppressions)
        assert not is_suppressed(5, "AIG003", suppressions)

    def test_different_line_not_suppressed(self):
        suppressions = {5: None}
        assert not is_suppressed(6, "AIG001", suppressions)


class TestIntegration:
    """Test suppression works end-to-end with the scanner."""

    def test_suppressed_finding_not_reported(self, tmp_path):
        """A bare except with suppression comment should not be flagged."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "try:\n"
            "    pass\n"
            "except:  # aiguard: ignore AIG001\n"
            "    pass\n"
        )

        from aiguard.scanner import Scanner

        scanner = Scanner()
        report = scanner.scan(str(test_file))

        aig001_findings = [
            f for f in report.file_reports[0].findings
            if f.rule_id == "AIG001"
        ]
        assert len(aig001_findings) == 0

    def test_unsuppressed_finding_still_reported(self, tmp_path):
        """A bare except without suppression should still be flagged."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "try:\n"
            "    pass\n"
            "except:\n"
            "    pass\n"
        )

        from aiguard.scanner import Scanner

        scanner = Scanner()
        report = scanner.scan(str(test_file))

        aig001_findings = [
            f for f in report.file_reports[0].findings
            if f.rule_id == "AIG001"
        ]
        assert len(aig001_findings) > 0

    def test_suppress_wrong_rule_still_reports(self, tmp_path):
        """Suppressing AIG002 should NOT suppress AIG001 findings."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "try:\n"
            "    pass\n"
            "except:  # aiguard: ignore AIG002\n"
            "    pass\n"
        )

        from aiguard.scanner import Scanner

        scanner = Scanner()
        report = scanner.scan(str(test_file))

        aig001_findings = [
            f for f in report.file_reports[0].findings
            if f.rule_id == "AIG001"
        ]
        assert len(aig001_findings) > 0
