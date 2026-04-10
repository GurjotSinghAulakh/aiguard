"""Tests for AIG017 — SQL injection detector."""

import ast

from aiguard.detectors.sql_injection import SQLInjectionDetector


def _detect(source: str) -> list:
    tree = ast.parse(source)
    detector = SQLInjectionDetector()
    return detector.detect(source, tree, "test.py")


class TestFStringInjection:
    """Test f-string SQL injection detection."""

    def test_fstring_select(self):
        source = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        findings = _detect(source)
        assert len(findings) >= 1
        assert "f-string" in findings[0].message.lower()

    def test_fstring_insert(self):
        source = (
            'query = f"INSERT INTO logs (msg) VALUES ({message})"'
        )
        findings = _detect(source)
        assert len(findings) >= 1

    def test_fstring_delete(self):
        source = 'query = f"DELETE FROM users WHERE name = {name}"'
        findings = _detect(source)
        assert len(findings) >= 1


class TestFormatInjection:
    """Test .format() SQL injection detection."""

    def test_format_select(self):
        source = (
            'query = '
            '"SELECT * FROM users WHERE id = {}".format(uid)'
        )
        findings = _detect(source)
        assert len(findings) >= 1
        assert ".format()" in findings[0].message


class TestPercentFormatInjection:
    """Test % formatting SQL injection detection."""

    def test_percent_select(self):
        source = (
            'query = "SELECT * FROM users WHERE id = %s" % user_id'
        )
        findings = _detect(source)
        assert len(findings) >= 1
        assert "%" in findings[0].message


class TestConcatInjection:
    """Test string concatenation SQL injection detection."""

    def test_concat_select(self):
        source = (
            'query = "SELECT * FROM users WHERE name = " + user_name'
        )
        findings = _detect(source)
        assert len(findings) >= 1
        assert "concatenation" in findings[0].message


class TestSafePatterns:
    """Test that safe patterns are NOT flagged."""

    def test_parameterized_query(self):
        source = (
            'cursor.execute('
            '"SELECT * FROM users WHERE id = ?", (user_id,))'
        )
        findings = _detect(source)
        assert len(findings) == 0

    def test_static_sql_string(self):
        source = 'query = "SELECT * FROM users"'
        findings = _detect(source)
        assert len(findings) == 0

    def test_normal_fstring(self):
        source = 'msg = f"Hello {name}, welcome!"'
        findings = _detect(source)
        assert len(findings) == 0

    def test_string_concat_with_constants(self):
        source = 'query = "SELECT * " + "FROM users"'
        findings = _detect(source)
        assert len(findings) == 0
