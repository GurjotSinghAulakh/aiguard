"""Tests for the diff mode module."""

from __future__ import annotations

from aiguard.diff import (
    ChangedRegion,
    _parse_hunk_header,
    _parse_unified_diff,
    filter_findings_to_diff,
)
from aiguard.models import Finding, Severity


class TestParseHunkHeader:
    def test_single_line_added(self):
        region = _parse_hunk_header("@@ -10,0 +11 @@ some context")
        assert region is not None
        assert region.start == 11
        assert region.end == 11

    def test_multi_line_added(self):
        region = _parse_hunk_header("@@ -10,0 +11,5 @@ some context")
        assert region is not None
        assert region.start == 11
        assert region.end == 15

    def test_pure_deletion_returns_none(self):
        region = _parse_hunk_header("@@ -10,3 +10,0 @@ some context")
        assert region is None

    def test_standard_change(self):
        region = _parse_hunk_header("@@ -5,3 +5,4 @@ def foo():")
        assert region is not None
        assert region.start == 5
        assert region.end == 8


class TestParseUnifiedDiff:
    def test_parse_python_diff(self):
        diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -10,0 +11,3 @@
+new line 1
+new line 2
+new line 3
"""
        result = _parse_unified_diff(diff)
        # Should have one file with one region
        matching = [k for k in result if k.endswith("src/app.py")]
        assert len(matching) == 1
        regions = result[matching[0]]
        assert len(regions) == 1
        assert regions[0].start == 11
        assert regions[0].end == 13

    def test_ignores_non_code_files(self):
        diff = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,0 +2,1 @@
+new line
"""
        result = _parse_unified_diff(diff)
        assert len(result) == 0

    def test_multiple_hunks(self):
        diff = """diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -5,2 +5,3 @@
+added
@@ -20,0 +21,2 @@
+added1
+added2
"""
        result = _parse_unified_diff(diff)
        matching = [k for k in result if k.endswith("src/app.py")]
        assert len(matching) == 1
        regions = result[matching[0]]
        assert len(regions) == 2


class TestFilterFindings:
    def _make_finding(self, file_path: str, line: int) -> Finding:
        return Finding(
            rule_id="TEST001",
            rule_name="test",
            message="test finding",
            file_path=file_path,
            line=line,
            severity=Severity.WARNING,
        )

    def test_keeps_findings_in_changed_region(self):
        findings = [
            self._make_finding("/app.py", 12),
            self._make_finding("/app.py", 50),
        ]
        regions = {
            "/app.py": [ChangedRegion(start=10, end=15)],
        }
        filtered = filter_findings_to_diff(findings, regions)
        assert len(filtered) == 1
        assert filtered[0].line == 12

    def test_removes_findings_outside_changed_region(self):
        findings = [
            self._make_finding("/app.py", 5),
        ]
        regions = {
            "/app.py": [ChangedRegion(start=10, end=15)],
        }
        filtered = filter_findings_to_diff(findings, regions)
        assert len(filtered) == 0

    def test_removes_findings_in_unchanged_files(self):
        findings = [
            self._make_finding("/other.py", 10),
        ]
        regions = {
            "/app.py": [ChangedRegion(start=10, end=15)],
        }
        filtered = filter_findings_to_diff(findings, regions)
        assert len(filtered) == 0

    def test_multiple_regions(self):
        findings = [
            self._make_finding("/app.py", 5),
            self._make_finding("/app.py", 12),
            self._make_finding("/app.py", 25),
            self._make_finding("/app.py", 50),
        ]
        regions = {
            "/app.py": [
                ChangedRegion(start=10, end=15),
                ChangedRegion(start=24, end=26),
            ],
        }
        filtered = filter_findings_to_diff(findings, regions)
        assert len(filtered) == 2
        assert filtered[0].line == 12
        assert filtered[1].line == 25

    def test_empty_regions(self):
        findings = [self._make_finding("/app.py", 10)]
        filtered = filter_findings_to_diff(findings, {})
        assert len(filtered) == 0
