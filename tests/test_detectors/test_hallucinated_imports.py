"""Tests for AIG004: Hallucinated Imports detector."""

from __future__ import annotations

import ast

import pytest

from aiguard.detectors.hallucinated_imports import HallucinatedImportsDetector


@pytest.fixture
def detector():
    return HallucinatedImportsDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestHallucinatedImports:
    def test_nonexistent_package_flagged(self, detector):
        code = "import superai_magic_tools"
        findings = run(detector, code)
        assert len(findings) > 0

    def test_stdlib_not_flagged(self, detector):
        code = "import os\nimport json\nimport pathlib"
        findings = run(detector, code)
        assert len(findings) == 0

    def test_from_import_nonexistent(self, detector):
        code = "from ai_hallucinated_pkg import something"
        findings = run(detector, code)
        assert len(findings) > 0

    def test_installed_package_not_flagged(self, detector):
        code = "import pytest"
        findings = run(detector, code)
        assert len(findings) == 0
