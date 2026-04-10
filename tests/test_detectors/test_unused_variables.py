"""Tests for AIG009: Unused Variables detector."""

from __future__ import annotations

import ast

import pytest

from aiguard.detectors.unused_variables import UnusedVariablesDetector


@pytest.fixture
def detector():
    return UnusedVariablesDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestUnusedVariables:
    def test_unused_variable_flagged(self, detector):
        code = """
def example():
    x = 10
    y = 20
    return x
"""
        findings = run(detector, code)
        assert any("y" in f.message for f in findings)

    def test_all_used_not_flagged(self, detector):
        code = """
def example():
    x = 10
    y = 20
    return x + y
"""
        findings = run(detector, code)
        assert len(findings) == 0

    def test_underscore_not_flagged(self, detector):
        code = """
def example():
    _ = some_function()
    return True
"""
        findings = run(detector, code)
        underscore = [f for f in findings if '"_"' in f.message]
        assert len(underscore) == 0
