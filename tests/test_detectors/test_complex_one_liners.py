"""Tests for AIG008: Complex One-Liners detector."""

from __future__ import annotations

import ast

import pytest

from aiguard.detectors.complex_one_liners import ComplexOneLinersDetector


@pytest.fixture
def detector():
    return ComplexOneLinersDetector(config={"max_depth": 1})


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestNestedComprehensions:
    def test_nested_list_comp_flagged(self, detector):
        code = """
result = [[j for j in range(i) if j % 2 == 0] for i in range(10) if i > 3]
"""
        findings = run(detector, code)
        assert len(findings) > 0

    def test_simple_comprehension_not_flagged(self, detector):
        code = """
result = [i * 2 for i in range(10)]
"""
        findings = run(detector, code)
        assert len(findings) == 0


class TestChainedTernary:
    def test_chained_ternary_flagged(self, detector):
        code = """
x = "a" if val > 10 else "b" if val > 5 else "c" if val > 0 else "d"
"""
        findings = run(detector, code)
        assert len(findings) > 0

    def test_single_ternary_not_flagged(self, detector):
        code = """
x = "yes" if condition else "no"
"""
        findings = run(detector, code)
        assert len(findings) == 0
