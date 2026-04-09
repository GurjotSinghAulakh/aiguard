"""Tests for AIG002: Tautological Code detector."""

import ast
import pytest
from aiguard.detectors.tautological_code import TautologicalCodeDetector


@pytest.fixture
def detector():
    return TautologicalCodeDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestConstantConditions:
    def test_if_true(self, detector):
        code = """
if True:
    print("always")
"""
        findings = run(detector, code)
        assert any("always True" in f.message for f in findings)

    def test_if_false(self, detector):
        code = """
if False:
    print("never")
"""
        findings = run(detector, code)
        assert any("always False" in f.message for f in findings)

    def test_normal_condition_not_flagged(self, detector):
        code = """
x = 5
if x > 3:
    print("ok")
"""
        findings = run(detector, code)
        assert len(findings) == 0


class TestUnreachableCode:
    def test_code_after_return(self, detector):
        code = """
def foo():
    return 42
    print("unreachable")
"""
        findings = run(detector, code)
        assert any("Unreachable" in f.message for f in findings)

    def test_code_after_raise(self, detector):
        code = """
def foo():
    raise ValueError("boom")
    print("unreachable")
"""
        findings = run(detector, code)
        assert any("Unreachable" in f.message for f in findings)


class TestSelfComparison:
    def test_x_equals_x(self, detector):
        code = """
x = 5
if x == x:
    pass
"""
        findings = run(detector, code)
        assert any("itself" in f.message for f in findings)


class TestBoolComparison:
    def test_equals_true(self, detector):
        code = """
x = True
if x == True:
    pass
"""
        findings = run(detector, code)
        assert any("Redundant" in f.message for f in findings)
