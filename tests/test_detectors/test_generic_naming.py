"""Tests for AIG010: Generic Naming detector."""

import ast

import pytest

from aiguard.detectors.generic_naming import GenericNamingDetector


@pytest.fixture
def detector():
    return GenericNamingDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestParameterNames:
    def test_generic_param_flagged(self, detector):
        code = """
def process(data, val):
    return data + val
"""
        findings = run(detector, code)
        assert any("data" in f.message for f in findings)
        assert any("val" in f.message for f in findings)

    def test_descriptive_param_ok(self, detector):
        code = """
def calculate_tax(income, tax_rate):
    return income * tax_rate
"""
        findings = run(detector, code)
        assert len(findings) == 0

    def test_self_cls_not_flagged(self, detector):
        code = """
class Foo:
    def method(self, data):
        return data
"""
        findings = run(detector, code)
        # 'self' should not be flagged, but 'data' should
        assert not any("self" in f.message for f in findings)


class TestVariableNames:
    def test_generic_variable_flagged(self, detector):
        code = """
def foo():
    result = 42
    temp = result * 2
    return temp
"""
        findings = run(detector, code)
        assert any("result" in f.message for f in findings)
        assert any("temp" in f.message for f in findings)
