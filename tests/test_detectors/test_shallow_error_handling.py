"""Tests for AIG001: Shallow Error Handling detector."""

import ast

import pytest

from aiguard.detectors.shallow_error_handling import ShallowErrorHandlingDetector
from aiguard.models import Severity


@pytest.fixture
def detector():
    return ShallowErrorHandlingDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestBareExcept:
    def test_bare_except_detected(self, detector):
        code = """
try:
    x = 1 / 0
except:
    pass
"""
        findings = run(detector, code)
        assert any("Bare" in f.message for f in findings)
        assert any(f.severity == Severity.ERROR for f in findings)

    def test_specific_except_not_flagged(self, detector):
        code = """
try:
    x = 1 / 0
except ZeroDivisionError as e:
    print(e)
    raise
"""
        findings = run(detector, code)
        assert len(findings) == 0


class TestBroadExcept:
    def test_exception_catch_flagged(self, detector):
        code = """
try:
    x = 1
except Exception:
    pass
"""
        findings = run(detector, code)
        assert any("too broad" in f.message for f in findings)

    def test_base_exception_catch_flagged(self, detector):
        code = """
try:
    x = 1
except BaseException:
    pass
"""
        findings = run(detector, code)
        assert any("too broad" in f.message for f in findings)


class TestEmptyHandler:
    def test_pass_only_flagged(self, detector):
        code = """
try:
    x = 1
except ValueError:
    pass
"""
        findings = run(detector, code)
        assert any("silently swallows" in f.message for f in findings)

    def test_handler_with_logging_not_flagged(self, detector):
        code = """
try:
    x = 1
except ValueError as e:
    logger.error(f"Failed: {e}")
"""
        findings = run(detector, code)
        assert not any("silently swallows" in f.message for f in findings)
