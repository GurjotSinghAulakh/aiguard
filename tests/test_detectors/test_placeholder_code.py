"""Tests for AIG007: Placeholder Code detector."""

import ast

import pytest

from aiguard.detectors.placeholder_code import PlaceholderCodeDetector


@pytest.fixture
def detector():
    return PlaceholderCodeDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestPassPlaceholders:
    def test_pass_only_function(self, detector):
        code = """
def my_function():
    pass
"""
        findings = run(detector, code)
        assert any("pass" in f.message for f in findings)

    def test_pass_with_docstring_only(self, detector):
        code = """
def my_function():
    \"\"\"Does something.\"\"\"
    pass
"""
        findings = run(detector, code)
        assert any("pass" in f.message for f in findings)

    def test_abstract_method_not_flagged(self, detector):
        code = """
from abc import abstractmethod

class Base:
    @abstractmethod
    def my_method(self):
        pass
"""
        findings = run(detector, code)
        assert not any("pass" in f.message and "placeholder" in f.message for f in findings)


class TestTodoComments:
    def test_todo_detected(self, detector):
        code = """
# TODO implement this feature
x = 1
"""
        findings = run(detector, code)
        assert any("TODO" in f.message for f in findings)

    def test_fixme_detected(self, detector):
        code = """
# FIXME: broken logic
x = 1
"""
        findings = run(detector, code)
        assert any("FIXME" in f.message for f in findings)


class TestNotImplementedError:
    def test_not_implemented_flagged(self, detector):
        code = """
def my_function():
    raise NotImplementedError("do later")
"""
        findings = run(detector, code)
        assert any("NotImplementedError" in f.message for f in findings)
