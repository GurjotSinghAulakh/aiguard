"""Tests for AIG003: Over-commenting detector."""

from __future__ import annotations

import ast

import pytest

from aiguard.detectors.over_commenting import OverCommentingDetector


@pytest.fixture
def detector():
    return OverCommentingDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestOverCommenting:
    def test_obvious_comments_flagged(self, detector):
        code = """
# Initialize the result variable
result = 0
# Loop through the range
for i in range(10):
    # Add i to result
    result += i
# Return the result
"""
        findings = run(detector, code)
        assert len(findings) > 0

    def test_clean_code_not_flagged(self, detector):
        code = '''
def sum_evens(n):
    """Sum even numbers up to n."""
    return sum(i for i in range(n) if i % 2 == 0)
'''
        findings = run(detector, code)
        assert len(findings) == 0

    def test_useful_comments_not_flagged(self, detector):
        code = """
# HACK: workaround for upstream bug #1234
result = fallback_method()
"""
        findings = run(detector, code)
        assert len(findings) == 0
