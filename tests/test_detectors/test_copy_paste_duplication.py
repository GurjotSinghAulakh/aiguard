"""Tests for AIG005: Copy-Paste Duplication detector."""

from __future__ import annotations

import ast

import pytest

from aiguard.detectors.copy_paste_duplication import (
    CopyPasteDuplicationDetector,
)


@pytest.fixture
def detector():
    return CopyPasteDuplicationDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestDuplication:
    def test_near_identical_functions_flagged(self, detector):
        code = """
def process_users(users):
    results = []
    for user in users:
        if user.get("active"):
            name = user.get("name", "Unknown")
            email = user.get("email", "")
            results.append({"name": name, "email": email, "type": "user"})
    return results

def process_admins(admins):
    results = []
    for admin in admins:
        if admin.get("active"):
            name = admin.get("name", "Unknown")
            email = admin.get("email", "")
            results.append({"name": name, "email": email, "type": "admin"})
    return results
"""
        findings = run(detector, code)
        assert len(findings) > 0
        assert any("similar" in f.message.lower() for f in findings)

    def test_different_functions_not_flagged(self, detector):
        code = """
def add(a, b):
    return a + b

def multiply(a, b):
    result = 0
    for _ in range(b):
        result += a
    return result
"""
        findings = run(detector, code)
        assert len(findings) == 0

    def test_single_function_not_flagged(self, detector):
        code = """
def only_one():
    return 42
"""
        findings = run(detector, code)
        assert len(findings) == 0
