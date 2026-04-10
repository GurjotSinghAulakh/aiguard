"""Tests for AIG006: Missing Input Validation detector."""

from __future__ import annotations

import ast

import pytest

from aiguard.detectors.missing_input_validation import (
    MissingInputValidationDetector,
)


@pytest.fixture
def detector():
    return MissingInputValidationDetector()


def run(detector, code):
    tree = ast.parse(code)
    return detector.detect(code, tree, "test.py")


class TestMissingValidation:
    def test_no_validation_flagged(self, detector):
        code = """
def send_email(recipient, subject, body, cc_list):
    message = f"To: {recipient}\\nSubject: {subject}\\n\\n{body}"
    for cc in cc_list:
        message += f"\\nCC: {cc}"
    return message
"""
        findings = run(detector, code)
        assert len(findings) > 0

    def test_with_validation_not_flagged(self, detector):
        code = """
def calculate(x, y, operation):
    if not isinstance(operation, str):
        raise ValueError("operation must be a string")
    if operation == "add":
        return x + y
    return None
"""
        findings = run(detector, code)
        assert len(findings) == 0

    def test_private_function_not_flagged(self, detector):
        code = """
def _private_helper(data):
    return data * 2
"""
        findings = run(detector, code)
        assert len(findings) == 0

    def test_no_params_not_flagged(self, detector):
        code = """
def get_config():
    return {"debug": True}
"""
        findings = run(detector, code)
        assert len(findings) == 0
