"""Shared test fixtures for AIGuard tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    """Path to the test fixtures directory."""
    return FIXTURES_DIR


def parse_python(source: str) -> ast.Module:
    """Helper to parse Python source for tests."""
    return ast.parse(source)
