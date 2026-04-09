"""Formatter registry for AIGuard."""

from __future__ import annotations

from aiguard.formatters.base import BaseFormatter
from aiguard.formatters.json_fmt import JsonFormatter
from aiguard.formatters.sarif import SarifFormatter
from aiguard.formatters.terminal import TerminalFormatter

_FORMATTERS: dict[str, type[BaseFormatter]] = {
    "terminal": TerminalFormatter,
    "json": JsonFormatter,
    "sarif": SarifFormatter,
}


def get_formatter(name: str) -> BaseFormatter:
    """Get a formatter instance by name."""
    if name not in _FORMATTERS:
        raise ValueError(f"Unknown formatter: {name}. Available: {list(_FORMATTERS.keys())}")
    return _FORMATTERS[name]()


def list_formatters() -> list[str]:
    """List available formatter names."""
    return list(_FORMATTERS.keys())
