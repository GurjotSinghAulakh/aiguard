"""Auto-fix infrastructure for AIGuard.

Each fixer is registered against a rule_id and can transform source code
to resolve the corresponding finding automatically.
"""

from __future__ import annotations

from typing import Callable

# Registry: rule_id -> fixer function
_FIXERS: dict[str, Callable[[str, int], str]] = {}


def register_fixer(rule_id: str):
    """Decorator to register a fixer function for a rule."""
    def wrapper(fn: Callable[[str, int], str]):
        _FIXERS[rule_id] = fn
        return fn
    return wrapper


def get_fixer(rule_id: str) -> Callable[[str, int], str] | None:
    """Get the fixer for a rule, or None if no fix is available."""
    return _FIXERS.get(rule_id)


def get_fixable_rules() -> set[str]:
    """Return set of rule IDs that have auto-fixers."""
    return set(_FIXERS.keys())


# Import fixers to trigger registration
from aiguard.fixers import builtin  # noqa: F401, E402
