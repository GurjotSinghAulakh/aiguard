"""Detector registry for AIGuard."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiguard.detectors.base import BaseDetector

_REGISTRY: dict[str, type[BaseDetector]] = {}


def register(cls: type[BaseDetector]) -> type[BaseDetector]:
    """Class decorator that registers a detector in the global registry."""
    _REGISTRY[cls.rule_id] = cls
    return cls


def get_all_detectors() -> dict[str, type[BaseDetector]]:
    """Return all registered detectors."""
    return dict(_REGISTRY)


def get_detector(rule_id: str) -> type[BaseDetector] | None:
    """Get a detector class by rule ID."""
    return _REGISTRY.get(rule_id)


def load_builtin_detectors() -> None:
    """Import all built-in detector modules to trigger registration."""
    from aiguard.detectors import (  # noqa: F401
        shallow_error_handling,
        tautological_code,
        over_commenting,
        hallucinated_imports,
        copy_paste_duplication,
        missing_input_validation,
        placeholder_code,
        complex_one_liners,
        unused_variables,
        generic_naming,
    )
