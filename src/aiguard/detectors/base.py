"""Base detector interface for AIGuard."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from aiguard.models import Finding, Language, Severity


class BaseDetector(ABC):
    """Abstract base class for all code quality detectors.

    Subclasses must define class-level attributes and implement detect().
    Use the @register decorator from aiguard.detectors to register.
    """

    rule_id: ClassVar[str]
    rule_name: ClassVar[str]
    description: ClassVar[str]
    severity: ClassVar[Severity] = Severity.WARNING
    languages: ClassVar[tuple[Language, ...]] = (Language.PYTHON,)

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        """Run detection on a single file.

        Args:
            source: Raw source code string.
            ast_tree: Language-specific AST (ast.Module for Python).
            file_path: Path to the source file.

        Returns:
            List of findings detected in this file.
        """
        ...

    def _make_finding(
        self,
        message: str,
        file_path: str,
        line: int,
        end_line: int | None = None,
        column: int = 0,
        confidence: float = 1.0,
        suggestion: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Helper to create a Finding with this detector's metadata."""
        return Finding(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            message=message,
            file_path=file_path,
            line=line,
            end_line=end_line,
            column=column,
            severity=severity or self.severity,
            confidence=confidence,
            suggestion=suggestion,
        )
