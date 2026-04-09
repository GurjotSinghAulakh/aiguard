"""AIG001: Detect shallow error handling patterns typical of AI-generated code."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class ShallowErrorHandlingDetector(BaseDetector):
    """Detects bare except clauses, overly broad exception catches,
    and empty except bodies — common AI code generation patterns."""

    rule_id = "AIG001"
    rule_name = "shallow-error-handling"
    description = "Detects bare except clauses and overly broad exception catches"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    BROAD_EXCEPTIONS = {"Exception", "BaseException"}

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.ExceptHandler):
                findings.extend(self._check_except_handler(node, file_path))

        return findings

    def _check_except_handler(
        self, node: ast.ExceptHandler, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Bare except (no exception type specified)
        if node.type is None:
            findings.append(
                self._make_finding(
                    message="Bare 'except:' clause catches all exceptions including "
                    "KeyboardInterrupt and SystemExit",
                    file_path=file_path,
                    line=node.lineno,
                    severity=Severity.ERROR,
                    confidence=1.0,
                    suggestion="Catch a specific exception type, e.g., 'except ValueError:'",
                )
            )

        # Overly broad exception catch
        elif isinstance(node.type, ast.Name) and node.type.id in self.BROAD_EXCEPTIONS:
            findings.append(
                self._make_finding(
                    message=f"Catching '{node.type.id}' is too broad — "
                    "this hides bugs and makes debugging harder",
                    file_path=file_path,
                    line=node.lineno,
                    confidence=0.9,
                    suggestion="Catch specific exception types relevant to the operation",
                )
            )

        # Empty except body (just 'pass' or '...')
        if self._is_empty_handler(node):
            findings.append(
                self._make_finding(
                    message="Exception handler silently swallows errors with no "
                    "logging or re-raise",
                    file_path=file_path,
                    line=node.lineno,
                    confidence=0.95,
                    suggestion="At minimum, log the exception or add a comment explaining "
                    "why it's intentionally silenced",
                )
            )

        return findings

    def _is_empty_handler(self, node: ast.ExceptHandler) -> bool:
        """Check if an except handler body is effectively empty."""
        if not node.body:
            return True

        if len(node.body) == 1:
            stmt = node.body[0]
            # Just 'pass'
            if isinstance(stmt, ast.Pass):
                return True
            # Just '...' (Ellipsis)
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                if stmt.value.value is ...:
                    return True

        return False
