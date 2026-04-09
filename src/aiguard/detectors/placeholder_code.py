"""AIG007: Detect placeholder code disguised as complete implementation."""

from __future__ import annotations

import ast
import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class PlaceholderCodeDetector(BaseDetector):
    """Detects placeholder code that looks like it's complete but isn't.

    AI often generates functions with 'pass', 'NotImplementedError',
    TODO/FIXME comments, or '...' bodies without clearly signaling
    that the implementation is incomplete.
    """

    rule_id = "AIG007"
    rule_name = "placeholder-code"
    description = "Detects placeholder code disguised as complete implementation"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    # Patterns in comments/strings that suggest incomplete code
    INCOMPLETE_PATTERNS = [
        re.compile(r"#\s*TODO", re.I),
        re.compile(r"#\s*FIXME", re.I),
        re.compile(r"#\s*HACK", re.I),
        re.compile(r"#\s*XXX", re.I),
        re.compile(r"#\s*PLACEHOLDER", re.I),
        re.compile(r"#\s*add\s+(your|actual|real)\s+", re.I),
        re.compile(r"#\s*implement\s+(this|here|later)", re.I),
        re.compile(r"#\s*replace\s+(this|with)", re.I),
        re.compile(r"#\s*fill\s+in\s+", re.I),
        re.compile(r"#\s*\.\.\.\s*(add|implement|complete|fill)", re.I),
    ]

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        # Check for pass/... in non-abstract methods
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_placeholder_function(node, file_path))

        # Check for TODO/FIXME patterns
        findings.extend(self._check_incomplete_comments(source, file_path))

        return findings

    def _check_placeholder_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> list[Finding]:
        findings = []

        # Skip abstract methods (they're supposed to have pass/...)
        if self._is_abstract(node):
            return findings

        # Skip __init__ with just super().__init__()
        if node.name == "__init__":
            return findings

        body = self._get_effective_body(node)

        if not body:
            return findings

        # Check for 'pass' as the only statement
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            findings.append(
                self._make_finding(
                    message=f"Function '{node.name}' has only 'pass' — "
                    "placeholder disguised as implementation",
                    file_path=file_path,
                    line=node.lineno,
                    confidence=0.85,
                    suggestion="Implement the function or mark it clearly as "
                    "abstract/not-yet-implemented.",
                )
            )

        # Check for Ellipsis (...) as the only statement
        elif len(body) == 1 and isinstance(body[0], ast.Expr):
            if isinstance(body[0].value, ast.Constant) and body[0].value.value is ...:
                findings.append(
                    self._make_finding(
                        message=f"Function '{node.name}' has only '...' — "
                        "appears incomplete",
                        file_path=file_path,
                        line=node.lineno,
                        confidence=0.8,
                        suggestion="Implement the function body.",
                    )
                )

        # Check for NotImplementedError raise
        for stmt in body:
            if isinstance(stmt, ast.Raise) and stmt.exc:
                if isinstance(stmt.exc, ast.Call):
                    func = stmt.exc.func
                    if isinstance(func, ast.Name) and func.id == "NotImplementedError":
                        findings.append(
                            self._make_finding(
                                message=f"Function '{node.name}' raises NotImplementedError — "
                                "implementation is missing",
                                file_path=file_path,
                                line=stmt.lineno,
                                confidence=0.9,
                                suggestion="Implement the function or mark it as abstract "
                                "if it's meant to be overridden.",
                            )
                        )

        return findings

    def _check_incomplete_comments(
        self, source: str, file_path: str
    ) -> list[Finding]:
        findings = []

        for i, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            for pattern in self.INCOMPLETE_PATTERNS:
                if pattern.search(stripped):
                    findings.append(
                        self._make_finding(
                            message=f"Incomplete code marker found: '{stripped[:80]}'",
                            file_path=file_path,
                            line=i,
                            severity=Severity.INFO,
                            confidence=0.7,
                            suggestion="Complete the implementation or remove if resolved.",
                        )
                    )
                    break  # Only one finding per line

        return findings

    def _is_abstract(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if a function is decorated with @abstractmethod."""
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name) and decorator.id == "abstractmethod":
                return True
            if isinstance(decorator, ast.Attribute) and decorator.attr == "abstractmethod":
                return True
        return False

    def _get_effective_body(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[ast.stmt]:
        """Get function body excluding docstring."""
        body = node.body
        if not body:
            return []

        # Skip docstring
        if (
            isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            return body[1:]

        return body
