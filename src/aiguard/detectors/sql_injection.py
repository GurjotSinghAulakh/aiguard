"""AIG017: Detect SQL injection patterns in Python code."""

from __future__ import annotations

import ast
import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# SQL keywords that indicate a query string
_SQL_KEYWORDS = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b",
    re.IGNORECASE,
)


@register
class SQLInjectionDetector(BaseDetector):
    """Detects potential SQL injection vulnerabilities.

    AI-generated code often uses string formatting (f-strings, .format(),
    % formatting, or concatenation) to build SQL queries instead of
    parameterized queries, creating injection vulnerabilities.
    """

    rule_id = "AIG017"
    rule_name = "sql-injection"
    description = (
        "Detects SQL queries built with string formatting "
        "instead of parameterized queries"
    )
    severity = Severity.ERROR
    languages = (Language.PYTHON,)

    def detect(
        self, source: str, ast_tree: Any, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            # f-string with SQL keywords
            if isinstance(node, ast.JoinedStr):
                findings.extend(
                    self._check_fstring(node, file_path)
                )

            # "...".format(...) with SQL
            elif isinstance(node, ast.Call):
                findings.extend(
                    self._check_format_call(node, file_path)
                )

            # "..." % (vars) with SQL
            elif isinstance(node, ast.BinOp) and isinstance(
                node.op, ast.Mod
            ):
                findings.extend(
                    self._check_percent_format(node, file_path)
                )

            # "SELECT * FROM " + user_input
            elif isinstance(node, ast.BinOp) and isinstance(
                node.op, ast.Add
            ):
                findings.extend(
                    self._check_string_concat(node, file_path)
                )

        return findings

    def _check_fstring(
        self, node: ast.JoinedStr, file_path: str
    ) -> list[Finding]:
        """Check f-strings for SQL query patterns."""
        # Extract the literal parts of the f-string
        literal_parts = []
        has_expressions = False
        for value in node.values:
            if isinstance(value, ast.Constant):
                literal_parts.append(str(value.value))
            elif isinstance(value, ast.FormattedValue):
                has_expressions = True

        if not has_expressions:
            return []

        combined = " ".join(literal_parts)
        if _SQL_KEYWORDS.search(combined):
            return [
                self._make_finding(
                    message=(
                        "SQL query built with f-string — "
                        "vulnerable to SQL injection"
                    ),
                    file_path=file_path,
                    line=node.lineno,
                    confidence=0.9,
                    suggestion=(
                        "Use parameterized queries: "
                        "cursor.execute('SELECT * FROM users "
                        "WHERE id = ?', (user_id,))"
                    ),
                )
            ]

        return []

    def _check_format_call(
        self, node: ast.Call, file_path: str
    ) -> list[Finding]:
        """Check .format() calls on SQL strings."""
        if not isinstance(node.func, ast.Attribute):
            return []
        if node.func.attr != "format":
            return []

        # Check if the object being formatted is a SQL string
        obj = node.func.value
        if isinstance(obj, ast.Constant) and isinstance(obj.value, str):
            if _SQL_KEYWORDS.search(obj.value):
                return [
                    self._make_finding(
                        message=(
                            "SQL query built with .format() — "
                            "vulnerable to SQL injection"
                        ),
                        file_path=file_path,
                        line=node.lineno,
                        confidence=0.9,
                        suggestion=(
                            "Use parameterized queries instead "
                            "of string formatting"
                        ),
                    )
                ]

        return []

    def _check_percent_format(
        self, node: ast.BinOp, file_path: str
    ) -> list[Finding]:
        """Check %-formatting on SQL strings."""
        if isinstance(node.left, ast.Constant) and isinstance(
            node.left.value, str
        ):
            if _SQL_KEYWORDS.search(node.left.value):
                return [
                    self._make_finding(
                        message=(
                            "SQL query built with % formatting — "
                            "vulnerable to SQL injection"
                        ),
                        file_path=file_path,
                        line=node.lineno,
                        confidence=0.85,
                        suggestion=(
                            "Use parameterized queries instead "
                            "of % string formatting"
                        ),
                    )
                ]

        return []

    def _check_string_concat(
        self, node: ast.BinOp, file_path: str
    ) -> list[Finding]:
        """Check string concatenation with SQL keywords."""
        # Check if left side is a SQL string constant
        if isinstance(node.left, ast.Constant) and isinstance(
            node.left.value, str
        ):
            if _SQL_KEYWORDS.search(node.left.value):
                # Right side must be a variable (not another constant)
                if not isinstance(node.right, ast.Constant):
                    return [
                        self._make_finding(
                            message=(
                                "SQL query built with string "
                                "concatenation — vulnerable to "
                                "SQL injection"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.85,
                            suggestion=(
                                "Use parameterized queries instead "
                                "of string concatenation"
                            ),
                        )
                    ]

        return []
