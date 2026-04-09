"""AIG002: Detect tautological and dead code patterns."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class TautologicalCodeDetector(BaseDetector):
    """Detects always-true/false conditions, unreachable code after return,
    and other dead code patterns common in AI-generated code."""

    rule_id = "AIG002"
    rule_name = "tautological-code"
    description = "Detects always-true/false conditions and unreachable code"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            # Check for if True / if False
            if isinstance(node, ast.If):
                findings.extend(self._check_constant_condition(node, file_path))

            # Check for unreachable code after return/raise/break/continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_unreachable_code(node, file_path))

            # Check for x == x comparisons
            if isinstance(node, ast.Compare):
                findings.extend(self._check_self_comparison(node, file_path))

            # Check for redundant boolean comparisons: x == True, x == False
            if isinstance(node, ast.Compare):
                findings.extend(self._check_bool_comparison(node, file_path))

        return findings

    def _check_constant_condition(
        self, node: ast.If, file_path: str
    ) -> list[Finding]:
        findings = []

        test = node.test
        if isinstance(test, ast.Constant):
            if test.value is True:
                findings.append(
                    self._make_finding(
                        message="Condition is always True — the 'if' block always executes",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Remove the condition and keep the body, "
                        "or remove the entire block if unneeded",
                    )
                )
            elif test.value is False:
                findings.append(
                    self._make_finding(
                        message="Condition is always False — the 'if' block never executes",
                        file_path=file_path,
                        line=node.lineno,
                        suggestion="Remove the dead code block entirely",
                    )
                )

        return findings

    def _check_unreachable_code(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> list[Finding]:
        findings = []

        for i, stmt in enumerate(node.body):
            if isinstance(stmt, (ast.Return, ast.Raise)) and i < len(node.body) - 1:
                next_stmt = node.body[i + 1]
                # Don't flag function/class defs after return (common pattern)
                if not isinstance(next_stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    findings.append(
                        self._make_finding(
                            message="Unreachable code after "
                            f"{'return' if isinstance(stmt, ast.Return) else 'raise'} "
                            "statement",
                            file_path=file_path,
                            line=next_stmt.lineno,
                            confidence=0.95,
                            suggestion="Remove the unreachable code or restructure the logic",
                        )
                    )
                break  # Only flag the first unreachable statement

        return findings

    def _check_self_comparison(
        self, node: ast.Compare, file_path: str
    ) -> list[Finding]:
        findings = []

        if len(node.ops) == 1 and len(node.comparators) == 1:
            left = node.left
            right = node.comparators[0]
            op = node.ops[0]

            if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                if left.id == right.id and isinstance(op, (ast.Eq, ast.Is)):
                    findings.append(
                        self._make_finding(
                            message=f"Comparing '{left.id}' to itself is always True",
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.9,
                            suggestion="This is likely a copy-paste error — "
                            "compare to the intended variable",
                        )
                    )

        return findings

    def _check_bool_comparison(
        self, node: ast.Compare, file_path: str
    ) -> list[Finding]:
        findings = []

        if len(node.ops) == 1 and len(node.comparators) == 1:
            comp = node.comparators[0]
            op = node.ops[0]

            if isinstance(comp, ast.Constant) and isinstance(comp.value, bool):
                if isinstance(op, (ast.Eq, ast.Is)):
                    findings.append(
                        self._make_finding(
                            message=f"Redundant comparison to {comp.value} — "
                            "use the expression directly",
                            file_path=file_path,
                            line=node.lineno,
                            severity=Severity.INFO,
                            suggestion=f"Use 'x' instead of 'x == {comp.value}'"
                            if comp.value
                            else f"Use 'not x' instead of 'x == {comp.value}'",
                        )
                    )

        return findings
