"""AIG009: Detect unused variables."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class UnusedVariablesDetector(BaseDetector):
    """Detects variables that are assigned but never used.

    AI-generated code frequently assigns intermediate results to variables
    that are never referenced again.
    """

    rule_id = "AIG009"
    rule_name = "unused-variables"
    description = "Detects variables assigned but never used"
    severity = Severity.INFO
    languages = (Language.PYTHON,)

    # Names to always ignore
    IGNORED_NAMES = {"_", "__", "self", "cls"}

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        # Analyze each function scope independently
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_function(node, file_path))

        return findings

    def _check_function(
        self, func: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> list[Finding]:
        findings = []

        assignments: dict[str, int] = {}  # name -> line number
        usages: set[str] = set()

        # Collect all assignments and usages within this function
        for node in ast.walk(func):
            # Track assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name = target.id
                        if name not in self.IGNORED_NAMES and not name.startswith("_"):
                            assignments[name] = node.lineno

            # Track augmented assignments (+=, etc.)
            elif isinstance(node, ast.AugAssign):
                if isinstance(node.target, ast.Name):
                    usages.add(node.target.id)  # Also counts as usage

            # Track Name references (usages)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                usages.add(node.id)

            # Track attribute access (obj.attr — 'obj' is used)
            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    usages.add(node.value.id)

            # Track subscript access (obj[key] — 'obj' is used)
            elif isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Name):
                    usages.add(node.value.id)

            # Track function calls (func() — 'func' is used)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    usages.add(node.func.id)

            # Track return values
            elif isinstance(node, ast.Return) and node.value:
                if isinstance(node.value, ast.Name):
                    usages.add(node.value.id)

        # Find unused assignments
        for name, line in assignments.items():
            if name not in usages:
                findings.append(
                    self._make_finding(
                        message=f"Variable '{name}' is assigned but never used "
                        f"in function '{func.name}'",
                        file_path=file_path,
                        line=line,
                        confidence=0.8,
                        suggestion=f"Remove the unused variable '{name}' or "
                        "prefix with '_' if intentionally unused.",
                    )
                )

        return findings
