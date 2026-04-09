"""AIG006: Detect missing input validation in public functions."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class MissingInputValidationDetector(BaseDetector):
    """Detects public functions with parameters but no input validation.

    AI-generated code frequently skips input validation, assuming all
    inputs are valid. This leads to cryptic errors deep in the call stack.
    """

    rule_id = "AIG006"
    rule_name = "missing-input-validation"
    description = "Detects public functions with no input validation"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    # AST node types that suggest validation
    VALIDATION_INDICATORS = {
        "isinstance",
        "issubclass",
        "hasattr",
        "callable",
        "len",
    }

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.iter_child_nodes(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                finding = self._check_function(node, file_path)
                if finding:
                    findings.append(finding)

            elif isinstance(node, ast.ClassDef):
                for item in ast.iter_child_nodes(node):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        finding = self._check_function(item, file_path)
                        if finding:
                            findings.append(finding)

        return findings

    def _check_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str
    ) -> Finding | None:
        """Check if a public function validates its inputs."""
        # Skip private/protected functions
        if node.name.startswith("_"):
            return None

        # Skip functions with no meaningful parameters
        params = self._get_params(node)
        if len(params) == 0:
            return None

        # Skip very short functions (likely simple getters/setters)
        if len(node.body) <= 2:
            return None

        # Skip if function has type hints on all params (partial defense)
        if self._all_params_annotated(node):
            return None

        # Check if there's any validation in the first few statements
        check_depth = min(5, len(node.body))
        early_body = node.body[:check_depth]

        if self._has_validation(early_body):
            return None

        return self._make_finding(
            message=f"Public function '{node.name}' has {len(params)} parameter(s) "
            f"({', '.join(params)}) but no input validation",
            file_path=file_path,
            line=node.lineno,
            confidence=0.65,
            suggestion="Add input validation (type checks, value range checks, "
            "None checks) at the start of the function.",
        )

    def _get_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        """Get parameter names excluding self/cls."""
        params = []
        for arg in node.args.args:
            if arg.arg not in ("self", "cls"):
                params.append(arg.arg)
        params.extend(arg.arg for arg in node.args.kwonlyargs)
        return params

    def _all_params_annotated(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if all parameters have type annotations."""
        for arg in node.args.args:
            if arg.arg in ("self", "cls"):
                continue
            if arg.annotation is None:
                return False
        return True

    def _has_validation(self, stmts: list[ast.stmt]) -> bool:
        """Check if statements contain input validation patterns."""
        for stmt in stmts:
            # Skip docstrings
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                continue

            source_dump = ast.dump(stmt)

            # Check for isinstance, hasattr, etc.
            for indicator in self.VALIDATION_INDICATORS:
                if indicator in source_dump:
                    return True

            # Check for 'if ... raise' pattern
            if isinstance(stmt, ast.If):
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Raise):
                        return True

            # Check for assert statements
            if isinstance(stmt, ast.Assert):
                return True

            # Check for 'raise' at top level
            if isinstance(stmt, ast.Raise):
                return True

        return False
