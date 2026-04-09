"""AIG010: Detect generic/meaningless variable names."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class GenericNamingDetector(BaseDetector):
    """Detects generic, meaningless variable and parameter names.

    AI-generated code frequently uses vague names like 'data', 'result',
    'temp', 'val', 'info' that make the code harder to understand.
    """

    rule_id = "AIG010"
    rule_name = "generic-naming"
    description = "Detects generic variable names that lack semantic meaning"
    severity = Severity.INFO
    languages = (Language.PYTHON,)

    DEFAULT_BLOCKLIST = {
        "data", "result", "results", "temp", "tmp", "val", "value",
        "info", "obj", "item", "items", "stuff", "thing", "things",
        "element", "elements", "var", "variable", "ret", "retval",
        "output", "out", "inp", "input_data", "output_data",
        "my_list", "my_dict", "my_var", "my_data",
        "foo", "bar", "baz", "qux",
    }

    # Context where generic names are acceptable
    ALLOWED_CONTEXTS = {
        # In comprehensions, short names are fine
        "comprehension",
        # In lambda, short names are fine
        "lambda",
    }

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        blocklist = self.DEFAULT_BLOCKLIST.copy()
        extra = self.config.get("blocklist", [])
        if extra:
            blocklist.update(extra)

        # Check function parameter names
        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(
                    self._check_params(node, file_path, blocklist)
                )
                findings.extend(
                    self._check_assignments(node, file_path, blocklist)
                )

        return findings

    def _check_params(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        blocklist: set[str],
    ) -> list[Finding]:
        findings = []

        for arg in func.args.args:
            if arg.arg in ("self", "cls"):
                continue
            if arg.arg.lower() in blocklist:
                findings.append(
                    self._make_finding(
                        message=f"Parameter '{arg.arg}' in function '{func.name}' "
                        "is too generic — use a descriptive name",
                        file_path=file_path,
                        line=func.lineno,
                        confidence=0.7,
                        suggestion=f"Rename '{arg.arg}' to describe what it represents "
                        f"(e.g., 'user_data' instead of 'data').",
                    )
                )

        return findings

    def _check_assignments(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        file_path: str,
        blocklist: set[str],
    ) -> list[Finding]:
        findings = []

        for node in ast.walk(func):
            # Skip comprehension variables
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                continue

            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.lower() in blocklist:
                        findings.append(
                            self._make_finding(
                                message=f"Variable '{target.id}' is too generic — "
                                "use a descriptive name",
                                file_path=file_path,
                                line=node.lineno,
                                confidence=0.65,
                                suggestion=f"Rename '{target.id}' to describe its "
                                "purpose or content.",
                            )
                        )

        return findings
