"""AIG008: Detect overly complex one-liners."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class ComplexOneLinersDetector(BaseDetector):
    """Detects overly complex single-line expressions.

    AI models sometimes try to be clever with deeply nested comprehensions,
    chained ternary operators, or excessively complex lambda expressions.
    """

    rule_id = "AIG008"
    rule_name = "complex-one-liners"
    description = "Detects overly complex one-liner expressions"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        max_depth = self.config.get("max_depth", 4)

        for node in ast.walk(ast_tree):
            # Check comprehensions
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                depth = self._comprehension_depth(node)
                if depth > max_depth:
                    findings.append(
                        self._make_finding(
                            message=f"Deeply nested comprehension (depth {depth}) — "
                            "hard to read and maintain",
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.85,
                            suggestion="Break this into a regular loop or multiple "
                            "steps for clarity.",
                        )
                    )

            # Check nested ternary operators
            if isinstance(node, ast.IfExp):
                depth = self._ternary_depth(node)
                if depth >= 2:
                    findings.append(
                        self._make_finding(
                            message=f"Chained ternary expression (depth {depth}) — "
                            "use if/elif/else for clarity",
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.9,
                            suggestion="Replace chained ternary with explicit "
                            "if/elif/else block.",
                        )
                    )

            # Check complex lambda expressions
            if isinstance(node, ast.Lambda):
                body_depth = self._node_depth(node.body)
                if body_depth > max_depth:
                    findings.append(
                        self._make_finding(
                            message=f"Complex lambda (depth {body_depth}) — "
                            "consider using a named function",
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.8,
                            suggestion="Replace with a named function for readability "
                            "and easier debugging.",
                        )
                    )

        return findings

    def _comprehension_depth(self, node: ast.AST) -> int:
        """Count nesting depth of comprehensions."""
        depth = 0
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                depth = max(depth, 1 + self._comprehension_depth(child))

        # Also count number of 'for' clauses in this comprehension
        if hasattr(node, "generators"):
            for_count = len(node.generators)
            if_count = sum(len(g.ifs) for g in node.generators)
            depth = max(depth, for_count + if_count - 1)

        return depth

    def _ternary_depth(self, node: ast.IfExp) -> int:
        """Count nesting depth of ternary expressions."""
        depth = 1
        for child in (node.body, node.orelse):
            if isinstance(child, ast.IfExp):
                depth = max(depth, 1 + self._ternary_depth(child))
        return depth

    def _node_depth(self, node: ast.AST) -> int:
        """Calculate the maximum nesting depth of an AST node."""
        max_child_depth = 0
        for child in ast.iter_child_nodes(node):
            child_depth = self._node_depth(child)
            max_child_depth = max(max_child_depth, child_depth)
        return 1 + max_child_depth
