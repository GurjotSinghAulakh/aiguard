"""AIG005: Detect copy-paste duplication patterns."""

from __future__ import annotations

import ast
import difflib
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class CopyPasteDuplicationDetector(BaseDetector):
    """Detects near-identical code blocks — a hallmark of AI generation.

    AI models frequently produce multiple functions or code blocks that
    are almost identical with only minor variations, instead of abstracting
    the common pattern.
    """

    rule_id = "AIG005"
    rule_name = "copy-paste-duplication"
    description = "Detects near-identical code blocks suggesting copy-paste"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        threshold = self.config.get("similarity_threshold", 0.85)
        min_lines = self.config.get("min_lines", 4)

        # Extract function bodies
        functions = self._extract_functions(ast_tree, source)

        # Compare all pairs
        seen_pairs: set[tuple[str, str]] = set()
        for i, (name_a, body_a, line_a) in enumerate(functions):
            for name_b, body_b, line_b in functions[i + 1 :]:
                pair_key = (name_a, name_b)
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                # Skip very short functions
                if len(body_a.splitlines()) < min_lines or len(body_b.splitlines()) < min_lines:
                    continue

                ratio = difflib.SequenceMatcher(
                    None, body_a, body_b
                ).ratio()

                if ratio >= threshold:
                    findings.append(
                        self._make_finding(
                            message=f"Functions '{name_a}' (line {line_a}) and "
                            f"'{name_b}' (line {line_b}) are {ratio:.0%} similar — "
                            "likely copy-pasted with minor changes",
                            file_path=file_path,
                            line=line_a,
                            end_line=line_b,
                            confidence=min(1.0, ratio),
                            suggestion="Extract the common logic into a shared function "
                            "and parameterize the differences.",
                        )
                    )

        return findings

    def _extract_functions(
        self, tree: ast.Module, source: str
    ) -> list[tuple[str, str, int]]:
        """Extract function bodies as (name, body_text, start_line) tuples."""
        lines = source.splitlines()
        functions = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not hasattr(node, "end_lineno") or node.end_lineno is None:
                    continue

                # Get the function body (excluding the def line and docstring)
                body_start = node.body[0].lineno if node.body else node.lineno + 1

                # Skip docstring if present
                if (
                    node.body
                    and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)
                ):
                    if len(node.body) > 1:
                        body_start = node.body[1].lineno
                    else:
                        continue  # Function is just a docstring

                body_text = "\n".join(lines[body_start - 1 : node.end_lineno])
                if body_text.strip():
                    functions.append((node.name, body_text, node.lineno))

        return functions
