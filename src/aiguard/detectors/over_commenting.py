"""AIG003: Detect over-commenting patterns typical of AI-generated code."""

from __future__ import annotations

import ast
import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class OverCommentingDetector(BaseDetector):
    """Detects excessive and obvious commenting patterns.

    AI models tend to comment every line with trivially obvious descriptions
    like '# Initialize the variable' for 'x = 0'.
    """

    rule_id = "AIG003"
    rule_name = "over-commenting"
    description = "Detects excessive and obvious comments typical of AI code"
    severity = Severity.INFO
    languages = (Language.PYTHON,)

    # Patterns that indicate obvious/redundant comments
    OBVIOUS_PATTERNS = [
        re.compile(r"#\s*(initialize|init|set|create|define|declare)\s+(the\s+)?\w+", re.I),
        re.compile(r"#\s*(import|importing)\s+(the\s+)?\w+", re.I),
        re.compile(r"#\s*return\s+(the\s+)?\w+", re.I),
        re.compile(r"#\s*(loop|iterate)\s+(through|over)\s+", re.I),
        re.compile(r"#\s*print\s+(the\s+)?\w+", re.I),
        re.compile(r"#\s*(check|see)\s+if\s+", re.I),
        re.compile(r"#\s*increment\s+", re.I),
        re.compile(r"#\s*decrement\s+", re.I),
        re.compile(r"#\s*add\s+\d+\s+to\s+", re.I),
        re.compile(r"#\s*open\s+(the\s+)?file", re.I),
        re.compile(r"#\s*close\s+(the\s+)?file", re.I),
        re.compile(r"#\s*call\s+(the\s+)?\w+\s*(function|method)?", re.I),
    ]

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        lines = source.splitlines()
        if not lines:
            return findings

        # Check comment-to-code ratio per function
        findings.extend(self._check_comment_ratio(source, ast_tree, file_path))

        # Check for obvious/redundant inline comments
        findings.extend(self._check_obvious_comments(lines, file_path))

        return findings

    def _check_comment_ratio(
        self, source: str, ast_tree: Any, file_path: str
    ) -> list[Finding]:
        findings = []
        max_ratio = self.config.get("max_comment_ratio", 0.6)

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not hasattr(node, "end_lineno") or node.end_lineno is None:
                    continue

                start = node.lineno
                end = node.end_lineno
                func_lines = source.splitlines()[start - 1 : end]

                comment_lines = 0
                code_lines = 0
                for line in func_lines:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if stripped.startswith("#"):
                        comment_lines += 1
                    else:
                        code_lines += 1

                total = comment_lines + code_lines
                if total >= 5 and code_lines > 0:
                    ratio = comment_lines / total
                    if ratio > max_ratio:
                        findings.append(
                            self._make_finding(
                                message=f"Function '{node.name}' has {comment_lines} comment "
                                f"lines out of {total} total lines "
                                f"({ratio:.0%} comment ratio)",
                                file_path=file_path,
                                line=start,
                                end_line=end,
                                confidence=0.8,
                                suggestion="Remove obvious comments that just restate the code. "
                                "Comments should explain 'why', not 'what'.",
                            )
                        )

        return findings

    def _check_obvious_comments(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        findings = []
        obvious_count = 0
        first_obvious_line = 0

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped.startswith("#"):
                continue

            for pattern in self.OBVIOUS_PATTERNS:
                if pattern.search(stripped):
                    obvious_count += 1
                    if first_obvious_line == 0:
                        first_obvious_line = i
                    break

        # Flag if there are multiple obvious comments
        if obvious_count >= 3:
            findings.append(
                self._make_finding(
                    message=f"Found {obvious_count} obvious/redundant comments "
                    "(e.g., '# Initialize the variable' for 'x = 0')",
                    file_path=file_path,
                    line=first_obvious_line,
                    confidence=0.75,
                    suggestion="Remove comments that merely restate what the code does. "
                    "Good comments explain WHY, not WHAT.",
                )
            )

        return findings
