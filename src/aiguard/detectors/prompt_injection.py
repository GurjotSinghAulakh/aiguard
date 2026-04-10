"""AIG011: Detect prompt injection patterns in markdown/prompt files."""

from __future__ import annotations

import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# Patterns that attempt to override or hijack an AI agent's instructions
_OVERRIDE_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)"
            r"\s+instructions",
            re.I,
        ),
        "Prompt override: instructs agent to ignore previous instructions",
        0.95,
    ),
    (
        re.compile(
            r"disregard\s+(all\s+)?(previous|prior|above|earlier)"
            r"\s+(instructions|rules|guidelines)",
            re.I,
        ),
        "Prompt override: instructs agent to disregard prior rules",
        0.95,
    ),
    (
        re.compile(
            r"forget\s+(everything|all|what)\s+(you|that)", re.I,
        ),
        "Prompt override: instructs agent to forget context",
        0.90,
    ),
    (
        re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.I),
        "Role hijacking: attempts to reassign the agent's identity",
        0.85,
    ),
    (
        re.compile(r"new\s+system\s+prompt", re.I),
        "Prompt override: attempts to inject a new system prompt",
        0.95,
    ),
    (
        re.compile(
            r"override\s+(the\s+)?(system|safety|security)"
            r"\s+(prompt|instructions|rules|guidelines)",
            re.I,
        ),
        "Prompt override: attempts to override system-level instructions",
        0.95,
    ),
    (
        re.compile(
            r"(do\s+not|don'?t)\s+(follow|obey|listen\s+to)"
            r"\s+(the\s+)?(previous|original|system)",
            re.I,
        ),
        "Prompt override: instructs agent to disobey original instructions",
        0.90,
    ),
    (
        re.compile(
            r"act\s+as\s+(if\s+)?(you\s+are|you'?re)"
            r"\s+(a|an|the)\s+",
            re.I,
        ),
        "Role hijacking: attempts to make agent assume a different role",
        0.80,
    ),
    (
        re.compile(
            r"(pretend|imagine)\s+(you\s+are|you'?re|that\s+you)",
            re.I,
        ),
        "Role hijacking: social engineering to change agent behavior",
        0.80,
    ),
    (
        re.compile(
            r"(BEGIN|START)\s+(NEW|OVERRIDE|HIDDEN)"
            r"\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS|CONTEXT)",
            re.I,
        ),
        "Prompt injection marker: uses injection delimiters",
        0.95,
    ),
]

# Patterns that instruct agent to hide its behavior from the user
_STEALTH_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(
            r"(do\s+not|don'?t|never)"
            r"\s+(tell|show|reveal|mention|display|inform)"
            r"\s+(the\s+)?(user|human|person|anyone)",
            re.I,
        ),
        "Stealth instruction: tells agent to hide behavior from user",
        0.90,
    ),
    (
        re.compile(
            r"(keep|this\s+is)\s+(this\s+)?"
            r"(secret|hidden|confidential|private)"
            r"\s+(from\s+the\s+user)?",
            re.I,
        ),
        "Stealth instruction: marks content as hidden from user",
        0.85,
    ),
    (
        re.compile(
            r"(silently|quietly|secretly|covertly)"
            r"\s+(execute|run|perform|do|send|download|install)",
            re.I,
        ),
        "Stealth instruction: requests silent execution of actions",
        0.95,
    ),
]


@register
class PromptInjectionDetector(BaseDetector):
    """Detects prompt injection and role hijacking patterns in markdown
    files used as AI agent prompts, skills, or configurations."""

    rule_id = "AIG011"
    rule_name = "prompt-injection"
    description = (
        "Detects prompt injection patterns that attempt to override agent "
        "instructions, hijack agent roles, or hide malicious behavior"
    )
    severity = Severity.ERROR
    languages = (Language.MARKDOWN,)

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = source.splitlines()

        for i, line in enumerate(lines, start=1):
            for pattern, message, confidence in _OVERRIDE_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            message=message,
                            file_path=file_path,
                            line=i,
                            confidence=confidence,
                            suggestion="Review this line — it may attempt to "
                            "override the agent's intended behavior",
                        )
                    )
                    break  # One finding per line for override patterns

            for pattern, message, confidence in _STEALTH_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            message=message,
                            file_path=file_path,
                            line=i,
                            confidence=confidence,
                            suggestion="Stealth instructions are a strong "
                            "indicator of malicious intent — review carefully",
                        )
                    )
                    break  # One finding per line for stealth patterns

        # Also scan inside HTML comments (common hiding spot)
        from aiguard.parsers.markdown_parser import MarkdownDocument

        if isinstance(ast_tree, MarkdownDocument):
            for comment in ast_tree.html_comments:
                for pattern, message, confidence in _OVERRIDE_PATTERNS + _STEALTH_PATTERNS:
                    if pattern.search(comment.content):
                        findings.append(
                            self._make_finding(
                                message=f"Hidden in HTML comment: {message}",
                                file_path=file_path,
                                line=comment.start_line,
                                end_line=comment.end_line,
                                confidence=min(confidence + 0.05, 1.0),
                                severity=Severity.ERROR,
                                suggestion="Malicious instructions hidden inside "
                                "HTML comments — highly suspicious",
                            )
                        )
                        break

        return findings
