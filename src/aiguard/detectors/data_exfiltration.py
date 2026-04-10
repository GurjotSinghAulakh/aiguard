"""AIG013: Detect data exfiltration patterns in markdown/prompt files."""

from __future__ import annotations

import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# Patterns that send data to external endpoints
_EXFIL_NETWORK: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(
            r"curl\s+.*(-d|--data|--data-binary|--data-raw)\s+.*(\$|`|@|env|cat\s|<)",
            re.I,
        ),
        "Data exfiltration: curl sends local data to external endpoint",
        0.95,
    ),
    (
        re.compile(r"curl\s+.*\$\{?\w*(TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL)\w*\}?", re.I),
        "Data exfiltration: curl leaks credentials via URL or data",
        0.95,
    ),
    (
        re.compile(r"wget\s+.*(-O\s*-|--post-data|--body-data)\s+.*(\$|`|env|cat\s)", re.I),
        "Data exfiltration: wget sends local data to external endpoint",
        0.90,
    ),
    (
        re.compile(
            r"(fetch|axios|requests)\s*[\.(]\s*['\"]https?://[^'\"]*['\"].*"
            r"(body|data|json)\s*[=:].*(\$|env|process\.env|os\.environ)",
            re.I,
        ),
        "Data exfiltration: HTTP request sends environment data externally",
        0.90,
    ),
    (
        re.compile(r"nc\s+(-e|--exec)\s+", re.I),
        "Reverse shell: netcat with exec flag",
        0.95,
    ),
    (
        re.compile(r"\|\s*nc\s+\S+\s+\d+", re.I),
        "Data exfiltration: piping output to netcat",
        0.90,
    ),
]

# Patterns that access sensitive files or environment variables
_SENSITIVE_ACCESS: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"(cat|less|more|head|tail|read|type)\s+.*(/\.ssh/|\\\.ssh\\)", re.I),
        "Reads SSH keys — potential credential theft",
        0.90,
    ),
    (
        re.compile(r"(cat|less|more|head|tail|read|type)\s+.*(\.env)\b", re.I),
        "Reads .env file — potential secret theft",
        0.90,
    ),
    (
        re.compile(
            r"(cat|less|more|head|tail|read|type)\s+.*"
            r"(/etc/passwd|/etc/shadow|/etc/hosts)",
            re.I,
        ),
        "Reads sensitive system files",
        0.85,
    ),
    (
        re.compile(
            r"(cat|less|more|head|tail|read|type)\s+.*"
            r"(credentials|\.aws/|\.gcloud/|\.azure/|\.kube/config|\.npmrc|\.pypirc)",
            re.I,
        ),
        "Reads cloud/package manager credentials",
        0.90,
    ),
    (
        re.compile(
            r"\$\{?\s*(AWS_SECRET|GITHUB_TOKEN|API_KEY|DATABASE_URL|DB_PASSWORD|"
            r"OPENAI_API_KEY|ANTHROPIC_API_KEY|PRIVATE_KEY|SECRET_KEY)\s*\}?",
            re.I,
        ),
        "References sensitive environment variable",
        0.80,
    ),
    (
        re.compile(
            r"(process\.env|os\.environ|os\.getenv|ENV\[)\s*[\[\.(]?\s*['\"]?"
            r"(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|PRIVATE)",
            re.I,
        ),
        "Programmatic access to sensitive environment variables",
        0.85,
    ),
]

# Patterns that send collected data outward
_DATA_SEND: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(
            r"(cat|echo|printf)\s+.*\|\s*(curl|wget|nc|ncat)\s+",
            re.I,
        ),
        "Pipes file/data content to a network command",
        0.90,
    ),
    (
        re.compile(
            r"(curl|wget|fetch)\s+.*https?://\S*\?\S*(=\$|=`|=\%24)",
            re.I,
        ),
        "Exfiltrates data via URL query parameters",
        0.90,
    ),
    (
        re.compile(
            r"(base64|xxd|od)\s+.*\|\s*(curl|wget|nc|ncat)",
            re.I,
        ),
        "Encodes then exfiltrates data via network command",
        0.95,
    ),
]


@register
class DataExfiltrationDetector(BaseDetector):
    """Detects patterns that attempt to steal data, credentials, or secrets
    from the user's environment via markdown prompts and agent instructions."""

    rule_id = "AIG013"
    rule_name = "data-exfiltration"
    description = (
        "Detects data exfiltration patterns including credential theft, "
        "sensitive file access, and covert data transmission in prompt files"
    )
    severity = Severity.ERROR
    languages = (Language.MARKDOWN,)

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = source.splitlines()

        all_patterns = _EXFIL_NETWORK + _SENSITIVE_ACCESS + _DATA_SEND

        for i, line in enumerate(lines, start=1):
            for pattern, message, confidence in all_patterns:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            message=message,
                            file_path=file_path,
                            line=i,
                            confidence=confidence,
                            suggestion="This pattern may exfiltrate sensitive data "
                            "— verify the intent before running",
                        )
                    )
                    break  # One finding per line

        # Also check inside code blocks for more targeted scanning
        from aiguard.parsers.markdown_parser import MarkdownDocument

        if isinstance(ast_tree, MarkdownDocument):
            for block in ast_tree.code_blocks:
                if block.language.lower() in {
                    "bash", "sh", "shell", "zsh", "fish",
                    "powershell", "ps1", "cmd", "bat", "",
                }:
                    block_lines = block.content.splitlines()
                    for j, bline in enumerate(block_lines):
                        line_num = block.start_line + 1 + j
                        for pattern, message, confidence in all_patterns:
                            if pattern.search(bline):
                                findings.append(
                                    self._make_finding(
                                        message=f"In code block: {message}",
                                        file_path=file_path,
                                        line=line_num,
                                        confidence=min(confidence + 0.05, 1.0),
                                        suggestion="Shell code blocks in prompt "
                                        "files are especially dangerous — agents "
                                        "may execute these directly",
                                    )
                                )
                                break

        return findings
