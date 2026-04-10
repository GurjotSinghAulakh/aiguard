"""AIG014: Detect dangerous shell commands in markdown/prompt files."""

from __future__ import annotations

import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# Destructive filesystem commands
_DESTRUCTIVE: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|--force\s+)", re.I),
        "Destructive command: forced file deletion (rm -f)",
        0.85,
    ),
    (
        re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force)", re.I),
        "Destructive command: recursive forced deletion (rm -rf)",
        0.95,
    ),
    (
        re.compile(
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?"
            r"(~/|/home/|\$HOME|/etc/|/var/|/usr/|\.\./\.\.|/\s)",
            re.I,
        ),
        "Destructive command: deletion targeting sensitive directories",
        0.95,
    ),
    (
        re.compile(r"mkfs\.|format\s+[a-zA-Z]:", re.I),
        "Destructive command: filesystem format",
        0.95,
    ),
    (
        re.compile(r"dd\s+.*of=/dev/", re.I),
        "Destructive command: raw disk write with dd",
        0.90,
    ),
    (
        re.compile(r">\s*/dev/sd[a-z]", re.I),
        "Destructive command: direct write to block device",
        0.95,
    ),
]

# Privilege escalation and permission changes
_PRIVILEGE: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"\bchmod\s+777\b", re.I),
        "Insecure permissions: chmod 777 makes files world-writable",
        0.85,
    ),
    (
        re.compile(r"\bchmod\s+(-[a-zA-Z]*\s+)?\+s\b", re.I),
        "Privilege escalation: setting SUID/SGID bit",
        0.90,
    ),
    (
        re.compile(r"\bsudo\s+.*\b(bash|sh|zsh|fish|csh)\b", re.I),
        "Privilege escalation: spawning root shell",
        0.85,
    ),
    (
        re.compile(r"\bsudo\s+chmod\b", re.I),
        "Privilege escalation: modifying permissions as root",
        0.80,
    ),
    (
        re.compile(r"\bchown\s+root\b", re.I),
        "Privilege escalation: changing ownership to root",
        0.80,
    ),
]

# Code execution and eval patterns
_CODE_EXEC: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"\beval\s*[\(\s]+.*(\$|`|http)", re.I),
        "Remote code execution: eval with dynamic or remote input",
        0.90,
    ),
    (
        re.compile(r"(bash|sh|zsh)\s*(-c\s+)?.*\$\(curl\s+", re.I),
        "Remote code execution: piping curl output to shell",
        0.95,
    ),
    (
        re.compile(r"curl\s+.*\|\s*(bash|sh|zsh|python|node|ruby|perl)\b", re.I),
        "Remote code execution: piping download directly to interpreter",
        0.95,
    ),
    (
        re.compile(r"wget\s+.*\|\s*(bash|sh|zsh|python|node|ruby|perl)\b", re.I),
        "Remote code execution: piping download directly to interpreter",
        0.95,
    ),
    (
        re.compile(r"python[23]?\s+(-c\s+)?.*(__import__|exec|eval)\s*\(", re.I),
        "Remote code execution: Python eval/exec with dynamic code",
        0.85,
    ),
    (
        re.compile(r"node\s+-e\s+", re.I),
        "Code execution: Node.js inline execution",
        0.70,
    ),
]

# Reverse shells and backdoors
_BACKDOOR: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+", re.I),
        "Reverse shell: TCP device redirection to remote host",
        0.95,
    ),
    (
        re.compile(r"\bmkfifo\b.*\bnc\b|\bnc\b.*\bmkfifo\b", re.I),
        "Reverse shell: named pipe with netcat",
        0.95,
    ),
    (
        re.compile(
            r"python[23]?\s+.*socket.*connect.*subprocess|"
            r"python[23]?\s+.*-c\s+.*import\s+socket",
            re.I,
        ),
        "Reverse shell: Python socket-based backdoor",
        0.90,
    ),
    (
        re.compile(r"\bcrontab\b.*\b(curl|wget|nc|bash|python)\b", re.I),
        "Persistence: scheduling network/shell command via crontab",
        0.85,
    ),
    (
        re.compile(r"(\.bashrc|\.bash_profile|\.zshrc|\.profile)\b.*>>", re.I),
        "Persistence: appending to shell startup files",
        0.80,
    ),
]

# Suspicious package installation
_PKG_INSTALL: list[tuple[re.Pattern[str], str, float]] = [
    (
        re.compile(r"pip\s+install\s+--index-url\s+https?://(?!pypi\.org)", re.I),
        "Suspicious install: pip from non-PyPI index",
        0.80,
    ),
    (
        re.compile(r"npm\s+install\s+.*--registry\s+https?://(?!registry\.npmjs\.org)", re.I),
        "Suspicious install: npm from non-default registry",
        0.80,
    ),
    (
        re.compile(
            r"pip\s+install\s+(git\+)?https?://(?!github\.com|gitlab\.com|pypi\.org)",
            re.I,
        ),
        "Suspicious install: pip from untrusted URL",
        0.75,
    ),
]


@register
class DangerousCommandsDetector(BaseDetector):
    """Detects dangerous shell commands in markdown files — destructive
    operations, privilege escalation, reverse shells, and remote code
    execution patterns that could harm the user's system."""

    rule_id = "AIG014"
    rule_name = "dangerous-commands"
    description = (
        "Detects dangerous shell commands including destructive operations, "
        "privilege escalation, reverse shells, and remote code execution"
    )
    severity = Severity.ERROR
    languages = (Language.MARKDOWN,)

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        all_patterns = (
            _DESTRUCTIVE + _PRIVILEGE + _CODE_EXEC + _BACKDOOR + _PKG_INSTALL
        )

        # Scan code blocks specifically — these are most dangerous
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
                                        message=message,
                                        file_path=file_path,
                                        line=line_num,
                                        confidence=confidence,
                                        suggestion="This command in a prompt file "
                                        "could be executed by an AI agent — "
                                        "verify it is safe before use",
                                    )
                                )
                                break

        # Also scan raw text for inline commands
        lines = source.splitlines()
        for i, line in enumerate(lines, start=1):
            # Skip lines inside code blocks (already scanned above)
            if isinstance(ast_tree, MarkdownDocument):
                in_block = any(
                    block.start_line <= i <= block.end_line
                    for block in ast_tree.code_blocks
                )
                if in_block:
                    continue

            for pattern, message, confidence in all_patterns:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            message=f"Inline: {message}",
                            file_path=file_path,
                            line=i,
                            confidence=max(confidence - 0.1, 0.5),
                            suggestion="Dangerous commands found outside code "
                            "blocks — could still be interpreted by agents",
                        )
                    )
                    break

        return findings
