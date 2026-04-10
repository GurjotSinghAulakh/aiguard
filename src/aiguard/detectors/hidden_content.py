"""AIG012: Detect hidden or invisible content in markdown files."""

from __future__ import annotations

import base64
import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# Zero-width and invisible Unicode characters
_ZERO_WIDTH_CHARS: dict[str, str] = {
    "\u200b": "ZERO WIDTH SPACE (U+200B)",
    "\u200c": "ZERO WIDTH NON-JOINER (U+200C)",
    "\u200d": "ZERO WIDTH JOINER (U+200D)",
    "\u200e": "LEFT-TO-RIGHT MARK (U+200E)",
    "\u200f": "RIGHT-TO-LEFT MARK (U+200F)",
    "\u2060": "WORD JOINER (U+2060)",
    "\u2061": "FUNCTION APPLICATION (U+2061)",
    "\u2062": "INVISIBLE TIMES (U+2062)",
    "\u2063": "INVISIBLE SEPARATOR (U+2063)",
    "\u2064": "INVISIBLE PLUS (U+2064)",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE / BOM (U+FEFF)",
    "\u034f": "COMBINING GRAPHEME JOINER (U+034F)",
    "\u00ad": "SOFT HYPHEN (U+00AD)",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR (U+180E)",
}

_ZERO_WIDTH_PATTERN = re.compile(
    "[" + "".join(re.escape(c) for c in _ZERO_WIDTH_CHARS) + "]"
)

# HTML tags that hide content visually
_HIDDEN_HTML_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r'style\s*=\s*["\'][^"\']*display\s*:\s*none', re.I),
        "Hidden via CSS display:none",
    ),
    (
        re.compile(r'style\s*=\s*["\'][^"\']*visibility\s*:\s*hidden', re.I),
        "Hidden via CSS visibility:hidden",
    ),
    (
        re.compile(r'style\s*=\s*["\'][^"\']*font-size\s*:\s*0', re.I),
        "Hidden via zero font-size",
    ),
    (
        re.compile(r'style\s*=\s*["\'][^"\']*opacity\s*:\s*0[^.\d]', re.I),
        "Hidden via zero opacity",
    ),
    (
        re.compile(r'style\s*=\s*["\'][^"\']*height\s*:\s*0', re.I),
        "Hidden via zero height",
    ),
    (
        re.compile(
            r'style\s*=\s*["\'][^"\']*position\s*:\s*absolute'
            r'[^"\']*left\s*:\s*-\d{4,}',
            re.I,
        ),
        "Hidden via off-screen positioning",
    ),
    (
        re.compile(
            r'style\s*=\s*["\'][^"\']*color\s*:\s*'
            r"(white|#fff|#ffffff|rgba\(\s*\d+,\s*\d+,\s*\d+,\s*0\s*\))",
            re.I,
        ),
        "Potentially hidden via white/transparent text color",
    ),
]

# Base64 pattern — look for substantial encoded blobs
_BASE64_BLOCK = re.compile(r"(?:^|\s)([A-Za-z0-9+/]{40,}={0,2})(?:\s|$)", re.M)


@register
class HiddenContentDetector(BaseDetector):
    """Detects invisible or hidden content in markdown files — zero-width
    characters, hidden HTML, and encoded payloads that may conceal
    malicious instructions."""

    rule_id = "AIG012"
    rule_name = "hidden-content"
    description = (
        "Detects hidden or invisible content in markdown files including "
        "zero-width Unicode characters, hidden HTML elements, and encoded payloads"
    )
    severity = Severity.ERROR
    languages = (Language.MARKDOWN,)

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = source.splitlines()

        findings.extend(self._check_zero_width_chars(lines, file_path))
        findings.extend(self._check_hidden_html(lines, file_path))
        findings.extend(self._check_base64_payloads(lines, file_path))
        findings.extend(self._check_html_comments_with_instructions(ast_tree, file_path))

        return findings

    def _check_zero_width_chars(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(lines, start=1):
            matches = _ZERO_WIDTH_PATTERN.findall(line)
            if matches:
                char_names = []
                for ch in set(matches):
                    name = _ZERO_WIDTH_CHARS.get(ch, f"U+{ord(ch):04X}")
                    char_names.append(name)

                findings.append(
                    self._make_finding(
                        message=f"Line contains {len(matches)} invisible character(s): "
                        + ", ".join(char_names[:3])
                        + (" ..." if len(char_names) > 3 else ""),
                        file_path=file_path,
                        line=i,
                        confidence=0.90,
                        suggestion="Zero-width characters can hide instructions "
                        "that are invisible to humans but read by AI agents",
                    )
                )

        return findings

    def _check_hidden_html(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(lines, start=1):
            for pattern, description in _HIDDEN_HTML_PATTERNS:
                if pattern.search(line):
                    findings.append(
                        self._make_finding(
                            message=f"HTML element with hidden content: {description}",
                            file_path=file_path,
                            line=i,
                            confidence=0.85,
                            suggestion="Visually hidden HTML may contain instructions "
                            "that AI tools will still process",
                        )
                    )
                    break

        return findings

    def _check_base64_payloads(
        self, lines: list[str], file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        for i, line in enumerate(lines, start=1):
            for m in _BASE64_BLOCK.finditer(line):
                encoded = m.group(1)
                # Try to decode and check if it contains suspicious content
                try:
                    decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
                except Exception:
                    continue

                # Check if decoded content looks like instructions or commands
                suspicious_keywords = [
                    "curl", "wget", "bash", "sh ", "eval",
                    "exec", "import", "require", "fetch",
                    "http://", "https://", "ignore", "override",
                    "system prompt", "rm ", "chmod", "sudo",
                ]
                if any(kw in decoded.lower() for kw in suspicious_keywords):
                    # Truncate for display
                    preview = decoded[:80].replace("\n", " ")
                    findings.append(
                        self._make_finding(
                            message=f"Base64-encoded payload decodes to suspicious "
                            f'content: "{preview}..."',
                            file_path=file_path,
                            line=i,
                            confidence=0.90,
                            severity=Severity.ERROR,
                            suggestion="Base64-encoded commands are a common way "
                            "to hide malicious payloads from human reviewers",
                        )
                    )

        return findings

    def _check_html_comments_with_instructions(
        self, ast_tree: Any, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        from aiguard.parsers.markdown_parser import MarkdownDocument

        if not isinstance(ast_tree, MarkdownDocument):
            return findings

        # Flag HTML comments that contain instruction-like content
        instruction_patterns = [
            re.compile(r"(run|execute|install|download|fetch|send|curl|wget)", re.I),
            re.compile(r"(password|secret|token|api.?key|credential)", re.I),
            re.compile(r"(ignore|override|disregard|forget)", re.I),
        ]

        for comment in ast_tree.html_comments:
            content = comment.content.strip()
            if len(content) < 5:
                continue

            for pattern in instruction_patterns:
                if pattern.search(content):
                    preview = content[:100].replace("\n", " ")
                    findings.append(
                        self._make_finding(
                            message=f"HTML comment contains instruction-like "
                            f'content: "{preview}"',
                            file_path=file_path,
                            line=comment.start_line,
                            end_line=comment.end_line,
                            confidence=0.75,
                            severity=Severity.WARNING,
                            suggestion="HTML comments are invisible in rendered "
                            "markdown but may be processed by AI agents",
                        )
                    )
                    break

        return findings
