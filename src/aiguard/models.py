"""Core data models for AIGuard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Finding severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class Language(Enum):
    """Supported programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"


@dataclass(frozen=True)
class Finding:
    """A single code quality finding."""

    rule_id: str
    rule_name: str
    message: str
    file_path: str
    line: int
    end_line: Optional[int] = None
    column: int = 0
    severity: Severity = Severity.WARNING
    confidence: float = 1.0
    suggestion: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "message": self.message,
            "file_path": self.file_path,
            "line": self.line,
            "end_line": self.end_line,
            "column": self.column,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "suggestion": self.suggestion,
        }


@dataclass
class FileReport:
    """Report for a single file."""

    file_path: str
    language: Language
    findings: list[Finding] = field(default_factory=list)
    lines_scanned: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "language": self.language.value,
            "findings": [f.to_dict() for f in self.findings],
            "lines_scanned": self.lines_scanned,
        }


@dataclass
class ScanReport:
    """Complete scan report across all files."""

    file_reports: list[FileReport] = field(default_factory=list)
    score: int = 100
    files_scanned: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_rule: dict[str, int] = field(default_factory=dict)
    config_path: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "files_scanned": self.files_scanned,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_rule": self.findings_by_rule,
            "file_reports": [fr.to_dict() for fr in self.file_reports if fr.has_findings],
        }
