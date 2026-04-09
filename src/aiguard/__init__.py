"""AIGuard - AI Code Quality Guard.

Detect common failure patterns in AI-generated code.
"""

__version__ = "0.1.0"

from aiguard.models import Finding, FileReport, ScanReport, Severity, Language
from aiguard.scanner import Scanner
from aiguard.config import Config

__all__ = [
    "Finding",
    "FileReport",
    "ScanReport",
    "Severity",
    "Language",
    "Scanner",
    "Config",
]
