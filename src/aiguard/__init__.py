"""AIGuard - AI Code Quality Guard.

Detect common failure patterns in AI-generated code.
"""

__version__ = "0.3.0"

from aiguard.config import Config
from aiguard.models import FileReport, Finding, Language, ScanReport, Severity
from aiguard.scanner import Scanner

__all__ = [
    "Finding",
    "FileReport",
    "ScanReport",
    "Severity",
    "Language",
    "Scanner",
    "Config",
]
