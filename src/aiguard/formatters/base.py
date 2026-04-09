"""Base formatter interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aiguard.models import ScanReport


class BaseFormatter(ABC):
    """Abstract base class for output formatters."""

    @abstractmethod
    def format(self, report: ScanReport) -> str:
        """Format a scan report into a string.

        Args:
            report: The scan report to format.

        Returns:
            Formatted string output.
        """
        ...
