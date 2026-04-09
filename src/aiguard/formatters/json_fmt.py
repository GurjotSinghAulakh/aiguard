"""JSON formatter for AIGuard."""

from __future__ import annotations

import json

from aiguard.formatters.base import BaseFormatter
from aiguard.models import ScanReport


class JsonFormatter(BaseFormatter):
    """Outputs scan results as structured JSON."""

    def format(self, report: ScanReport) -> str:
        """Format report as JSON.

        Args:
            report: The scan report.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
