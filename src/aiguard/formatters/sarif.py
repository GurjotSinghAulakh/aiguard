"""SARIF 2.1.0 formatter for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from pathlib import Path

from aiguard.formatters.base import BaseFormatter
from aiguard.models import ScanReport, Severity

# SARIF severity mapping
_SARIF_LEVELS = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


class SarifFormatter(BaseFormatter):
    """Produces SARIF 2.1.0 JSON for GitHub Code Scanning.

    The output is directly consumable by:
        github/codeql-action/upload-sarif@v3
    """

    def format(self, report: ScanReport) -> str:
        """Format report as SARIF 2.1.0 JSON.

        Args:
            report: The scan report.

        Returns:
            SARIF JSON string.
        """
        # Collect unique rules
        rules_map: dict[str, dict] = {}
        results: list[dict] = []

        for file_report in report.file_reports:
            for finding in file_report.findings:
                # Register rule
                if finding.rule_id not in rules_map:
                    rule_def: dict = {
                        "id": finding.rule_id,
                        "name": finding.rule_name,
                        "shortDescription": {"text": finding.rule_name},
                        "defaultConfiguration": {
                            "level": _SARIF_LEVELS.get(finding.severity, "warning")
                        },
                    }
                    if finding.suggestion:
                        rule_def["help"] = {
                            "text": finding.suggestion,
                            "markdown": finding.suggestion,
                        }
                    rules_map[finding.rule_id] = rule_def

                # Build result
                result: dict = {
                    "ruleId": finding.rule_id,
                    "level": _SARIF_LEVELS.get(finding.severity, "warning"),
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": self._to_uri(finding.file_path),
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": finding.line,
                                    "startColumn": finding.column + 1,  # SARIF is 1-based
                                },
                            }
                        }
                    ],
                    "properties": {
                        "confidence": finding.confidence,
                    },
                }

                if finding.end_line:
                    result["locations"][0]["physicalLocation"]["region"][
                        "endLine"
                    ] = finding.end_line

                if finding.suggestion:
                    result["fixes"] = [
                        {
                            "description": {"text": finding.suggestion},
                        }
                    ]

                results.append(result)

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AIGuard",
                            "informationUri": "https://github.com/aiguard/aiguard",
                            "version": "0.1.0",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "toolExecutionNotifications": [],
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _to_uri(self, file_path: str) -> str:
        """Convert a file path to a relative URI."""
        try:
            rel = Path(file_path).relative_to(Path.cwd())
            return str(rel).replace("\\", "/")
        except ValueError:
            return file_path.replace("\\", "/")
