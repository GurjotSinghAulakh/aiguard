"""Inline suppression support for AIGuard.

Supports the following comment patterns:
  Python:   # aiguard: ignore
            # aiguard: ignore AIG001
            # aiguard: ignore AIG001, AIG002
  Markdown: <!-- aiguard: ignore -->
            <!-- aiguard: ignore AIG011 -->
            <!-- aiguard: ignore AIG011, AIG012 -->

A suppression comment on a line silences findings on that line.
"""

from __future__ import annotations

import re

# Matches "aiguard: ignore" optionally followed by comma-separated rule IDs
_SUPPRESS_PATTERN = re.compile(
    r"aiguard:\s*ignore(?:\s+(AIG\d+(?:\s*,\s*AIG\d+)*))?",
    re.IGNORECASE,
)


def parse_suppressions(source: str) -> dict[int, set[str] | None]:
    """Parse inline suppression comments from source code.

    Returns:
        Dict mapping 1-based line numbers to either:
        - None  (suppress ALL rules on that line)
        - set of rule IDs to suppress (e.g. {"AIG001", "AIG002"})
    """
    suppressions: dict[int, set[str] | None] = {}

    for lineno, line in enumerate(source.splitlines(), start=1):
        match = _SUPPRESS_PATTERN.search(line)
        if match:
            rule_list = match.group(1)
            if rule_list:
                rule_ids = {
                    r.strip().upper()
                    for r in rule_list.split(",")
                }
                suppressions[lineno] = rule_ids
            else:
                # Bare "aiguard: ignore" — suppress everything
                suppressions[lineno] = None

    return suppressions


def is_suppressed(
    line: int,
    rule_id: str,
    suppressions: dict[int, set[str] | None],
) -> bool:
    """Check whether a finding at the given line is suppressed."""
    if line not in suppressions:
        return False

    suppressed_rules = suppressions[line]
    # None means suppress all rules
    if suppressed_rules is None:
        return True

    return rule_id.upper() in suppressed_rules
