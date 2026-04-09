"""Diff mode — only report findings in changed lines.

Supports:
  - git diff (staged, unstaged, branch comparison)
  - explicit file lists
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("aiguard")


@dataclass
class ChangedRegion:
    """A contiguous range of changed lines in a file."""

    start: int  # 1-based inclusive
    end: int  # 1-based inclusive


def get_changed_files_and_lines(
    diff_target: str = "HEAD",
    staged: bool = False,
    repo_root: str | None = None,
) -> dict[str, list[ChangedRegion]]:
    """Get files and line ranges that changed in a git diff.

    Args:
        diff_target: What to diff against. Examples:
            - "HEAD" (default) — uncommitted changes vs last commit
            - "main" — current branch vs main
            - "HEAD~3" — last 3 commits
        staged: If True, only show staged changes (--cached).
        repo_root: Root of the git repo. Auto-detected if None.

    Returns:
        Dict mapping file paths to list of changed line regions.
        Only includes files with Python/JS extensions.
    """
    cmd = ["git", "diff", "--unified=0", "--no-color"]

    if staged:
        cmd.append("--cached")

    cmd.append(diff_target)

    if repo_root:
        cmd = ["git", "-C", repo_root] + cmd[1:]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.warning(f"Git diff failed: {e}")
        return {}

    if result.returncode != 0:
        # Could be not a git repo or invalid ref
        logger.warning(f"Git diff returned {result.returncode}: {result.stderr.strip()}")
        return {}

    return _parse_unified_diff(result.stdout, repo_root)


def get_staged_files() -> dict[str, list[ChangedRegion]]:
    """Convenience: get only staged (pre-commit) changes."""
    return get_changed_files_and_lines(diff_target="HEAD", staged=True)


def _parse_unified_diff(
    diff_output: str, repo_root: str | None = None
) -> dict[str, list[ChangedRegion]]:
    """Parse unified diff output into file -> changed regions map.

    We only care about added/modified lines (+ lines), not removed lines.
    """
    result: dict[str, list[ChangedRegion]] = {}
    current_file: str | None = None

    root = Path(repo_root).resolve() if repo_root else Path.cwd().resolve()

    for line in diff_output.splitlines():
        # New file header: +++ b/path/to/file.py
        if line.startswith("+++ b/"):
            rel_path = line[6:]  # Strip '+++ b/'
            current_file = str(root / rel_path)

            # Only track supported file types
            ext = Path(rel_path).suffix.lower()
            if ext not in (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx"):
                current_file = None
                continue

            if current_file not in result:
                result[current_file] = []

        # Hunk header: @@ -old_start,old_count +new_start,new_count @@
        elif line.startswith("@@") and current_file:
            region = _parse_hunk_header(line)
            if region:
                result[current_file].append(region)

    return result


def _parse_hunk_header(line: str) -> ChangedRegion | None:
    """Parse a unified diff hunk header to extract new file line range.

    Format: @@ -old_start[,old_count] +new_start[,new_count] @@ [context]

    We only care about the +new_start,new_count part (added lines).
    """
    try:
        # Find the +start,count portion
        parts = line.split()
        new_range = None
        for part in parts:
            if part.startswith("+") and not part.startswith("+++"):
                new_range = part[1:]  # Strip the '+'
                break

        if not new_range:
            return None

        if "," in new_range:
            start_str, count_str = new_range.split(",", 1)
            start = int(start_str)
            count = int(count_str)
        else:
            start = int(new_range)
            count = 1

        if count == 0:
            return None  # Pure deletion, no new lines

        return ChangedRegion(start=start, end=start + count - 1)

    except (ValueError, IndexError):
        return None


def filter_findings_to_diff(
    findings: list,
    changed_regions: dict[str, list[ChangedRegion]],
) -> list:
    """Filter findings to only include those in changed regions.

    Args:
        findings: List of Finding objects.
        changed_regions: Output of get_changed_files_and_lines().

    Returns:
        Filtered list of findings that fall within changed lines.
    """
    filtered = []

    for finding in findings:
        file_path = finding.file_path
        if file_path not in changed_regions:
            continue

        regions = changed_regions[file_path]
        finding_line = finding.line

        for region in regions:
            if region.start <= finding_line <= region.end:
                filtered.append(finding)
                break

    return filtered
