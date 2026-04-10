"""Scanner orchestrator — the core pipeline of AIGuard."""

from __future__ import annotations

import logging
from pathlib import Path

import pathspec

import aiguard.parsers.markdown_parser  # noqa: F401 — triggers parser registration
import aiguard.parsers.python_parser  # noqa: F401 — triggers parser registration
from aiguard.config import Config
from aiguard.detectors import get_all_detectors, load_builtin_detectors
from aiguard.detectors.base import BaseDetector
from aiguard.fixers import get_fixer
from aiguard.models import FileReport, Finding, ScanReport, Severity
from aiguard.parsers import get_language_for_file, get_parser
from aiguard.plugins.loader import load_plugins
from aiguard.scoring import compute_score, severity_counts
from aiguard.suppression import is_suppressed, parse_suppressions

logger = logging.getLogger("aiguard")


class Scanner:
    """Orchestrates file walking, parsing, detection, and scoring.

    Usage:
        config = Config.load()
        scanner = Scanner(config)
        report = scanner.scan("./src")
    """

    def __init__(self, config: Config | None = None):
        self.config = config or Config.default()

        # Load all detectors
        load_builtin_detectors()
        load_plugins()

        # Instantiate enabled detectors
        self.detectors: list[BaseDetector] = []
        for rule_id, detector_cls in get_all_detectors().items():
            if self.config.is_rule_enabled(rule_id):
                options = self.config.get_rule_options(rule_id)
                instance = detector_cls(config=options)

                # Apply severity override from config
                severity_override = self.config.get_rule_severity(rule_id)
                if severity_override:
                    try:
                        instance.severity = Severity(severity_override)
                    except ValueError:
                        pass

                self.detectors.append(instance)

        # Build ignore spec
        self._ignore_spec = pathspec.PathSpec.from_lines(
            "gitignore", self.config.ignore_patterns
        )

    def scan(
        self,
        target: str,
        diff_target: str | None = None,
        diff_staged: bool = False,
        fix: bool = False,
    ) -> ScanReport:
        """Scan a file or directory and return a full report.

        Args:
            target: Path to a file or directory to scan.
            diff_target: If set, only report findings in lines changed
                since this git ref (e.g. "HEAD", "main", "HEAD~3").
            diff_staged: If True, only scan staged changes (for pre-commit).

        Returns:
            ScanReport with findings, scores, and breakdowns.
        """
        # If diff mode, get changed regions first
        changed_regions = None
        if diff_target or diff_staged:
            from aiguard.diff import get_changed_files_and_lines, get_staged_files

            if diff_staged:
                changed_regions = get_staged_files()
            else:
                changed_regions = get_changed_files_and_lines(
                    diff_target=diff_target or "HEAD"
                )

            if not changed_regions:
                logger.info("No changed files found in diff.")
                return ScanReport()

        target_path = Path(target).resolve()

        if target_path.is_file():
            files = [target_path]
        elif target_path.is_dir():
            files = self._collect_files(target_path)
        else:
            logger.warning(f"Target not found: {target}")
            return ScanReport()

        # In diff mode, only scan files that changed
        if changed_regions is not None:
            changed_file_set = set(changed_regions.keys())
            files = [f for f in files if str(f.resolve()) in changed_file_set]

        file_reports: list[FileReport] = []
        all_findings: list[Finding] = []
        total_lines = 0

        for file_path in files:
            report = self._scan_file(file_path, fix=fix)
            if report:
                # In diff mode, filter findings to only changed lines
                if changed_regions is not None:
                    from aiguard.diff import filter_findings_to_diff

                    report.findings = filter_findings_to_diff(
                        report.findings, changed_regions
                    )

                file_reports.append(report)
                all_findings.extend(report.findings)
                total_lines += report.lines_scanned

        # Compute score
        score = compute_score(
            findings=all_findings,
            files_scanned=len(file_reports),
            total_lines=total_lines,
            weights=self.config.score_weights,
        )

        # Build summary
        findings_by_rule: dict[str, int] = {}
        for f in all_findings:
            findings_by_rule[f.rule_id] = findings_by_rule.get(f.rule_id, 0) + 1

        return ScanReport(
            file_reports=file_reports,
            score=score,
            files_scanned=len(file_reports),
            total_findings=len(all_findings),
            findings_by_severity=severity_counts(all_findings),
            findings_by_rule=findings_by_rule,
        )

    def _collect_files(self, directory: Path) -> list[Path]:
        """Walk a directory and collect scannable files."""
        files = []

        # Also respect .gitignore if it exists
        gitignore_path = directory / ".gitignore"
        gitignore_spec = None
        if gitignore_path.exists():
            with open(gitignore_path) as f:
                gitignore_spec = pathspec.PathSpec.from_lines(
                    "gitignore", f.readlines()
                )

        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue

            rel_path = str(path.relative_to(directory))

            # Check ignore patterns
            if self._ignore_spec.match_file(rel_path):
                continue
            if gitignore_spec and gitignore_spec.match_file(rel_path):
                continue

            # Check if we have a parser for this file type
            lang = get_language_for_file(str(path))
            if lang is not None:
                files.append(path)

        return files

    def _scan_file(self, file_path: Path, fix: bool = False) -> FileReport | None:
        """Scan a single file with all applicable detectors."""
        language = get_language_for_file(str(file_path))
        if language is None:
            return None

        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning(f"Could not read {file_path}: {e}")
            return None

        if not source.strip():
            return None

        # Parse the source
        try:
            parser = get_parser(language)
            ast_tree = parser.parse(source, str(file_path))
        except Exception as e:
            logger.warning(f"Parse error in {file_path}: {e}")
            return None

        # Parse inline suppression comments
        suppressions = parse_suppressions(source)

        # Run applicable detectors
        findings: list[Finding] = []
        for detector in self.detectors:
            if language not in detector.languages:
                continue
            try:
                detector_findings = detector.detect(source, ast_tree, str(file_path))
                findings.extend(detector_findings)
            except Exception as e:
                logger.warning(
                    f"Detector {detector.rule_id} failed on {file_path}: {e}"
                )

        # Filter out suppressed findings
        if suppressions:
            findings = [
                f for f in findings
                if not is_suppressed(f.line, f.rule_id, suppressions)
            ]

        # Auto-fix mode: apply fixes and remove fixed findings
        if fix:
            fixed_findings, source = self._apply_fixes(
                findings, source, file_path
            )
            if fixed_findings:
                # Write the fixed source back to disk
                try:
                    file_path.write_text(source, encoding="utf-8")
                    logger.info(
                        f"Fixed {len(fixed_findings)} issue(s) in {file_path}"
                    )
                except OSError as e:
                    logger.warning(f"Could not write fixes to {file_path}: {e}")
                # Remove fixed findings from report
                fixed_set = set(id(f) for f in fixed_findings)
                findings = [f for f in findings if id(f) not in fixed_set]

        return FileReport(
            file_path=str(file_path),
            language=language,
            findings=sorted(findings, key=lambda f: f.line),
            lines_scanned=len(source.splitlines()),
        )

    def _apply_fixes(
        self,
        findings: list[Finding],
        source: str,
        file_path: Path,
    ) -> tuple[list[Finding], str]:
        """Apply auto-fixes for findings that have registered fixers.

        Applies fixes from bottom to top (highest line first) so that
        line numbers remain stable as we modify the source.

        Returns:
            Tuple of (fixed_findings, modified_source).
        """
        # Sort findings by line descending so fixes don't shift line numbers
        fixable = []
        for f in sorted(findings, key=lambda f: f.line, reverse=True):
            fixer = get_fixer(f.rule_id)
            if fixer is not None:
                fixable.append((f, fixer))

        fixed: list[Finding] = []
        for finding, fixer in fixable:
            try:
                new_source = fixer(source, finding.line)
                if new_source != source:
                    source = new_source
                    fixed.append(finding)
            except Exception as e:
                logger.warning(
                    f"Fixer for {finding.rule_id} failed on "
                    f"{file_path}:{finding.line}: {e}"
                )

        return fixed, source
