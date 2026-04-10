"""Configuration loading for AIGuard."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class RuleConfig:
    """Configuration for a single rule."""

    enabled: bool = True
    severity: str | None = None
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    """AIGuard configuration."""

    rules: dict[str, RuleConfig] = field(default_factory=dict)
    ignore_patterns: list[str] = field(default_factory=list)
    score_fail_threshold: int = 60
    score_weights: dict[str, int] = field(default_factory=dict)

    @classmethod
    def default(cls) -> Config:
        """Create a default configuration with all rules enabled."""
        return cls(
            rules={},
            ignore_patterns=[
                "**/__pycache__/**",
                "**/node_modules/**",
                "**/.venv/**",
                "**/venv/**",
                "**/.git/**",
                "**/dist/**",
                "**/build/**",
                "**/*.min.js",
                "**/*.min.css",
            ],
            score_fail_threshold=60,
            score_weights={"error": 10, "warning": 3, "info": 1},
        )

    @classmethod
    def load(cls, path: str | None = None) -> Config:
        """Load configuration from a .aiguard.yml file.

        If no path is given, searches upward from cwd for .aiguard.yml.
        Falls back to default config if no file found.
        """
        config_path = cls._find_config(path)
        if config_path is None:
            return cls.default()

        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}

        return cls._parse(raw)

    @classmethod
    def _find_config(cls, path: str | None = None) -> Path | None:
        """Find the configuration file."""
        if path:
            p = Path(path)
            if p.exists():
                return p
            return None

        current = Path.cwd()
        for directory in [current, *current.parents]:
            candidate = directory / ".aiguard.yml"
            if candidate.exists():
                return candidate
            candidate = directory / ".aiguard.yaml"
            if candidate.exists():
                return candidate

        return None

    @classmethod
    def _parse(cls, raw: dict) -> Config:
        """Parse raw YAML dict into Config."""
        config = cls.default()

        # Parse rules
        if "rules" in raw:
            for rule_id, rule_raw in raw["rules"].items():
                if isinstance(rule_raw, dict):
                    enabled = rule_raw.pop("enabled", True)
                    severity = rule_raw.pop("severity", None)
                    config.rules[rule_id] = RuleConfig(
                        enabled=enabled,
                        severity=severity,
                        options=rule_raw,
                    )
                elif isinstance(rule_raw, bool):
                    config.rules[rule_id] = RuleConfig(enabled=rule_raw)

        # Parse ignore patterns
        if "ignore" in raw:
            config.ignore_patterns.extend(raw["ignore"])

        # Parse score settings
        if "score" in raw:
            score_raw = raw["score"]
            if "fail_threshold" in score_raw:
                config.score_fail_threshold = int(score_raw["fail_threshold"])
            if "weights" in score_raw:
                config.score_weights.update(score_raw["weights"])

        return config

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled."""
        if rule_id in self.rules:
            return self.rules[rule_id].enabled
        return True  # Enabled by default

    def get_rule_severity(self, rule_id: str) -> str | None:
        """Get severity override for a rule."""
        if rule_id in self.rules:
            return self.rules[rule_id].severity
        return None

    def get_rule_options(self, rule_id: str) -> dict[str, Any]:
        """Get custom options for a rule."""
        if rule_id in self.rules:
            return self.rules[rule_id].options
        return {}

    def generate_default_yaml(self) -> str:
        """Generate a default .aiguard.yml content."""
        return """# AIGuard Configuration
# Documentation: https://github.com/GurjotSinghAulakh/aiguard

# Rules configuration
# Each rule can be enabled/disabled and configured individually
rules:
  AIG001:  # Shallow error handling
    enabled: true
    severity: warning
  AIG002:  # Tautological code
    enabled: true
  AIG003:  # Over-commenting
    enabled: true
    max_comment_ratio: 0.6
  AIG004:  # Hallucinated imports
    enabled: true
    severity: error
  AIG005:  # Copy-paste duplication
    enabled: true
    similarity_threshold: 0.85
  AIG006:  # Missing input validation
    enabled: true
  AIG007:  # Placeholder code
    enabled: true
  AIG008:  # Complex one-liners
    enabled: true
    max_depth: 4
  AIG009:  # Unused variables
    enabled: true
  AIG010:  # Generic naming
    enabled: true
  AIG011:  # Prompt injection
    enabled: true
    severity: error
  AIG012:  # Hidden content
    enabled: true
    severity: error
  AIG013:  # Data exfiltration
    enabled: true
    severity: error
  AIG014:  # Dangerous commands
    enabled: true
    severity: error
  AIG015:  # Hardcoded secrets
    enabled: true
    severity: error
  AIG016:  # Insecure defaults
    enabled: true
    severity: error
  AIG017:  # SQL injection
    enabled: true
    severity: error
  AIG018:  # Async anti-patterns
    enabled: true
    severity: warning

# File patterns to ignore (glob syntax)
ignore:
  - "tests/**"
  - "migrations/**"
  - "**/vendor/**"

# Scoring configuration
score:
  fail_threshold: 60   # CI exits non-zero if score < this
  weights:
    error: 10
    warning: 3
    info: 1
"""
