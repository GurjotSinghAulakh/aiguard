"""Tests for configuration loading."""

import pytest
from pathlib import Path

from aiguard.config import Config, RuleConfig


class TestConfigDefault:
    def test_default_has_ignore_patterns(self):
        config = Config.default()
        assert len(config.ignore_patterns) > 0

    def test_default_has_score_weights(self):
        config = Config.default()
        assert "error" in config.score_weights
        assert "warning" in config.score_weights

    def test_all_rules_enabled_by_default(self):
        config = Config.default()
        assert config.is_rule_enabled("AIG001")
        assert config.is_rule_enabled("AIG999")  # Unknown rules also enabled


class TestConfigParse:
    def test_parse_rules(self):
        raw = {
            "rules": {
                "AIG001": {"enabled": False, "severity": "error"},
                "AIG002": True,
            }
        }
        config = Config._parse(raw)
        assert not config.is_rule_enabled("AIG001")
        assert config.get_rule_severity("AIG001") == "error"

    def test_parse_ignore(self):
        raw = {"ignore": ["tests/**", "docs/**"]}
        config = Config._parse(raw)
        assert "tests/**" in config.ignore_patterns

    def test_parse_score(self):
        raw = {"score": {"fail_threshold": 80}}
        config = Config._parse(raw)
        assert config.score_fail_threshold == 80


class TestConfigFile:
    def test_load_from_file(self, tmp_path):
        config_file = tmp_path / ".aiguard.yml"
        config_file.write_text("""
rules:
  AIG001:
    enabled: false
score:
  fail_threshold: 90
""")
        config = Config.load(str(config_file))
        assert not config.is_rule_enabled("AIG001")
        assert config.score_fail_threshold == 90

    def test_load_nonexistent_returns_default(self):
        config = Config.load("/nonexistent/.aiguard.yml")
        assert config.score_fail_threshold == 60  # Default

    def test_generate_default_yaml(self):
        config = Config.default()
        yaml_str = config.generate_default_yaml()
        assert "AIG001" in yaml_str
        assert "fail_threshold" in yaml_str
