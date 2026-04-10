"""AIG015: Detect hardcoded secrets in source code."""

from __future__ import annotations

import ast
import re
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# High-entropy pattern for hex/base64 strings (32+ chars)
_HIGH_ENTROPY_HEX = re.compile(r"[0-9a-fA-F]{32,}")
_HIGH_ENTROPY_B64 = re.compile(r"[A-Za-z0-9+/=]{40,}")

# Known API key prefixes
_API_KEY_PREFIXES = re.compile(
    r"(?:"
    r"sk-[a-zA-Z0-9]{20,}"        # OpenAI
    r"|sk_live_[a-zA-Z0-9]{20,}"  # Stripe
    r"|sk_test_[a-zA-Z0-9]{20,}"  # Stripe test
    r"|pk_live_[a-zA-Z0-9]{20,}"  # Stripe public
    r"|ghp_[a-zA-Z0-9]{36}"       # GitHub PAT
    r"|gho_[a-zA-Z0-9]{36}"       # GitHub OAuth
    r"|github_pat_[a-zA-Z0-9_]{30,}"  # GitHub fine-grained
    r"|glpat-[a-zA-Z0-9\-]{20,}"  # GitLab
    r"|AKIA[A-Z0-9]{16}"          # AWS Access Key
    r"|xoxb-[0-9a-zA-Z\-]{20,}"   # Slack bot
    r"|xoxp-[0-9a-zA-Z\-]{20,}"   # Slack user
    r"|AIza[a-zA-Z0-9_\\-]{35}"   # Google API
    r"|sq0[a-z]{3}-[a-zA-Z0-9\-_]{22,}"  # Square
    r"|eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}"  # JWT
    r")"
)

# Variable name patterns that suggest secrets
_SECRET_VAR_NAMES = re.compile(
    r"(?i)"
    r"(?:api[_-]?key|api[_-]?secret|api[_-]?token"
    r"|secret[_-]?key|private[_-]?key|auth[_-]?token"
    r"|access[_-]?token|access[_-]?key"
    r"|password|passwd|pwd"
    r"|client[_-]?secret|client[_-]?id"
    r"|database[_-]?url|db[_-]?password|db[_-]?pass"
    r"|encryption[_-]?key|signing[_-]?key"
    r"|bearer[_-]?token|refresh[_-]?token"
    r"|aws[_-]?secret|aws[_-]?key"
    r"|stripe[_-]?key|openai[_-]?key"
    r"|webhook[_-]?secret|jwt[_-]?secret)"
)

# Patterns that indicate it's NOT a hardcoded secret
_SAFE_PATTERNS = {
    "os.environ",
    "os.getenv",
    "environ.get",
    "environ[",
    "config.",
    "settings.",
    "getattr(",
    "os.environ.get",
    "vault.",
    "${",
    "{{",
    "<your",
    "your_",
    "xxx",
    "***",
    "...",
    "CHANGE_ME",
    "REPLACE_ME",
    "INSERT_",
    "placeholder",
    "example",
}


@register
class HardcodedSecretsDetector(BaseDetector):
    """Detects hardcoded API keys, tokens, passwords, and secrets.

    AI-generated code frequently includes placeholder or real credentials
    that should never be committed to version control.
    """

    rule_id = "AIG015"
    rule_name = "hardcoded-secrets"
    description = "Detects hardcoded API keys, passwords, and secrets"
    severity = Severity.ERROR
    languages = (Language.PYTHON,)

    def detect(
        self, source: str, ast_tree: Any, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Assign):
                findings.extend(
                    self._check_assignment(node, source, file_path)
                )
            elif isinstance(node, ast.Call):
                findings.extend(
                    self._check_function_call(node, source, file_path)
                )

        return findings

    def _check_assignment(
        self, node: ast.Assign, source: str, file_path: str
    ) -> list[Finding]:
        findings = []

        # Get variable name
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue

            var_name = target.id

            # Check if the value is a hardcoded string
            value = node.value
            if not (
                isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                continue

            secret_val = value.value

            # Path 1: variable name suggests a secret
            if _SECRET_VAR_NAMES.search(var_name):
                if self._is_real_secret(secret_val):
                    findings.append(
                        self._make_finding(
                            message=(
                                f"Hardcoded secret in '{var_name}' — "
                                f"credential should not be in source code"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.9,
                            suggestion=(
                                "Use environment variables: "
                                f"os.environ['{var_name.upper()}']"
                            ),
                        )
                    )

            # Path 2: value matches a known API key pattern
            elif _API_KEY_PREFIXES.search(secret_val):
                findings.append(
                    self._make_finding(
                        message=(
                            f"Known API key/token format detected in "
                            f"'{var_name}' — credential should not "
                            f"be in source code"
                        ),
                        file_path=file_path,
                        line=node.lineno,
                        confidence=0.95,
                        suggestion=(
                            "Use environment variables: "
                            f"os.environ['{var_name.upper()}']"
                        ),
                    )
                )

        return findings

    def _check_function_call(
        self, node: ast.Call, source: str, file_path: str
    ) -> list[Finding]:
        """Check for known API key patterns in function arguments."""
        findings = []

        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(
                arg.value, str
            ):
                if _API_KEY_PREFIXES.search(arg.value):
                    findings.append(
                        self._make_finding(
                            message=(
                                "API key or token passed as literal string — "
                                "use environment variables instead"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.95,
                            suggestion=(
                                "Store the key in an environment variable "
                                "and use os.environ['KEY_NAME']"
                            ),
                        )
                    )

        for kw in node.keywords:
            if isinstance(kw.value, ast.Constant) and isinstance(
                kw.value.value, str
            ):
                val = kw.value.value
                kw_name = kw.arg or ""
                if _SECRET_VAR_NAMES.search(kw_name) and self._is_real_secret(
                    val
                ):
                    findings.append(
                        self._make_finding(
                            message=(
                                f"Hardcoded secret in keyword '{kw_name}' — "
                                f"credential should not be in source code"
                            ),
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.85,
                            suggestion=(
                                "Use environment variables: "
                                f"os.environ['{kw_name.upper()}']"
                            ),
                        )
                    )

        return findings

    def _is_real_secret(self, value: str) -> bool:
        """Check if a string looks like a real secret (not a placeholder)."""
        if len(value) < 8:
            return False

        # Check for safe/placeholder patterns
        lower = value.lower()
        for safe in _SAFE_PATTERNS:
            if safe in lower:
                return False

        # Check for known API key formats
        if _API_KEY_PREFIXES.search(value):
            return True

        # Check for high-entropy hex strings
        if _HIGH_ENTROPY_HEX.fullmatch(value):
            return True

        # Check for high-entropy base64-like strings
        if _HIGH_ENTROPY_B64.fullmatch(value) and len(value) >= 40:
            return True

        # If it looks like a real password/token (mixed case, digits, symbols)
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(not c.isalnum() for c in value)
        char_classes = sum([has_upper, has_lower, has_digit, has_special])

        if char_classes >= 3 and len(value) >= 16:
            return True

        return False
