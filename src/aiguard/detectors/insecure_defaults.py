"""AIG016: Detect insecure default settings in code."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# (keyword_name, dangerous_value, suggestion)
_INSECURE_KWARGS: list[tuple[str, Any, str]] = [
    ("debug", True, "Set debug=False in production code"),
    ("verify", False, "Never disable SSL verification (verify=False)"),
    ("check_hostname", False, "Do not disable hostname checking"),
    ("cert_reqs", "CERT_NONE", "Always require SSL certificates"),
    (
        "shell",
        True,
        "Avoid shell=True — it enables shell injection attacks",
    ),
    (
        "safe",
        False,
        "Do not disable safe mode (safe=False)",
    ),
]

# Function calls that are dangerous
_DANGEROUS_CALLS: dict[str, str] = {
    "eval": "Avoid eval() — it executes arbitrary code. Use ast.literal_eval() instead",
    "exec": "Avoid exec() — it executes arbitrary code",
    "compile": "Be cautious with compile() — consider if it's truly needed",
    "__import__": "Avoid __import__() — use importlib.import_module() instead",
}

# Dangerous attribute calls: (module, method, suggestion)
_DANGEROUS_METHODS: list[tuple[str, str, str]] = [
    (
        "pickle",
        "loads",
        "pickle.loads() on untrusted data can execute arbitrary code — "
        "use json.loads() instead",
    ),
    (
        "pickle",
        "load",
        "pickle.load() on untrusted data can execute arbitrary code — "
        "use json.load() instead",
    ),
    (
        "yaml",
        "load",
        "yaml.load() is unsafe without Loader — "
        "use yaml.safe_load() instead",
    ),
    (
        "marshal",
        "loads",
        "marshal.loads() on untrusted data can crash the interpreter",
    ),
    (
        "shelve",
        "open",
        "shelve uses pickle internally — unsafe with untrusted data",
    ),
    (
        "tempfile",
        "mktemp",
        "tempfile.mktemp() is insecure — "
        "use tempfile.mkstemp() or NamedTemporaryFile instead",
    ),
]


@register
class InsecureDefaultsDetector(BaseDetector):
    """Detects insecure default settings and dangerous function calls.

    AI-generated code often copies patterns with debug=True, verify=False,
    eval(), pickle.loads(), and other unsafe defaults that create
    security vulnerabilities.
    """

    rule_id = "AIG016"
    rule_name = "insecure-defaults"
    description = (
        "Detects insecure defaults like debug=True, verify=False, eval()"
    )
    severity = Severity.ERROR
    languages = (Language.PYTHON,)

    def detect(
        self, source: str, ast_tree: Any, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Call):
                findings.extend(self._check_call(node, file_path))

        return findings

    def _check_call(
        self, node: ast.Call, file_path: str
    ) -> list[Finding]:
        findings = []

        # Check for dangerous bare function calls (eval, exec)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in _DANGEROUS_CALLS:
                findings.append(
                    self._make_finding(
                        message=_DANGEROUS_CALLS[func_name],
                        file_path=file_path,
                        line=node.lineno,
                        confidence=0.95,
                    )
                )

        # Check for dangerous method calls (pickle.loads, etc.)
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            obj = node.func.value
            if isinstance(obj, ast.Name):
                for mod, meth, suggestion in _DANGEROUS_METHODS:
                    if obj.id == mod and method_name == meth:
                        # Special case: yaml.load with Loader is safe
                        if mod == "yaml" and meth == "load":
                            has_loader = any(
                                kw.arg == "Loader" for kw in node.keywords
                            )
                            if has_loader:
                                continue
                        findings.append(
                            self._make_finding(
                                message=suggestion,
                                file_path=file_path,
                                line=node.lineno,
                                confidence=0.9,
                            )
                        )

        # Check for insecure keyword arguments
        for kw in node.keywords:
            if kw.arg is None:
                continue
            for kw_name, bad_val, suggestion in _INSECURE_KWARGS:
                if kw.arg != kw_name:
                    continue
                if isinstance(kw.value, ast.Constant):
                    if kw.value.value == bad_val:
                        findings.append(
                            self._make_finding(
                                message=(
                                    f"Insecure default: "
                                    f"{kw_name}={bad_val!r}"
                                ),
                                file_path=file_path,
                                line=node.lineno,
                                confidence=0.9,
                                suggestion=suggestion,
                            )
                        )
                elif isinstance(kw.value, ast.NameConstant):
                    # Python 3.7 compat
                    if kw.value.value == bad_val:  # type: ignore[attr-defined]
                        findings.append(
                            self._make_finding(
                                message=(
                                    f"Insecure default: "
                                    f"{kw_name}={bad_val!r}"
                                ),
                                file_path=file_path,
                                line=node.lineno,
                                confidence=0.9,
                                suggestion=suggestion,
                            )
                        )

        return findings
