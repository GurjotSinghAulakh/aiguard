"""AIG018: Detect async/await anti-patterns in Python code."""

from __future__ import annotations

import ast
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

# Functions that block the event loop
_BLOCKING_CALLS: dict[str, str] = {
    "sleep": "time.sleep() blocks the event loop — use asyncio.sleep() instead",
    "input": "input() blocks the event loop — use aioconsole.ainput() or run in executor",
}

# Module-level blocking calls
_BLOCKING_METHODS: dict[str, dict[str, str]] = {
    "time": {
        "sleep": (
            "time.sleep() inside async function blocks the event loop — "
            "use 'await asyncio.sleep()' instead"
        ),
    },
    "requests": {
        "get": "requests.get() blocks the event loop — use aiohttp or httpx instead",
        "post": "requests.post() blocks the event loop — use aiohttp or httpx instead",
        "put": "requests.put() blocks the event loop — use aiohttp or httpx instead",
        "delete": "requests.delete() blocks the event loop — use aiohttp or httpx instead",
        "patch": "requests.patch() blocks the event loop — use aiohttp or httpx instead",
        "head": "requests.head() blocks the event loop — use aiohttp or httpx instead",
    },
    "urllib": {
        "urlopen": (
            "urllib.urlopen() blocks the event loop — "
            "use aiohttp instead"
        ),
    },
    "os": {
        "system": (
            "os.system() blocks the event loop — "
            "use asyncio.create_subprocess_shell() instead"
        ),
    },
    "subprocess": {
        "run": (
            "subprocess.run() blocks the event loop — "
            "use asyncio.create_subprocess_exec() instead"
        ),
        "call": (
            "subprocess.call() blocks the event loop — "
            "use asyncio.create_subprocess_exec() instead"
        ),
        "check_output": (
            "subprocess.check_output() blocks the event loop — "
            "use asyncio.create_subprocess_exec() instead"
        ),
    },
}


@register
class AsyncAntiPatternsDetector(BaseDetector):
    """Detects common async/await anti-patterns.

    AI-generated async code frequently uses blocking calls like
    time.sleep(), requests.get(), or subprocess.run() inside async
    functions, which defeats the purpose of async and blocks the
    event loop.
    """

    rule_id = "AIG018"
    rule_name = "async-antipatterns"
    description = (
        "Detects blocking calls in async functions and other "
        "async anti-patterns"
    )
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    def detect(
        self, source: str, ast_tree: Any, file_path: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.AsyncFunctionDef):
                findings.extend(
                    self._check_async_function(node, file_path)
                )

        return findings

    def _check_async_function(
        self, func: ast.AsyncFunctionDef, file_path: str
    ) -> list[Finding]:
        findings = []

        has_await = False
        for node in ast.walk(func):
            if isinstance(node, ast.Await):
                has_await = True

            # Check for blocking calls
            if isinstance(node, ast.Call):
                findings.extend(
                    self._check_blocking_call(
                        node, func.name, file_path
                    )
                )

        # Async function without any await
        if not has_await:
            findings.append(
                self._make_finding(
                    message=(
                        f"Async function '{func.name}' never uses "
                        f"'await' — consider making it synchronous"
                    ),
                    file_path=file_path,
                    line=func.lineno,
                    severity=Severity.INFO,
                    confidence=0.8,
                    suggestion=(
                        "Remove 'async' keyword if no I/O-bound "
                        "operations need awaiting"
                    ),
                )
            )

        return findings

    def _check_blocking_call(
        self,
        node: ast.Call,
        func_name: str,
        file_path: str,
    ) -> list[Finding]:
        findings = []

        # Check bare function calls: sleep(), input()
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if name in _BLOCKING_CALLS:
                findings.append(
                    self._make_finding(
                        message=_BLOCKING_CALLS[name],
                        file_path=file_path,
                        line=node.lineno,
                        confidence=0.85,
                    )
                )

        # Check method calls: time.sleep(), requests.get()
        elif isinstance(node.func, ast.Attribute):
            method = node.func.attr
            obj = node.func.value
            if isinstance(obj, ast.Name):
                module = obj.id
                if (
                    module in _BLOCKING_METHODS
                    and method in _BLOCKING_METHODS[module]
                ):
                    findings.append(
                        self._make_finding(
                            message=_BLOCKING_METHODS[module][method],
                            file_path=file_path,
                            line=node.lineno,
                            confidence=0.9,
                        )
                    )

            # Check for open() — file I/O blocks
            if isinstance(node.func, ast.Attribute):
                pass  # already handled above
            elif isinstance(node.func, ast.Name):
                pass  # already handled above

        # Check bare open() in async context
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            findings.append(
                self._make_finding(
                    message=(
                        "open() blocks the event loop — "
                        "use aiofiles.open() instead"
                    ),
                    file_path=file_path,
                    line=node.lineno,
                    confidence=0.75,
                    suggestion=(
                        "Use 'async with aiofiles.open(path) as f:'"
                    ),
                )
            )

        return findings
