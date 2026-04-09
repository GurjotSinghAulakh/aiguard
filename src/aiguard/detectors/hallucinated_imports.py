"""AIG004: Detect potentially hallucinated imports."""

from __future__ import annotations

import ast
import sys
from typing import Any

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


# Python stdlib module names (3.10+)
_STDLIB_MODULES: set[str] = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else {
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "audioop", "base64", "bdb", "binascii", "binhex",
    "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk",
    "cmath", "cmd", "code", "codecs", "codeop", "collections", "colorsys",
    "compileall", "concurrent", "configparser", "contextlib", "contextvars",
    "copy", "copyreg", "cProfile", "crypt", "csv", "ctypes", "curses",
    "dataclasses", "datetime", "dbm", "decimal", "difflib", "dis",
    "distutils", "doctest", "email", "encodings", "enum", "errno",
    "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "fractions",
    "ftplib", "functools", "gc", "getopt", "getpass", "gettext", "glob",
    "graphlib", "grp", "gzip", "hashlib", "heapq", "hmac", "html", "http",
    "idlelib", "imaplib", "imghdr", "imp", "importlib", "inspect", "io",
    "ipaddress", "itertools", "json", "keyword", "lib2to3", "linecache",
    "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math",
    "mimetypes", "mmap", "modulefinder", "multiprocessing", "netrc", "nis",
    "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
    "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
    "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr",
    "pydoc", "queue", "quopri", "random", "re", "readline", "reprlib",
    "resource", "rlcompleter", "runpy", "sched", "secrets", "select",
    "selectors", "shelve", "shlex", "shutil", "signal", "site", "smtpd",
    "smtplib", "sndhdr", "socket", "socketserver", "spwd", "sqlite3",
    "sre_compile", "sre_constants", "sre_parse", "ssl", "stat",
    "statistics", "string", "stringprep", "struct", "subprocess", "sunau",
    "symtable", "sys", "sysconfig", "syslog", "tabnanny", "tarfile",
    "telnetlib", "tempfile", "termios", "test", "textwrap", "threading",
    "time", "timeit", "tkinter", "token", "tokenize", "tomllib", "trace",
    "traceback", "tracemalloc", "tty", "turtle", "turtledemo", "types",
    "typing", "unicodedata", "unittest", "urllib", "uu", "uuid", "venv",
    "warnings", "wave", "weakref", "webbrowser", "winreg", "winsound",
    "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile",
    "zipimport", "zlib", "_thread",
}


@register
class HallucinatedImportsDetector(BaseDetector):
    """Detects imports that likely don't exist — a common AI hallucination.

    AI models frequently generate imports for packages or modules that
    don't exist, or confuse similar package names.
    """

    rule_id = "AIG004"
    rule_name = "hallucinated-imports"
    description = "Detects imports that may not exist (AI hallucination)"
    severity = Severity.ERROR
    languages = (Language.PYTHON,)

    # Known commonly hallucinated packages
    KNOWN_HALLUCINATIONS = {
        "utils",           # AI loves to import from a local 'utils' that doesn't exist
        "helpers",         # Same pattern
        "config",          # Often hallucinated as a package
        "database",        # AI assumes this exists
        "models",          # Often hallucinated
        "sklearn.neural_network.MLPTransformer",  # Doesn't exist
        "torch.utils.tensorboard",                # Often confused path
        "tensorflow.keras.optimizers.AdamW",      # Version-dependent
    }

    def detect(self, source: str, ast_tree: Any, file_path: str) -> list[Finding]:
        findings: list[Finding] = []

        if not isinstance(ast_tree, ast.Module):
            return findings

        for node in ast.walk(ast_tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    finding = self._check_import(alias.name, node.lineno, file_path)
                    if finding:
                        findings.append(finding)

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    finding = self._check_import(node.module, node.lineno, file_path)
                    if finding:
                        findings.append(finding)

        return findings

    def _check_import(
        self, module_name: str, line: int, file_path: str
    ) -> Finding | None:
        """Check if an import is likely hallucinated."""
        top_level = module_name.split(".")[0]

        # Skip stdlib — always valid
        if top_level in _STDLIB_MODULES:
            return None

        # Skip relative imports (handled differently)
        if module_name.startswith("."):
            return None

        # Check against known hallucinations
        if module_name in self.KNOWN_HALLUCINATIONS:
            return self._make_finding(
                message=f"Import '{module_name}' is commonly hallucinated by AI — "
                "verify this module exists in your project",
                file_path=file_path,
                line=line,
                confidence=0.7,
                suggestion=f"Check if '{module_name}' actually exists in your project. "
                "AI often generates imports for modules that don't exist.",
            )

        # Try to verify the import is installable
        try:
            import importlib.metadata

            try:
                importlib.metadata.distribution(top_level)
                return None  # Package exists in environment
            except importlib.metadata.PackageNotFoundError:
                pass

            # Also check if it's importable (could be a local module)
            import importlib.util

            spec = importlib.util.find_spec(top_level)
            if spec is not None:
                return None  # Module is importable

        except (ModuleNotFoundError, ValueError):
            pass

        # Module not found — flag it
        return self._make_finding(
            message=f"Import '{module_name}' not found in environment — "
            "may be hallucinated or missing from requirements",
            file_path=file_path,
            line=line,
            confidence=0.6,
            suggestion=f"Verify '{module_name}' is a real package and add it to "
            "requirements.txt/pyproject.toml, or remove if hallucinated.",
        )
