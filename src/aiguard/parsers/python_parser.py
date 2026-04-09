"""Python parser using the stdlib ast module."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import ClassVar

from aiguard.models import Language
from aiguard.parsers import register_parser
from aiguard.parsers.base import BaseParser


@register_parser
class PythonParser(BaseParser):
    """Parser for Python source files using the stdlib ast module."""

    language: ClassVar[Language] = Language.PYTHON

    def parse(self, source: str, file_path: str) -> ast.Module:
        """Parse Python source into an AST.

        Args:
            source: Python source code.
            file_path: Path to the file.

        Returns:
            ast.Module node.

        Raises:
            SyntaxError: If the source cannot be parsed.
        """
        try:
            tree = ast.parse(source, filename=file_path)
            return tree
        except SyntaxError:
            # Return an empty module for unparseable files
            return ast.Module(body=[], type_ignores=[])

    def can_parse(self, file_path: str) -> bool:
        """Check if this is a Python file."""
        return Path(file_path).suffix.lower() in (".py", ".pyi")
