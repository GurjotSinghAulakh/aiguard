"""Base parser interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from aiguard.models import Language


class BaseParser(ABC):
    """Abstract base class for language parsers."""

    language: ClassVar[Language]

    @abstractmethod
    def parse(self, source: str, file_path: str) -> Any:
        """Parse source code and return a language-specific AST.

        Args:
            source: The source code string.
            file_path: Path to the file (for error messages).

        Returns:
            Language-specific AST object.
        """
        ...

    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """Check if this parser can handle the given file.

        Args:
            file_path: Path to the file.

        Returns:
            True if this parser handles the file's language.
        """
        ...
