"""Parser registry for AIGuard."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiguard.parsers.base import BaseParser

from aiguard.models import Language

_PARSERS: dict[Language, type[BaseParser]] = {}


def register_parser(cls: type[BaseParser]) -> type[BaseParser]:
    """Register a parser class."""
    _PARSERS[cls.language] = cls
    return cls


def get_parser(language: Language) -> BaseParser:
    """Get a parser instance for a language."""
    if language not in _PARSERS:
        raise ValueError(f"No parser registered for {language}")
    return _PARSERS[language]()


def get_language_for_file(file_path: str) -> Language | None:
    """Determine the language of a file from its extension."""
    ext_map = {
        ".py": Language.PYTHON,
        ".pyi": Language.PYTHON,
        ".md": Language.MARKDOWN,
        ".mdx": Language.MARKDOWN,
        # JavaScript support coming soon:
        # ".js": Language.JAVASCRIPT,
        # ".jsx": Language.JAVASCRIPT,
        # ".ts": Language.JAVASCRIPT,
        # ".tsx": Language.JAVASCRIPT,
    }
    from pathlib import Path

    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext)
