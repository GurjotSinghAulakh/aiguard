"""Markdown parser for AIGuard — extracts structured elements from .md files."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from aiguard.models import Language
from aiguard.parsers import register_parser
from aiguard.parsers.base import BaseParser


@dataclass
class CodeBlock:
    """A fenced code block extracted from markdown."""

    language: str
    content: str
    start_line: int
    end_line: int


@dataclass
class HtmlComment:
    """An HTML comment extracted from markdown."""

    content: str
    start_line: int
    end_line: int


@dataclass
class Link:
    """A link or URL extracted from markdown."""

    url: str
    text: str
    line: int


@dataclass
class MarkdownDocument:
    """Structured representation of a markdown file."""

    lines: list[str] = field(default_factory=list)
    code_blocks: list[CodeBlock] = field(default_factory=list)
    html_comments: list[HtmlComment] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    raw_text: str = ""


_FENCE_OPEN = re.compile(r"^(`{3,}|~{3,})(\w*)")
_HTML_COMMENT_START = re.compile(r"<!--")
_HTML_COMMENT_END = re.compile(r"-->")
_MD_LINK = re.compile(r"\[([^\]]*)\]\(([^)]+)\)")
_BARE_URL = re.compile(r"https?://\S+")


@register_parser
class MarkdownParser(BaseParser):
    """Parser for markdown files — extracts code blocks, comments, and links."""

    language = Language.MARKDOWN

    def parse(self, source: str, file_path: str) -> Any:
        doc = MarkdownDocument(raw_text=source)
        doc.lines = source.splitlines()

        self._extract_code_blocks(doc)
        self._extract_html_comments(doc)
        self._extract_links(doc)

        return doc

    def can_parse(self, file_path: str) -> bool:
        from pathlib import Path

        return Path(file_path).suffix.lower() in {".md", ".mdx"}

    def _extract_code_blocks(self, doc: MarkdownDocument) -> None:
        in_block = False
        fence_char = ""
        fence_len = 0
        block_lang = ""
        block_lines: list[str] = []
        block_start = 0

        for i, line in enumerate(doc.lines, start=1):
            if not in_block:
                m = _FENCE_OPEN.match(line.strip())
                if m:
                    in_block = True
                    fence_char = m.group(1)[0]
                    fence_len = len(m.group(1))
                    block_lang = m.group(2) or ""
                    block_lines = []
                    block_start = i
            else:
                stripped = line.strip()
                if (
                    stripped.startswith(fence_char * fence_len)
                    and stripped.rstrip(fence_char) == ""
                    and len(stripped) >= fence_len
                ):
                    doc.code_blocks.append(
                        CodeBlock(
                            language=block_lang,
                            content="\n".join(block_lines),
                            start_line=block_start,
                            end_line=i,
                        )
                    )
                    in_block = False
                else:
                    block_lines.append(line)

    def _extract_html_comments(self, doc: MarkdownDocument) -> None:
        in_comment = False
        comment_lines: list[str] = []
        comment_start = 0

        for i, line in enumerate(doc.lines, start=1):
            if not in_comment:
                if _HTML_COMMENT_START.search(line):
                    comment_start = i
                    # Check for single-line comment
                    if _HTML_COMMENT_END.search(line):
                        content = re.sub(
                            r".*?<!--\s*", "", line
                        )
                        content = re.sub(r"\s*-->.*", "", content)
                        doc.html_comments.append(
                            HtmlComment(
                                content=content,
                                start_line=i,
                                end_line=i,
                            )
                        )
                    else:
                        in_comment = True
                        content = re.sub(r".*?<!--\s*", "", line)
                        comment_lines = [content]
            else:
                if _HTML_COMMENT_END.search(line):
                    content = re.sub(r"\s*-->.*", "", line)
                    comment_lines.append(content)
                    doc.html_comments.append(
                        HtmlComment(
                            content="\n".join(comment_lines),
                            start_line=comment_start,
                            end_line=i,
                        )
                    )
                    in_comment = False
                    comment_lines = []
                else:
                    comment_lines.append(line)

    def _extract_links(self, doc: MarkdownDocument) -> None:
        for i, line in enumerate(doc.lines, start=1):
            for m in _MD_LINK.finditer(line):
                doc.links.append(Link(url=m.group(2), text=m.group(1), line=i))
            for m in _BARE_URL.finditer(line):
                # Skip if already captured as a markdown link
                url = m.group(0).rstrip(")")
                if f"]({url}" not in line:
                    doc.links.append(Link(url=url, text="", line=i))
