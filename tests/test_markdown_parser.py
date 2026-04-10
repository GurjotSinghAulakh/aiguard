"""Tests for the Markdown parser."""

from __future__ import annotations

import pytest

from aiguard.parsers.markdown_parser import MarkdownParser


@pytest.fixture
def parser():
    return MarkdownParser()


class TestCodeBlocks:
    def test_fenced_code_block(self, parser):
        text = "# Title\n\n```python\nprint('hello')\n```\n"
        doc = parser.parse(text, "test.md")
        assert len(doc.code_blocks) == 1
        assert doc.code_blocks[0].language == "python"
        assert "print" in doc.code_blocks[0].content

    def test_multiple_code_blocks(self, parser):
        text = "```bash\nls\n```\n\n```python\nx = 1\n```\n"
        doc = parser.parse(text, "test.md")
        assert len(doc.code_blocks) == 2
        assert doc.code_blocks[0].language == "bash"
        assert doc.code_blocks[1].language == "python"

    def test_code_block_without_language(self, parser):
        text = "```\nsome code\n```\n"
        doc = parser.parse(text, "test.md")
        assert len(doc.code_blocks) == 1
        assert doc.code_blocks[0].language == ""

    def test_tilde_fence(self, parser):
        text = "~~~bash\necho hi\n~~~\n"
        doc = parser.parse(text, "test.md")
        assert len(doc.code_blocks) == 1


class TestHtmlComments:
    def test_single_line_comment(self, parser):
        text = "<!-- this is a comment -->"
        doc = parser.parse(text, "test.md")
        assert len(doc.html_comments) == 1
        assert "this is a comment" in doc.html_comments[0].content

    def test_multiline_comment(self, parser):
        text = "<!--\nline 1\nline 2\n-->"
        doc = parser.parse(text, "test.md")
        assert len(doc.html_comments) == 1
        assert "line 1" in doc.html_comments[0].content

    def test_no_comments(self, parser):
        text = "# Just a heading\n\nSome text."
        doc = parser.parse(text, "test.md")
        assert len(doc.html_comments) == 0


class TestLinks:
    def test_markdown_link(self, parser):
        text = "Check [this link](https://example.com) out."
        doc = parser.parse(text, "test.md")
        assert len(doc.links) >= 1
        assert any(link.url == "https://example.com" for link in doc.links)

    def test_bare_url(self, parser):
        text = "Visit https://example.com for more."
        doc = parser.parse(text, "test.md")
        assert len(doc.links) >= 1


class TestCanParse:
    def test_md_file(self, parser):
        assert parser.can_parse("README.md") is True

    def test_mdx_file(self, parser):
        assert parser.can_parse("doc.mdx") is True

    def test_py_file(self, parser):
        assert parser.can_parse("script.py") is False
