# Contributing to AIGuard

Thank you for your interest in contributing to AIGuard! This guide will help you get started.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/GurjotSinghAulakh/aiguard.git
cd aiguard

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Verify everything works
pytest
```

## How to Contribute

### Reporting Bugs

1. Check existing issues first to avoid duplicates
2. Use the **Bug Report** issue template
3. Include: Python version, OS, steps to reproduce, expected vs actual behavior

### Suggesting Features

1. Open a **Feature Request** issue
2. Describe the problem you're trying to solve
3. Explain your proposed solution

### Writing Code

1. **Fork** the repository
2. Create a **feature branch**: `git checkout -b feature/my-feature`
3. Make your changes
4. **Write tests** for your changes
5. Run the test suite: `pytest`
6. Run the linter: `ruff check src/ tests/`
7. **Commit** with a clear message
8. **Push** and open a Pull Request

### Writing a Custom Detector

This is the most impactful way to contribute! Here's the template:

```python
# src/aiguard/detectors/my_detector.py

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class MyDetector(BaseDetector):
    rule_id = "AIG0XX"           # Get next available ID
    rule_name = "my-detector"
    description = "What it detects"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    def detect(self, source, ast_tree, file_path):
        findings = []
        # Your detection logic here
        return findings
```

Then:
1. Add your module import to `src/aiguard/detectors/__init__.py` in `load_builtin_detectors()`
2. Create a test fixture in `tests/fixtures/`
3. Create tests in `tests/test_detectors/`

### Writing a Prompt Security Detector

Prompt security detectors scan `.md` files instead of Python code. They use `Language.MARKDOWN` and receive a `MarkdownDocument` as the AST:

```python
# src/aiguard/detectors/my_prompt_detector.py

from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity


@register
class MyPromptDetector(BaseDetector):
    rule_id = "AIG0XX"
    rule_name = "my-prompt-rule"
    description = "What it detects in prompt files"
    severity = Severity.ERROR
    languages = (Language.MARKDOWN,)

    def detect(self, source, ast_tree, file_path):
        findings = []
        lines = source.splitlines()

        # Scan raw text line by line
        for i, line in enumerate(lines, start=1):
            if "suspicious_pattern" in line:
                findings.append(self._make_finding(
                    message="Found suspicious pattern",
                    file_path=file_path,
                    line=i,
                ))

        # Access parsed structure via ast_tree (MarkdownDocument)
        from aiguard.parsers.markdown_parser import MarkdownDocument
        if isinstance(ast_tree, MarkdownDocument):
            for block in ast_tree.code_blocks:
                pass  # Check code blocks
            for comment in ast_tree.html_comments:
                pass  # Check HTML comments

        return findings
```

For test fixtures, create `.md` files in `tests/fixtures/` with both malicious and safe examples. See `tests/fixtures/malicious_prompt.md` and `tests/fixtures/safe_prompt.md` for reference.

### Commit Message Convention

We follow conventional commits:

```
feat: add new detector for XYZ pattern
fix: correct false positive in AIG003
docs: update custom rules guide
test: add edge case tests for AIG001
refactor: simplify scanner file walking
```

## Code Style

- We use **Ruff** for linting and formatting
- Line length: 100 characters
- Type hints are encouraged
- Docstrings for all public functions (Google style)

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all tests pass
4. Request review from a maintainer
5. Squash commits if requested

## First-Time Contributors

Look for issues labeled **`good first issue`** — these are specifically chosen to be approachable for newcomers. Some ideas:

- Add a new detection pattern to an existing detector
- Improve error messages or suggestions
- Add test cases for edge cases
- Improve documentation

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
