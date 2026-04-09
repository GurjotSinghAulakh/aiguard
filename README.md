# AIGuard

**AI Code Quality Guard — catch the bugs AI leaves behind.**

[![CI](https://github.com/GurjotSinghAulakh/aiguard/actions/workflows/ci.yml/badge.svg)](https://github.com/GurjotSinghAulakh/aiguard/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/aiguard)](https://pypi.org/project/aiguard/)
[![Python](https://img.shields.io/pypi/pyversions/aiguard)](https://pypi.org/project/aiguard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AI-generated code is **"almost right"** — it compiles, passes linting, follows conventions... but has subtle bugs that are harder to find than writing it yourself. **66% of developers** say this is their #1 frustration with AI coding tools.

AIGuard is a static analysis tool that catches the **specific patterns where AI-generated code goes wrong**: shallow error handling, hallucinated imports, copy-paste duplication, missing validation, placeholder code disguised as complete, and more.

```
$ aiguard scan ./src

src/api/handlers.py
  E       12  Bare 'except:' catches all exceptions including KeyboardInterrupt  AIG001
  W       34  Functions 'get_users' and 'get_admins' are 92% similar             AIG005
  W       67  Public function 'process' has 4 params but no input validation     AIG006

src/utils/helpers.py
  I       5   Variable 'data' is too generic — use a descriptive name            AIG010
  W       22  Function 'transform' has only 'pass' — placeholder code            AIG007

  ┌─────────────────── AI Code Health Score ───────────────────┐
  │  ████████████████████████████░░░░░░░░░░░░  72/100  ~       │
  └────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
pip install aiguard
```

```bash
# Scan a directory
aiguard scan ./src

# Scan a single file
aiguard scan app.py

# JSON output for CI pipelines
aiguard scan ./src --format json

# SARIF for GitHub Code Scanning
aiguard scan ./src --format sarif --output results.sarif

# Fail CI if score is below 70
aiguard scan ./src --fail-under 70
```

## Detection Rules

| Rule | Name | What It Catches | Severity |
|------|------|----------------|----------|
| **AIG001** | shallow-error-handling | Bare `except:`, catching `Exception`, empty handlers | Error |
| **AIG002** | tautological-code | `if True`, unreachable code after `return`, `x == x` | Warning |
| **AIG003** | over-commenting | `# Initialize the variable` for `x = 0` (AI loves this) | Info |
| **AIG004** | hallucinated-imports | Imports that don't exist in your environment | Error |
| **AIG005** | copy-paste-duplication | Near-identical functions with minor variations | Warning |
| **AIG006** | missing-input-validation | Public functions with params but no guards | Warning |
| **AIG007** | placeholder-code | `pass`/`...`/`NotImplementedError` disguised as done | Warning |
| **AIG008** | complex-one-liners | Nested comprehensions, chained ternaries | Warning |
| **AIG009** | unused-variables | Assigned but never referenced | Info |
| **AIG010** | generic-naming | `data`, `result`, `temp`, `val` — meaningless names | Info |

List all rules:

```bash
aiguard list-rules
```

## Configuration

Generate a config file:

```bash
aiguard init
```

This creates `.aiguard.yml`:

```yaml
rules:
  AIG001:
    enabled: true
    severity: error
  AIG003:
    enabled: true
    max_comment_ratio: 0.6
  AIG005:
    enabled: true
    similarity_threshold: 0.85

ignore:
  - "tests/**"
  - "migrations/**"

score:
  fail_threshold: 60
  weights:
    error: 10
    warning: 3
    info: 1
```

## GitHub Actions

Add to your workflow:

```yaml
# .github/workflows/aiguard.yml
name: AI Code Quality
on: [push, pull_request]

jobs:
  aiguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: GurjotSinghAulakh/aiguard@v1
        with:
          path: './src'
          fail-under: '70'
```

Findings appear as **inline annotations** on your PRs via GitHub Code Scanning (SARIF).

## Output Formats

| Format | Use Case | Flag |
|--------|----------|------|
| `terminal` | Local development (default) | `--format terminal` |
| `json` | CI pipelines, custom tooling | `--format json` |
| `sarif` | GitHub Code Scanning | `--format sarif` |

## Writing Custom Rules (Plugins)

Create a detector in your own package:

```python
from aiguard.detectors import register
from aiguard.detectors.base import BaseDetector
from aiguard.models import Finding, Language, Severity

@register
class MyCustomDetector(BaseDetector):
    rule_id = "CUSTOM001"
    rule_name = "my-custom-rule"
    description = "Detects my specific pattern"
    severity = Severity.WARNING
    languages = (Language.PYTHON,)

    def detect(self, source, ast_tree, file_path):
        findings = []
        # Your detection logic using ast_tree
        return findings
```

Register via entry points in your `pyproject.toml`:

```toml
[project.entry-points."aiguard.detectors"]
my_rule = "my_package:MyCustomDetector"
```

## Why AIGuard?

Traditional linters (pylint, ruff, eslint) catch **syntax-level** issues. AI-generated code passes all of those. The bugs are at a **higher level**:

- The error handling *exists* but is **shallow** (catches everything, does nothing)
- The code *works* but is **copy-pasted** 5 times with minor changes
- The function *has parameters* but **never validates** them
- The import *looks right* but the **package doesn't exist**
- The code *looks complete* but it's just **`pass` with a docstring**

AIGuard catches these patterns because they are **specific to how AI generates code**.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Good first issues are labeled [`good first issue`](https://github.com/GurjotSinghAulakh/aiguard/labels/good%20first%20issue).

## License

MIT License. See [LICENSE](LICENSE) for details.
