# Changelog

All notable changes to AIGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-04-10

### Added

- **Prompt Security Scanner** — 4 new detectors that scan `.md` and `.mdx` files for hidden malicious content:
  - AIG011: Prompt injection (override instructions, role hijacking, stealth commands)
  - AIG012: Hidden content (zero-width Unicode, invisible HTML, base64 payloads)
  - AIG013: Data exfiltration (credential theft, sensitive file access, data piping)
  - AIG014: Dangerous commands (rm -rf, curl|bash, reverse shells, privilege escalation)
- **Markdown language support** — new `MarkdownParser` that extracts code blocks, HTML comments, and links
- `.md` and `.mdx` file extension scanning
- `aiguard-prompt-scan` pre-commit hook for markdown files
- 59 new tests (133 total)

## [0.3.0] - 2026-04-09

### Added

- **Diff mode** — `--diff HEAD`, `--diff main` to only scan changed lines
- **Staged mode** — `--staged` flag for pre-commit hook integration
- **Pre-commit hook** — `.pre-commit-hooks.yaml` for automatic scanning on commit
- Both `aiguard` and `ai-guard` CLI commands now work

### Fixed

- Fixed ruff linting issues for CI compatibility
- Fixed parser registration bug
- Corrected all GitHub URLs to point to the actual repo

## [0.1.0] - 2026-04-09

### Added

- Initial release of AIGuard
- 10 built-in detection rules (AIG001-AIG010):
  - AIG001: Shallow error handling
  - AIG002: Tautological/dead code
  - AIG003: Over-commenting
  - AIG004: Hallucinated imports
  - AIG005: Copy-paste duplication
  - AIG006: Missing input validation
  - AIG007: Placeholder code
  - AIG008: Complex one-liners
  - AIG009: Unused variables
  - AIG010: Generic naming
- CLI with `scan`, `list-rules`, and `init` commands
- Terminal, JSON, and SARIF output formats
- AI Code Health Score (0-100)
- `.aiguard.yml` configuration file support
- GitHub Actions integration
- Plugin system for third-party detectors
- Python language support via stdlib `ast`
