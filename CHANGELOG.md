# Changelog

All notable changes to AIGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
