# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in AIGuard, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **gs@aulakh.no**

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix release**: Within 2 weeks for critical issues

## Scope

AIGuard is a static analysis tool that reads source code files. Security concerns include:

- **Path traversal**: Scanning paths outside intended directories
- **Code execution**: AIGuard should never execute scanned code
- **Dependency vulnerabilities**: Issues in our dependencies
- **Plugin system abuse**: Malicious third-party plugins

## Best Practices for Users

- Only scan code you trust
- Review third-party AIGuard plugins before installing
- Keep AIGuard updated to the latest version
