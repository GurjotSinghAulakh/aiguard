# AIGuard for VS Code

Real-time detection of AI-generated code issues directly in your editor.

## Features

- **Real-time diagnostics** — errors, warnings, and info squiggles on save
- **Status bar score** — your AI Code Health Score (0-100) always visible
- **Auto-fix** — one command to fix issues AIGuard knows how to resolve
- **18 detection rules** — from shallow error handling to hardcoded secrets to SQL injection

## Requirements

- Python 3.9+
- AIGuard CLI installed: `pip install ai-guard-cli`

## Commands

| Command | Description |
|---------|-------------|
| `AIGuard: Scan Current File` | Run AIGuard on the active file |
| `AIGuard: Scan Workspace` | Run AIGuard on the entire workspace |
| `AIGuard: Auto-Fix Current File` | Apply automatic fixes |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `aiguard.enable` | `true` | Enable/disable diagnostics |
| `aiguard.executablePath` | `"aiguard"` | Path to the aiguard CLI |
| `aiguard.runOnSave` | `true` | Scan when files are saved |
| `aiguard.runOnType` | `false` | Scan as you type (debounced) |
| `aiguard.configPath` | `""` | Path to `.aiguard.yml` |
| `aiguard.failUnder` | `0` | Show warning if score is below threshold |

## Development

```bash
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

## Packaging

```bash
npm run package
# Creates aiguard-0.5.0.vsix
```

Install the `.vsix`:
```bash
code --install-extension aiguard-0.5.0.vsix
```
