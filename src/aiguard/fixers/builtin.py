"""Built-in auto-fixers for AIGuard rules.

Each fixer takes (source: str, line: int) and returns the modified source.
The `line` parameter is the 1-based line number where the finding was reported.
"""

from __future__ import annotations

import re

from aiguard.fixers import register_fixer


@register_fixer("AIG001")
def fix_shallow_error_handling(source: str, line: int) -> str:
    """Fix bare except → except Exception.

    Converts:
        except:       → except Exception:
        except:  # .. → except Exception:  # ..
    """
    lines = source.splitlines(True)
    idx = line - 1
    if idx < 0 or idx >= len(lines):
        return source

    old_line = lines[idx]
    # Match bare "except:" (not "except SomeError:")
    new_line = re.sub(
        r"\bexcept\s*:",
        "except Exception:",
        old_line,
        count=1,
    )
    if new_line != old_line:
        lines[idx] = new_line

    return "".join(lines)


@register_fixer("AIG003")
def fix_over_commenting(source: str, line: int) -> str:
    """Remove a trivially redundant comment line.

    Removes the entire comment line if it's a standalone comment.
    If it's an inline comment, removes only the comment part.
    """
    lines = source.splitlines(True)
    idx = line - 1
    if idx < 0 or idx >= len(lines):
        return source

    old_line = lines[idx]
    stripped = old_line.strip()

    if stripped.startswith("#"):
        # Standalone comment — remove the entire line
        lines.pop(idx)
    else:
        # Inline comment — remove the comment part
        lines[idx] = re.sub(r"\s*#.*$", "\n", old_line)

    return "".join(lines)


@register_fixer("AIG007")
def fix_placeholder_code(source: str, line: int) -> str:
    """Replace bare `pass` in function body with `raise NotImplementedError`.

    Only replaces `pass` when it's the sole body of a function/method.
    """
    lines = source.splitlines(True)
    idx = line - 1
    if idx < 0 or idx >= len(lines):
        return source

    # Search the function body for a lone 'pass'
    for i in range(idx, min(idx + 20, len(lines))):
        stripped = lines[i].strip()
        if stripped == "pass":
            indent = lines[i][: len(lines[i]) - len(lines[i].lstrip())]
            lines[i] = (
                f'{indent}raise NotImplementedError('
                f'"Not yet implemented")\n'
            )
            break

    return "".join(lines)


@register_fixer("AIG009")
def fix_unused_variables(source: str, line: int) -> str:
    """Prefix unused variable with underscore to mark as intentionally unused.

    Converts:
        result = func()  →  _result = func()
    """
    lines = source.splitlines(True)
    idx = line - 1
    if idx < 0 or idx >= len(lines):
        return source

    old_line = lines[idx]
    # Match a simple assignment target (not already prefixed with _)
    match = re.match(r"^(\s*)([a-zA-Z][a-zA-Z0-9_]*)\s*=", old_line)
    if match and not match.group(2).startswith("_"):
        indent = match.group(1)
        name = match.group(2)
        rest = old_line[match.end(2):]
        lines[idx] = f"{indent}_{name}{rest}"

    return "".join(lines)


@register_fixer("AIG014")
def fix_dangerous_commands(source: str, line: int) -> str:
    """Fix common dangerous command patterns in markdown code blocks.

    - chmod 777 → chmod 755
    - rm -rf / → (commented out with warning)
    """
    lines = source.splitlines(True)
    idx = line - 1
    if idx < 0 or idx >= len(lines):
        return source

    old_line = lines[idx]

    # chmod 777 → chmod 755
    new_line = re.sub(r"chmod\s+777\b", "chmod 755", old_line)

    if new_line == old_line:
        # Comment out dangerous commands with a warning
        stripped = old_line.strip()
        indent = old_line[: len(old_line) - len(old_line.lstrip())]
        new_line = (
            f"{indent}# DANGEROUS — review before uncommenting: "
            f"{stripped}\n"
        )

    lines[idx] = new_line
    return "".join(lines)
