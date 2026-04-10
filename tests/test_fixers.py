"""Tests for auto-fix functionality."""

from aiguard.fixers import get_fixable_rules, get_fixer
from aiguard.fixers.builtin import (
    fix_dangerous_commands,
    fix_over_commenting,
    fix_placeholder_code,
    fix_shallow_error_handling,
    fix_unused_variables,
)


class TestFixerRegistry:
    """Test fixer registration and lookup."""

    def test_fixable_rules_registered(self):
        rules = get_fixable_rules()
        assert "AIG001" in rules
        assert "AIG007" in rules
        assert "AIG009" in rules

    def test_get_fixer_returns_function(self):
        fixer = get_fixer("AIG001")
        assert fixer is not None
        assert callable(fixer)

    def test_get_fixer_returns_none_for_unknown(self):
        assert get_fixer("AIG999") is None


class TestFixShallowErrorHandling:
    """Test AIG001 fixer."""

    def test_bare_except_to_exception(self):
        source = "try:\n    pass\nexcept:\n    pass\n"
        result = fix_shallow_error_handling(source, 3)
        assert "except Exception:" in result
        assert "except:" not in result

    def test_bare_except_with_comment(self):
        source = "try:\n    pass\nexcept:  # handle\n    pass\n"
        result = fix_shallow_error_handling(source, 3)
        assert "except Exception:  # handle" in result

    def test_preserves_specific_exception(self):
        source = "try:\n    pass\nexcept ValueError:\n    pass\n"
        result = fix_shallow_error_handling(source, 3)
        assert "except ValueError:" in result


class TestFixOverCommenting:
    """Test AIG003 fixer."""

    def test_removes_standalone_comment(self):
        source = "x = 1\n# increment x\nx += 1\n"
        result = fix_over_commenting(source, 2)
        assert "# increment" not in result
        assert "x = 1\n" in result
        assert "x += 1\n" in result

    def test_removes_inline_comment(self):
        source = "x = 1  # set x to 1\n"
        result = fix_over_commenting(source, 1)
        assert "# set x" not in result
        assert "x = 1" in result


class TestFixPlaceholderCode:
    """Test AIG007 fixer."""

    def test_pass_to_not_implemented(self):
        source = "def foo():\n    pass\n"
        result = fix_placeholder_code(source, 1)
        assert "raise NotImplementedError" in result
        assert "pass" not in result

    def test_preserves_indentation(self):
        source = "class Foo:\n    def bar(self):\n        pass\n"
        result = fix_placeholder_code(source, 2)
        assert '        raise NotImplementedError("Not yet implemented")' in result


class TestFixUnusedVariables:
    """Test AIG009 fixer."""

    def test_prefix_with_underscore(self):
        source = "result = compute()\n"
        result = fix_unused_variables(source, 1)
        assert "_result = compute()" in result

    def test_already_prefixed_unchanged(self):
        source = "_result = compute()\n"
        result = fix_unused_variables(source, 1)
        assert "_result = compute()" in result
        # Should not become __result
        assert "__result" not in result


class TestFixDangerousCommands:
    """Test AIG014 fixer."""

    def test_chmod_777_to_755(self):
        source = "chmod 777 /var/www\n"
        result = fix_dangerous_commands(source, 1)
        assert "chmod 755 /var/www" in result

    def test_dangerous_command_commented_out(self):
        source = "rm -rf /\n"
        result = fix_dangerous_commands(source, 1)
        assert "# DANGEROUS" in result
        assert "rm -rf /" in result


class TestFixIntegration:
    """Test auto-fix end-to-end through the scanner."""

    def test_fix_writes_file(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "try:\n"
            "    pass\n"
            "except:\n"
            "    pass\n"
        )

        from aiguard.scanner import Scanner

        scanner = Scanner()
        scanner.scan(str(test_file), fix=True)

        fixed_content = test_file.read_text()
        assert "except Exception:" in fixed_content

    def test_fix_removes_finding_from_report(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "try:\n"
            "    pass\n"
            "except:\n"
            "    pass\n"
        )

        from aiguard.scanner import Scanner

        scanner = Scanner()
        report = scanner.scan(str(test_file), fix=True)

        # The bare-except finding should be gone (it was fixed)
        bare_except_findings = [
            f for fr in report.file_reports
            for f in fr.findings
            if "Bare" in f.message
        ]
        assert len(bare_except_findings) == 0
