"""Tests for AIG016 — Insecure defaults detector."""

import ast

from aiguard.detectors.insecure_defaults import InsecureDefaultsDetector


def _detect(source: str) -> list:
    tree = ast.parse(source)
    detector = InsecureDefaultsDetector()
    return detector.detect(source, tree, "test.py")


class TestDangerousCalls:
    """Test detection of dangerous function calls."""

    def test_eval_detected(self):
        findings = _detect('result = eval(user_input)')
        assert len(findings) >= 1
        assert "eval" in findings[0].message.lower()

    def test_exec_detected(self):
        findings = _detect('exec(user_code)')
        assert len(findings) >= 1
        assert "exec" in findings[0].message.lower()


class TestInsecureKeywords:
    """Test detection of insecure keyword arguments."""

    def test_debug_true(self):
        findings = _detect('app.run(debug=True)')
        assert len(findings) >= 1
        assert "debug" in findings[0].message.lower()

    def test_verify_false(self):
        findings = _detect('requests.get(url, verify=False)')
        assert len(findings) >= 1
        assert "verify" in findings[0].message.lower()

    def test_shell_true(self):
        findings = _detect('subprocess.run(cmd, shell=True)')
        assert len(findings) >= 1
        assert "shell" in findings[0].message.lower()


class TestDangerousMethods:
    """Test detection of dangerous method calls."""

    def test_pickle_loads(self):
        findings = _detect('data = pickle.loads(raw)')
        assert len(findings) >= 1
        assert "pickle" in findings[0].message.lower()

    def test_yaml_load_unsafe(self):
        findings = _detect('data = yaml.load(raw)')
        assert len(findings) >= 1
        assert "yaml" in findings[0].message.lower()

    def test_yaml_load_with_loader_safe(self):
        source = 'data = yaml.load(raw, Loader=yaml.SafeLoader)'
        findings = _detect(source)
        yaml_findings = [
            f for f in findings if "yaml" in f.message.lower()
        ]
        assert len(yaml_findings) == 0

    def test_tempfile_mktemp(self):
        findings = _detect('f = tempfile.mktemp()')
        assert len(findings) >= 1
        assert "mktemp" in findings[0].message.lower()


class TestSafePatterns:
    """Test that safe patterns are NOT flagged."""

    def test_debug_false(self):
        findings = _detect('app.run(debug=False)')
        debug_findings = [
            f for f in findings if "debug" in f.message.lower()
        ]
        assert len(debug_findings) == 0

    def test_verify_true(self):
        findings = _detect('requests.get(url, verify=True)')
        verify_findings = [
            f for f in findings if "verify" in f.message.lower()
        ]
        assert len(verify_findings) == 0

    def test_normal_function_call(self):
        findings = _detect('result = process(data)')
        assert len(findings) == 0
