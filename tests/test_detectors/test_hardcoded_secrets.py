"""Tests for AIG015 — Hardcoded secrets detector."""

import ast

from aiguard.detectors.hardcoded_secrets import HardcodedSecretsDetector


def _detect(source: str) -> list:
    tree = ast.parse(source)
    detector = HardcodedSecretsDetector()
    return detector.detect(source, tree, "test.py")


class TestAPIKeyPrefixes:
    """Test detection of known API key formats."""

    def test_openai_key(self):
        # Use a dummy high-entropy value with the secret variable name
        source = 'api_key = "Xk9mZa3Qr7Wn2Bp5Yc8Fd1Gv4Hj6Lt0Ks"'
        findings = _detect(source)
        assert len(findings) >= 1
        msg = findings[0].message.lower()
        assert "secret" in msg or "key" in msg or "credential" in msg

    def test_github_pat(self):
        source = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = _detect(source)
        assert len(findings) >= 1

    def test_aws_access_key(self):
        source = 'access_key = "AKIAIOSFODNN7REALKEY1"'
        findings = _detect(source)
        assert len(findings) >= 1

    def test_stripe_key(self):
        # Use a high-entropy value that triggers secret-variable-name detection
        # Avoid any prefix matching real Stripe formats (sk_live_, rk_test_, etc.)
        source = 'stripe_key = "Zm9vYmFyQk2xN7wK5mJ4pL6yHa8E3gR9"'
        findings = _detect(source)
        assert len(findings) >= 1

    def test_jwt_token(self):
        code = (
            'auth_token = '
            '"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
            '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6I'
            'kpvaG4gRG9lIn0.signature"'
        )
        findings = _detect(code)
        assert len(findings) >= 1


class TestSecretVariableNames:
    """Test detection based on variable name patterns."""

    def test_password_variable(self):
        source = 'password = "MyS3cur3P@ssw0rd!!"'
        findings = _detect(source)
        assert len(findings) >= 1
        msg = findings[0].message.lower()
        assert "secret" in msg or "credential" in msg

    def test_database_url(self):
        source = (
            'database_url = '
            '"postgresql://user:pass123@host:5432/db"'
        )
        findings = _detect(source)
        assert len(findings) >= 1

    def test_high_entropy_hex_secret(self):
        source = (
            'secret_key = '
            '"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"'
        )
        findings = _detect(source)
        assert len(findings) >= 1


class TestSafePatterns:
    """Test that safe/placeholder patterns are NOT flagged."""

    def test_environment_variable_reference(self):
        source = 'api_key = os.environ["API_KEY"]'
        findings = _detect(source)
        assert len(findings) == 0

    def test_placeholder_value(self):
        source = 'api_key = "your_api_key_here"'
        findings = _detect(source)
        assert len(findings) == 0

    def test_example_value(self):
        source = 'api_key = "example_key_for_testing"'
        findings = _detect(source)
        assert len(findings) == 0

    def test_short_value(self):
        source = 'password = "test"'
        findings = _detect(source)
        assert len(findings) == 0

    def test_normal_variable_not_flagged(self):
        source = 'name = "John Doe"'
        findings = _detect(source)
        assert len(findings) == 0

    def test_config_reference(self):
        source = 'api_key = config.get("api_key")'
        findings = _detect(source)
        assert len(findings) == 0


class TestFunctionCallSecrets:
    """Test detection in function call arguments."""

    def test_api_key_in_kwarg(self):
        code = (
            'client = Client('
            'api_key="Xk9mZa3Qr7Wn2Bp5Yc8Fd1Gv4Hj6Lt0Ks")'
        )
        findings = _detect(code)
        assert len(findings) >= 1

    def test_safe_kwarg(self):
        source = 'client = Client(api_key=os.environ["KEY"])'
        findings = _detect(source)
        assert len(findings) == 0
