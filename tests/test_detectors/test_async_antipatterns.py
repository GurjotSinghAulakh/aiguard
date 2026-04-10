"""Tests for AIG018 — Async anti-patterns detector."""

import ast

from aiguard.detectors.async_antipatterns import AsyncAntiPatternsDetector


def _detect(source: str) -> list:
    tree = ast.parse(source)
    detector = AsyncAntiPatternsDetector()
    return detector.detect(source, tree, "test.py")


class TestBlockingCalls:
    """Test detection of blocking calls in async functions."""

    def test_time_sleep_in_async(self):
        source = (
            "import asyncio\n"
            "async def fetch():\n"
            "    time.sleep(1)\n"
            "    await asyncio.sleep(0)\n"
        )
        findings = _detect(source)
        blocking = [f for f in findings if "time.sleep" in f.message]
        assert len(blocking) >= 1

    def test_requests_get_in_async(self):
        source = (
            "async def fetch_data():\n"
            "    resp = requests.get(url)\n"
            "    await asyncio.sleep(0)\n"
        )
        findings = _detect(source)
        blocking = [f for f in findings if "requests" in f.message]
        assert len(blocking) >= 1

    def test_subprocess_run_in_async(self):
        source = (
            "async def run_cmd():\n"
            "    subprocess.run(['ls'])\n"
            "    await asyncio.sleep(0)\n"
        )
        findings = _detect(source)
        blocking = [f for f in findings if "subprocess" in f.message]
        assert len(blocking) >= 1

    def test_open_in_async(self):
        source = (
            "async def read_file():\n"
            "    f = open('test.txt')\n"
            "    await asyncio.sleep(0)\n"
        )
        findings = _detect(source)
        open_findings = [f for f in findings if "open()" in f.message]
        assert len(open_findings) >= 1


class TestNoAwait:
    """Test detection of async functions without await."""

    def test_async_without_await(self):
        source = (
            "async def compute():\n"
            "    return 1 + 2\n"
        )
        findings = _detect(source)
        no_await = [f for f in findings if "never uses" in f.message]
        assert len(no_await) >= 1

    def test_async_with_await_ok(self):
        source = (
            "async def fetch():\n"
            "    result = await some_coro()\n"
            "    return result\n"
        )
        findings = _detect(source)
        no_await = [f for f in findings if "never uses" in f.message]
        assert len(no_await) == 0


class TestSafePatterns:
    """Test that sync functions are NOT flagged."""

    def test_sync_time_sleep_ok(self):
        source = (
            "def slow():\n"
            "    time.sleep(1)\n"
        )
        findings = _detect(source)
        assert len(findings) == 0

    def test_sync_requests_ok(self):
        source = (
            "def fetch():\n"
            "    return requests.get(url)\n"
        )
        findings = _detect(source)
        assert len(findings) == 0

    def test_sync_open_ok(self):
        source = (
            "def read():\n"
            "    with open('f.txt') as f:\n"
            "        return f.read()\n"
        )
        findings = _detect(source)
        assert len(findings) == 0
