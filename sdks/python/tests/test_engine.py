"""Tests for the kvlar Python SDK engine wrapper."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch, MagicMock

import pytest

from kvlar import KvlarEngine, Decision, KvlarError
from kvlar.engine import EvalResult, TestResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_which():
    """Patch shutil.which so the binary check passes."""
    with patch("kvlar.engine.shutil.which", return_value="/usr/local/bin/kvlar"):
        yield


@pytest.fixture
def engine(mock_which):
    """A KvlarEngine with mocked binary lookup."""
    return KvlarEngine("policy.yaml")


# ---------------------------------------------------------------------------
# Constructor tests
# ---------------------------------------------------------------------------


class TestKvlarEngineInit:
    def test_raises_if_binary_not_found(self):
        with patch("kvlar.engine.shutil.which", return_value=None):
            with pytest.raises(KvlarError, match="kvlar binary not found"):
                KvlarEngine("policy.yaml")

    def test_custom_binary(self):
        with patch("kvlar.engine.shutil.which", return_value="/opt/kvlar"):
            eng = KvlarEngine("policy.yaml", binary="/opt/kvlar")
            assert eng.binary == "/opt/kvlar"

    def test_stores_policy_path(self, mock_which):
        eng = KvlarEngine("/tmp/my-policy.yaml")
        assert str(eng.policy_path) == "/tmp/my-policy.yaml"


# ---------------------------------------------------------------------------
# evaluate() tests
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_allow_json(self, engine):
        output = json.dumps({"decision": "allow", "rule_id": "allow-read"})
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed):
            result = engine.evaluate({"tool": "read_file"})
            assert result.decision == Decision.ALLOW
            assert result.rule_id == "allow-read"

    def test_deny_json(self, engine):
        output = json.dumps({
            "decision": "deny",
            "rule_id": "deny-delete",
            "reason": "Deletes not allowed",
        })
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed):
            result = engine.evaluate({"tool": "delete_file", "arguments": {"path": "/etc"}})
            assert result.decision == Decision.DENY
            assert result.rule_id == "deny-delete"
            assert result.reason == "Deletes not allowed"

    def test_require_approval_json(self, engine):
        output = json.dumps({"decision": "require_approval", "rule_id": "approve-write"})
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed):
            result = engine.evaluate({"tool": "write_file"})
            assert result.decision == Decision.REQUIRE_APPROVAL

    def test_fallback_human_readable_allow(self, engine):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ALLOW\n", stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed):
            result = engine.evaluate({"tool": "read_file"})
            assert result.decision == Decision.ALLOW

    def test_fallback_human_readable_deny(self, engine):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="DENY: blocked\n", stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed):
            result = engine.evaluate({"tool": "delete_file"})
            assert result.decision == Decision.DENY

    def test_passes_arguments(self, engine):
        output = json.dumps({"decision": "allow"})
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed) as mock_run:
            engine.evaluate({
                "tool": "read_file",
                "arguments": {"path": "/home"},
                "agent_id": "agent-1",
            })
            call_args = mock_run.call_args[0][0]
            assert "--tool" in call_args
            assert "read_file" in call_args
            assert "--args" in call_args
            assert "--agent" in call_args
            assert "agent-1" in call_args

    def test_timeout_raises(self, engine):
        with patch(
            "kvlar.engine.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="kvlar", timeout=30),
        ):
            with pytest.raises(KvlarError, match="timed out"):
                engine.evaluate({"tool": "read_file"})

    def test_command_error_raises(self, engine):
        with patch(
            "kvlar.engine.subprocess.run",
            side_effect=subprocess.CalledProcessError(
                returncode=1, cmd="kvlar", stderr="bad policy"
            ),
        ):
            with pytest.raises(KvlarError, match="failed"):
                engine.evaluate({"tool": "read_file"})


# ---------------------------------------------------------------------------
# test_policy() tests
# ---------------------------------------------------------------------------


class TestTestPolicy:
    def test_passing_suite(self, engine):
        output = "Running 3 tests...\n3 passed, 0 failed\nAll tests passed!"
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=output, stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed):
            result = engine.test_policy("policy.test.yaml")
            assert result.passed is True
            assert result.total == 3
            assert result.failures == 0

    def test_failing_suite(self, engine):
        output = "Running 5 tests...\n3 passed, 2 failed"
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout=output, stderr="")

        with patch("kvlar.engine.subprocess.run", return_value=completed):
            result = engine.test_policy("policy.test.yaml")
            assert result.passed is False
            assert result.total == 5
            assert result.failures == 2


# ---------------------------------------------------------------------------
# validate() tests
# ---------------------------------------------------------------------------


class TestValidate:
    def test_valid_policy(self, engine):
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="OK", stderr="")
        with patch("kvlar.engine.subprocess.run", return_value=completed):
            assert engine.validate() is True

    def test_invalid_policy(self, engine):
        completed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="parse error")
        with patch("kvlar.engine.subprocess.run", return_value=completed):
            assert engine.validate() is False


# ---------------------------------------------------------------------------
# Data class tests
# ---------------------------------------------------------------------------


class TestDataClasses:
    def test_decision_values(self):
        assert Decision.ALLOW.value == "allow"
        assert Decision.DENY.value == "deny"
        assert Decision.REQUIRE_APPROVAL.value == "require_approval"

    def test_eval_result_defaults(self):
        r = EvalResult(decision=Decision.ALLOW)
        assert r.rule_id is None
        assert r.reason is None
        assert r.raw == {}

    def test_test_result_defaults(self):
        r = TestResult(passed=True)
        assert r.total == 0
        assert r.failures == 0
        assert r.output == ""
