"""Kvlar policy engine — subprocess wrapper around the kvlar CLI."""

from __future__ import annotations

import json
import subprocess
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class KvlarError(Exception):
    """Raised when the kvlar CLI is missing or returns an unexpected error."""


class Decision(Enum):
    """Policy evaluation outcome."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class EvalResult:
    """Result of a policy evaluation."""

    decision: Decision
    rule_id: str | None = None
    reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    """Result of running a policy test suite."""

    passed: bool
    total: int = 0
    failures: int = 0
    output: str = ""


class KvlarEngine:
    """Wraps the ``kvlar`` CLI binary for policy evaluation.

    Parameters
    ----------
    policy_path:
        Path to the YAML policy file.
    binary:
        Name or path of the kvlar binary.  Defaults to ``"kvlar"``.
    """

    def __init__(self, policy_path: str | Path, *, binary: str = "kvlar") -> None:
        self.policy_path = Path(policy_path)
        self.binary = binary
        self._resolve_binary()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, action: dict[str, Any]) -> EvalResult:
        """Evaluate a tool-call action against the loaded policy.

        Parameters
        ----------
        action:
            A dict with at least ``"tool"`` (str).  May include
            ``"arguments"`` (dict) and ``"agent_id"`` (str).

        Returns
        -------
        EvalResult
            The policy decision, optional rule id, reason, and raw JSON.
        """
        args = [
            self.binary,
            "eval",
            "-f",
            str(self.policy_path),
            "--tool",
            action["tool"],
        ]

        tool_args = action.get("arguments", {})
        if tool_args:
            args.extend(["--args", json.dumps(tool_args)])

        agent_id = action.get("agent_id")
        if agent_id:
            args.extend(["--agent", agent_id])

        result = self._run(args)

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Fallback: parse the human-readable output
            stdout = result.stdout.strip().lower()
            if "allow" in stdout:
                return EvalResult(decision=Decision.ALLOW, raw={})
            if "require" in stdout and "approval" in stdout:
                return EvalResult(decision=Decision.REQUIRE_APPROVAL, raw={})
            return EvalResult(decision=Decision.DENY, raw={})

        decision_str = data.get("decision", "deny").lower()
        try:
            decision = Decision(decision_str)
        except ValueError:
            decision = Decision.DENY

        return EvalResult(
            decision=decision,
            rule_id=data.get("rule_id"),
            reason=data.get("reason"),
            raw=data,
        )

    def test_policy(self, test_file: str | Path) -> TestResult:
        """Run a ``kvlar test`` suite against a test-YAML file.

        Parameters
        ----------
        test_file:
            Path to the ``.test.yaml`` file.

        Returns
        -------
        TestResult
        """
        args = [self.binary, "test", "-f", str(test_file)]
        result = self._run(args, check=False)

        output = result.stdout + result.stderr
        passed = result.returncode == 0

        # Try to extract counts from output (e.g., "5 passed, 1 failed")
        total = 0
        failures = 0
        for line in output.splitlines():
            line_lower = line.lower()
            if "passed" in line_lower or "failed" in line_lower:
                import re

                nums = re.findall(r"(\d+)\s+(passed|failed)", line_lower)
                for count, kind in nums:
                    total += int(count)
                    if kind == "failed":
                        failures += int(count)

        return TestResult(
            passed=passed,
            total=total,
            failures=failures,
            output=output.strip(),
        )

    def validate(self) -> bool:
        """Validate the policy file syntax.

        Returns ``True`` if the policy is valid.
        """
        args = [self.binary, "validate", "-f", str(self.policy_path)]
        result = self._run(args, check=False)
        return result.returncode == 0

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _resolve_binary(self) -> None:
        """Verify the kvlar binary is available."""
        if shutil.which(self.binary) is None:
            raise KvlarError(
                f"kvlar binary not found: '{self.binary}'. "
                "Install it with: cargo install kvlar-cli"
            )

    def _run(
        self,
        args: list[str],
        *,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run a kvlar CLI command and return the result."""
        try:
            return subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=30,
                check=check,
            )
        except subprocess.TimeoutExpired as exc:
            raise KvlarError(f"kvlar command timed out: {' '.join(args)}") from exc
        except subprocess.CalledProcessError as exc:
            raise KvlarError(
                f"kvlar command failed (exit {exc.returncode}): {exc.stderr.strip()}"
            ) from exc
        except FileNotFoundError as exc:
            raise KvlarError(
                f"kvlar binary not found: '{self.binary}'. "
                "Install it with: cargo install kvlar-cli"
            ) from exc
