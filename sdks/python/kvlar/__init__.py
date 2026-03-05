"""Kvlar — Runtime security for AI agents.

Python SDK that wraps the kvlar CLI for policy evaluation and testing.
Requires the `kvlar` binary on PATH (install via `cargo install kvlar-cli`).
"""

from kvlar.engine import KvlarEngine, Decision, KvlarError

__version__ = "0.1.0"
__all__ = ["KvlarEngine", "Decision", "KvlarError"]
