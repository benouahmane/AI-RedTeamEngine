"""Standard interface every offensive tool wrapper implements.

Contract:
- `name`, `phase`, `mitre_techniques` are class-level metadata used by the agent
  to reason about which tool to pick.
- `execute(**params)` runs the tool and returns a `ToolResult` with structured
  `findings`, the raw output, and the exact command that was run.
- `param_schema()` lets the agent learn the expected parameters from the tool
  itself rather than hardcoding them in the system prompt.
"""
from __future__ import annotations

import enum
import shlex
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from config import settings


class ToolStatus(str, enum.Enum):
    SUCCESS = "success"
    NO_FINDINGS = "no_findings"
    PARTIAL = "partial"           # tool ran but output was malformed/incomplete
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ToolResult:
    status: ToolStatus
    command: str
    raw_output: str
    findings: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "command": self.command,
            "findings": self.findings,
            "error": self.error,
            "duration_sec": round(self.duration_sec, 2),
        }


class OffensiveTool(ABC):
    """Abstract base class for tool wrappers."""

    # ─── class-level metadata (the agent reads these) ────────────────────
    name: ClassVar[str]
    phase: ClassVar[str]                          # see memory.models.AttackPhase values
    mitre_techniques: ClassVar[list[str]] = []
    description: ClassVar[str] = ""

    # ─── lifecycle ───────────────────────────────────────────────────────
    @abstractmethod
    def execute(self, **params: Any) -> ToolResult:
        """Run the tool with the given parameters and return structured findings."""

    def param_schema(self) -> dict[str, Any]:
        """JSON-schema-ish description of accepted params; override per tool.

        The agent uses this to construct valid tool calls. Default returns an
        empty schema — concrete wrappers should override.
        """
        return {"type": "object", "properties": {}, "required": []}

    # ─── helpers shared by subprocess-backed wrappers ────────────────────
    def _run(
        self,
        argv: list[str],
        *,
        timeout: int | None = None,
        check: bool = False,
        input_data: str | None = None,
    ) -> tuple[int, str, str, float]:
        """Run a subprocess and return (returncode, stdout, stderr, duration_sec).

        Use this from concrete `execute()` methods rather than calling
        `subprocess.run` directly so timeout handling and command logging are
        consistent across every tool.
        """
        import time

        timeout = timeout or settings.tool_execution_timeout_sec
        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check,
                input=input_data,
            )
            duration = time.monotonic() - start
            return proc.returncode, proc.stdout, proc.stderr, duration
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            return -1, exc.stdout or "", f"Timeout after {timeout}s", duration

    @staticmethod
    def quote(argv: list[str]) -> str:
        return shlex.join(argv)
