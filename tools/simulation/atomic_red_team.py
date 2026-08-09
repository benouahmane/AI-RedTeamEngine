"""Atomic Red Team wrapper — run individual MITRE ATT&CK atomic tests.

Drives `Invoke-AtomicTest` (the Invoke-AtomicRedTeam PowerShell module) via
`pwsh`. Each atomic maps to a single ATT&CK technique, so this is the engine's
fine-grained technique-validation and purple-team telemetry generator: pick a
technique, optionally check prerequisites, execute, then clean up.

Requires PowerShell (`pwsh`) and the Invoke-AtomicRedTeam module installed.
"""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register

_TECH_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_EXEC_RE = re.compile(r"Executing test:\s*(?P<name>.+)", re.IGNORECASE)
_DONE_RE = re.compile(r"Done executing test:\s*(?P<name>.+)", re.IGNORECASE)
_ERROR_RE = re.compile(r"(?im)^.*(exception|error|failed)\b.*$")


@register
class AtomicRedTeamTool(OffensiveTool):
    name = "atomic_red_team"
    phase = "post_exploit"
    mitre_techniques = ["T1059.001"]
    description = """
    Run a single MITRE ATT&CK atomic test by technique id (e.g. 'T1059.001').
    Use `action='prereqs'` to check/install prerequisites, `'run'` to execute
    (the default), and `'cleanup'` to revert. Each test is mapped to exactly one
    technique, making this ideal for targeted detection validation and for
    generating labelled telemetry for the paired Blue Team engine.
    """

    ACTIONS = {"prereqs", "run", "cleanup", "details"}

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "technique": {"type": "string", "description": "ATT&CK id, e.g. T1003 or T1059.001"},
                "action": {"type": "string", "enum": sorted(self.ACTIONS), "default": "run"},
                "test_numbers": {"type": "array", "items": {"type": "integer"},
                                 "description": "specific atomic test indices to run"},
            },
            "required": ["technique"],
        }

    def execute(self, **params: Any) -> ToolResult:
        technique = (params.get("technique") or "").strip()
        if not _TECH_RE.match(technique):
            return ToolResult(ToolStatus.ERROR, "", "",
                              error=f"invalid technique id {technique!r} (expected like T1059.001)")
        action = params.get("action", "run")
        if action not in self.ACTIONS:
            return ToolResult(ToolStatus.ERROR, "", "", error=f"unknown action {action!r}")

        flag = {
            "prereqs": "-GetPrereqs",
            "run": "",
            "cleanup": "-Cleanup",
            "details": "-ShowDetailsBrief",
        }[action]
        ps = f"Invoke-AtomicTest {technique}"
        if flag:
            ps += f" {flag}"
        if params.get("test_numbers"):
            nums = ",".join(str(int(n)) for n in params["test_numbers"])
            ps += f" -TestNumbers {nums}"

        argv = ["pwsh", "-NoProfile", "-Command",
                f"Import-Module Invoke-AtomicRedTeam -ErrorAction Stop; {ps}"]
        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout,
                              error=stderr.strip() or "timeout", duration_sec=duration)

        executed = [m.group("name").strip() for m in _EXEC_RE.finditer(stdout)]
        completed = [m.group("name").strip() for m in _DONE_RE.finditer(stdout)]
        errors = [m.group(0).strip() for m in _ERROR_RE.finditer(stdout + "\n" + stderr)][:10]

        findings = {
            "technique": technique,
            "action": action,
            "executed_tests": executed,
            "completed_tests": completed,
            "errors": errors,
        }
        if rc != 0 and not executed and stderr.strip():
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"Invoke-AtomicTest exited {rc}: {stderr.strip()[:300]}",
                findings=findings, duration_sec=duration,
            )

        status = ToolStatus.SUCCESS if (executed or completed) else ToolStatus.NO_FINDINGS
        return ToolResult(status, cmd, stdout, findings=findings, duration_sec=duration)
