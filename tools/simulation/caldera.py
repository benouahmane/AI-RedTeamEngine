"""MITRE CALDERA wrapper — automated adversary emulation via the REST API.

Talks to a running CALDERA server (`caldera_url` + `caldera_api_key` in .env)
over its v2 API. Useful for MITRE ATT&CK-mapped, repeatable attack chains that
complement the engine's interactive tooling — and for generating telemetry the
paired Blue Team project (P2-BLUE) can detect.

Actions:
  - list_adversaries  — available adversary profiles (ability chains)
  - list_agents       — deployed CALDERA agents (sandcat/manx) and their host
  - start_operation   — launch an adversary profile against the agent group
  - operation_report  — pull the result of a running/finished operation
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from config import settings
from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


@register
class CalderaTool(OffensiveTool):
    name = "caldera"
    phase = "objective"
    mitre_techniques = ["T1059", "T1071", "T1105"]
    description = """
    MITRE CALDERA adversary emulation. Requires CALDERA agents already deployed
    on lab targets. Use `action='list_adversaries'` / `'list_agents'` to
    discover what's available, `action='start_operation'` with an
    `adversary_id` to launch an ATT&CK-mapped chain, and
    `action='operation_report'` with `operation_id` to collect results. Ideal
    for repeatable, fully-mapped attack simulations and purple-team telemetry.
    """

    ACTIONS = {"list_adversaries", "list_agents", "start_operation", "operation_report"}

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": sorted(self.ACTIONS)},
                "adversary_id": {"type": "string", "description": "for start_operation"},
                "group": {"type": "string", "default": "red", "description": "agent group to target"},
                "name": {"type": "string", "description": "operation name"},
                "operation_id": {"type": "string", "description": "for operation_report"},
                "planner": {"type": "string", "default": "atomic"},
            },
            "required": ["action"],
        }

    def execute(self, **params: Any) -> ToolResult:
        action = params.get("action")
        if action not in self.ACTIONS:
            return ToolResult(ToolStatus.ERROR, "", "", error=f"unknown action {action!r}")

        start = time.monotonic()
        try:
            if action == "list_adversaries":
                data = self._request("GET", "/api/v2/adversaries")
                rows = [{"adversary_id": a.get("adversary_id"), "name": a.get("name"),
                         "abilities": len(a.get("atomic_ordering") or [])} for a in data]
                return self._ok("GET /api/v2/adversaries", {"adversaries": rows, "count": len(rows)}, start)

            if action == "list_agents":
                data = self._request("GET", "/api/v2/agents")
                rows = [{"paw": a.get("paw"), "host": a.get("host"), "platform": a.get("platform"),
                         "username": a.get("username"), "group": a.get("group")} for a in data]
                return self._ok("GET /api/v2/agents", {"agents": rows, "count": len(rows)}, start)

            if action == "start_operation":
                adv = params.get("adversary_id")
                if not adv:
                    return ToolResult(ToolStatus.ERROR, "", "", error="start_operation requires adversary_id")
                body = {
                    "name": params.get("name") or f"op-{int(time.time())}",
                    "adversary": {"adversary_id": adv},
                    "group": params.get("group", "red"),
                    "planner": {"id": params.get("planner", "atomic")},
                    "autonomous": 1,
                }
                data = self._request("POST", "/api/v2/operations", json=body)
                op_id = data.get("id") if isinstance(data, dict) else None
                return self._ok("POST /api/v2/operations",
                                {"operation_id": op_id, "state": (data or {}).get("state")}, start)

            if action == "operation_report":
                op_id = params.get("operation_id")
                if not op_id:
                    return ToolResult(ToolStatus.ERROR, "", "", error="operation_report requires operation_id")
                data = self._request("POST", f"/api/v2/operations/{op_id}/report", json={})
                steps = _summarise_report(data)
                status = ToolStatus.SUCCESS if steps["executed"] else ToolStatus.NO_FINDINGS
                return ToolResult(status, f"POST /api/v2/operations/{op_id}/report", "",
                                  findings={"operation_id": op_id, **steps},
                                  duration_sec=time.monotonic() - start)
        except httpx.HTTPError as exc:
            return ToolResult(ToolStatus.ERROR, f"<caldera {action}>", "",
                              error=f"CALDERA API error: {type(exc).__name__}: {exc}",
                              duration_sec=time.monotonic() - start)

        return ToolResult(ToolStatus.ERROR, "", "", error=f"unhandled action {action!r}")

    # ─── helpers ──────────────────────────────────────────────────────────

    def _request(self, method: str, path: str, *, json: dict | None = None) -> Any:
        """One CALDERA REST call. Patched in tests to avoid a live server."""
        resp = httpx.request(
            method,
            f"{settings.caldera_url.rstrip('/')}{path}",
            headers={"KEY": settings.caldera_api_key, "Content-Type": "application/json"},
            json=json,
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _ok(cmd: str, findings: dict[str, Any], start: float) -> ToolResult:
        count = findings.get("count")
        status = ToolStatus.NO_FINDINGS if count == 0 else ToolStatus.SUCCESS
        return ToolResult(status, cmd, "", findings=findings, duration_sec=time.monotonic() - start)


def _summarise_report(report: Any) -> dict[str, Any]:
    """Reduce a CALDERA operation report to executed-link counts.

    Accepts either a top-level `links` list or a `steps` list (CALDERA's report
    shape has shifted across versions); a CALDERA link `status` of 0 == success.
    """
    if not isinstance(report, dict):
        return {"executed": 0, "succeeded": 0, "steps": []}
    links = report.get("links")
    if links is None:
        steps_field = report.get("steps")
        links = steps_field if isinstance(steps_field, list) else []

    out: list[dict[str, Any]] = []
    succeeded = 0
    for link in links or []:
        ability = link.get("ability") if isinstance(link.get("ability"), dict) else {}
        if link.get("status") == 0:
            succeeded += 1
        out.append({
            "ability": ability.get("name") or link.get("name"),
            "technique": ability.get("technique_id") or link.get("technique_id"),
            "status": link.get("status"),
            "host": link.get("host") or link.get("paw"),
        })
    return {"executed": len(out), "succeeded": succeeded, "steps": out}
