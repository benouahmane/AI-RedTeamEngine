"""Nikto wrapper — known web server vulnerability checks.

Uses `-Format json -output <tmpfile>` since nikto's stdout is human-readable
mixed with progress lines and not safe to parse.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


@register
class NiktoTool(OffensiveTool):
    name = "nikto"
    phase = "vuln_id"
    mitre_techniques = ["T1595.002"]
    description = """
    Web server vulnerability scanner — checks for outdated software, dangerous
    files, server misconfigurations, default credentials.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer", "default": 80},
                "ssl": {"type": "boolean", "default": False},
            },
            "required": ["host"],
        }

    def execute(self, **params: Any) -> ToolResult:
        host = params["host"]
        port = params.get("port", 80)
        ssl = params.get("ssl", False)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fp:
            outfile = Path(fp.name)

        try:
            argv = [
                "nikto",
                "-h", host,
                "-port", str(port),
                "-Format", "json",
                "-output", str(outfile),
                "-ask", "no",
                "-nointeractive",
            ]
            if ssl:
                argv += ["-ssl"]

            rc, stdout, stderr, duration = self._run(argv)
            cmd = self.quote(argv)

            if rc == -1:
                return ToolResult(
                    ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration,
                )

            vulnerabilities: list[dict[str, Any]] = []
            target_meta: dict[str, Any] = {}
            if outfile.exists() and outfile.stat().st_size > 0:
                try:
                    data = json.loads(outfile.read_text())
                    # nikto json structure: {"host":..., "port":..., "vulnerabilities":[...]}
                    if isinstance(data, list) and data:
                        data = data[0]
                    target_meta = {
                        "host": data.get("host") or host,
                        "ip": data.get("ip"),
                        "port": data.get("port") or port,
                        "banner": data.get("banner"),
                    }
                    for v in data.get("vulnerabilities") or []:
                        vulnerabilities.append({
                            "id": v.get("id"),
                            "osvdb": v.get("OSVDB") or v.get("osvdb"),
                            "method": v.get("method"),
                            "url": v.get("url"),
                            "name": v.get("msg") or v.get("description"),
                            "description": v.get("msg") or v.get("description"),
                            "host": data.get("host") or host,
                            "severity": "info",
                        })
                except json.JSONDecodeError as exc:
                    return ToolResult(
                        ToolStatus.PARTIAL, cmd, stdout,
                        error=f"could not parse nikto json: {exc}",
                        duration_sec=duration,
                    )

            if rc != 0 and not vulnerabilities:
                return ToolResult(
                    ToolStatus.ERROR, cmd, stdout + stderr,
                    error=f"nikto exited {rc}: {stderr.strip()[:300]}",
                    duration_sec=duration,
                )

            status = ToolStatus.SUCCESS if vulnerabilities else ToolStatus.NO_FINDINGS
            return ToolResult(
                status=status,
                command=cmd,
                raw_output=stdout,
                findings={
                    **target_meta,
                    "vulnerabilities": vulnerabilities,
                    "count": len(vulnerabilities),
                },
                duration_sec=duration,
            )
        finally:
            outfile.unlink(missing_ok=True)
