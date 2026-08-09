"""theHarvester wrapper — passive OSINT (emails, subdomains, hosts).

Runs `theHarvester -d <domain> -b <sources> -f <prefix>` and reads the
generated JSON file (theHarvester writes <prefix>.json next to the prefix).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


_DEFAULT_SOURCES = ["bing", "duckduckgo", "crtsh", "hackertarget"]


@register
class TheHarvesterTool(OffensiveTool):
    name = "theharvester"
    phase = "recon"
    mitre_techniques = ["T1589", "T1590", "T1596"]
    description = """
    Passive OSINT collector — gathers emails, subdomains, IPs, and employee
    names from public sources. Use only against the engagement's target domain.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "sources": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["domain"],
        }

    def execute(self, **params: Any) -> ToolResult:
        domain = params["domain"]
        sources = params.get("sources") or _DEFAULT_SOURCES
        limit = params.get("limit", 100)

        with tempfile.TemporaryDirectory(prefix="harvester-") as tmpdir:
            prefix = Path(tmpdir) / "out"
            argv = [
                "theHarvester",
                "-d", domain,
                "-b", ",".join(sources),
                "-l", str(limit),
                "-f", str(prefix),
            ]

            rc, stdout, stderr, duration = self._run(argv)
            cmd = self.quote(argv)

            if rc == -1:
                return ToolResult(
                    ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration,
                )

            json_path = prefix.with_suffix(".json")
            findings: dict[str, Any] = {"domain": domain}
            if json_path.exists():
                try:
                    data = json.loads(json_path.read_text())
                    findings["emails"] = data.get("emails") or []
                    findings["hosts"] = data.get("hosts") or []
                    findings["ips"] = data.get("ips") or []
                    findings["asns"] = data.get("asns") or []
                    findings["urls"] = data.get("urls") or []
                except (json.JSONDecodeError, OSError) as exc:
                    return ToolResult(
                        ToolStatus.PARTIAL, cmd, stdout,
                        findings=findings,
                        error=f"could not parse {json_path.name}: {exc}",
                        duration_sec=duration,
                    )
            else:
                # theHarvester sometimes prints results to stdout but writes no JSON
                # if all sources fail — surface it as PARTIAL rather than ERROR.
                if rc != 0:
                    return ToolResult(
                        ToolStatus.ERROR, cmd, stdout + stderr,
                        error=f"theHarvester exited {rc}: {stderr.strip()[:300]}",
                        duration_sec=duration,
                    )

            total = sum(len(findings.get(k) or []) for k in ("emails", "hosts", "ips", "urls"))
            findings["total"] = total
            status = ToolStatus.SUCCESS if total else ToolStatus.NO_FINDINGS
            return ToolResult(
                status=status,
                command=cmd,
                raw_output=stdout,
                findings=findings,
                duration_sec=duration,
            )
