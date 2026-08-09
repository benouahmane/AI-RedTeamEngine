"""Nuclei wrapper — template-based CVE/misconfiguration scanner.

Runs with `-jsonl` for line-delimited JSON output and parses each finding.
"""
from __future__ import annotations

import json
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]


@register
class NucleiTool(OffensiveTool):
    name = "nuclei"
    phase = "vuln_id"
    mitre_techniques = ["T1595.002", "T1190"]
    description = """
    Template-based vulnerability scanner with thousands of CVE checks.
    Use after recon has identified live HTTP/network services. Filter by
    severity to keep noise down (e.g. severities=['high','critical']).
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or IP"},
                "severities": {
                    "type": "array",
                    "items": {"type": "string", "enum": _SEVERITY_ORDER},
                },
                "tags": {"type": "array", "items": {"type": "string"}},
                "rate_limit": {"type": "integer", "default": 150},
            },
            "required": ["target"],
        }

    def execute(self, **params: Any) -> ToolResult:
        target = params["target"]
        severities = params.get("severities") or ["medium", "high", "critical"]
        tags = params.get("tags") or []
        rate_limit = params.get("rate_limit", 150)

        argv = [
            "nuclei",
            "-target", target,
            "-jsonl",
            "-silent",
            "-severity", ",".join(severities),
            "-rl", str(rate_limit),
        ]
        if tags:
            argv += ["-tags", ",".join(tags)]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration)

        findings: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = doc.get("info") or {}
            findings.append({
                "template_id": doc.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": doc.get("matched-at"),
                "host": doc.get("host"),
                "type": doc.get("type"),
                "cve": (info.get("classification") or {}).get("cve-id"),
                "cvss_score": (info.get("classification") or {}).get("cvss-score"),
                "description": info.get("description"),
                "reference": info.get("reference"),
            })

        if rc != 0 and not findings:
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"nuclei exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        # Severity tally for the agent
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity") or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        status = ToolStatus.SUCCESS if findings else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout,
            findings={
                "target": target,
                "vulnerabilities": findings,
                "severity_counts": severity_counts,
                "total": len(findings),
            },
            duration_sec=duration,
        )
