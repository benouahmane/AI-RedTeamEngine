"""Gobuster wrapper — directory/file/vhost/dns brute-forcing.

Currently implements directory mode against an HTTP target.
"""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


_LINE_RE = re.compile(r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]")


@register
class GobusterTool(OffensiveTool):
    name = "gobuster"
    phase = "enumeration"
    mitre_techniques = ["T1595.003"]
    description = """
    Directory/file/vhost brute-forcer. Use against any HTTP service after
    initial recon to surface hidden endpoints, admin panels, and backup files.
    """

    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "e.g. http://10.0.0.5"},
                "wordlist": {"type": "string"},
                "extensions": {"type": "string", "description": "comma-sep, e.g. 'php,html'"},
                "threads": {"type": "integer", "default": 50},
                "status_codes": {"type": "string", "default": "200,204,301,302,307,401,403"},
            },
            "required": ["url"],
        }

    def execute(self, **params: Any) -> ToolResult:
        url = params["url"]
        wordlist = params.get("wordlist") or self.DEFAULT_WORDLIST
        threads = params.get("threads", 50)
        extensions = params.get("extensions")
        status_codes = params.get("status_codes", "200,204,301,302,307,401,403")

        argv = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-t", str(threads),
            "-s", status_codes,
            "-q",                  # quiet — drop banner
            "--no-error",
        ]
        if extensions:
            argv += ["-x", extensions]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration)
        if rc != 0 and not stdout.strip():
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"gobuster exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        paths: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            m = _LINE_RE.match(line.strip())
            if m:
                paths.append({
                    "path": m.group("path"),
                    "status": int(m.group("status")),
                    "size": int(m.group("size")),
                })

        status = ToolStatus.SUCCESS if paths else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout,
            findings={"url": url, "paths": paths, "count": len(paths)},
            duration_sec=duration,
        )
