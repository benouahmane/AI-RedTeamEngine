"""sqlmap wrapper — automated SQL injection detection and exploitation.

Runs `sqlmap --batch` against a URL (optionally with POST data / cookie) and
parses the human-readable report for: whether a parameter is injectable, which
parameters, the injection techniques, the back-end DBMS, and — when the agent
asks to dump — enumerated databases / tables.

Why parse stdout rather than `--results-file`: sqlmap's CSV results file only
covers `--dump`; the injection verdict and DBMS banner live in stdout.
"""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


# "Parameter: id (GET)"  /  "Type: boolean-based blind"  /  "back-end DBMS: MySQL"
_PARAM_RE = re.compile(r"^Parameter:\s*(?P<param>[^\(]+?)\s*\((?P<place>\w+)\)", re.MULTILINE)
_TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>.+)$", re.MULTILINE)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>.+)", re.IGNORECASE)
_INJECTABLE_RE = re.compile(r"is vulnerable|appears to be .*injectable|sqlmap identified", re.IGNORECASE)
_DB_RE = re.compile(r"available databases\s*\[\d+\]:(?P<block>(?:\s*\[\*\]\s*\S+)+)", re.IGNORECASE)


@register
class SqlmapTool(OffensiveTool):
    name = "sqlmap"
    phase = "exploitation"
    mitre_techniques = ["T1190", "T1213"]
    description = """
    Automated SQL injection. Point `url` at a parameterised endpoint (e.g.
    'http://10.0.0.5/item.php?id=1'); pass `data` for POST bodies and `cookie`
    for authenticated testing. Set `action='dbs'` / `'tables'` / `'dump'` to
    enumerate or extract once an injection is confirmed. Always runs --batch
    (non-interactive). Lab targets only.
    """

    ACTIONS = {"test", "dbs", "tables", "dump"}

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "target URL with a parameter"},
                "action": {"type": "string", "enum": sorted(self.ACTIONS), "default": "test"},
                "data": {"type": "string", "description": "POST body, e.g. 'user=a&pass=b'"},
                "cookie": {"type": "string"},
                "db": {"type": "string", "description": "database name for tables/dump"},
                "table": {"type": "string", "description": "table name for dump"},
                "level": {"type": "integer", "default": 1, "description": "1-5"},
                "risk": {"type": "integer", "default": 1, "description": "1-3"},
                "dbms": {"type": "string", "description": "hint, e.g. mysql, mssql, postgresql"},
                "extra_args": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["url"],
        }

    def execute(self, **params: Any) -> ToolResult:
        url = params.get("url")
        if not url:
            return ToolResult(ToolStatus.ERROR, "", "", error="sqlmap requires `url`")
        action = params.get("action", "test")
        if action not in self.ACTIONS:
            return ToolResult(ToolStatus.ERROR, "", "", error=f"unknown action {action!r}")

        argv = ["sqlmap", "-u", url, "--batch", "--disable-coloring",
                "--level", str(params.get("level", 1)), "--risk", str(params.get("risk", 1))]
        if params.get("data"):
            argv += ["--data", params["data"]]
        if params.get("cookie"):
            argv += ["--cookie", params["cookie"]]
        if params.get("dbms"):
            argv += ["--dbms", params["dbms"]]
        if action == "dbs":
            argv += ["--dbs"]
        elif action == "tables":
            argv += ["--tables"]
            if params.get("db"):
                argv += ["-D", params["db"]]
        elif action == "dump":
            argv += ["--dump"]
            if params.get("db"):
                argv += ["-D", params["db"]]
            if params.get("table"):
                argv += ["-T", params["table"]]
        argv += list(params.get("extra_args") or [])

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout,
                              error=stderr.strip() or "timeout", duration_sec=duration)

        findings = _parse(stdout)
        if rc != 0 and not findings["injectable"] and stderr.strip():
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"sqlmap exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        status = ToolStatus.SUCCESS if findings["injectable"] else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status, command=cmd, raw_output=stdout,
            findings=findings, duration_sec=duration,
        )


def _parse(stdout: str) -> dict[str, Any]:
    injectable = bool(_INJECTABLE_RE.search(stdout))
    params = [m.group("param").strip() for m in _PARAM_RE.finditer(stdout)]
    techniques = [m.group("type").strip() for m in _TYPE_RE.finditer(stdout)]
    dbms_match = _DBMS_RE.search(stdout)
    databases: list[str] = []
    db_block = _DB_RE.search(stdout)
    if db_block:
        databases = re.findall(r"\[\*\]\s*(\S+)", db_block.group("block"))

    findings = {
        "injectable": injectable,
        "parameters": params,
        "techniques": techniques,
        "dbms": dbms_match.group("dbms").strip() if dbms_match else None,
        "databases": databases,
    }
    # Surface as a vulnerability the agent can ingest into the register.
    if injectable:
        findings["vulnerabilities"] = [{
            "name": "SQL injection",
            "severity": "high",
            "cve": None,
            "description": f"Injectable parameter(s): {', '.join(params) or 'unknown'}; "
                           f"DBMS: {findings['dbms'] or 'unknown'}",
            "matched_at": params[0] if params else None,
        }]
    return findings
