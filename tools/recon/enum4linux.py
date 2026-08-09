"""enum4linux-ng wrapper — SMB / LDAP / RPC enumeration.

enum4linux-ng can emit structured YAML/JSON with `-oJ <prefix>` (writes
`<prefix>.json`). We prefer that over scraping its console output. Parses out
the OS, domain/workgroup, users, groups, and shares — the bread-and-butter of
Windows/Samba enumeration that feeds credential spraying and lateral movement.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


@register
class Enum4linuxTool(OffensiveTool):
    name = "enum4linux"
    phase = "enumeration"
    mitre_techniques = ["T1087", "T1135", "T1069"]
    description = """
    SMB/RPC/LDAP enumerator for Windows and Samba hosts. Run after recon finds
    139/445 open to list users, groups, shares, password policy, and the
    domain/workgroup. Null-session by default; supply `username`/`password`
    for authenticated enumeration. Feeds discovered users into credential
    attacks and shares into lateral movement.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP or hostname"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "shares": {"type": "boolean", "default": True},
                "users": {"type": "boolean", "default": True},
                "groups": {"type": "boolean", "default": True},
                "policy": {"type": "boolean", "default": True},
            },
            "required": ["target"],
        }

    def execute(self, **params: Any) -> ToolResult:
        target = params.get("target")
        if not target:
            return ToolResult(ToolStatus.ERROR, "", "", error="enum4linux requires `target`")

        with tempfile.TemporaryDirectory() as tmp:
            prefix = str(Path(tmp) / "e4l")
            argv = ["enum4linux-ng", "-A", "-oJ", prefix]
            if params.get("username"):
                argv += ["-u", params["username"]]
            if params.get("password"):
                argv += ["-p", params["password"]]
            argv.append(target)

            rc, stdout, stderr, duration = self._run(argv)
            cmd = self.quote(argv)

            if rc == -1:
                return ToolResult(ToolStatus.TIMEOUT, cmd, stdout,
                                  error=stderr.strip() or "timeout", duration_sec=duration)

            data: dict[str, Any] = {}
            json_path = Path(prefix + ".json")
            if json_path.exists():
                try:
                    data = json.loads(json_path.read_text())
                except (json.JSONDecodeError, OSError):
                    data = {}

        findings = _parse(data, target)
        if not data and rc != 0 and stderr.strip():
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"enum4linux-ng exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        has_signal = bool(findings["users"] or findings["shares"] or findings["groups"])
        status = ToolStatus.SUCCESS if has_signal else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status, command=cmd, raw_output=stdout or json.dumps(data)[:5000],
            findings=findings, duration_sec=duration,
        )


def _parse(data: dict[str, Any], target: str) -> dict[str, Any]:
    def _names(section: Any) -> list[str]:
        """enum4linux-ng nests results as {index: {username/groupname/...}} maps."""
        out: list[str] = []
        if isinstance(section, dict):
            for v in section.values():
                if isinstance(v, dict):
                    name = v.get("username") or v.get("groupname") or v.get("name")
                    if name:
                        out.append(name)
                elif isinstance(v, str):
                    out.append(v)
        elif isinstance(section, list):
            out = [str(v) for v in section]
        return out

    os_info = data.get("os_info") or {}
    smb_info = data.get("smb_dialects") or {}
    shares_raw = data.get("shares") or {}
    shares = []
    if isinstance(shares_raw, dict):
        for name, meta in shares_raw.items():
            access = (meta or {}).get("access") if isinstance(meta, dict) else None
            shares.append({"name": name, "access": access})

    return {
        "target": target,
        "os": os_info.get("OS") or os_info.get("os") if isinstance(os_info, dict) else None,
        "domain": data.get("domain") or (data.get("workgroup") if isinstance(data, dict) else None),
        "users": _names(data.get("users")),
        "groups": _names(data.get("groups")),
        "shares": shares,
        "smb": smb_info if isinstance(smb_info, dict) else {},
    }
