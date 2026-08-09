"""Hydra wrapper — online credential brute-forcer.

Parses hydra's stdout for `[<port>][<service>] host: ... login: ... password: ...`
success lines, plus the final "X valid passwords found" summary.
"""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


_HIT_RE = re.compile(
    r"\[(?P<port>\d+)\]\[(?P<service>[\w\-]+)\]\s+host:\s*(?P<host>\S+)"
    r"(?:\s+login:\s*(?P<login>\S+))?"
    r"(?:\s+password:\s*(?P<password>\S+))?"
)
_VALID_RE = re.compile(r"(\d+)\s+valid\s+password(?:s)?\s+found", re.IGNORECASE)


@register
class HydraTool(OffensiveTool):
    name = "hydra"
    phase = "exploitation"
    mitre_techniques = ["T1110.001", "T1110.003"]
    description = """
    Online password brute-forcer. Use against SSH, FTP, RDP, SMB, HTTP forms.
    Always supply a curated wordlist; never run against production.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "service": {"type": "string", "description": "ssh|ftp|smb|rdp|http-post-form|..."},
                "userlist": {"type": "string", "description": "path to user wordlist"},
                "passlist": {"type": "string", "description": "path to password wordlist"},
                "username": {"type": "string", "description": "single username (alternative to userlist)"},
                "password": {"type": "string", "description": "single password (alternative to passlist)"},
                "port": {"type": "integer"},
                "threads": {"type": "integer", "default": 4},
                "stop_on_first": {"type": "boolean", "default": True},
                "extra_args": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["target", "service"],
        }

    def execute(self, **params: Any) -> ToolResult:
        target = params["target"]
        service = params["service"]
        userlist = params.get("userlist")
        passlist = params.get("passlist")
        username = params.get("username")
        password = params.get("password")
        port = params.get("port")
        threads = params.get("threads", 4)
        stop_on_first = params.get("stop_on_first", True)
        extra = list(params.get("extra_args") or [])

        if not (userlist or username):
            return ToolResult(
                ToolStatus.ERROR, "", "",
                error="must supply either `userlist` or `username`",
            )
        if not (passlist or password):
            return ToolResult(
                ToolStatus.ERROR, "", "",
                error="must supply either `passlist` or `password`",
            )

        argv = ["hydra", "-t", str(threads), "-I"]
        if username:
            argv += ["-l", username]
        else:
            argv += ["-L", userlist]
        if password:
            argv += ["-p", password]
        else:
            argv += ["-P", passlist]
        if port:
            argv += ["-s", str(port)]
        if stop_on_first:
            argv += ["-f"]
        argv += extra
        argv += [target, service]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(
                ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration,
            )

        credentials: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            m = _HIT_RE.search(line)
            if not m:
                continue
            credentials.append({
                "host": m.group("host"),
                "port": int(m.group("port")),
                "service": m.group("service"),
                "username": m.group("login"),
                "password": m.group("password"),
            })

        valid_count = 0
        m_valid = _VALID_RE.search(stdout)
        if m_valid:
            valid_count = int(m_valid.group(1))

        # rc != 0 isn't necessarily an error — hydra exits 0 on success and
        # may exit non-zero when 0 creds are found; only treat it as error
        # if there's a real stderr message and no findings.
        if rc not in (0,) and not credentials and stderr.strip():
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"hydra exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        status = ToolStatus.SUCCESS if credentials else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout,
            findings={
                "target": target,
                "service": service,
                "credentials": credentials,
                "count": len(credentials),
                "reported_valid": valid_count,
            },
            duration_sec=duration,
        )
