"""John the Ripper wrapper — offline hash cracking.

Two-phase: (1) `john [opts] <hashfile>` to crack, (2) `john --show <hashfile>`
to dump cracked credentials in `user:password:::extra` form.
"""
from __future__ import annotations

from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


@register
class JohnTool(OffensiveTool):
    name = "john"
    phase = "post_exploit"
    mitre_techniques = ["T1110.002"]
    description = """
    Offline hash cracker. Use after dumping /etc/shadow, NTDS.dit, or
    SAM hashes. Supports many hash formats — pass `format` if known.
    """

    DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "format": {"type": "string", "description": "e.g. NT, sha512crypt, krb5tgs"},
                "wordlist": {"type": "string"},
                "rules": {"type": "boolean", "default": False},
                "session": {"type": "string", "description": "named session for resume"},
            },
            "required": ["hash_file"],
        }

    def execute(self, **params: Any) -> ToolResult:
        hash_file = params["hash_file"]
        fmt = params.get("format")
        wordlist = params.get("wordlist") or self.DEFAULT_WORDLIST
        rules = params.get("rules", False)
        session = params.get("session")

        argv = ["john", f"--wordlist={wordlist}"]
        if fmt:
            argv += [f"--format={fmt}"]
        if rules:
            argv += ["--rules"]
        if session:
            argv += [f"--session={session}"]
        argv += [hash_file]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(
                ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration,
            )

        # Phase 2: --show to extract cracked credentials
        show_argv = ["john", "--show"]
        if fmt:
            show_argv += [f"--format={fmt}"]
        show_argv += [hash_file]
        rc2, show_out, show_err, dur2 = self._run(show_argv, timeout=60)
        if rc2 == -1:
            show_out = ""

        cracked: list[dict[str, Any]] = []
        for line in show_out.splitlines():
            line = line.strip()
            if not line or line.startswith(("0 password", "No password")):
                continue
            # Skip the trailing summary line "N password hashes cracked, M left"
            if "password hashes cracked" in line.lower() or "password hash cracked" in line.lower():
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                cracked.append({
                    "username": parts[0],
                    "password": parts[1],
                })

        if rc != 0 and not cracked and stderr.strip():
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"john exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        status = ToolStatus.SUCCESS if cracked else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout + "\n--- show ---\n" + show_out,
            findings={
                "format": fmt,
                "credentials": cracked,
                "count": len(cracked),
            },
            duration_sec=duration + dur2,
        )
