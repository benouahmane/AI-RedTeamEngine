"""Hashcat wrapper — GPU-accelerated hash cracking.

Two-phase: (1) run hashcat to crack, (2) re-invoke with `--show` to extract
cracked pairs from the potfile in a deterministic format.
"""
from __future__ import annotations

from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


@register
class HashcatTool(OffensiveTool):
    name = "hashcat"
    phase = "post_exploit"
    mitre_techniques = ["T1110.002"]
    description = """
    GPU hash cracker. Faster than John for large NTLM/Kerberos hash sets.
    Specify `mode` (e.g. 1000=NTLM, 13100=Kerberos AS-REP).
    """

    DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string"},
                "mode": {"type": "integer", "description": "hashcat -m mode number"},
                "wordlist": {"type": "string"},
                "rules": {"type": "string", "description": "rules file path"},
                "attack_mode": {
                    "type": "integer",
                    "default": 0,
                    "description": "0=straight, 3=brute-force, 6=hybrid",
                },
                "force": {"type": "boolean", "default": True},
            },
            "required": ["hash_file", "mode"],
        }

    def execute(self, **params: Any) -> ToolResult:
        hash_file = params["hash_file"]
        mode = int(params["mode"])
        wordlist = params.get("wordlist") or self.DEFAULT_WORDLIST
        rules = params.get("rules")
        attack_mode = int(params.get("attack_mode", 0))
        force = params.get("force", True)

        argv = [
            "hashcat",
            "-m", str(mode),
            "-a", str(attack_mode),
            "--quiet",
            "--potfile-disable=0",
            hash_file,
            wordlist,
        ]
        if rules:
            argv += ["-r", rules]
        if force:
            argv += ["--force"]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(
                ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration,
            )
        # hashcat returns 0 on success, 1 when "exhausted with no hits".
        # Anything else combined with empty stdout is a real error.
        if rc not in (0, 1) and not stdout.strip():
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"hashcat exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        # Phase 2: --show to dump cracked hashes in `hash:plain` format
        show_argv = ["hashcat", "-m", str(mode), "--show", "--quiet", hash_file]
        rc2, show_out, show_err, dur2 = self._run(show_argv, timeout=60)
        if rc2 == -1:
            show_out = ""

        cracked: list[dict[str, Any]] = []
        for line in show_out.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            # hashcat prints `hash:plaintext` (sometimes with extra colons in the hash)
            hash_part, _, plain = line.rpartition(":")
            cracked.append({"hash": hash_part, "plaintext": plain})

        status = ToolStatus.SUCCESS if cracked else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout + "\n--- show ---\n" + show_out,
            findings={
                "mode": mode,
                "credentials": cracked,
                "count": len(cracked),
            },
            duration_sec=duration + dur2,
        )
