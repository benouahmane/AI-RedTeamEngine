"""CrackMapExec / NetExec wrapper — AD swiss-army knife.

Supports SMB / LDAP / WinRM / MSSQL / SSH protocols. Useful in three modes:

  - **auth probe**: spray a credential against a CIDR; flag valid logins and
    `Pwn3d!` hosts where the principal is local admin.
  - **enumeration**: pair auth with `--shares` / `--sessions` / `--users` /
    `--loggedon-users` to list resources.
  - **secret extraction**: with `--sam` / `--lsa` / `--ntds` (or `-M lsassy`).

Output is line-based with a fixed prefix (`PROTO  HOST  PORT  NAME  [marker] …`)
and `[+]`/`[*]`/`[-]` semantics — easy to parse with a single regex.
"""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


_PROTOCOLS = ("smb", "ldap", "winrm", "mssql", "ssh", "ftp", "rdp")

# CME / nxc lines look like:
#   SMB  10.0.0.5  445  DC01  [+] LAB.LOCAL\admin:Password1 (Pwn3d!)
# ANSI colour codes are stripped before matching.
_LINE = re.compile(
    r"^(?P<proto>\w+)\s+(?P<host>\S+)\s+(?P<port>\d+)\s+"
    r"(?P<name>\S+)\s+\[(?P<marker>[+\-*])\]\s+(?P<msg>.*)$"
)
_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_PWN3D = re.compile(r"\(Pwn3d!\)", re.IGNORECASE)
# For credential lines: `DOMAIN\user:password` or `user:password` or `user:hash`
_CRED = re.compile(r"^(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^:\s]+):(?P<secret>\S+)")


@register
class CrackMapExecTool(OffensiveTool):
    name = "crackmapexec"
    phase = "lateral_movement"
    mitre_techniques = ["T1110.001", "T1021.002", "T1003"]
    description = """
    SMB/LDAP/MSSQL/SSH/WinRM swiss-army knife — credential spraying, lateral
    movement, share enumeration, secrets dumping. Use `--shares` to list
    accessible shares, `--sam`/`--lsa`/`--ntds` to dump secrets, or pass a
    `module` (e.g. lsassy, mimikatz, spider_plus). When pairing with a hash,
    set `ntlm_hash` instead of `password`.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "protocol": {"type": "string", "enum": list(_PROTOCOLS)},
                "targets": {"type": "string", "description": "IP, CIDR, hostname, or path to a file"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "ntlm_hash": {"type": "string"},
                "domain": {"type": "string"},
                "local_auth": {"type": "boolean", "default": False},
                "shares": {"type": "boolean", "default": False},
                "sessions": {"type": "boolean", "default": False},
                "loggedon_users": {"type": "boolean", "default": False},
                "users": {"type": "boolean", "default": False},
                "groups": {"type": "boolean", "default": False},
                "sam": {"type": "boolean", "default": False},
                "lsa": {"type": "boolean", "default": False},
                "ntds": {"type": "boolean", "default": False},
                "module": {"type": "string", "description": "e.g. lsassy, mimikatz, spider_plus"},
                "module_options": {"type": "object", "description": "key=value options for -o"},
            },
            "required": ["protocol", "targets"],
        }

    def execute(self, **params: Any) -> ToolResult:
        protocol = params.get("protocol")
        if protocol not in _PROTOCOLS:
            return ToolResult(ToolStatus.ERROR, "", "",
                              error=f"Unknown protocol: {protocol!r}")

        if params.get("password") and params.get("ntlm_hash"):
            return ToolResult(ToolStatus.ERROR, "", "",
                              error="provide either password or ntlm_hash, not both")

        argv: list[str] = ["crackmapexec", protocol, params["targets"]]
        if params.get("username"):
            argv += ["-u", params["username"]]
        if params.get("password"):
            argv += ["-p", params["password"]]
        if params.get("ntlm_hash"):
            argv += ["-H", params["ntlm_hash"]]
        if params.get("domain"):
            argv += ["-d", params["domain"]]
        if params.get("local_auth"):
            argv.append("--local-auth")
        for flag in ("shares", "sessions", "users", "groups", "sam", "lsa", "ntds"):
            if params.get(flag):
                argv.append(f"--{flag}")
        if params.get("loggedon_users"):
            argv.append("--loggedon-users")
        if module := params.get("module"):
            argv += ["-M", module]
        for k, v in (params.get("module_options") or {}).items():
            argv += ["-o", f"{k}={v}"]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout,
                              error=stderr.strip() or "timeout", duration_sec=duration)

        findings = _parse(stdout, protocol)
        # CME exits 0 even when no creds work; rely on findings, not rc.
        if rc != 0 and not findings.get("hosts") and not findings.get("messages"):
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"crackmapexec exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        has_signal = bool(
            findings.get("valid_credentials")
            or findings.get("pwned_hosts")
            or findings.get("shares")
            or findings.get("dumped_secrets")
        )
        status = ToolStatus.SUCCESS if has_signal else (
            ToolStatus.NO_FINDINGS if findings.get("hosts")
            else ToolStatus.PARTIAL
        )
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout,
            findings=findings,
            duration_sec=duration,
        )


# ────────────────────────────────────────────────────────────────────────────


def _parse(text: str, protocol: str) -> dict[str, Any]:
    text = _ANSI.sub("", text)
    hosts: dict[str, dict[str, Any]] = {}
    valid_credentials: list[dict[str, Any]] = []
    pwned_hosts: list[str] = []
    shares: list[dict[str, Any]] = []
    dumped_secrets: list[dict[str, Any]] = []
    messages: list[dict[str, str]] = []
    in_share_block = False

    for raw in text.splitlines():
        line = raw.rstrip()
        m = _LINE.match(line)
        if not m:
            # `--shares` prints a tabular block after the [+] header; capture it
            # separately as best-effort host:share rows.
            if in_share_block and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    shares.append({"share": parts[0], "permissions": parts[1],
                                   "remark": " ".join(parts[2:])})
            continue
        in_share_block = False

        host = m.group("host")
        name = m.group("name")
        marker = m.group("marker")
        msg = m.group("msg").strip()
        host_entry = hosts.setdefault(host, {"host": host, "name": name, "lines": []})
        host_entry["lines"].append({"marker": marker, "msg": msg})

        if marker == "+":
            cred = _CRED.match(msg)
            if cred:
                entry = {
                    "host": host,
                    "name": name,
                    "domain": cred.group("domain"),
                    "username": cred.group("user"),
                    "secret": cred.group("secret"),
                    "is_admin": bool(_PWN3D.search(msg)),
                    "raw": msg,
                }
                # secretsdump output looks like `Administrator:500:aad3...:31d6...:::`
                if msg.count(":") >= 4 and ":::" in msg:
                    dumped_secrets.append(entry)
                else:
                    valid_credentials.append(entry)
                if entry["is_admin"] and host not in pwned_hosts:
                    pwned_hosts.append(host)
            elif msg.lower().startswith("enumerated shares") or "Share" in msg:
                in_share_block = True
        elif marker == "*":
            messages.append({"host": host, "msg": msg})

    return {
        "protocol": protocol,
        "hosts": list(hosts.values()),
        "valid_credentials": valid_credentials,
        "pwned_hosts": pwned_hosts,
        "shares": shares,
        "dumped_secrets": dumped_secrets,
        "messages": messages,
        "host_count": len(hosts),
        "credential_count": len(valid_credentials),
    }
