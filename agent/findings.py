"""Normalise heterogeneous tool `findings` dicts into entity rows.

Every wrapper emits credentials and compromise signals in its own shape
(hydra → `credentials[*].password`, crackmapexec → `valid_credentials`,
impacket secretsdump → `credentials[*].nt_hash`, kerberos tools → `tickets`,
metasploit → `session_id`, …). The agent loop needs a single, predictable
representation to write into the `credentials` / `hosts` entity tables and to
drive credential-reuse decisions.

These functions are deliberately pure (no DB, no I/O) so they can be unit
tested against recorded tool output without a database.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_NTLM_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_KRB_ASREP_USER = re.compile(r"\$krb5asrep\$\d+\$([^@$:]+)@", re.IGNORECASE)
_KRB_TGS_USER = re.compile(r"\$krb5tgs\$\d+\$\*([^$*]+)\$", re.IGNORECASE)


@dataclass(frozen=True)
class NormalisedCredential:
    username: str
    secret: str
    secret_type: str                 # password | ntlm | kerberos | hash
    host_ip: str | None = None
    service: str | None = None
    domain: str | None = None
    privilege: str | None = None     # user | admin | domain_admin

    def dedup_key(self) -> tuple[str, str, str | None]:
        return (self.username, self.secret, self.host_ip)


def _looks_like_ntlm(value: str | None) -> bool:
    return bool(value and _NTLM_RE.match(value))


def _host_only(target: str | None) -> str | None:
    """Strip scheme / port from an IP, host:port, or URL."""
    if not target:
        return None
    host = target
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    # keep IPv6 in brackets intact; otherwise drop a :port suffix
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host or None


def _krb_username(ticket: str) -> str:
    m = _KRB_ASREP_USER.search(ticket) or _KRB_TGS_USER.search(ticket)
    return m.group(1) if m else "(kerberoast)"


def extract_credentials(
    findings: dict,
    *,
    default_host: str | None = None,
) -> list[NormalisedCredential]:
    """Pull every credential-shaped artefact out of a findings dict."""
    if not findings:
        return []

    out: list[NormalisedCredential] = []
    domain = findings.get("domain")
    default_host = _host_only(default_host)

    # 1) Generic `credentials` list — hydra, john, hashcat, impacket secretsdump.
    for c in findings.get("credentials") or []:
        if not isinstance(c, dict):
            continue
        username = c.get("username") or c.get("user") or "(unknown)"
        host = _host_only(c.get("host")) or default_host
        if c.get("nt_hash"):
            secret, stype = c["nt_hash"], "ntlm"
            priv = "admin" if c.get("rid") == 500 else None
        elif c.get("password"):
            secret, stype, priv = c["password"], "password", None
        elif c.get("plaintext"):
            secret, stype, priv = c["plaintext"], "password", None
        elif c.get("secret"):
            secret = c["secret"]
            stype = "ntlm" if _looks_like_ntlm(secret) else "password"
            priv = None
        elif c.get("hash"):
            secret, stype, priv = c["hash"], "hash", None
        else:
            continue
        out.append(NormalisedCredential(
            username=username, secret=str(secret), secret_type=stype,
            host_ip=host, service=c.get("service"),
            domain=c.get("domain") or domain, privilege=priv,
        ))

    # 2) crackmapexec valid logins.
    protocol = findings.get("protocol")
    for c in findings.get("valid_credentials") or []:
        if not isinstance(c, dict) or not c.get("secret"):
            continue
        secret = c["secret"]
        out.append(NormalisedCredential(
            username=c.get("username") or "(unknown)",
            secret=str(secret),
            secret_type="ntlm" if _looks_like_ntlm(secret) else "password",
            host_ip=_host_only(c.get("host")) or default_host,
            service=protocol,
            domain=c.get("domain") or domain,
            privilege="admin" if c.get("is_admin") else None,
        ))

    # 3) crackmapexec / secretsdump `rid:lm:nt:::` dumps — keep the NT hash.
    for c in findings.get("dumped_secrets") or []:
        if not isinstance(c, dict) or not c.get("secret"):
            continue
        parts = str(c["secret"]).split(":")
        nt = parts[2] if len(parts) >= 3 and _looks_like_ntlm(parts[2]) else None
        out.append(NormalisedCredential(
            username=c.get("username") or "(unknown)",
            secret=nt or str(c["secret"]),
            secret_type="ntlm" if nt else "hash",
            host_ip=_host_only(c.get("host")) or default_host,
            service="smb",
            domain=c.get("domain") or domain,
            privilege="admin" if c.get("is_admin") else None,
        ))

    # 4) Kerberos roast hashes (impacket / rubeus) — crackable secrets.
    for ticket in findings.get("tickets") or []:
        if not isinstance(ticket, str):
            continue
        out.append(NormalisedCredential(
            username=_krb_username(ticket),
            secret=ticket,
            secret_type="kerberos",
            host_ip=default_host,
            service="kerberos",
            domain=domain,
        ))

    # de-duplicate within a single findings dict
    seen: set[tuple[str, str, str | None]] = set()
    deduped: list[NormalisedCredential] = []
    for cred in out:
        if cred.dedup_key() in seen:
            continue
        seen.add(cred.dedup_key())
        deduped.append(cred)
    return deduped


# Wrappers whose SUCCESS implies an interactive foothold on `target`.
_SHELL_TOOLS = {"pwncat", "metasploit"}
_LATERAL_EXEC_ACTIONS = {"psexec", "wmiexec", "smbexec"}


def extract_compromised_hosts(
    findings: dict,
    *,
    tool_name: str | None = None,
    target: str | None = None,
    success: bool = False,
) -> set[str]:
    """Return the set of host IPs this result proves we have control over."""
    hosts: set[str] = set()
    if not findings:
        findings = {}

    for h in findings.get("pwned_hosts") or []:
        host = _host_only(h)
        if host:
            hosts.add(host)

    for c in findings.get("valid_credentials") or []:
        if isinstance(c, dict) and c.get("is_admin"):
            host = _host_only(c.get("host"))
            if host:
                hosts.add(host)

    tgt = _host_only(target)
    if tgt:
        # Metasploit session handle.
        if findings.get("session_id") is not None:
            hosts.add(tgt)
        # Impacket lateral exec that produced output.
        if (
            tool_name == "impacket"
            and findings.get("action") in _LATERAL_EXEC_ACTIONS
            and findings.get("output")
        ):
            hosts.add(tgt)
        # A pwncat shell that connected and enumerated successfully.
        if tool_name == "pwncat" and success:
            hosts.add(tgt)

    return hosts
