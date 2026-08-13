"""Normalise heterogeneous tool `findings` dicts into entity rows.

Every wrapper emits credentials, vulnerabilities and compromise signals in its
own shape (hydra → `credentials[*].password`, crackmapexec → `valid_credentials`,
impacket secretsdump → `credentials[*].nt_hash`, kerberos tools → `tickets`,
nuclei/openvas/nikto → `vulnerabilities`, metasploit → `session_id`, …). The
agent loop needs a single, predictable representation to write into the
`credentials` / `vulnerabilities` / `hosts` entity tables and to drive
credential-reuse decisions.

These functions are deliberately pure (no DB, no I/O) so they can be unit
tested against recorded tool output without a database.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

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


@dataclass(frozen=True)
class NormalisedVulnerability:
    host_ip: str
    title: str
    severity: str                    # critical | high | medium | low | info
    port: int | None = None
    service: str | None = None
    cve: str | None = None
    cvss: float | None = None
    description: str | None = None
    evidence: str | None = None
    exploited: bool = False

    def dedup_key(self) -> tuple[str, str, str | None, int | None]:
        return (self.host_ip, self.title, self.cve, self.port)


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


# The five buckets the report template and risk rating understand. Scanners
# disagree on spelling ("informational", "moderate", "unknown"), so everything
# is funnelled through here before it reaches the register.
_SEVERITY_ALIASES = {
    "critical": "critical", "crit": "critical",
    "high": "high",
    "medium": "medium", "med": "medium", "moderate": "medium",
    "low": "low",
    "info": "info", "informational": "info", "information": "info",
    "none": "info", "log": "info", "debug": "info", "unknown": "info",
}


def _severity(value: Any, *, default: str = "info") -> str:
    return _SEVERITY_ALIASES.get(str(value or "").strip().lower(), default)


def _port_of(value: Any) -> int | None:
    """Coerce a port from an int, "445", or an openvas-style "445/tcp"."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value < 65536 else None
    text = str(value).split("/", 1)[0].strip()
    return int(text) if text.isdigit() and 0 < int(text) < 65536 else None


def _port_from_target(target: str | None) -> int | None:
    """Port embedded in "10.0.0.5:8080" or "http://10.0.0.5:8080/x"."""
    if not target:
        return None
    host = target.split("://", 1)[-1].split("/", 1)[0]
    if host.count(":") != 1:
        return None                                  # bare host, or IPv6
    return _port_of(host.split(":", 1)[1])


def _rhost_of(options: Any) -> str | None:
    if not isinstance(options, dict):
        return None
    return next(
        (str(v) for k, v in options.items() if str(k).upper() in {"RHOSTS", "RHOST"}),
        None,
    )


def _rport_of(options: Any) -> int | None:
    if not isinstance(options, dict):
        return None
    return next(
        (_port_of(v) for k, v in options.items() if str(k).upper() in {"RPORT"}),
        None,
    )


def _msf_service(module_path: str | None) -> str | None:
    """Service name out of "exploit/<platform>/<service>/<name>"."""
    parts = (module_path or "").split("/")
    return parts[2] if len(parts) > 3 else None


def extract_vulnerabilities(
    findings: dict,
    *,
    tool_name: str | None = None,
    target: str | None = None,
    success: bool = False,
) -> list[NormalisedVulnerability]:
    """Pull every vulnerability-shaped artefact out of a findings dict.

    Two sources, and the register is dishonest without both:

    1. **Scanner output** (`findings["vulnerabilities"]` — nuclei, openvas,
       nikto). Suspected until proven; `exploited` stays False.
    2. **Confirmed exploitation.** A shell on the target is the strongest
       evidence a vulnerability exists, but nothing used to record it — so the
       engine could root a host and still report zero findings, rated
       "Informational". That is the most misleading outcome a pentest report
       can produce, so successful exploitation now writes its own entry with
       the CVE Metasploit already knows about.
    """
    if not findings:
        return []

    out: list[NormalisedVulnerability] = []
    default_host = _host_only(target)

    # 1) Scanner shape, shared by nuclei / openvas / nikto.
    for v in findings.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        raw_host = v.get("host") or findings.get("host") or target
        host = _host_only(raw_host) or default_host
        if not host:
            continue
        out.append(NormalisedVulnerability(
            host_ip=host,
            title=v.get("name") or v.get("template_id") or v.get("id") or "(unnamed)",
            severity=_severity(v.get("severity")),
            port=_port_of(v.get("port") or v.get("port_spec"))
                 or _port_of(findings.get("port"))
                 or _port_from_target(raw_host),
            service=v.get("service") or v.get("type"),
            cve=v.get("cve") or (v.get("cves") or [None])[0],
            cvss=v["cvss_score"] if v.get("cvss_score") is not None else v.get("cvss"),
            description=v.get("description"),
            evidence=v.get("matched_at") or v.get("url"),
        ))

    # 2) Metasploit exploit that actually produced a session. `module` is only
    #    present on the exploit action, which keeps session_run/session_list —
    #    verification of an existing finding — from logging duplicates.
    module = findings.get("module")
    if tool_name == "metasploit" and module and findings.get("session_id") is not None:
        session = findings.get("session") or {}
        host = _host_only(_rhost_of(findings.get("options"))) or default_host
        cves = [c for c in (findings.get("cves") or []) if c]
        if host:
            out.append(NormalisedVulnerability(
                host_ip=host,
                # Metasploit's own module title reads like a finding name
                # ("Samba 'username map script' Command Execution"); the path
                # is the fallback when moduleinfo is unavailable.
                title=findings.get("module_name") or module,
                severity="critical",
                port=_port_of(session.get("session_port")) or _rport_of(findings.get("options")),
                service=_msf_service(module),
                cve=cves[0] if cves else None,
                description=findings.get("module_description"),
                evidence=(
                    f"Metasploit session {findings['session_id']} opened via {module}"
                    + (f" ({session.get('type')})" if session.get("type") else "")
                    + (f" — {session.get('info')}" if session.get("info") else "")
                ),
                exploited=True,
            ))

    # 3) Footholds obtained with valid credentials rather than a CVE. Still
    #    findings — just not module-attributable ones.
    if default_host:
        if (
            tool_name == "impacket"
            and findings.get("action") in _LATERAL_EXEC_ACTIONS
            and findings.get("output")
        ):
            out.append(NormalisedVulnerability(
                host_ip=default_host,
                title=f"Remote command execution via {findings['action']} "
                      f"with valid credentials",
                severity="high",
                service="smb",
                description="Authenticated remote command execution succeeded, "
                            "granting code execution on the host.",
                evidence=str(findings["output"])[:1000],
                exploited=True,
            ))
        if tool_name == "pwncat" and success:
            out.append(NormalisedVulnerability(
                host_ip=default_host,
                title="Interactive shell access obtained",
                severity="high",
                description="A shell was established and enumerated successfully.",
                exploited=True,
            ))

    for c in findings.get("valid_credentials") or []:
        if not isinstance(c, dict) or not c.get("is_admin"):
            continue
        host = _host_only(c.get("host")) or default_host
        if not host:
            continue
        out.append(NormalisedVulnerability(
            host_ip=host,
            title=f"Administrative access with valid credentials "
                  f"({c.get('username') or 'unknown user'})",
            severity="high",
            service=findings.get("protocol"),
            description="The credential authenticates with administrative "
                        "privileges on this host.",
            exploited=True,
        ))

    seen: set[tuple[str, str, str | None, int | None]] = set()
    deduped: list[NormalisedVulnerability] = []
    for vuln in out:
        if vuln.dedup_key() in seen:
            continue
        seen.add(vuln.dedup_key())
        deduped.append(vuln)
    return deduped
