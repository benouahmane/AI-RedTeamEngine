"""Tests for credential / compromise normalisation (agent/findings.py).

These are pure-function tests over the recorded findings shapes each wrapper
emits — the contract the agent relies on to populate the credentials table and
flag compromised hosts.
"""
from __future__ import annotations

from agent.findings import (
    extract_compromised_hosts,
    extract_credentials,
    extract_vulnerabilities,
)


def test_extract_hydra_password():
    findings = {"credentials": [
        {"host": "192.168.56.101", "port": 22, "service": "ssh",
         "username": "msfadmin", "password": "msfadmin"},
    ]}
    creds = extract_credentials(findings)
    assert len(creds) == 1
    c = creds[0]
    assert c.username == "msfadmin"
    assert c.secret == "msfadmin"
    assert c.secret_type == "password"
    assert c.host_ip == "192.168.56.101"
    assert c.service == "ssh"


def test_extract_john_and_hashcat_shapes():
    john = extract_credentials({"credentials": [{"username": "root", "password": "toor"}]},
                               default_host="10.0.0.5")
    assert john[0].host_ip == "10.0.0.5"
    assert john[0].secret == "toor"

    hashcat = extract_credentials({"credentials": [{"hash": "5f4dcc…", "plaintext": "password"}]})
    assert hashcat[0].secret == "password"
    assert hashcat[0].secret_type == "password"


def test_extract_secretsdump_nt_hash_admin():
    findings = {"credentials": [
        {"domain": "LAB", "username": "Administrator", "rid": 500,
         "lm_hash": "aad3b435b51404eeaad3b435b51404ee",
         "nt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0"},
    ]}
    creds = extract_credentials(findings)
    assert creds[0].secret == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert creds[0].secret_type == "ntlm"
    assert creds[0].privilege == "admin"
    assert creds[0].domain == "LAB"


def test_extract_crackmapexec_valid_creds_detects_ntlm():
    findings = {
        "protocol": "smb",
        "valid_credentials": [
            {"host": "10.0.0.5", "domain": "LAB.LOCAL", "username": "admin",
             "secret": "Password1", "is_admin": True},
            {"host": "10.0.0.6", "domain": "LAB.LOCAL", "username": "svc",
             "secret": "31d6cfe0d16ae931b73c59d7e0c089c0", "is_admin": False},
        ],
    }
    creds = extract_credentials(findings)
    by_user = {c.username: c for c in creds}
    assert by_user["admin"].secret_type == "password"
    assert by_user["admin"].privilege == "admin"
    assert by_user["admin"].service == "smb"
    assert by_user["svc"].secret_type == "ntlm"


def test_extract_dumped_secrets_pulls_nt_hash():
    findings = {"dumped_secrets": [
        {"host": "10.0.0.5", "domain": "LAB.LOCAL", "username": "krbtgt",
         "secret": "502:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::",
         "is_admin": False},
    ]}
    creds = extract_credentials(findings)
    assert creds[0].username == "krbtgt"
    assert creds[0].secret == "abcdef0123456789abcdef0123456789"
    assert creds[0].secret_type == "ntlm"


def test_extract_kerberos_tickets_username_parsed():
    findings = {
        "domain": "LAB.LOCAL",
        "tickets": [
            "$krb5asrep$23$alice@LAB.LOCAL:abcdef0123456789",
            "$krb5tgs$23$*svc_sql$LAB.LOCAL$MSSQLSvc/sql*$deadbeef",
        ],
    }
    creds = extract_credentials(findings)
    users = {c.username for c in creds}
    assert "alice" in users
    assert "svc_sql" in users
    assert all(c.secret_type == "kerberos" for c in creds)


def test_extract_credentials_dedupes():
    findings = {"credentials": [
        {"username": "root", "password": "toor", "host": "10.0.0.1"},
        {"username": "root", "password": "toor", "host": "10.0.0.1"},
    ]}
    assert len(extract_credentials(findings)) == 1


def test_compromise_from_pwned_hosts_and_session():
    assert extract_compromised_hosts({"pwned_hosts": ["10.0.0.5"]}) == {"10.0.0.5"}
    assert extract_compromised_hosts(
        {"session_id": 3}, tool_name="metasploit", target="192.168.56.101:4444",
    ) == {"192.168.56.101"}


def test_compromise_from_impacket_exec_and_pwncat():
    imp = extract_compromised_hosts(
        {"action": "psexec", "output": "uid=0(root)"},
        tool_name="impacket", target="10.0.0.6",
    )
    assert imp == {"10.0.0.6"}

    pw = extract_compromised_hosts({}, tool_name="pwncat", target="10.0.0.7", success=True)
    assert pw == {"10.0.0.7"}
    # no success → no compromise
    assert extract_compromised_hosts({}, tool_name="pwncat", target="10.0.0.7", success=False) == set()


def test_compromise_admin_credential_marks_host():
    findings = {"valid_credentials": [
        {"host": "10.0.0.5", "username": "admin", "secret": "x", "is_admin": True},
    ]}
    assert "10.0.0.5" in extract_compromised_hosts(findings, tool_name="crackmapexec")


# ─── vulnerability normalisation ──────────────────────────────────────────


def test_extract_nuclei_vulnerability_shape():
    findings = {
        "target": "http://10.0.0.5:8080",
        "vulnerabilities": [
            {"template_id": "CVE-2021-44228", "name": "Apache Log4j RCE",
             "severity": "critical", "host": "http://10.0.0.5:8080",
             "matched_at": "http://10.0.0.5:8080/api", "type": "http",
             "cve": "CVE-2021-44228", "cvss_score": 10.0,
             "description": "JNDI lookup"},
        ],
    }
    v = extract_vulnerabilities(findings, tool_name="nuclei", target="10.0.0.5")[0]
    assert v.host_ip == "10.0.0.5"
    assert v.title == "Apache Log4j RCE"
    assert v.severity == "critical"
    assert v.cve == "CVE-2021-44228"
    assert v.cvss == 10.0
    assert v.port == 8080
    assert v.exploited is False


def test_extract_openvas_shape_normalises_severity_and_port():
    findings = {"vulnerabilities": [
        {"host": "10.0.0.5", "port": 445, "port_spec": "445/tcp",
         "name": "SMB signing disabled", "severity": "Moderate",
         "cvss_score": 5.3, "cves": ["CVE-1999-0519"], "description": "…"},
    ]}
    v = extract_vulnerabilities(findings, tool_name="openvas")[0]
    assert v.severity == "medium"          # "Moderate" is not a template class
    assert v.port == 445
    assert v.cve == "CVE-1999-0519"


def test_successful_exploit_becomes_a_critical_finding():
    """The regression that mattered: root on the box, zero findings recorded."""
    findings = {
        "module": "exploit/multi/samba/usermap_script",
        "module_name": 'Samba "username map script" Command Execution',
        "module_description": "This module exploits a command execution vulnerability.",
        "cves": ["CVE-2007-2447"],
        "options": {"RHOSTS": "192.168.163.131", "RPORT": 139},
        "job_id": 3,
        "session_id": 1,
        "session": {"type": "shell", "session_port": 139, "info": "uid=0(root)"},
    }
    vulns = extract_vulnerabilities(
        findings, tool_name="metasploit", target="192.168.163.131", success=True,
    )
    assert len(vulns) == 1
    v = vulns[0]
    assert v.host_ip == "192.168.163.131"
    assert v.title == 'Samba "username map script" Command Execution'
    assert v.severity == "critical"
    assert v.cve == "CVE-2007-2447"
    assert v.service == "samba"
    assert v.port == 139
    assert v.exploited is True
    assert "session 1" in v.evidence


def test_exploit_without_session_records_nothing():
    """No session means no proof — the module launching is not a finding."""
    findings = {
        "module": "exploit/unix/ftp/vsftpd_234_backdoor",
        "cves": ["CVE-2011-2523"],
        "options": {"RHOSTS": "192.168.163.131"},
        "job_id": 2, "session_id": None, "session": None,
    }
    assert extract_vulnerabilities(
        findings, tool_name="metasploit", target="192.168.163.131",
    ) == []


def test_session_run_does_not_duplicate_the_exploit_finding():
    """session_run carries session_id but no module — it verifies, not discovers."""
    findings = {"session_id": "1", "command": "id", "output": "uid=0(root)"}
    assert extract_vulnerabilities(
        findings, tool_name="metasploit", target="192.168.163.131", success=True,
    ) == []


def test_credential_based_footholds_are_findings():
    imp = extract_vulnerabilities(
        {"action": "psexec", "output": "uid=0(root)"},
        tool_name="impacket", target="10.0.0.6", success=True,
    )
    assert imp[0].severity == "high"
    assert imp[0].exploited is True

    cme = extract_vulnerabilities(
        {"protocol": "smb", "valid_credentials": [
            {"host": "10.0.0.5", "username": "admin", "secret": "x", "is_admin": True},
            {"host": "10.0.0.6", "username": "svc", "secret": "y", "is_admin": False},
        ]},
        tool_name="crackmapexec",
    )
    assert len(cme) == 1                    # non-admin logins are not findings
    assert "admin" in cme[0].title
    assert cme[0].host_ip == "10.0.0.5"


def test_extract_vulnerabilities_dedupes():
    findings = {"vulnerabilities": [
        {"host": "10.0.0.5", "name": "dup", "severity": "high", "port": 80},
        {"host": "10.0.0.5", "name": "dup", "severity": "high", "port": 80},
    ]}
    assert len(extract_vulnerabilities(findings)) == 1
