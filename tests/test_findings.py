"""Tests for credential / compromise normalisation (agent/findings.py).

These are pure-function tests over the recorded findings shapes each wrapper
emits — the contract the agent relies on to populate the credentials table and
flag compromised hosts.
"""
from __future__ import annotations

from agent.findings import extract_compromised_hosts, extract_credentials


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
