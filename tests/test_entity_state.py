"""Tests for credential persistence, host compromise, and the entity snapshot
that gets fed into the agent prompt (memory/queries.py)."""
from __future__ import annotations

from memory import queries


def test_upsert_credential_dedupes(db, pentest_session):
    sid = pentest_session.id
    a = queries.upsert_credential(db, sid, username="root", secret="toor",
                                  secret_type="password", host_ip="10.0.0.1")
    assert a is not None
    # identical → returns None, no second row
    dup = queries.upsert_credential(db, sid, username="root", secret="toor",
                                    secret_type="password", host_ip="10.0.0.1")
    assert dup is None
    # different host → new row
    b = queries.upsert_credential(db, sid, username="root", secret="toor",
                                  secret_type="password", host_ip="10.0.0.2")
    assert b is not None
    assert len(queries.creds_for(db, sid)) == 2


def test_mark_host_compromised_creates_then_flags(db, pentest_session):
    sid = pentest_session.id
    host = queries.mark_host_compromised(db, sid, "10.0.0.9", note="via metasploit")
    assert host.is_compromised is True
    assert "metasploit" in (host.notes or "")
    # idempotent on an existing host
    again = queries.mark_host_compromised(db, sid, "10.0.0.9", note="via pwncat")
    assert again.is_compromised is True
    assert again.id == host.id


def test_entity_snapshot_shape(db, pentest_session):
    sid = pentest_session.id
    queries.upsert_host(
        db, sid, "10.0.0.5", hostname="metasploitable",
        os_fingerprint="Linux 2.6",
        ports=[{"port": 22, "service": "ssh"}, {"port": 445, "service": "smb"}],
        services=[{"port": 22, "name": "ssh"}, {"port": 445, "name": "smb"}],
    )
    queries.mark_host_compromised(db, sid, "10.0.0.5")
    queries.upsert_credential(db, sid, username="msfadmin", secret="msfadmin",
                              secret_type="password", host_ip="10.0.0.5", service="ssh")
    queries.record_vulnerability(db, sid, host_ip="10.0.0.5", title="vsftpd backdoor",
                                 severity="critical", cve="CVE-2011-2523")

    snap = queries.entity_snapshot(db, sid)
    assert snap["counts"]["hosts"] == 1
    assert snap["counts"]["compromised_hosts"] == 1
    assert snap["counts"]["credentials"] == 1
    assert snap["hosts"][0]["compromised"] is True
    assert {s["port"] for s in snap["hosts"][0]["services"]} == {22, 445}
    assert snap["credentials"][0]["username"] == "msfadmin"
    assert snap["vulnerabilities"][0]["cve"] == "CVE-2011-2523"


def test_entity_snapshot_truncates_long_secret(db, pentest_session):
    sid = pentest_session.id
    queries.upsert_credential(db, sid, username="u", secret="A" * 500, secret_type="hash")
    snap = queries.entity_snapshot(db, sid)
    assert len(snap["credentials"][0]["secret"]) == 200
