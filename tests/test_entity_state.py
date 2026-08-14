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


def test_upsert_vulnerability_dedupes_and_upgrades_exploited(db, pentest_session):
    sid = pentest_session.id
    a = queries.upsert_vulnerability(db, sid, host_ip="10.0.0.5", port=445,
                                     title="Samba RCE", severity="critical",
                                     cve="CVE-2007-2447")
    assert a is not None
    assert a.exploited is False

    # Same finding again, now proven — no second row, but the row is upgraded.
    dup = queries.upsert_vulnerability(db, sid, host_ip="10.0.0.5", port=445,
                                       title="Samba RCE", severity="critical",
                                       cve="CVE-2007-2447", exploited=True,
                                       evidence="session 1 opened")
    assert dup is None
    vulns = queries.vulns_for(db, sid)
    assert len(vulns) == 1
    assert vulns[0].exploited is True
    assert vulns[0].evidence == "session 1 opened"

    # A different port is a different finding.
    assert queries.upsert_vulnerability(db, sid, host_ip="10.0.0.5", port=139,
                                        title="Samba RCE", severity="critical",
                                        cve="CVE-2007-2447") is not None
    assert len(queries.vulns_for(db, sid)) == 2


def test_vulns_ordered_by_severity_then_proof(db, pentest_session):
    """An exploited RCE carries no CVSS, so CVSS-only ordering buried it."""
    sid = pentest_session.id
    queries.record_vulnerability(db, sid, host_ip="10.0.0.5", title="TLS cipher",
                                 severity="info", cvss=2.6)
    queries.record_vulnerability(db, sid, host_ip="10.0.0.5", title="Samba RCE",
                                 severity="critical", cvss=None, exploited=True)
    assert [v.title for v in queries.vulns_for(db, sid)] == ["Samba RCE", "TLS cipher"]


def test_mark_host_compromised_creates_then_flags(db, pentest_session):
    sid = pentest_session.id
    host = queries.mark_host_compromised(db, sid, "10.0.0.9", note="via metasploit")
    assert host.is_compromised is True
    assert "metasploit" in (host.notes or "")
    # idempotent on an existing host
    again = queries.mark_host_compromised(db, sid, "10.0.0.9", note="via pwncat")
    assert again.is_compromised is True
    assert again.id == host.id


def test_stale_running_sessions_detected_and_aborted(db, pentest_session):
    """Ctrl-C and VM power-offs stranded sessions at RUNNING for ever: a dead
    process cannot update its own row, so something external must."""
    from datetime import datetime, timedelta

    from memory.models import AgentDecision, SessionStatus

    sid = pentest_session.id
    pentest_session.status = SessionStatus.RUNNING
    pentest_session.started_at = datetime.utcnow() - timedelta(hours=3)
    db.add(AgentDecision(
        session_id=sid, step_number=1, context={}, proposed_action={},
        created_at=datetime.utcnow() - timedelta(hours=2),
    ))
    db.commit()

    assert len(queries.stale_running_sessions(db, idle_minutes=30)) == 1
    # A generous window spares a session that is merely slow.
    assert queries.stale_running_sessions(db, idle_minutes=600) == []

    aborted = queries.abort_stale_sessions(db, idle_minutes=30)
    assert [s.id for s in aborted] == [sid]
    assert pentest_session.status == SessionStatus.ABORTED
    # completed_at is backdated to the last real activity, not "now".
    assert pentest_session.completed_at < datetime.utcnow() - timedelta(minutes=90)
    # Idempotent — no longer RUNNING, so a second sweep finds nothing.
    assert queries.abort_stale_sessions(db, idle_minutes=30) == []


def test_stale_sweep_ignores_recent_and_finished_sessions(db, pentest_session):
    from datetime import datetime, timedelta

    from memory.models import SessionStatus

    pentest_session.status = SessionStatus.RUNNING
    pentest_session.started_at = datetime.utcnow() - timedelta(minutes=2)
    db.commit()
    assert queries.stale_running_sessions(db, idle_minutes=30) == []

    # A session that died before its first step is judged on started_at.
    pentest_session.started_at = datetime.utcnow() - timedelta(hours=1)
    db.commit()
    assert len(queries.stale_running_sessions(db, idle_minutes=30)) == 1

    # Completed sessions are never touched, however old.
    pentest_session.status = SessionStatus.COMPLETED
    db.commit()
    assert queries.stale_running_sessions(db, idle_minutes=30) == []


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
