"""End-to-end report rendering — verifies the seven §3.3 sections render
against a populated session, plus the file-write path used by the CLI and API.
"""
from __future__ import annotations

import json

from memory import queries, task_tree
from memory.models import (
    AgentDecision,
    AttackPhase,
    Credential,
    Host,
    NodeStatus,
    Vulnerability,
)
from reports import ReportGenerator


def _populate(db, session) -> None:
    roots = task_tree.bootstrap_phases(db, session)
    recon = next(r for r in roots if r.phase == AttackPhase.RECON)
    [scan] = task_tree.expand(db, recon, [{
        "title": "nmap full TCP scan",
        "phase": AttackPhase.RECON,
        "mitre_ttp": "T1046",
        "tool_name": "nmap",
    }])
    task_tree.start(db, scan)
    task_tree.complete(
        db, scan,
        command="nmap -sV 192.168.56.101",
        raw_output="<nmaprun>...</nmaprun>",
        findings={"hosts": [{"ip": "192.168.56.101", "ports": [22, 80]}]},
    )

    db.add(Host(
        session_id=session.id, ip="192.168.56.101", hostname="metasploitable",
        os_fingerprint="Linux 2.6", ports=[{"port": 22}, {"port": 80}],
        is_compromised=True,
    ))
    db.add(Vulnerability(
        session_id=session.id, host_ip="192.168.56.101", port=21,
        service="vsftpd", cve="CVE-2011-2523", cvss=10.0, severity="critical",
        title="vsftpd 2.3.4 backdoor", mitre_ttp="T1190", exploited=True,
    ))
    db.add(Credential(
        session_id=session.id, host_ip="192.168.56.101", service="ssh",
        username="msfadmin", secret="msfadmin", secret_type="password",
        privilege="user",
    ))
    db.add(AgentDecision(
        session_id=session.id, task_node_id=scan.id, step_number=1,
        context={"phase": "recon"},
        proposed_action={"action": "execute_tool",
                         "new_node": {"tool_name": "nmap"}},
        actual_command="nmap -sV 192.168.56.101",
        result_summary={"status": "success"},
        llm_model="claude-sonnet-4-6",
        llm_input_tokens=1200, llm_output_tokens=80,
    ))
    db.commit()


def test_render_html_includes_all_seven_sections(db, pentest_session) -> None:
    _populate(db, pentest_session)
    html = ReportGenerator().render_html(db, pentest_session)

    for heading in (
        "1. Executive Summary",
        "2. Scope",
        "3. Attack Narrative",
        "4. Evidence Table",
        "5. Vulnerability Register",
        "6. MITRE ATT&amp;CK Coverage Matrix",
        "7. Recommendations",
    ):
        assert heading in html, f"missing section heading: {heading}"

    # Appendices required by FYP §8.1
    assert "Appendix A" in html
    assert "Appendix B" in html


def test_render_includes_session_data(db, pentest_session) -> None:
    _populate(db, pentest_session)
    html = ReportGenerator().render_html(db, pentest_session)

    assert "192.168.56.101" in html
    assert "vsftpd 2.3.4 backdoor" in html
    assert "CVE-2011-2523" in html
    assert "T1046" in html
    assert "nmap full TCP scan" in html
    # Risk rating bubbles up from the highest severity (critical)
    assert "Critical" in html


def test_render_handles_empty_session(db, pentest_session) -> None:
    """A session with only the bootstrap tree must still render every section."""
    task_tree.bootstrap_phases(db, pentest_session)
    html = ReportGenerator().render_html(db, pentest_session)

    assert "1. Executive Summary" in html
    assert "7. Recommendations" in html
    # Empty register collapses to the recommendations fallback bullet
    assert "No vulnerabilities recorded" in html
    assert "Informational" in html


def test_decision_log_resolves_tool_from_reused_nodes(db, pentest_session) -> None:
    """new_node is null when the agent reuses a node an expand_tree created,
    which left Appendix B's Tool column blank for most of a run."""
    roots = task_tree.bootstrap_phases(db, pentest_session)
    exploit_root = next(r for r in roots if r.phase == AttackPhase.EXPLOITATION)
    [node] = task_tree.expand(db, exploit_root, [{
        "title": "Exploit Samba usermap_script",
        "phase": AttackPhase.EXPLOITATION,
        "mitre_ttp": "T1190",
        "tool_name": "metasploit",
    }])
    task_tree.start(db, node)
    task_tree.complete(db, node, command="msfrpc.exploit(...)", raw_output="",
                       findings={})
    db.add(AgentDecision(
        session_id=pentest_session.id, task_node_id=node.id, step_number=3,
        context={}, proposed_action={"action": "execute_tool",
                                     "node_id": str(node.id), "new_node": None},
        result_summary={"status": "success"},
    ))
    db.commit()

    html = ReportGenerator().render_html(db, pentest_session)
    rows = html.split("Appendix B")[1]
    assert "metasploit" in rows


def test_compromised_host_is_never_rated_informational(db, pentest_session) -> None:
    """The regression this guards: the engine rooted the target and the report
    still read '0 vulnerability findings / Informational'."""
    task_tree.bootstrap_phases(db, pentest_session)
    db.add(Host(session_id=pentest_session.id, ip="192.168.163.131",
                hostname="metasploitable", is_compromised=True))
    db.commit()

    html = ReportGenerator().render_html(db, pentest_session)

    assert "Informational" not in html
    assert "Critical" in html
    assert "1 host(s) were compromised" in html
    # …and the fallback "expand the test scope" advice must not appear.
    assert "No vulnerabilities recorded — consider expanding" not in html
    assert "Rebuild" in html


def test_findings_excerpt_is_capped() -> None:
    """A full-port nmap result is ~700 lines of JSON; unclipped it overflowed
    its <pre> and printed on top of the rows beneath it."""
    from reports.generator import EXCERPT_LINES, excerpt

    big = {"hosts": [{"port": p, "service": f"svc{p}"} for p in range(200)]}
    out = excerpt(big)
    assert out.count("\n") + 1 <= EXCERPT_LINES + 1     # +1 for the marker line
    assert "truncated" in out
    assert "lines total" in out

    # Small findings pass through untouched and stay valid JSON.
    small = {"session_id": "1", "output": "uid=0(root)"}
    assert "truncated" not in excerpt(small)
    assert json.loads(excerpt(small)) == small


def test_evidence_table_clips_overflow(db, pentest_session) -> None:
    _populate(db, pentest_session)
    html = ReportGenerator().render_html(db, pentest_session)
    assert 'class="evidence"' in html
    assert "overflow: hidden" in html
    # The old inline cap let overflow paint over the following rows.
    assert 'style="max-height:200px"' not in html


def test_write_persists_report_file(db, pentest_session, tmp_path) -> None:
    _populate(db, pentest_session)
    path = ReportGenerator(output_dir=tmp_path).write(db, pentest_session)
    assert path.exists()
    assert path.suffix == ".html"
    assert path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
