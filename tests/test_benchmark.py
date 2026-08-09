"""Tests for the benchmark scorer — builds a synthetic completed session in
the in-memory DB and checks the computed precision/recall, coverage, capability
and efficiency metrics."""
from __future__ import annotations

from datetime import datetime, timedelta

from benchmark.manifest import GroundTruth
from benchmark.scorer import score_session
from memory import queries
from memory.models import (
    AgentDecision,
    AttackPhase,
    NodeStatus,
    TaskNode,
)


def _build_session(db, session):
    start = datetime(2026, 6, 13, 12, 0, 0)
    session.started_at = start
    session.completed_at = start + timedelta(minutes=10)

    # hosts: found 22 + 80 (miss 445), compromised
    queries.upsert_host(db, session.id, "10.0.0.5",
                        ports=[{"port": 22}, {"port": 80}],
                        services=[{"port": 22, "name": "ssh"}])
    queries.mark_host_compromised(db, session.id, "10.0.0.5")

    # vulns: one true CVE (with TTP), one false-positive CVE
    queries.record_vulnerability(db, session.id, host_ip="10.0.0.5",
                                 title="vsftpd backdoor", severity="critical",
                                 cve="CVE-2011-2523", mitre_ttp="T1190")
    queries.record_vulnerability(db, session.id, host_ip="10.0.0.5",
                                 title="bogus", severity="low", cve="CVE-9999-0000")

    # PTT nodes: recon (T1046) + exploitation (T1190, completed at +2min)
    recon = TaskNode(session_id=session.id, title="scan", phase=AttackPhase.RECON,
                     status=NodeStatus.COMPLETED, mitre_ttp="T1046",
                     completed_at=start + timedelta(minutes=1))
    expl = TaskNode(session_id=session.id, title="exploit", phase=AttackPhase.EXPLOITATION,
                    status=NodeStatus.COMPLETED, mitre_ttp="T1190",
                    completed_at=start + timedelta(minutes=2),
                    raw_output="uid=0(root) flag{captured-me}")
    db.add_all([recon, expl])

    # decisions for step + token accounting
    for i in range(2):
        db.add(AgentDecision(
            session_id=session.id, step_number=i, context={}, proposed_action={},
            llm_model="claude-sonnet-4-6", llm_input_tokens=1000, llm_output_tokens=200,
            created_at=start + timedelta(minutes=i),
        ))
    db.commit()


def _truth() -> GroundTruth:
    return GroundTruth.from_dict({
        "target": "10.0.0.5",
        "name": "Synthetic",
        "known_open_ports": [22, 80, 445],
        "known_cves": ["CVE-2011-2523"],
        "expected_techniques": ["T1046", "T1190"],
        "flags": ["flag{captured-me}", "flag{missing}"],
        "manual_baseline": {"technique_coverage": 0.9, "hosts_compromised": 1},
    })


def test_scorer_coverage_metrics(db, pentest_session):
    _build_session(db, pentest_session)
    score = score_session(db, pentest_session, _truth())

    # ports: 2 of 3 found, all found are real (recall rounded to 4 dp by the scorer)
    assert score.ports.true_positives == 2
    assert score.ports.recall == round(2 / 3, 4)
    assert score.ports.precision == 1.0

    # cves: found the real one (recall 1.0) but also a false positive (precision .5)
    assert score.cves.recall == 1.0
    assert score.cves.precision == 0.5
    assert score.vuln_false_positive_rate == 0.5

    # technique coverage: both expected techniques used → 100%
    assert score.technique_coverage == 1.0
    assert "T1190" in score.techniques_used


def test_scorer_capability_and_efficiency(db, pentest_session):
    _build_session(db, pentest_session)
    score = score_session(db, pentest_session, _truth())

    assert score.compromised is True
    assert score.hosts_compromised == 1
    # one of two flags present in node output
    assert score.flags_captured == 1
    assert score.flags_total == 2
    # first foothold (exploitation) completed at +2min = 120s
    assert score.time_to_first_shell_sec == 120.0

    assert score.agent_steps == 2
    assert score.input_tokens == 2000
    assert score.output_tokens == 400
    # 2000 in + 400 out on sonnet (3/1M in, 15/1M out)
    assert abs(score.llm_cost_usd - (2000 * 3 + 400 * 15) / 1_000_000) < 1e-9
    assert score.duration_sec == 600.0


def test_scorer_markdown_renders(db, pentest_session):
    _build_session(db, pentest_session)
    score = score_session(db, pentest_session, _truth())
    md = score.to_markdown()
    assert "Benchmark — Synthetic" in md
    assert "Port recall" in md
    assert "Estimated LLM cost" in md
