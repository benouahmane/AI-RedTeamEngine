"""Tests for the Pentesting Task Tree."""
from __future__ import annotations

from memory import task_tree
from memory.models import AttackPhase, NodeStatus


def test_bootstrap_creates_one_root_per_phase(db, pentest_session) -> None:
    roots = task_tree.bootstrap_phases(db, pentest_session)
    assert len(roots) == len(AttackPhase)
    phases = {r.phase for r in roots}
    assert phases == set(AttackPhase)
    assert all(r.parent_id is None for r in roots)
    assert all(r.depth == 0 for r in roots)


def test_pick_next_returns_highest_priority_pending(db, pentest_session) -> None:
    [recon] = [
        r for r in task_tree.bootstrap_phases(db, pentest_session)
        if r.phase == AttackPhase.RECON
    ]
    task_tree.expand(db, recon, [
        {"title": "low",  "phase": AttackPhase.RECON, "priority": 2, "tool_name": "nmap"},
        {"title": "high", "phase": AttackPhase.RECON, "priority": 5, "tool_name": "nmap"},
        {"title": "mid",  "phase": AttackPhase.RECON, "priority": 3, "tool_name": "nmap"},
    ])
    picked = task_tree.pick_next(db, pentest_session.id)
    assert picked is not None
    # Priority 5 root beats the children (priority 5) only by created_at order;
    # the recon root is created first so it should win the tiebreak.
    assert picked.priority == 5


def test_complete_records_findings(db, pentest_session) -> None:
    roots = task_tree.bootstrap_phases(db, pentest_session)
    n = roots[0]
    task_tree.start(db, n)
    task_tree.complete(
        db, n,
        command="nmap -sV 10.0.0.1",
        raw_output="<xml/>",
        findings={"hosts": [{"ip": "10.0.0.1", "ports": [{"port": 22}]}]},
    )
    db.refresh(n)
    assert n.status == NodeStatus.COMPLETED
    assert n.findings["hosts"][0]["ip"] == "10.0.0.1"


def test_fail_marks_status_and_records_error(db, pentest_session) -> None:
    n = task_tree.bootstrap_phases(db, pentest_session)[0]
    task_tree.fail(db, n, "tool exited non-zero")
    db.refresh(n)
    assert n.status == NodeStatus.FAILED
    assert "exited" in (n.error or "")


def test_context_for_llm_summarises_state(db, pentest_session) -> None:
    roots = task_tree.bootstrap_phases(db, pentest_session)
    task_tree.start(db, roots[0])
    task_tree.complete(db, roots[1])
    ctx = task_tree.context_for_llm(db, pentest_session.id)
    assert ctx["tree_size"] == len(roots)
    assert len(ctx["in_progress"]) == 1
    assert len(ctx["recent_completed"]) == 1
    assert ctx["phase_counts"]["recon"] >= 1


def test_to_ascii_renders_tree(db, pentest_session) -> None:
    roots = task_tree.bootstrap_phases(db, pentest_session)
    task_tree.expand(db, roots[0], [
        {"title": "Nmap full TCP scan", "phase": AttackPhase.RECON, "tool_name": "nmap"},
    ])
    art = task_tree.to_ascii(db, pentest_session.id)
    assert "Reconnaissance" in art
    assert "Nmap full TCP scan" in art
    assert "[ ]" in art   # pending glyph
