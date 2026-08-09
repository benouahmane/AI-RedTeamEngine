"""Tests for the MITRE ATT&CK coverage matrix."""
from __future__ import annotations

from memory import task_tree
from memory.models import AttackPhase
from reports.mitre_mapper import build_coverage_matrix


def test_empty_session_has_zero_coverage(db, pentest_session) -> None:
    matrix = build_coverage_matrix(db, pentest_session.id)
    assert matrix["covered"] == 0
    assert matrix["total"] > 0
    assert matrix["coverage_pct"] == 0.0


def test_completed_node_with_ttp_marks_technique(db, pentest_session) -> None:
    roots = task_tree.bootstrap_phases(db, pentest_session)
    recon = next(r for r in roots if r.phase == AttackPhase.RECON)
    [child] = task_tree.expand(db, recon, [{
        "title": "nmap scan",
        "phase": AttackPhase.RECON,
        "mitre_ttp": "T1046",
        "tool_name": "nmap",
    }])
    task_tree.start(db, child)
    task_tree.complete(db, child, command="nmap", findings={})

    matrix = build_coverage_matrix(db, pentest_session.id)
    recon_row = next(t for t in matrix["matrix"] if "Reconnaissance" in t["tactic"])
    t1046 = next(r for r in recon_row["techniques"] if r["ttp"] == "T1046")
    assert t1046["exercised"] is True
    assert len(t1046["occurrences"]) == 1
