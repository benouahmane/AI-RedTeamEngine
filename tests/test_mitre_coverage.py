"""Tests for the MITRE ATT&CK coverage matrix."""
from __future__ import annotations

import tools  # noqa: F401  — registers the wrappers
from memory import task_tree
from memory.models import AttackPhase
from reports.mitre_mapper import TACTIC_TECHNIQUES, build_coverage_matrix
from tools.registry import all_tools


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


def test_catalogue_covers_every_registered_tool() -> None:
    """A TTP a tool advertises but the catalogue omits is silently uncounted.

    Thirteen were missing — including T1059.004, which pwncat and the agent
    both use — so a run that exercised three techniques reported two.
    """
    catalogued = {ttp for techniques in TACTIC_TECHNIQUES.values() for ttp in techniques}
    advertised = {
        ttp for entry in all_tools() for ttp in (entry.get("mitre_techniques") or [])
    }
    missing = sorted(advertised - catalogued)
    assert not missing, (
        f"tools advertise {missing} but TACTIC_TECHNIQUES has no row for them; "
        f"they would be dropped from the coverage metric"
    )


def test_uncatalogued_ttps_are_surfaced_not_dropped(db, pentest_session) -> None:
    """The agent tags nodes with whatever TTP fits, not only catalogued ones."""
    roots = task_tree.bootstrap_phases(db, pentest_session)
    recon = next(r for r in roots if r.phase == AttackPhase.RECON)
    [child] = task_tree.expand(db, recon, [{
        "title": "exfiltrate over DNS",
        "phase": AttackPhase.RECON,
        "mitre_ttp": "T1048.003",          # deliberately outside the catalogue
        "tool_name": "nmap",
    }])
    task_tree.start(db, child)
    task_tree.complete(db, child, command="…", findings={})

    matrix = build_coverage_matrix(db, pentest_session.id)
    assert [u["ttp"] for u in matrix["uncatalogued"]] == ["T1048.003"]
    assert matrix["uncatalogued"][0]["occurrences"][0]["title"] == "exfiltrate over DNS"
    # Excluded from the percentage, but counted in the honest total.
    assert matrix["covered"] == 0
    assert matrix["exercised_total"] == 1


def test_execution_tactic_counts_shell_commands(db, pentest_session) -> None:
    """T1059.004 is what `session_run`/pwncat tag; it had nowhere to land."""
    roots = task_tree.bootstrap_phases(db, pentest_session)
    post = next(r for r in roots if r.phase == AttackPhase.POST_EXPLOIT)
    [child] = task_tree.expand(db, post, [{
        "title": "Verify root via id",
        "phase": AttackPhase.POST_EXPLOIT,
        "mitre_ttp": "T1059.004",
        "tool_name": "metasploit",
    }])
    task_tree.start(db, child)
    task_tree.complete(db, child, command="id", findings={})

    matrix = build_coverage_matrix(db, pentest_session.id)
    execution = next(t for t in matrix["matrix"] if "Execution" in t["tactic"])
    assert next(r for r in execution["techniques"] if r["ttp"] == "T1059.004")["exercised"]
    assert matrix["uncatalogued"] == []
