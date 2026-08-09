"""Build a MITRE ATT&CK coverage matrix from session task nodes."""
from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from memory import task_tree


# A pragmatic subset — the FYP brief expects coverage tracking for the
# techniques actually exercised by the tools the engine wraps.
TACTIC_TECHNIQUES: dict[str, list[str]] = {
    "TA0043 Reconnaissance":      ["T1046", "T1018", "T1595", "T1589", "T1590", "T1596"],
    "TA0007 Discovery":           ["T1083", "T1135", "T1087.002", "T1069.002", "T1482"],
    "TA0001 Initial Access":      ["T1190", "T1078"],
    "TA0004 Privilege Escalation": ["T1068", "T1548", "T1055"],
    "TA0006 Credential Access":   ["T1110.001", "T1110.002", "T1110.003",
                                   "T1003", "T1003.006", "T1558.001",
                                   "T1558.002", "T1558.003", "T1558.004"],
    "TA0008 Lateral Movement":    ["T1021.002", "T1550.003"],
    "TA0009 Collection":          ["T1005", "T1039"],
    "TA0040 Impact":              [],
}


def build_coverage_matrix(db: Session, session_id: uuid.UUID) -> dict[str, Any]:
    """Returns a dict suitable for direct rendering in the report template."""
    nodes = task_tree.all_nodes(db, session_id)
    hit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n in nodes:
        if not n.mitre_ttp:
            continue
        hit[n.mitre_ttp].append({
            "node_id": str(n.id),
            "title": n.title,
            "status": n.status.value,
            "tool": n.tool_name,
        })

    matrix = []
    for tactic, techniques in TACTIC_TECHNIQUES.items():
        rows = []
        for ttp in techniques:
            rows.append({
                "ttp": ttp,
                "exercised": ttp in hit,
                "occurrences": hit.get(ttp, []),
            })
        matrix.append({"tactic": tactic, "techniques": rows})

    total = sum(len(t["techniques"]) for t in matrix)
    covered = sum(1 for t in matrix for r in t["techniques"] if r["exercised"])
    return {"matrix": matrix, "covered": covered, "total": total,
            "coverage_pct": round(100 * covered / total, 1) if total else 0.0}
