"""Render a Cybertronium-style penetration test report.

Pulls every artefact required by FYP brief §3.3:
  - Executive summary
  - Scope + RoE
  - Attack narrative (chronological, from PTT)
  - Evidence table (command, output, finding, MITRE TTP)
  - Vulnerability register
  - MITRE ATT&CK coverage matrix
  - Recommendations
  - Appendix (raw outputs, decision log)
"""
from __future__ import annotations

import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from memory import queries, task_tree
from memory.models import NodeStatus, PentestSession
from reports.mitre_mapper import build_coverage_matrix


TEMPLATE_DIR = Path(__file__).parent / "templates"
DEFAULT_OUTPUT_DIR = Path("artefacts/reports")


class ReportGenerator:
    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render_html(self, db: Session, session: PentestSession) -> str:
        ctx = self._gather(db, session)
        return self.env.get_template("pentest_report.html.j2").render(**ctx)

    def write(self, db: Session, session: PentestSession) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        out = self.output_dir / f"{session.id}.html"
        out.write_text(self.render_html(db, session), encoding="utf-8")
        return out

    # ─────────────────────────────────────────────────────────────────────

    def _gather(self, db: Session, session: PentestSession) -> dict[str, Any]:
        nodes = task_tree.all_nodes(db, session.id)
        completed = [n for n in nodes if n.status == NodeStatus.COMPLETED]
        completed.sort(key=lambda n: n.completed_at or n.created_at)

        hosts = queries.hosts_for(db, session.id)
        vulns = queries.vulns_for(db, session.id)
        creds = queries.creds_for(db, session.id)
        decisions = queries.decisions_for(db, session.id)
        coverage = build_coverage_matrix(db, session.id)

        severity_counts = Counter(v.severity for v in vulns)
        risk_rating = self._risk_rating(severity_counts)

        return {
            "session": session,
            "hosts": hosts,
            "vulnerabilities": vulns,
            "credentials": creds,
            "narrative": completed,
            "decisions": decisions,
            "coverage": coverage,
            "severity_counts": dict(severity_counts),
            "risk_rating": risk_rating,
            "tree_ascii": task_tree.to_ascii(db, session.id),
        }

    @staticmethod
    def _risk_rating(severity_counts: Counter) -> str:
        if severity_counts.get("critical", 0) > 0:
            return "Critical"
        if severity_counts.get("high", 0) > 0:
            return "High"
        if severity_counts.get("medium", 0) > 0:
            return "Medium"
        if severity_counts.get("low", 0) > 0:
            return "Low"
        return "Informational"
