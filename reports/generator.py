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

import json
import shutil
import subprocess
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

# Evidence-table excerpt budget. A full-port nmap result is ~700 lines of JSON.
EXCERPT_LINES = 24
EXCERPT_CHARS = 1800


def excerpt(value: Any, max_lines: int = EXCERPT_LINES, max_chars: int = EXCERPT_CHARS) -> str:
    """Pretty-print a findings dict for the evidence table, capped.

    The column is headed "Findings (excerpt)" but used to render the entire
    dump: a single nmap result ran to four PDF pages, and because the <pre>
    limited its height with overflow left visible, the overflow was painted
    straight over the rows beneath it — two findings legibly on top of each
    other. Cap it here; the full findings stay in the database.
    """
    text = value if isinstance(value, str) else json.dumps(
        value, indent=2, sort_keys=True, default=str,
    )
    total = text.count("\n") + 1
    out = "\n".join(text.splitlines()[:max_lines])
    if len(out) > max_chars:
        out = out[:max_chars].rstrip()
    if len(out) < len(text):
        out += f"\n… truncated ({total} lines total; full findings retained in the database)"
    return out


class ReportGenerator:
    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or DEFAULT_OUTPUT_DIR
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["excerpt"] = excerpt

    def render_html(self, db: Session, session: PentestSession) -> str:
        ctx = self._gather(db, session)
        return self.env.get_template("pentest_report.html.j2").render(**ctx)

    def write(self, db: Session, session: PentestSession) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        out = self.output_dir / f"{session.id}.html"
        out.write_text(self.render_html(db, session), encoding="utf-8")
        return out

    def write_pdf(self, html_path: Path) -> Path:
        """Convert an already-rendered report to PDF.

        Tries the converters Kali is likely to have, in order of output quality.
        Raises RuntimeError with install guidance if none are present, rather
        than silently producing no PDF.
        """
        # Absolute: as_uri() below rejects relative paths, and the converters
        # are happier with full paths regardless of their working directory.
        html_path = html_path.resolve()
        pdf_path = html_path.with_suffix(".pdf")
        # (binary, argv builder). weasyprint honours the stylesheet most
        # faithfully; the headless browsers are the common fallbacks.
        converters: list[tuple[str, list[str]]] = [
            ("weasyprint", ["weasyprint", str(html_path), str(pdf_path)]),
            ("wkhtmltopdf", ["wkhtmltopdf", "--enable-local-file-access",
                             str(html_path), str(pdf_path)]),
            ("chromium", ["chromium", "--headless", "--disable-gpu", "--no-sandbox",
                          f"--print-to-pdf={pdf_path}", html_path.as_uri()]),
            ("google-chrome", ["google-chrome", "--headless", "--disable-gpu",
                               "--no-sandbox", f"--print-to-pdf={pdf_path}",
                               html_path.as_uri()]),
        ]
        tried: list[str] = []
        for binary, argv in converters:
            if not shutil.which(binary):
                continue
            tried.append(binary)
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=180)
            if proc.returncode == 0 and pdf_path.exists():
                return pdf_path
        if tried:
            raise RuntimeError(
                f"PDF conversion failed using {tried}. Last error: "
                f"{proc.stderr.strip()[:400]}"                          # noqa: F821
            )
        raise RuntimeError(
            "no HTML-to-PDF converter found. Install one:\n"
            "    sudo apt install -y weasyprint      # best CSS fidelity\n"
            "    sudo apt install -y wkhtmltopdf\n"
            "…or open the HTML in a browser and print to PDF."
        )

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

        compromised = [h for h in hosts if h.is_compromised]
        severity_counts = Counter(v.severity for v in vulns)
        risk_rating = self._risk_rating(severity_counts, compromised=bool(compromised))

        # The tool a step ran lives on the node it ran, not in the decision
        # JSON: `new_node` is null whenever the agent reused a node an earlier
        # expand_tree created, which left the Appendix B column blank for over
        # half of a typical run. Resolve through task_node_id first.
        node_tools = {n.id: n.tool_name for n in nodes}
        decision_rows = [
            {
                "step": d.step_number,
                "action": (d.proposed_action or {}).get("action"),
                "tool": node_tools.get(d.task_node_id)
                        or ((d.proposed_action or {}).get("new_node") or {}).get("tool_name"),
                "approved_by": d.approved_by,
                "input_tokens": d.llm_input_tokens,
                "output_tokens": d.llm_output_tokens,
            }
            for d in decisions
        ]

        return {
            "session": session,
            "hosts": hosts,
            "compromised_hosts": compromised,
            "vulnerabilities": vulns,
            "credentials": creds,
            "narrative": completed,
            "decisions": decisions,
            "decision_rows": decision_rows,
            "coverage": coverage,
            "severity_counts": dict(severity_counts),
            "risk_rating": risk_rating,
            "tree_ascii": task_tree.to_ascii(db, session.id),
        }

    @staticmethod
    def _risk_rating(severity_counts: Counter, *, compromised: bool = False) -> str:
        # A host the engine obtained a shell on is critical whatever the
        # scanners logged. Deriving the rating from scanner severities alone
        # let a rooted target be reported as "Informational".
        if compromised or severity_counts.get("critical", 0) > 0:
            return "Critical"
        if severity_counts.get("high", 0) > 0:
            return "High"
        if severity_counts.get("medium", 0) > 0:
            return "Medium"
        if severity_counts.get("low", 0) > 0:
            return "Low"
        return "Informational"
