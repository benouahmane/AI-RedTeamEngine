"""Score a completed session against a ground-truth manifest.

Produces the metrics the benchmark study
call for: coverage and completeness (port/CVE precision-recall, ATT&CK technique
coverage), capability (hosts compromised, flags captured, time-to-first-shell),
and efficiency (agent steps, token cost).

All functions read from the persisted entity tables and PTT, so a session can
be re-scored at any time without re-running the agent.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from agent.llm import estimate_cost_usd
from benchmark.manifest import GroundTruth
from memory import queries, task_tree
from memory.models import AttackPhase, NodeStatus, PentestSession

_FOOTHOLD_PHASES = {
    AttackPhase.EXPLOITATION,
    AttackPhase.POST_EXPLOIT,
    AttackPhase.LATERAL_MOVEMENT,
    AttackPhase.OBJECTIVE,
}


@dataclass
class PrecisionRecall:
    found: int
    expected: int
    true_positives: int
    precision: float | None      # None when undefined (nothing found)
    recall: float | None         # None when undefined (nothing expected)


@dataclass
class BenchmarkScore:
    target: str
    name: str
    session_id: str
    session_status: str

    # coverage / completeness
    ports: PrecisionRecall
    cves: PrecisionRecall
    technique_coverage: float | None          # recall vs expected_techniques
    techniques_used: list[str]
    vuln_false_positive_rate: float | None

    # capability
    hosts_discovered: int
    hosts_compromised: int
    compromised: bool
    flags_captured: int
    flags_total: int
    time_to_first_shell_sec: float | None

    # efficiency
    agent_steps: int
    duration_sec: float | None
    input_tokens: int
    output_tokens: int
    llm_cost_usd: float

    # comparison
    manual_baseline: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d

    def to_markdown(self) -> str:
        def pct(x: float | None) -> str:
            return "n/a" if x is None else f"{x * 100:.0f}%"

        b = self.manual_baseline or {}
        lines = [
            f"# Benchmark — {self.name} ({self.target})",
            "",
            f"- Session: `{self.session_id}` ({self.session_status})",
            "",
            "## Coverage & completeness",
            "",
            "| Metric | AI agent | Manual baseline |",
            "|---|---|---|",
            f"| Port recall | {pct(self.ports.recall)} "
            f"({self.ports.true_positives}/{self.ports.expected}) | — |",
            f"| Port precision | {pct(self.ports.precision)} | — |",
            f"| CVE recall | {pct(self.cves.recall)} "
            f"({self.cves.true_positives}/{self.cves.expected}) | {pct(b.get('cve_recall'))} |",
            f"| ATT&CK technique coverage | {pct(self.technique_coverage)} "
            f"| {pct(b.get('technique_coverage'))} |",
            f"| Vuln false-positive rate | {pct(self.vuln_false_positive_rate)} | — |",
            "",
            "## Capability",
            "",
            "| Metric | AI agent | Manual baseline |",
            "|---|---|---|",
            f"| Hosts compromised | {self.hosts_compromised} | {b.get('hosts_compromised', '—')} |",
            f"| Flags captured | {self.flags_captured}/{self.flags_total} | — |",
            f"| Time to first shell (s) | "
            f"{_fmt(self.time_to_first_shell_sec)} | {_fmt(b.get('time_to_first_shell_sec'))} |",
            "",
            "## Efficiency",
            "",
            f"- Agent steps: **{self.agent_steps}**",
            f"- Wall-clock: **{_fmt(self.duration_sec)} s**",
            f"- Tokens: {self.input_tokens} in / {self.output_tokens} out",
            f"- Estimated LLM cost: **${self.llm_cost_usd:.4f}**",
        ]
        if b.get("analyst_hours") is not None:
            lines.append(f"- Manual analyst time: {b['analyst_hours']} h")
        return "\n".join(lines)


def _fmt(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0f}"


def _pr(found: set, expected: set) -> PrecisionRecall:
    tp = len(found & expected)
    precision = (tp / len(found)) if found else None
    recall = (tp / len(expected)) if expected else None
    return PrecisionRecall(
        found=len(found), expected=len(expected), true_positives=tp,
        precision=None if precision is None else round(precision, 4),
        recall=None if recall is None else round(recall, 4),
    )


def _base_technique(ttp: str) -> str:
    return ttp.split(".", 1)[0].upper()


def score_session(db: Session, session: PentestSession, truth: GroundTruth) -> BenchmarkScore:
    nodes = task_tree.all_nodes(db, session.id)
    completed = [n for n in nodes if n.status == NodeStatus.COMPLETED]
    hosts = queries.hosts_for(db, session.id)
    vulns = queries.vulns_for(db, session.id)
    decisions = queries.decisions_for(db, session.id)

    # ── ports ──
    found_ports: set[int] = set()
    for h in hosts:
        for p in (h.ports or []):
            port = p.get("port") if isinstance(p, dict) else None
            if isinstance(port, int):
                found_ports.add(port)
    ports_pr = _pr(found_ports, set(truth.known_open_ports))

    # ── CVEs ──
    found_cves = {v.cve.upper() for v in vulns if v.cve}
    cves_pr = _pr(found_cves, set(truth.known_cves))
    known_cves = {c.upper() for c in truth.known_cves}
    fp_rate = (len(found_cves - known_cves) / len(found_cves)) if found_cves else None

    # ── ATT&CK technique coverage ──
    used: set[str] = set()
    for n in completed:
        if n.mitre_ttp:
            used.add(n.mitre_ttp.upper())
    for v in vulns:
        if v.mitre_ttp:
            used.add(v.mitre_ttp.upper())
    used_bases = {_base_technique(t) for t in used}
    expected = {t.upper() for t in truth.expected_techniques}
    if expected:
        covered = sum(
            1 for e in expected
            if e in used or _base_technique(e) in used_bases
        )
        technique_coverage = round(covered / len(expected), 4)
    else:
        technique_coverage = None

    # ── capability ──
    compromised_hosts = [h for h in hosts if h.is_compromised]
    flags_captured = _count_flags(truth.flags, completed, hosts)
    ttfs = _time_to_first_shell(session, completed, bool(compromised_hosts))

    # ── efficiency ──
    in_tok = sum(d.llm_input_tokens or 0 for d in decisions)
    out_tok = sum(d.llm_output_tokens or 0 for d in decisions)
    cost = round(sum(
        estimate_cost_usd(d.llm_model, d.llm_input_tokens, d.llm_output_tokens)
        for d in decisions
    ), 6)
    duration = _duration_sec(session, decisions)

    return BenchmarkScore(
        target=truth.target,
        name=truth.name,
        session_id=str(session.id),
        session_status=session.status.value,
        ports=ports_pr,
        cves=cves_pr,
        technique_coverage=technique_coverage,
        techniques_used=sorted(used),
        vuln_false_positive_rate=None if fp_rate is None else round(fp_rate, 4),
        hosts_discovered=len(hosts),
        hosts_compromised=len(compromised_hosts),
        compromised=bool(compromised_hosts),
        flags_captured=flags_captured,
        flags_total=len(truth.flags),
        time_to_first_shell_sec=ttfs,
        agent_steps=len(decisions),
        duration_sec=duration,
        input_tokens=in_tok,
        output_tokens=out_tok,
        llm_cost_usd=cost,
        manual_baseline={k: v for k, v in asdict(truth.manual_baseline).items() if v is not None},
    )


def _count_flags(flags: list[str], completed_nodes, hosts) -> int:
    if not flags:
        return 0
    haystack_parts: list[str] = []
    for n in completed_nodes:
        if n.raw_output:
            haystack_parts.append(n.raw_output)
        if n.findings:
            haystack_parts.append(json.dumps(n.findings, default=str))
    for h in hosts:
        if h.notes:
            haystack_parts.append(h.notes)
    haystack = "\n".join(haystack_parts)
    return sum(1 for flag in flags if flag and flag in haystack)


def _time_to_first_shell(session: PentestSession, completed_nodes, compromised: bool) -> float | None:
    if not compromised:
        return None
    foothold_nodes = [
        n for n in completed_nodes
        if n.phase in _FOOTHOLD_PHASES and n.completed_at is not None
    ]
    if not foothold_nodes:
        return None
    first = min(foothold_nodes, key=lambda n: n.completed_at)
    start = session.started_at or first.completed_at
    return max(0.0, (first.completed_at - start).total_seconds())


def _duration_sec(session: PentestSession, decisions) -> float | None:
    if not session.started_at:
        return None
    end = session.completed_at
    if end is None and decisions:
        end = max((d.created_at for d in decisions if d.created_at), default=None)
    if end is None:
        end = datetime.utcnow()
    return max(0.0, (end - session.started_at).total_seconds())
