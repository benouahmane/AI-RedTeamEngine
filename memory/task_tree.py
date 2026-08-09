"""Pentesting Task Tree (PTT) operations.

The agent's primary working memory. Operations:

- `add_root` / `expand` — grow the tree
- `pick_next` — pull the highest-priority unblocked pending node
- `start` / `complete` / `fail` / `skip` — state transitions
- `context_for_llm` — produce a compact, token-efficient snapshot for the LLM prompt
- `to_ascii` — human-readable view for the dashboard / Mode B approvals
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from memory.models import (
    AttackPhase,
    NodeStatus,
    PentestSession,
    TaskNode,
)


# ────────────────────────────────────────────────────────────────────────────
# Mutations
# ────────────────────────────────────────────────────────────────────────────


def add_root(
    db: Session,
    session_id: uuid.UUID,
    title: str,
    phase: AttackPhase,
    *,
    rationale: str | None = None,
    target: str | None = None,
    priority: int = 5,
) -> TaskNode:
    """Create a top-level branch (typically one per attack phase)."""
    node = TaskNode(
        session_id=session_id,
        parent_id=None,
        depth=0,
        title=title,
        rationale=rationale,
        phase=phase,
        target=target,
        priority=priority,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


def expand(
    db: Session,
    parent: TaskNode,
    children: list[dict[str, Any]],
) -> list[TaskNode]:
    """Add child nodes under `parent`. Each dict is a kwargs-shaped node spec."""
    created: list[TaskNode] = []
    for spec in children:
        child = TaskNode(
            session_id=parent.session_id,
            parent_id=parent.id,
            depth=parent.depth + 1,
            phase=spec.get("phase", parent.phase),
            title=spec["title"],
            rationale=spec.get("rationale"),
            mitre_ttp=spec.get("mitre_ttp"),
            target=spec.get("target", parent.target),
            tool_name=spec.get("tool_name"),
            tool_params=spec.get("tool_params") or {},
            priority=spec.get("priority", 3),
        )
        db.add(child)
        created.append(child)
    db.commit()
    for c in created:
        db.refresh(c)
    return created


def start(db: Session, node: TaskNode) -> TaskNode:
    node.status = NodeStatus.IN_PROGRESS
    node.started_at = datetime.utcnow()
    db.commit()
    db.refresh(node)
    return node


def complete(
    db: Session,
    node: TaskNode,
    *,
    command: str | None = None,
    raw_output: str | None = None,
    findings: dict[str, Any] | None = None,
) -> TaskNode:
    node.status = NodeStatus.COMPLETED
    node.completed_at = datetime.utcnow()
    if command is not None:
        node.command = command
    if raw_output is not None:
        node.raw_output = raw_output[:50_000]   # cap stored output to avoid bloat
    if findings is not None:
        node.findings = findings
    db.commit()
    db.refresh(node)
    return node


def fail(db: Session, node: TaskNode, error: str) -> TaskNode:
    node.status = NodeStatus.FAILED
    node.completed_at = datetime.utcnow()
    node.error = error
    db.commit()
    db.refresh(node)
    return node


def skip(db: Session, node: TaskNode, reason: str) -> TaskNode:
    node.status = NodeStatus.SKIPPED
    node.completed_at = datetime.utcnow()
    node.error = reason
    db.commit()
    db.refresh(node)
    return node


def mark_awaiting_approval(db: Session, node: TaskNode) -> TaskNode:
    node.status = NodeStatus.AWAITING_APPROVAL
    db.commit()
    db.refresh(node)
    return node


def reject(db: Session, node: TaskNode, reason: str) -> TaskNode:
    node.status = NodeStatus.REJECTED
    node.error = reason
    db.commit()
    db.refresh(node)
    return node


# ────────────────────────────────────────────────────────────────────────────
# Queries
# ────────────────────────────────────────────────────────────────────────────


def pick_next(db: Session, session_id: uuid.UUID) -> TaskNode | None:
    """Highest-priority pending node whose blocker (if any) has completed."""
    stmt = (
        select(TaskNode)
        .where(TaskNode.session_id == session_id)
        .where(TaskNode.status == NodeStatus.PENDING)
        .order_by(TaskNode.priority.desc(), TaskNode.created_at.asc())
    )
    for candidate in db.scalars(stmt):
        if candidate.blocked_by_id is None:
            return candidate
        blocker = db.get(TaskNode, candidate.blocked_by_id)
        if blocker and blocker.status == NodeStatus.COMPLETED:
            return candidate
    return None


def get_roots(db: Session, session_id: uuid.UUID) -> list[TaskNode]:
    stmt = (
        select(TaskNode)
        .where(TaskNode.session_id == session_id)
        .where(TaskNode.parent_id.is_(None))
        .order_by(TaskNode.created_at.asc())
    )
    return list(db.scalars(stmt))


def all_nodes(db: Session, session_id: uuid.UUID) -> list[TaskNode]:
    stmt = (
        select(TaskNode)
        .where(TaskNode.session_id == session_id)
        .order_by(TaskNode.created_at.asc())
    )
    return list(db.scalars(stmt))


# ────────────────────────────────────────────────────────────────────────────
# Views — for LLM prompt and human dashboard
# ────────────────────────────────────────────────────────────────────────────


def context_for_llm(db: Session, session_id: uuid.UUID, *, recent_limit: int = 8) -> dict[str, Any]:
    """Compact tree snapshot fed into the agent prompt.

    Token-budget conscious: returns summaries, not raw output. The agent
    can ask for `raw_output` of a specific node by ID if it needs detail.
    """
    nodes = all_nodes(db, session_id)
    by_status: dict[NodeStatus, list[TaskNode]] = {s: [] for s in NodeStatus}
    for n in nodes:
        by_status[n.status].append(n)

    pending_sorted = sorted(
        by_status[NodeStatus.PENDING],
        key=lambda n: (-n.priority, n.created_at),
    )
    completed_recent = sorted(
        by_status[NodeStatus.COMPLETED],
        key=lambda n: n.completed_at or datetime.min,
        reverse=True,
    )[:recent_limit]

    return {
        "session_id": str(session_id),
        "tree_size": len(nodes),
        "in_progress": [n.to_summary() for n in by_status[NodeStatus.IN_PROGRESS]],
        "pending_top": [n.to_summary() for n in pending_sorted[:10]],
        "recent_completed": [n.to_summary() for n in completed_recent],
        "dead_ends": [
            n.to_summary()
            for n in (by_status[NodeStatus.FAILED] + by_status[NodeStatus.SKIPPED])
        ][-recent_limit:],
        "phase_counts": {
            phase.value: sum(1 for n in nodes if n.phase == phase)
            for phase in AttackPhase
        },
    }


_STATUS_GLYPH = {
    NodeStatus.PENDING: "[ ]",
    NodeStatus.IN_PROGRESS: "[↻]",
    NodeStatus.COMPLETED: "[✓]",
    NodeStatus.FAILED: "[✗]",
    NodeStatus.SKIPPED: "[~]",
    NodeStatus.AWAITING_APPROVAL: "[?]",
    NodeStatus.REJECTED: "[✗]",
}


def to_ascii(db: Session, session_id: uuid.UUID) -> str:
    """Render the tree as ASCII for human consumption."""
    nodes = all_nodes(db, session_id)
    by_parent: dict[uuid.UUID | None, list[TaskNode]] = {}
    for n in nodes:
        by_parent.setdefault(n.parent_id, []).append(n)

    lines: list[str] = []

    def render(node: TaskNode, prefix: str, is_last: bool) -> None:
        connector = "└── " if is_last else "├── "
        glyph = _STATUS_GLYPH.get(node.status, "[?]")
        lines.append(f"{prefix}{connector}{glyph} {node.title}")
        children = by_parent.get(node.id, [])
        for i, child in enumerate(children):
            extension = "    " if is_last else "│   "
            render(child, prefix + extension, i == len(children) - 1)

    roots = by_parent.get(None, [])
    for i, root in enumerate(roots):
        render(root, "", i == len(roots) - 1)

    return "\n".join(lines)


# ────────────────────────────────────────────────────────────────────────────
# Bootstrap — typical phase-rooted skeleton for a new session
# ────────────────────────────────────────────────────────────────────────────


def bootstrap_phases(db: Session, session: PentestSession) -> list[TaskNode]:
    """Seed the tree with one root per phase. Children are added by the agent
    as discoveries are made."""
    specs = [
        (AttackPhase.RECON, "Reconnaissance", 5),
        (AttackPhase.ENUMERATION, "Service enumeration", 4),
        (AttackPhase.VULN_ID, "Vulnerability identification", 4),
        (AttackPhase.EXPLOITATION, "Exploitation", 3),
        (AttackPhase.POST_EXPLOIT, "Post-exploitation", 3),
        (AttackPhase.LATERAL_MOVEMENT, "Lateral movement", 2),
        (AttackPhase.OBJECTIVE, "Objective completion", 2),
    ]
    return [
        add_root(db, session.id, title=title, phase=phase, target=session.target, priority=prio)
        for phase, title, prio in specs
    ]
