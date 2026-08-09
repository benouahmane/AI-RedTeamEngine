"""Operation mode handling — autonomous vs human-in-the-loop.

Mode A (autonomous): every proposed action executes immediately.
Mode B (human-in-loop): the agent marks a node `awaiting_approval`; the
analyst dashboard sees it and POSTs an approval/modification/rejection.
This module exposes a polling `ApprovalGateway` the agent loop blocks on.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy.orm import Session

from memory import task_tree
from memory.models import NodeStatus, OperationMode, TaskNode


@dataclass
class ApprovalDecision:
    approved: bool
    approver: str | None = None
    modified_params: dict[str, Any] | None = None
    rejection_reason: str | None = None


class ApprovalGateway(Protocol):
    """Pluggable approval source. The default `DBPollingGateway` polls the
    DB for status transitions; a CLI gateway is available for headless runs."""

    def request(self, db: Session, node: TaskNode, proposed: dict[str, Any]) -> ApprovalDecision: ...


class DBPollingGateway:
    """Marks the node `AWAITING_APPROVAL` then polls until status changes.

    The dashboard (`api/routes/approvals.py`) flips the status by calling
    `task_tree.start()` (approve), updating `tool_params` then start
    (modify+approve), or `task_tree.reject()`.
    """

    def __init__(self, poll_interval: float = 1.0, timeout: float = 3600.0) -> None:
        self.poll_interval = poll_interval
        self.timeout = timeout

    def request(self, db: Session, node: TaskNode, proposed: dict[str, Any]) -> ApprovalDecision:
        task_tree.mark_awaiting_approval(db, node)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            db.refresh(node)
            if node.status == NodeStatus.IN_PROGRESS:
                modified = None
                if node.tool_params and node.tool_params != proposed.get("tool_params"):
                    modified = node.tool_params
                return ApprovalDecision(approved=True, modified_params=modified)
            if node.status == NodeStatus.REJECTED:
                return ApprovalDecision(approved=False, rejection_reason=node.error)
            time.sleep(self.poll_interval)
        return ApprovalDecision(
            approved=False,
            rejection_reason=f"Approval timeout after {self.timeout}s",
        )


class CLIGateway:
    """Synchronous approval at the terminal — handy for headless runs."""

    def request(self, db: Session, node: TaskNode, proposed: dict[str, Any]) -> ApprovalDecision:
        import json
        print("\n" + "─" * 60)
        print(f"[Mode B] Proposed action for node {node.id}")
        print(f"  Title:   {node.title}")
        print(f"  Tool:    {proposed.get('tool_name')}")
        print(f"  Params:  {json.dumps(proposed.get('tool_params'), indent=2)}")
        print(f"  Why:     {proposed.get('rationale')}")
        ans = input("Approve? [y/N/skip]: ").strip().lower()
        if ans == "y":
            task_tree.start(db, node)
            return ApprovalDecision(approved=True, approver="cli")
        if ans == "skip":
            task_tree.skip(db, node, "skipped by analyst at CLI")
            return ApprovalDecision(approved=False, rejection_reason="skipped")
        task_tree.reject(db, node, "rejected by analyst at CLI")
        return ApprovalDecision(approved=False, rejection_reason="rejected")


def gateway_for(mode: OperationMode) -> ApprovalGateway | None:
    if mode == OperationMode.HUMAN_IN_LOOP:
        return DBPollingGateway()
    return None
