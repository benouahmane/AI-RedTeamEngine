"""Mode B (human-in-the-loop) approval endpoints.

The agent marks a node `awaiting_approval` and blocks. The dashboard polls
`GET /api/approvals/{session_id}/html` (or the JSON variant
`/pending/{session_id}`) and submits decisions through
`POST /api/approvals/{node_id}/{approve|reject}` (JSON or `/html` suffix).
"""
from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.deps import get_db_session
from api.templating import templates
from memory import task_tree
from memory.models import NodeStatus, TaskNode

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


def _pending_nodes(db: Session, session_id: uuid.UUID) -> list[TaskNode]:
    stmt = (
        select(TaskNode)
        .where(TaskNode.session_id == session_id)
        .where(TaskNode.status == NodeStatus.AWAITING_APPROVAL)
        .order_by(TaskNode.priority.desc(), TaskNode.created_at.asc())
    )
    return list(db.scalars(stmt))


def _render_panel(
    request: Request, db: Session, session_id: uuid.UUID
) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "_approvals_panel.html",
        {"session_id": session_id, "nodes": _pending_nodes(db, session_id)},
    )


@router.get("/pending/{session_id}")
def pending(session_id: uuid.UUID, db: Session = Depends(get_db_session)) -> list[dict[str, Any]]:
    return [
        n.to_summary() | {"rationale": n.rationale, "command_preview": n.command}
        for n in _pending_nodes(db, session_id)
    ]


@router.post("/{node_id}/approve")
def approve(
    node_id: uuid.UUID,
    payload: dict[str, Any] = Body(default_factory=dict),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    node = db.get(TaskNode, node_id)
    if node is None:
        raise HTTPException(404, "node not found")
    if node.status != NodeStatus.AWAITING_APPROVAL:
        raise HTTPException(409, f"node is {node.status.value}, not awaiting_approval")

    # Optional param override before approving
    if "tool_params" in payload and isinstance(payload["tool_params"], dict):
        node.tool_params = payload["tool_params"]
    task_tree.start(db, node)
    return {"id": str(node.id), "status": node.status.value}


@router.post("/{node_id}/reject")
def reject(
    node_id: uuid.UUID,
    payload: dict[str, Any] = Body(default_factory=dict),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    node = db.get(TaskNode, node_id)
    if node is None:
        raise HTTPException(404, "node not found")
    reason = payload.get("reason") or "rejected by analyst"
    task_tree.reject(db, node, reason)
    return {"id": str(node.id), "status": node.status.value, "reason": reason}


# ─────────────────────────────────────────────────────────────────────────
# HTMX endpoints — return the pending-approvals panel HTML
# ─────────────────────────────────────────────────────────────────────────


@router.get("/{session_id}/html", response_class=HTMLResponse)
def panel(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    return _render_panel(request, db, session_id)


@router.post("/{node_id}/approve/html", response_class=HTMLResponse)
def approve_html(
    node_id: uuid.UUID,
    request: Request,
    tool_params_json: str = Form(default=""),
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Approve a node via the dashboard form.

    `tool_params_json` is the JSON-serialised tool_params textarea. Empty or
    invalid JSON keeps the existing parameters rather than failing — the
    analyst is approving the action, not editing critical config.
    """
    node = db.get(TaskNode, node_id)
    if node is None:
        raise HTTPException(404, "node not found")
    if node.status != NodeStatus.AWAITING_APPROVAL:
        raise HTTPException(409, f"node is {node.status.value}, not awaiting_approval")

    if tool_params_json.strip():
        try:
            parsed = json.loads(tool_params_json)
            if isinstance(parsed, dict):
                node.tool_params = parsed
        except json.JSONDecodeError:
            pass  # fall through with existing params

    task_tree.start(db, node)
    return _render_panel(request, db, node.session_id)


@router.post("/{node_id}/reject/html", response_class=HTMLResponse)
def reject_html(
    node_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Reject a pending node. The reason comes from htmx's `hx-prompt`,
    delivered via the `HX-Prompt` request header."""
    node = db.get(TaskNode, node_id)
    if node is None:
        raise HTTPException(404, "node not found")
    reason = request.headers.get("HX-Prompt") or "rejected by analyst"
    task_tree.reject(db, node, reason)
    return _render_panel(request, db, node.session_id)
