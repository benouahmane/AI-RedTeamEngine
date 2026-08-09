"""Session lifecycle — create, list, get, render PTT, abort.

JSON endpoints serve programmatic clients (CLI, tests). HTMX-friendly
HTML endpoints (suffixed with `/html` or returning `HTMLResponse`) feed
fragments into the dashboard at `api/templates/`.
"""
from __future__ import annotations

import threading
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from agent import RedTeamAgent
from api.deps import get_db_session
from api.routes.reports import saved_report_path
from api.templating import templates
from environments import EnvironmentManager
from memory import queries, task_tree
from memory.db import SessionLocal
from memory.models import OperationMode, PentestSession, SessionStatus
from reports import ReportGenerator

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _start_agent_thread(session_id: uuid.UUID) -> None:
    """Spawn a daemon thread that runs the agent loop for `session_id`.

    Uses its own SQLAlchemy session (each thread must own its connection).
    Production should swap this for a worker queue (Celery/Arq) — fine for
    single-operator FYP runs.
    """
    def _run() -> None:
        with SessionLocal() as worker_db:
            session = worker_db.get(PentestSession, session_id)
            if session is None:
                return
            agent = RedTeamAgent(worker_db, session)
            agent.run()

    threading.Thread(target=_run, daemon=True, name=f"agent-{session_id}").start()


def _render_panel(request: Request, db: Session, session_id: uuid.UUID) -> HTMLResponse:
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    return templates.TemplateResponse(
        request,
        "_session_panel.html",
        {
            "session": s,
            "tree": task_tree.to_ascii(db, session_id) or "(empty tree)",
            "hosts": queries.hosts_for(db, session_id),
            "vulnerabilities": queries.vulns_for(db, session_id),
            "credentials": queries.creds_for(db, session_id),
            "decisions": queries.decisions_for(db, session_id)[-20:],
            "report_saved": saved_report_path(session_id) is not None,
        },
    )


class CreateSessionRequest(BaseModel):
    name: str
    target: str
    environment: str
    mode: OperationMode = OperationMode.HUMAN_IN_LOOP
    objective: str | None = None
    rules_of_engagement: dict[str, Any] = {}


class SessionSummary(BaseModel):
    id: uuid.UUID
    name: str
    target: str
    environment: str
    status: SessionStatus
    mode: OperationMode

    model_config = {"from_attributes": True}


@router.post("", status_code=status.HTTP_201_CREATED)
def create(req: CreateSessionRequest, db: Session = Depends(get_db_session)) -> dict[str, Any]:
    envs = EnvironmentManager()
    try:
        envs.get(req.environment)
    except KeyError as exc:
        raise HTTPException(400, str(exc)) from exc

    s = PentestSession(
        name=req.name,
        target=req.target,
        environment=req.environment,
        mode=req.mode,
        objective=req.objective,
        rules_of_engagement=req.rules_of_engagement,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    task_tree.bootstrap_phases(db, s)
    return {"id": str(s.id), "status": s.status.value}


@router.get("")
def list_all(db: Session = Depends(get_db_session)) -> list[SessionSummary]:
    return [SessionSummary.model_validate(s) for s in queries.list_sessions(db)]


@router.get("/{session_id}")
def get_one(session_id: uuid.UUID, db: Session = Depends(get_db_session)) -> dict[str, Any]:
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    return {
        **SessionSummary.model_validate(s).model_dump(),
        "objective": s.objective,
        "started_at": s.started_at,
        "completed_at": s.completed_at,
        "host_count": len(queries.hosts_for(db, session_id)),
        "vuln_count": len(queries.vulns_for(db, session_id)),
    }


@router.get("/{session_id}/tree")
def tree(session_id: uuid.UUID, db: Session = Depends(get_db_session)) -> dict[str, Any]:
    return {
        "ascii": task_tree.to_ascii(db, session_id),
        "context": task_tree.context_for_llm(db, session_id),
    }


@router.post("/{session_id}/start", status_code=status.HTTP_202_ACCEPTED)
def start(session_id: uuid.UUID, db: Session = Depends(get_db_session)) -> dict[str, str]:
    """Kick off the agent loop in a background thread."""
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    if s.status == SessionStatus.RUNNING:
        raise HTTPException(409, "session already running")
    _start_agent_thread(session_id)
    return {"id": str(session_id), "status": "starting"}


@router.post("/{session_id}/abort")
def abort(session_id: uuid.UUID, db: Session = Depends(get_db_session)) -> dict[str, str]:
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    s.status = SessionStatus.ABORTED
    db.commit()
    return {"id": str(session_id), "status": s.status.value}


# ─────────────────────────────────────────────────────────────────────────
# HTMX endpoints — return HTML fragments swapped into the dashboard
# ─────────────────────────────────────────────────────────────────────────


@router.get("/html", response_class=HTMLResponse)
def list_html(request: Request, db: Session = Depends(get_db_session)) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "_sessions_list.html",
        {"sessions": queries.list_sessions(db)},
    )


@router.get("/{session_id}/panel", response_class=HTMLResponse)
def panel(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    return _render_panel(request, db, session_id)


@router.get("/{session_id}/tree/html", response_class=HTMLResponse)
def tree_html(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    return templates.TemplateResponse(
        request, "_tree.html",
        {
            "tree": task_tree.to_ascii(db, session_id) or "(empty tree)",
            "session_id": session_id,
        },
    )


@router.post("/{session_id}/start/html", response_class=HTMLResponse)
def start_html(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    if s.status != SessionStatus.RUNNING:
        _start_agent_thread(session_id)
    return _render_panel(request, db, session_id)


@router.post("/{session_id}/abort/html", response_class=HTMLResponse)
def abort_html(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    s.status = SessionStatus.ABORTED
    db.commit()
    return _render_panel(request, db, session_id)


@router.post("/{session_id}/save-report/html", response_class=HTMLResponse)
def save_report_html(
    session_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    s = queries.get_session(db, session_id)
    if s is None:
        raise HTTPException(404, "session not found")
    ReportGenerator().write(db, s)
    return _render_panel(request, db, session_id)


@router.post("/form", response_class=HTMLResponse)
def create_from_form(
    request: Request,
    name: str = Form(...),
    target: str = Form(...),
    environment: str = Form(...),
    mode: str = Form("human_in_loop"),
    objective: str = Form(""),
    db: Session = Depends(get_db_session),
) -> HTMLResponse:
    """Form-data session creation, used by the dashboard's new-session form."""
    envs = EnvironmentManager()
    try:
        envs.get(environment)
    except KeyError as exc:
        raise HTTPException(400, str(exc)) from exc
    try:
        op_mode = OperationMode(mode)
    except ValueError as exc:
        raise HTTPException(400, f"invalid mode {mode!r}") from exc

    s = PentestSession(
        name=name,
        target=target,
        environment=environment,
        mode=op_mode,
        objective=objective or None,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    task_tree.bootstrap_phases(db, s)
    return _render_panel(request, db, s.id)
