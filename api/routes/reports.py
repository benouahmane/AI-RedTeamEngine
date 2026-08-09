"""Report rendering + download."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy.orm import Session

from api.deps import get_db_session
from memory import queries
from reports import ReportGenerator
from reports.generator import DEFAULT_OUTPUT_DIR

router = APIRouter(prefix="/api/reports", tags=["reports"])


def saved_report_path(session_id: uuid.UUID):
    path = DEFAULT_OUTPUT_DIR / f"{session_id}.html"
    return path if path.exists() else None


@router.get("/{session_id}/render", response_class=HTMLResponse)
def render(session_id: uuid.UUID, db: Session = Depends(get_db_session)) -> str:
    session = queries.get_session(db, session_id)
    if session is None:
        raise HTTPException(404, "session not found")
    return ReportGenerator().render_html(db, session)


@router.post("/{session_id}/save")
def save(session_id: uuid.UUID, db: Session = Depends(get_db_session)) -> dict[str, str]:
    session = queries.get_session(db, session_id)
    if session is None:
        raise HTTPException(404, "session not found")
    path = ReportGenerator().write(db, session)
    return {"path": str(path)}


@router.get("/{session_id}/download")
def download(session_id: uuid.UUID) -> FileResponse:
    path = saved_report_path(session_id)
    if path is None:
        raise HTTPException(404, "no saved report — finish the session or POST /save")
    return FileResponse(
        path,
        media_type="text/html",
        filename=f"pentest-report-{session_id}.html",
    )
