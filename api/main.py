"""FastAPI app — dashboard + JSON API."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from api.routes import approvals, reports, sessions
from api.templating import templates

app = FastAPI(
    title="AI Red Team Engine",
    description="Dashboard + JSON API for the AI-Powered Offensive Security Engine",
    version="0.1.0",
)

app.include_router(sessions.router)
app.include_router(approvals.router)
app.include_router(reports.router)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
