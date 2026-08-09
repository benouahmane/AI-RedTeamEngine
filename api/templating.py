"""Shared Jinja2 templates engine.

Importing `templates` from this module instead of constructing a new
`Jinja2Templates` per route guarantees every renderer points at the same
`api/templates/` directory and shares any filters/globals registered here.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _pretty_json(value: Any, indent: int = 2) -> str:
    """Jinja filter — pretty-print a value as JSON, falling back to str()."""
    try:
        return json.dumps(value, indent=indent, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


templates.env.filters["pretty_json"] = _pretty_json
