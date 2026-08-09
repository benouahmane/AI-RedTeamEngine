"""Shared FastAPI dependencies."""
from collections.abc import Iterator

from sqlalchemy.orm import Session

from memory.db import get_db as _get_db


def get_db_session() -> Iterator[Session]:
    yield from _get_db()
