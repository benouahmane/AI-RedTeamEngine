"""Pytest fixtures — in-memory SQLite for unit tests."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from memory.db import Base
import memory.models  # noqa: F401  (register tables)
from memory.models import OperationMode, PentestSession


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite:///:memory:", future=True)
    Base.metadata.create_all(engine)
    SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    session = SessionFactory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def pentest_session(db) -> PentestSession:
    s = PentestSession(
        name="test session",
        target="192.168.56.101",
        environment="env1",
        mode=OperationMode.AUTONOMOUS,
        objective="get root",
        rules_of_engagement={},
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return s
