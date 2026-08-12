"""SQLAlchemy models for session state and the Pentesting Task Tree (PTT).

The PTT (`TaskNode`) is the agent's primary working memory — instead of replaying
raw history, the agent reads the current tree state to decide the next action.
Entity tables (Host, Vulnerability, Credential) are populated as findings extracted
from completed task nodes.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from memory.db import Base


# ────────────────────────────────────────────────────────────────────────────
# Enums
# ────────────────────────────────────────────────────────────────────────────


class AttackPhase(str, enum.Enum):
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_ID = "vuln_id"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    LATERAL_MOVEMENT = "lateral_movement"
    OBJECTIVE = "objective"


class NodeStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    AWAITING_APPROVAL = "awaiting_approval"   # Mode B
    REJECTED = "rejected"                      # Mode B


class SessionStatus(str, enum.Enum):
    INITIALISING = "initialising"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ABORTED = "aborted"
    ERROR = "error"


class OperationMode(str, enum.Enum):
    AUTONOMOUS = "autonomous"
    HUMAN_IN_LOOP = "human_in_loop"


def pg_enum(python_enum: type[enum.Enum]) -> SAEnum:
    """Column type that stores an enum's VALUE, not its member name.

    SQLAlchemy defaults to persisting `.name` ("HUMAN_IN_LOOP"), but the Postgres
    types created in migrations/versions/0001_initial_schema.py hold the lowercase
    values ("human_in_loop"), so the default raises InvalidTextRepresentation on
    every insert. `values_callable` makes both sides agree.

    Always use this instead of SAEnum(...) directly for these enums.
    """
    return SAEnum(
        python_enum,
        values_callable=lambda members: [m.value for m in members],
    )


# Use JSONB on Postgres, fall back to JSON elsewhere (tests, sqlite).
JsonCol = JSONB().with_variant(JSON(), "sqlite")


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


# ────────────────────────────────────────────────────────────────────────────
# Pentest Session
# ────────────────────────────────────────────────────────────────────────────


class PentestSession(Base):
    __tablename__ = "pentest_sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    target: Mapped[str] = mapped_column(String(500))            # CIDR, IP, or hostname
    environment: Mapped[str] = mapped_column(String(50))         # env1 | env2 | env3
    mode: Mapped[OperationMode] = mapped_column(pg_enum(OperationMode))
    status: Mapped[SessionStatus] = mapped_column(
        pg_enum(SessionStatus), default=SessionStatus.INITIALISING
    )
    objective: Mapped[str | None] = mapped_column(Text)
    rules_of_engagement: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)

    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    task_nodes: Mapped[list["TaskNode"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    hosts: Mapped[list["Host"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    credentials: Mapped[list["Credential"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )
    decisions: Mapped[list["AgentDecision"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )


# ────────────────────────────────────────────────────────────────────────────
# Pentesting Task Tree (PTT)
# ────────────────────────────────────────────────────────────────────────────


class TaskNode(Base):
    """A single node in the Pentesting Task Tree.

    Trees are session-scoped. Roots have `parent_id = NULL`. Children inherit
    the same `session_id`. The agent navigates the tree to pick the next
    `pending` node with the highest priority and no unmet dependencies.
    """

    __tablename__ = "task_nodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pentest_sessions.id", ondelete="CASCADE")
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("task_nodes.id", ondelete="CASCADE")
    )
    blocked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("task_nodes.id", ondelete="SET NULL")
    )

    title: Mapped[str] = mapped_column(String(500))
    rationale: Mapped[str | None] = mapped_column(Text)         # why the agent added this node
    phase: Mapped[AttackPhase] = mapped_column(pg_enum(AttackPhase))
    mitre_ttp: Mapped[str | None] = mapped_column(String(50))    # e.g. "T1046"

    status: Mapped[NodeStatus] = mapped_column(pg_enum(NodeStatus), default=NodeStatus.PENDING)
    priority: Mapped[int] = mapped_column(Integer, default=3)    # 1 (low) – 5 (critical)
    depth: Mapped[int] = mapped_column(Integer, default=0)

    target: Mapped[str | None] = mapped_column(String(500))      # IP, host, URL the node operates on
    tool_name: Mapped[str | None] = mapped_column(String(100))
    tool_params: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)

    command: Mapped[str | None] = mapped_column(Text)
    raw_output: Mapped[str | None] = mapped_column(Text)
    findings: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)

    session: Mapped[PentestSession] = relationship(back_populates="task_nodes")
    parent: Mapped["TaskNode | None"] = relationship(
        "TaskNode", remote_side=[id], foreign_keys=[parent_id], back_populates="children"
    )
    children: Mapped[list["TaskNode"]] = relationship(
        "TaskNode", back_populates="parent", foreign_keys=[parent_id], cascade="all, delete-orphan"
    )

    def to_summary(self) -> dict[str, Any]:
        """Compact dict representation fed to the LLM."""
        return {
            "id": str(self.id),
            "title": self.title,
            "phase": self.phase.value,
            "status": self.status.value,
            "priority": self.priority,
            "mitre_ttp": self.mitre_ttp,
            "target": self.target,
            "tool": self.tool_name,
            "findings": self.findings,
        }


# ────────────────────────────────────────────────────────────────────────────
# Entity tables — derived from PTT findings, queryable for reports
# ────────────────────────────────────────────────────────────────────────────


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pentest_sessions.id", ondelete="CASCADE")
    )
    ip: Mapped[str] = mapped_column(String(45))
    hostname: Mapped[str | None] = mapped_column(String(255))
    os_fingerprint: Mapped[str | None] = mapped_column(String(255))
    ports: Mapped[list[dict[str, Any]]] = mapped_column(JsonCol, default=list)
    services: Mapped[list[dict[str, Any]]] = mapped_column(JsonCol, default=list)
    is_compromised: Mapped[bool] = mapped_column(default=False)
    notes: Mapped[str | None] = mapped_column(Text)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped[PentestSession] = relationship(back_populates="hosts")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pentest_sessions.id", ondelete="CASCADE")
    )
    host_ip: Mapped[str] = mapped_column(String(45))
    port: Mapped[int | None] = mapped_column(Integer)
    service: Mapped[str | None] = mapped_column(String(100))
    cve: Mapped[str | None] = mapped_column(String(50))
    cvss: Mapped[float | None] = mapped_column()
    severity: Mapped[str] = mapped_column(String(20))            # info/low/medium/high/critical
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    mitre_ttp: Mapped[str | None] = mapped_column(String(50))
    exploited: Mapped[bool] = mapped_column(default=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped[PentestSession] = relationship(back_populates="vulnerabilities")


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pentest_sessions.id", ondelete="CASCADE")
    )
    host_ip: Mapped[str | None] = mapped_column(String(45))
    service: Mapped[str | None] = mapped_column(String(100))
    username: Mapped[str] = mapped_column(String(255))
    secret: Mapped[str] = mapped_column(String(1000))            # cleartext, hash, or ticket
    secret_type: Mapped[str] = mapped_column(String(50))         # password / ntlm / kerberos / ssh_key
    domain: Mapped[str | None] = mapped_column(String(255))
    privilege: Mapped[str | None] = mapped_column(String(50))    # user / admin / domain_admin
    obtained_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped[PentestSession] = relationship(back_populates="credentials")


# ────────────────────────────────────────────────────────────────────────────
# Decision audit log (mandatory per FYP brief §8.1)
# ────────────────────────────────────────────────────────────────────────────


class AgentDecision(Base):
    """One row per LLM decision: context fed → proposed action → result.

    Required by FYP brief §8.1: every agent decision session must be logged.
    """
    __tablename__ = "agent_decisions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("pentest_sessions.id", ondelete="CASCADE")
    )
    task_node_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("task_nodes.id", ondelete="SET NULL")
    )
    step_number: Mapped[int] = mapped_column(Integer)

    context: Mapped[dict[str, Any]] = mapped_column(JsonCol)
    proposed_action: Mapped[dict[str, Any]] = mapped_column(JsonCol)
    actual_command: Mapped[str | None] = mapped_column(Text)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JsonCol, default=dict)
    approved_by: Mapped[str | None] = mapped_column(String(100))    # Mode B: who approved

    llm_model: Mapped[str | None] = mapped_column(String(100))
    llm_input_tokens: Mapped[int | None] = mapped_column(Integer)
    llm_output_tokens: Mapped[int | None] = mapped_column(Integer)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    session: Mapped[PentestSession] = relationship(back_populates="decisions")
