"""Decision audit logger — required by FYP brief §8.1.

Every LLM call is persisted with the context that was fed in, the proposed
action, the actual command executed, and the result. This is what enables
the post-engagement benchmark study (RQ1, RQ4).
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from memory.models import AgentDecision


class DecisionLogger:
    def __init__(self, db: Session, session_id: uuid.UUID) -> None:
        self.db = db
        self.session_id = session_id
        self._step = 0

    def next_step(self) -> int:
        self._step += 1
        return self._step

    def log(
        self,
        *,
        step_number: int,
        context: dict[str, Any],
        proposed_action: dict[str, Any],
        actual_command: str | None = None,
        result_summary: dict[str, Any] | None = None,
        approved_by: str | None = None,
        task_node_id: uuid.UUID | None = None,
        llm_model: str | None = None,
        llm_input_tokens: int | None = None,
        llm_output_tokens: int | None = None,
    ) -> AgentDecision:
        record = AgentDecision(
            session_id=self.session_id,
            task_node_id=task_node_id,
            step_number=step_number,
            context=_truncate(context),
            proposed_action=proposed_action,
            actual_command=actual_command,
            result_summary=_truncate(result_summary or {}),
            approved_by=approved_by,
            llm_model=llm_model,
            llm_input_tokens=llm_input_tokens,
            llm_output_tokens=llm_output_tokens,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record


def _truncate(payload: dict[str, Any], max_chars: int = 50_000) -> dict[str, Any]:
    """Trim large `raw_output` strings before persisting context/result blobs."""
    import json
    encoded = json.dumps(payload, default=str)
    if len(encoded) <= max_chars:
        return payload
    payload = dict(payload)
    payload["_truncated"] = True
    for key in ("raw_output", "output", "stdout", "stderr"):
        if key in payload and isinstance(payload[key], str):
            payload[key] = payload[key][:5_000] + f"... [truncated, original {len(payload[key])} chars]"
    return payload
