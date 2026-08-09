"""Run a benchmarked session end to end (or score an existing one)."""
from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path

from agent.core import RedTeamAgent
from agent.modes import gateway_for
from benchmark.manifest import GroundTruth, load_manifest
from benchmark.scorer import BenchmarkScore, score_session
from memory import queries, task_tree
from memory.db import SessionLocal
from memory.models import OperationMode, PentestSession

log = logging.getLogger("redteam.benchmark")

DEFAULT_OUTPUT_DIR = Path("artefacts/benchmarks")


def run_benchmark(
    manifest_path: str | Path,
    *,
    mode: OperationMode = OperationMode.AUTONOMOUS,
    max_steps: int | None = None,
    output_dir: Path | None = None,
) -> BenchmarkScore:
    """Run a fresh session against a manifest target and score it."""
    truth = load_manifest(manifest_path)
    with SessionLocal() as db:
        s = PentestSession(
            name=f"benchmark-{truth.name}",
            target=truth.target,
            environment=truth.environment,
            mode=mode,
            objective=truth.objective or "Benchmark run: maximise coverage and capture flags.",
        )
        db.add(s)
        db.commit()
        db.refresh(s)
        task_tree.bootstrap_phases(db, s)

        agent = RedTeamAgent(db, s, approval_gateway=gateway_for(mode), max_steps=max_steps)
        agent.run()

        score = score_session(db, s, truth)
        _write_artifacts(score, output_dir)
        return score


def score_existing(
    session_id: str,
    manifest_path: str | Path,
    *,
    output_dir: Path | None = None,
) -> BenchmarkScore:
    """Re-score an already-completed session without re-running the agent."""
    truth = load_manifest(manifest_path)
    with SessionLocal() as db:
        s = queries.get_session(db, uuid.UUID(session_id))
        if s is None:
            raise ValueError(f"session {session_id} not found")
        score = score_session(db, s, truth)
        _write_artifacts(score, output_dir)
        return score


def _write_artifacts(score: BenchmarkScore, output_dir: Path | None) -> tuple[Path, Path]:
    out = output_dir or DEFAULT_OUTPUT_DIR
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{score.session_id}.json"
    md_path = out / f"{score.session_id}.md"
    json_path.write_text(json.dumps(score.to_dict(), indent=2, default=str))
    md_path.write_text(score.to_markdown())
    log.info("benchmark written to %s and %s", json_path, md_path)
    return json_path, md_path
