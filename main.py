"""CLI entrypoint — start a session, list sessions, render a report.

Usage:

    python main.py init-db                                  # create tables (dev only — prefer alembic)
    python main.py run --target 192.168.56.101 --env env1
    python main.py list
    python main.py report <session_id>
    python main.py tree <session_id>
"""
from __future__ import annotations

import argparse
import logging
import sys
import uuid

from agent import RedTeamAgent
from agent.modes import CLIGateway
from agent.orchestrator import expand_targets, run_targets
from config import settings
from memory import queries, task_tree
from memory.db import Base, SessionLocal, engine
from memory.models import OperationMode, PentestSession
from reports import ReportGenerator


def cmd_init_db(_: argparse.Namespace) -> int:
    Base.metadata.create_all(engine)
    print("Tables created.")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    if not settings.allowed_cidrs:
        print("warning: ALLOWED_TARGET_RANGES is empty in .env — scope check is permissive",
              file=sys.stderr)

    with SessionLocal() as db:
        s = PentestSession(
            name=args.name or f"session-{args.target}",
            target=args.target,
            environment=args.env,
            mode=OperationMode(args.mode),
            objective=args.objective,
        )
        db.add(s)
        db.commit()
        db.refresh(s)
        print(f"Created session {s.id}")
        task_tree.bootstrap_phases(db, s)

        gateway = CLIGateway() if s.mode == OperationMode.HUMAN_IN_LOOP else None
        agent = RedTeamAgent(db, s, approval_gateway=gateway)
        agent.run()
        print(f"Session finished: {s.status.value}")
        if agent.report_path:
            print(f"Report written to {agent.report_path}")
    return 0


def cmd_run_range(args: argparse.Namespace) -> int:
    if not settings.allowed_cidrs:
        print("warning: ALLOWED_TARGET_RANGES is empty in .env — scope check is permissive",
              file=sys.stderr)
    targets = expand_targets(args.targets)
    print(f"Expanded to {len(targets)} target(s); running {args.workers} at a time.")
    results = run_targets(
        args.targets,
        environment=args.env,
        mode=OperationMode(args.mode),
        workers=args.workers,
        objective=args.objective,
        max_steps=args.max_steps,
    )
    print(f"\n{'TARGET':22s} {'STATUS':12s} SESSION")
    for r in results:
        print(f"{r.target:22s} {r.status:12s} {r.session_id or '-'}"
              + (f"  ({r.error})" if r.error else ""))
    failed = sum(1 for r in results if r.status in {"error"})
    return 1 if failed and failed == len(results) else 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from benchmark.runner import run_benchmark, score_existing

    if args.score_session:
        score = score_existing(args.score_session, args.manifest)
    else:
        score = run_benchmark(
            args.manifest,
            mode=OperationMode(args.mode),
            max_steps=args.max_steps,
        )
    print(score.to_markdown())
    print(f"\nArtifacts written under artefacts/benchmarks/{score.session_id}.{{json,md}}")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    with SessionLocal() as db:
        for s in queries.list_sessions(db):
            print(f"{s.id}  {s.status.value:12s}  {s.environment:6s}  {s.target:20s}  {s.name}")
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    """Close out sessions whose process died without updating its own row."""
    with SessionLocal() as db:
        stale = queries.stale_running_sessions(db, idle_minutes=args.idle_minutes)
        if not stale:
            print(f"No sessions stuck in 'running' for more than {args.idle_minutes} minutes.")
            return 0

        for s, last_at in stale:
            when = last_at or s.started_at
            print(f"{s.id}  {s.target:20s}  last activity {when:%Y-%m-%d %H:%M:%S}")
        if args.dry_run:
            print(f"\n{len(stale)} session(s) would be marked aborted (--dry-run).")
            return 0

        aborted = queries.abort_stale_sessions(db, idle_minutes=args.idle_minutes)
        print(f"\nMarked {len(aborted)} session(s) as aborted.")
    return 0


def cmd_tree(args: argparse.Namespace) -> int:
    sid = uuid.UUID(args.session_id)
    with SessionLocal() as db:
        print(task_tree.to_ascii(db, sid))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    sid = uuid.UUID(args.session_id)
    with SessionLocal() as db:
        s = queries.get_session(db, sid)
        if s is None:
            print(f"session {sid} not found", file=sys.stderr)
            return 1
        gen = ReportGenerator()
        path = gen.write(db, s)
        print(f"Report written to {path}")
        if getattr(args, "pdf", False):
            try:
                print(f"PDF written to {gen.write_pdf(path)}")
            except Exception as exc:                                   # noqa: BLE001
                # The HTML is already on disk and is the real artefact — a
                # missing converter shouldn't fail the command.
                print(f"PDF conversion failed: {exc}", file=sys.stderr)
                return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    parser = argparse.ArgumentParser(prog="redteam", description="AI Red Team Engine")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-db").set_defaults(func=cmd_init_db)

    p_run = sub.add_parser("run", help="start an agent session")
    p_run.add_argument("--target", required=True, help="IP, CIDR, or hostname")
    p_run.add_argument("--env", default="env1", choices=["env1", "env2", "env3"])
    p_run.add_argument("--mode", default=settings.default_mode,
                       choices=["autonomous", "human_in_loop"])
    p_run.add_argument("--name")
    p_run.add_argument("--objective")
    p_run.set_defaults(func=cmd_run)

    p_range = sub.add_parser("run-range",
                             help="run many targets concurrently (CIDR, comma list, or file)")
    p_range.add_argument("--targets", required=True,
                         help="CIDR (10.10.0.0/24), comma list, or path to a host file")
    p_range.add_argument("--env", default="env2", choices=["env1", "env2", "env3"])
    p_range.add_argument("--mode", default="autonomous",
                         choices=["autonomous", "human_in_loop"])
    p_range.add_argument("--workers", type=int, default=5)
    p_range.add_argument("--max-steps", type=int, default=None, dest="max_steps",
                         help="per-host step budget (defaults to MAX_STEPS_PER_HOST)")
    p_range.add_argument("--objective")
    p_range.set_defaults(func=cmd_run_range)

    p_bench = sub.add_parser("benchmark",
                             help="run a session against a ground-truth manifest and score it")
    p_bench.add_argument("--manifest", required=True,
                         help="path to a benchmark/ground_truth/*.json manifest")
    p_bench.add_argument("--mode", default="autonomous",
                         choices=["autonomous", "human_in_loop"])
    p_bench.add_argument("--max-steps", type=int, default=None, dest="max_steps")
    p_bench.add_argument("--score-session", dest="score_session", default=None,
                         help="score an existing session id instead of running a new one")
    p_bench.set_defaults(func=cmd_benchmark)

    sub.add_parser("list").set_defaults(func=cmd_list)

    p_rec = sub.add_parser(
        "reconcile",
        help="close out sessions left stuck in 'running' by a killed process",
    )
    p_rec.add_argument("--idle-minutes", type=int, default=30, dest="idle_minutes",
                       help="how long without a logged decision counts as dead (default 30)")
    p_rec.add_argument("--dry-run", action="store_true",
                       help="list what would change without writing")
    p_rec.set_defaults(func=cmd_reconcile)

    p_tree = sub.add_parser("tree")
    p_tree.add_argument("session_id")
    p_tree.set_defaults(func=cmd_tree)

    p_report = sub.add_parser("report")
    p_report.add_argument("session_id")
    p_report.add_argument("--pdf", action="store_true",
                          help="also write a PDF alongside the HTML")
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
