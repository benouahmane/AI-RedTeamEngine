"""Concurrent multi-host orchestration.

For Env 2 (50 VulnHub VMs) the dominant cost is wall-clock time: scanning and
enumerating dozens of hosts strictly one-after-another is what makes
time-to-exploit explode. `run_targets` fans a target list out across a thread
pool — each host gets its own DB session, `PentestSession`, and `RedTeamAgent`
so the runs are fully independent.

Threads (not processes) are the right tool here: every agent step is dominated
by blocking I/O — the LLM HTTP call and subprocess tool execution — so the GIL
is released almost the whole time.
"""
from __future__ import annotations

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from agent.core import RedTeamAgent
from agent.modes import gateway_for
from config import settings
from environments.config import ENVIRONMENTS
from memory import task_tree
from memory.db import SessionLocal
from memory.models import OperationMode, PentestSession, SessionStatus

log = logging.getLogger("redteam.orchestrator")


@dataclass
class TargetRunResult:
    target: str
    session_id: str | None
    status: str
    report_path: str | None = None
    error: str | None = None


def expand_targets(spec: str) -> list[str]:
    """Turn a target spec into a concrete host list.

    Accepts a CIDR (`10.10.0.0/24`), a comma-separated list, a path to a file
    with one target per line, or a single IP/hostname. CIDRs expand to host
    addresses (network/broadcast excluded for IPv4 /31+ ranges).
    """
    spec = spec.strip()
    path = Path(spec)
    if path.exists() and path.is_file():
        lines = path.read_text().splitlines()
        return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]

    if "," in spec:
        return [t.strip() for t in spec.split(",") if t.strip()]

    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return [spec]   # single IP or hostname
    if net.num_addresses == 1:
        return [str(net.network_address)]
    return [str(h) for h in net.hosts()]


def _run_one_target(
    target: str,
    *,
    environment: str,
    mode: OperationMode,
    objective: str | None,
    max_steps: int,
) -> TargetRunResult:
    """Run a full session against a single target in its own DB session."""
    with SessionLocal() as db:
        try:
            s = PentestSession(
                name=f"session-{target}",
                target=target,
                environment=environment,
                mode=mode,
                objective=objective,
            )
            db.add(s)
            db.commit()
            db.refresh(s)
            task_tree.bootstrap_phases(db, s)

            gateway = gateway_for(mode)
            agent = RedTeamAgent(db, s, approval_gateway=gateway, max_steps=max_steps)
            agent.run()
            return TargetRunResult(
                target=target,
                session_id=str(s.id),
                status=s.status.value,
                report_path=str(agent.report_path) if agent.report_path else None,
            )
        except Exception as exc:                                    # noqa: BLE001
            log.exception("target %s crashed", target)
            return TargetRunResult(target=target, session_id=None,
                                   status=SessionStatus.ERROR.value, error=str(exc))


def run_targets(
    target_spec: str,
    *,
    environment: str = "env1",
    mode: OperationMode = OperationMode.AUTONOMOUS,
    workers: int = 5,
    objective: str | None = None,
    max_steps: int | None = None,
) -> list[TargetRunResult]:
    """Run sessions against every host in `target_spec`, up to `workers` at once."""
    targets = expand_targets(target_spec)
    if not targets:
        return []
    per_host_steps = max_steps or settings.max_steps_per_host
    # Same fallback as the single-target path: an unset objective leaves every
    # session in the fan-out with a blank goal and a blank report field.
    spec = ENVIRONMENTS.get(environment)
    objective = objective or (spec.default_objective if spec else None)

    if mode == OperationMode.HUMAN_IN_LOOP and workers > 1:
        log.warning("human_in_loop with workers>1 interleaves approval prompts; "
                    "forcing workers=1 for sane interaction")
        workers = 1

    log.info("fanning out %d targets across %d workers (env=%s, mode=%s)",
             len(targets), workers, environment, mode.value)

    results: list[TargetRunResult] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {
            pool.submit(
                _run_one_target, t,
                environment=environment, mode=mode,
                objective=objective, max_steps=per_host_steps,
            ): t
            for t in targets
        }
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            log.info("[%s] %s%s", res.target, res.status,
                     f" → {res.report_path}" if res.report_path else "")

    results.sort(key=lambda r: targets.index(r.target))
    return results
