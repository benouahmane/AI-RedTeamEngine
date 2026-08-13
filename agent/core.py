"""ReAct-style agent loop.

For each step:
  1. Build a compact PTT snapshot (token-budget conscious)
  2. Ask the LLM to produce a JSON action
  3. Persist the decision (audit log)
  4. Mode B: block until analyst approval
  5. Execute the chosen tool
  6. Update the task node with the result
  7. Optionally extract entity rows (hosts/vulns/creds) from the findings

The loop terminates when the LLM returns `complete_session` or `abort`,
the step budget is exhausted, or no pending nodes remain.
"""
from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

import tools  # noqa: F401  — registers wrappers
from agent.decision_logger import DecisionLogger
from agent.findings import extract_compromised_hosts, extract_credentials
from agent.llm import LLMClient, get_llm_client
from agent.modes import ApprovalGateway, gateway_for
from agent.prompts import build_step_prompt, build_system_prompt
from config import settings
from memory import queries, task_tree
from memory.models import (
    AttackPhase,
    NodeStatus,
    OperationMode,
    PentestSession,
    SessionStatus,
    TaskNode,
)
from reports import ReportGenerator
from tools.base import ToolStatus
from tools.registry import get as get_tool

log = logging.getLogger("redteam.agent")


@dataclass
class StepResult:
    action: str
    node_id: uuid.UUID | None
    tool_status: ToolStatus | None
    summary: dict[str, Any]


class RedTeamAgent:
    def __init__(
        self,
        db: Session,
        session: PentestSession,
        *,
        llm: LLMClient | None = None,
        approval_gateway: ApprovalGateway | None = None,
        max_steps: int | None = None,
    ) -> None:
        self.db = db
        self.session = session
        self.llm = llm or get_llm_client(role="planner")
        self.gateway = approval_gateway or gateway_for(session.mode)
        self.logger = DecisionLogger(db, session.id)
        self._system_prompt = build_system_prompt()
        self._allowed = settings.allowed_cidrs
        self.max_steps = max_steps or settings.max_agent_steps
        self.report_path: Path | None = None

    # ─────────────────────────────────────────────────────────────────────
    # Public entrypoint
    # ─────────────────────────────────────────────────────────────────────

    def run(self) -> None:
        if not task_tree.get_roots(self.db, self.session.id):
            task_tree.bootstrap_phases(self.db, self.session)

        self.session.status = SessionStatus.RUNNING
        self.db.commit()

        previous_result: dict[str, Any] | None = None
        for _ in range(self.max_steps):
            try:
                step = self._step(previous_result)
            except Exception as exc:                                  # noqa: BLE001
                log.exception("Agent step crashed")
                self.session.status = SessionStatus.ERROR
                self.db.commit()
                raise
            if step.action in {"complete_session", "abort"}:
                self.session.status = (
                    SessionStatus.COMPLETED if step.action == "complete_session"
                    else SessionStatus.ABORTED
                )
                self.session.completed_at = datetime.utcnow()
                self.db.commit()
                self._finalize_report()
                return
            previous_result = step.summary
        else:
            log.warning("Agent hit step budget=%d", self.max_steps)
            self.session.status = SessionStatus.PAUSED
            self.db.commit()
            self._finalize_report()

    def _finalize_report(self) -> None:
        self.report_path = ReportGenerator().write(self.db, self.session)
        log.info("Report written to %s", self.report_path)

    # ─────────────────────────────────────────────────────────────────────
    # One step of the loop
    # ─────────────────────────────────────────────────────────────────────

    def _step(self, previous_result: dict[str, Any] | None) -> StepResult:
        step_no = self.logger.next_step()
        ctx = task_tree.context_for_llm(self.db, self.session.id)
        ascii_tree = task_tree.to_ascii(self.db, self.session.id)
        entities = queries.entity_snapshot(self.db, self.session.id)

        user_prompt = build_step_prompt(
            session_id=str(self.session.id),
            target=self.session.target,
            environment=self.session.environment,
            mode=self.session.mode.value,
            objective=self.session.objective or "",
            allowed_targets=self._allowed,
            tree_ascii=ascii_tree,
            tree_context=ctx,
            entity_state=entities,
            previous_result=previous_result,
        )
        llm_resp = self.llm.complete(self._system_prompt, user_prompt)
        decision = llm_resp.decision
        log.info("Step %d action=%s", step_no, decision.get("action"))

        action = decision.get("action")
        if action == "expand_tree":
            return self._handle_expand(step_no, ctx, decision, llm_resp)
        if action == "skip_node":
            return self._handle_skip(step_no, ctx, decision, llm_resp)
        if action == "complete_session":
            self.logger.log(
                step_number=step_no, context=ctx, proposed_action=decision,
                llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
                llm_output_tokens=llm_resp.output_tokens,
            )
            return StepResult(action, None, None, {"info": "session complete"})
        if action == "abort":
            self.logger.log(
                step_number=step_no, context=ctx, proposed_action=decision,
                llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
                llm_output_tokens=llm_resp.output_tokens,
            )
            return StepResult(action, None, None, {"info": "aborted by agent"})
        if action == "execute_tool":
            return self._handle_execute(step_no, ctx, decision, llm_resp)

        raise ValueError(f"Unknown action from LLM: {action!r}")

    # ─────────────────────────────────────────────────────────────────────
    # Action handlers
    # ─────────────────────────────────────────────────────────────────────

    def _handle_expand(self, step_no, ctx, decision, llm_resp) -> StepResult:
        parent_id = decision.get("node_id")
        parent = self.db.get(TaskNode, parent_id) if parent_id else None
        if parent is None:
            # Default to the root of the current focus phase
            roots = task_tree.get_roots(self.db, self.session.id)
            parent = roots[0]

        children_specs = [self._coerce_node_spec(s) for s in decision.get("expansion", [])]
        children = task_tree.expand(self.db, parent, children_specs)

        self.logger.log(
            step_number=step_no, context=ctx, proposed_action=decision,
            task_node_id=parent.id,
            result_summary={"created_children": [str(c.id) for c in children]},
            llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
            llm_output_tokens=llm_resp.output_tokens,
        )
        return StepResult("expand_tree", parent.id, None,
                          {"created": len(children), "parent": str(parent.id)})

    def _handle_skip(self, step_no, ctx, decision, llm_resp) -> StepResult:
        node = self.db.get(TaskNode, decision.get("node_id"))
        if node is None:
            return StepResult("skip_node", None, None, {"error": "node not found"})
        task_tree.skip(self.db, node, decision.get("reasoning_for_human") or "skipped by agent")
        self.logger.log(
            step_number=step_no, context=ctx, proposed_action=decision,
            task_node_id=node.id, result_summary={"skipped": True},
            llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
            llm_output_tokens=llm_resp.output_tokens,
        )
        return StepResult("skip_node", node.id, None, {"skipped": str(node.id)})

    def _handle_execute(self, step_no, ctx, decision, llm_resp) -> StepResult:
        # Locate or create the node
        node_id = decision.get("node_id")
        node = self.db.get(TaskNode, node_id) if node_id else None
        if node is None:
            spec = self._coerce_node_spec(decision.get("new_node") or {})
            roots = {r.phase: r for r in task_tree.get_roots(self.db, self.session.id)}
            phase = AttackPhase(spec.get("phase", "recon"))
            parent = roots.get(phase) or next(iter(roots.values()))
            node = task_tree.expand(self.db, parent, [spec])[0]

        # `or {}` rather than a get() default: models routinely send an explicit
        # "new_node": null when reusing an existing node, and a default only
        # applies to a missing key.
        new_node = decision.get("new_node") or {}
        proposed = {
            "tool_name": node.tool_name or new_node.get("tool_name"),
            "tool_params": node.tool_params or new_node.get("tool_params") or {},
            "rationale": node.rationale or new_node.get("rationale"),
        }

        # Reject before asking the human. Models sometimes point node_id at a
        # phase root, which carries no tool — there is nothing to approve, and
        # failing the root would strike out the entire phase. Bounce it back as
        # a step error so the agent retries with a leaf node or a new_node.
        if not proposed["tool_name"]:
            err = (
                f"node {node.id} ('{node.title}') has no tool attached — it is a "
                f"phase/planning node. Pick a pending leaf node that has a tool, "
                f"or supply new_node with tool_name and tool_params."
            )
            self.logger.log(
                step_number=step_no, context=ctx, proposed_action=decision,
                task_node_id=node.id, result_summary={"error": "no_tool_on_node"},
                llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
                llm_output_tokens=llm_resp.output_tokens,
            )
            return StepResult("execute_tool", node.id, ToolStatus.ERROR,
                              {"error": "no_tool_on_node", "detail": err})

        # Safety: refuse out-of-scope targets
        target = (proposed["tool_params"] or {}).get("target") or node.target
        if target and not self._target_in_scope(target):
            task_tree.fail(self.db, node, f"target {target} out of scope")
            self.logger.log(
                step_number=step_no, context=ctx, proposed_action=decision,
                task_node_id=node.id,
                result_summary={"error": "out_of_scope", "target": target},
                llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
                llm_output_tokens=llm_resp.output_tokens,
            )
            return StepResult("execute_tool", node.id, ToolStatus.ERROR,
                              {"error": "out_of_scope", "target": target})

        # Mode B: block on approval
        approver: str | None = None
        if self.gateway is not None:
            decision_obj = self.gateway.request(self.db, node, proposed)
            if not decision_obj.approved:
                task_tree.reject(self.db, node, decision_obj.rejection_reason or "rejected")
                self.logger.log(
                    step_number=step_no, context=ctx, proposed_action=decision,
                    task_node_id=node.id,
                    result_summary={"approved": False, "reason": decision_obj.rejection_reason},
                    llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
                    llm_output_tokens=llm_resp.output_tokens,
                )
                return StepResult("execute_tool", node.id, None,
                                  {"approved": False, "reason": decision_obj.rejection_reason})
            approver = decision_obj.approver or "dashboard"
            if decision_obj.modified_params:
                proposed["tool_params"] = decision_obj.modified_params
        else:
            task_tree.start(self.db, node)

        # Execute
        tool_name = proposed["tool_name"]
        if not tool_name:
            task_tree.fail(self.db, node, "no tool_name supplied")
            return StepResult("execute_tool", node.id, ToolStatus.ERROR, {"error": "no tool"})
        try:
            result = self._execute_with_retry(tool_name, proposed["tool_params"] or {})
        except Exception as exc:                                       # noqa: BLE001
            task_tree.fail(self.db, node, f"{type(exc).__name__}: {exc}")
            self.logger.log(
                step_number=step_no, context=ctx, proposed_action=decision,
                task_node_id=node.id, result_summary={"error": str(exc)},
                llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
                llm_output_tokens=llm_resp.output_tokens,
            )
            return StepResult("execute_tool", node.id, ToolStatus.ERROR,
                              {"error": str(exc)})

        # Persist into PTT
        if result.status in (ToolStatus.SUCCESS, ToolStatus.NO_FINDINGS, ToolStatus.PARTIAL):
            task_tree.complete(
                self.db, node,
                command=result.command,
                raw_output=result.raw_output,
                findings=result.findings,
            )
        else:
            task_tree.fail(self.db, node, result.error or "tool error")

        # Extract entities from findings
        self._ingest_findings(node, result.findings or {}, status=result.status)

        summary = result.to_dict()
        self.logger.log(
            step_number=step_no, context=ctx, proposed_action=decision,
            actual_command=result.command, task_node_id=node.id,
            result_summary=summary, approved_by=approver,
            llm_model=llm_resp.model, llm_input_tokens=llm_resp.input_tokens,
            llm_output_tokens=llm_resp.output_tokens,
        )
        return StepResult("execute_tool", node.id, result.status, summary)

    # ─────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────

    # Statuses that may be transient (network blip, daemon warming up) — worth
    # one retry with backoff before the agent has to re-plan around a dead end.
    _RETRYABLE = {ToolStatus.TIMEOUT, ToolStatus.ERROR}

    def _execute_with_retry(self, tool_name: str, params: dict[str, Any]):
        """Run a tool, retrying transient failures up to settings.tool_retry_attempts."""
        import time

        attempts = max(1, settings.tool_retry_attempts + 1)
        tool = get_tool(tool_name)
        result = tool.execute(**params)
        for attempt in range(1, attempts):
            if result.status not in self._RETRYABLE:
                return result
            if not self._is_transient(result.error):
                return result
            backoff = settings.tool_retry_backoff_sec * attempt
            log.info("tool %s returned %s; retry %d/%d after %.1fs",
                     tool_name, result.status.value, attempt, attempts - 1, backoff)
            time.sleep(backoff)
            result = tool.execute(**params)
        return result

    @staticmethod
    def _is_transient(error: str | None) -> bool:
        if not error:
            return True   # bare timeout with no message — assume transient
        e = error.lower()
        transient_markers = (
            "timeout", "connection refused", "could not connect", "reset by peer",
            "temporarily unavailable", "no route to host", "broken pipe",
        )
        return any(m in e for m in transient_markers)

    @staticmethod
    def _coerce_node_spec(spec: dict[str, Any]) -> dict[str, Any]:
        if "phase" in spec and isinstance(spec["phase"], str):
            try:
                spec = dict(spec)
                spec["phase"] = AttackPhase(spec["phase"])
            except ValueError:
                spec["phase"] = AttackPhase.RECON
        return spec

    def _target_in_scope(self, target: str) -> bool:
        if not self._allowed:
            return True   # no allowlist configured — operator's responsibility
        # Allow URLs by extracting the host
        host = target
        if "://" in host:
            host = host.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False  # hostname-only — require explicit IP-based allow
        for cidr in self._allowed:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _ingest_findings(
        self, node: TaskNode, findings: dict[str, Any],
        *, status: ToolStatus | None = None,
    ) -> None:
        """Translate tool findings into the entity tables."""
        # nmap-style: hosts → ports
        for host in findings.get("hosts", []) or []:
            ip = host.get("ip")
            if not ip:
                continue
            queries.upsert_host(
                self.db, self.session.id, ip,
                hostname=(host.get("hostnames") or [None])[0],
                os_fingerprint=host.get("os"),
                ports=host.get("ports") or [],
                services=[
                    {"port": p["port"], "name": p.get("service"),
                     "product": p.get("product"), "version": p.get("version")}
                    for p in (host.get("ports") or [])
                ],
            )
        # nuclei-style: vulnerabilities
        for v in findings.get("vulnerabilities", []) or []:
            queries.record_vulnerability(
                self.db, self.session.id,
                host_ip=(v.get("host") or "").split(":")[0] or "unknown",
                title=v.get("name") or v.get("template_id") or "(unnamed)",
                severity=v.get("severity") or "info",
                cve=v.get("cve"), cvss=v.get("cvss_score"),
                description=v.get("description"),
                evidence=v.get("matched_at"),
                mitre_ttp=node.mitre_ttp,
            )
        # credentials — hydra/john/hashcat/crackmapexec/impacket/rubeus/kerberos
        for cred in extract_credentials(findings, default_host=node.target):
            queries.upsert_credential(
                self.db, self.session.id,
                username=cred.username,
                secret=cred.secret,
                secret_type=cred.secret_type,
                host_ip=cred.host_ip,
                service=cred.service,
                domain=cred.domain,
                privilege=cred.privilege,
            )
        # compromise signals — sessions, pwn3d hosts, lateral exec, shells
        for ip in extract_compromised_hosts(
            findings,
            tool_name=node.tool_name,
            target=node.target,
            success=status == ToolStatus.SUCCESS,
        ):
            queries.mark_host_compromised(
                self.db, self.session.id, ip,
                note=f"via {node.tool_name or 'tool'} (node {node.id})",
            )
