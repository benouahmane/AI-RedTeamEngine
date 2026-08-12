# Architecture

Design notes for the AI Red Team Engine (CTM-FYP-2025-P1-RED). For setup and
operation see `INSTRUCTIONS.txt`; this document covers how the system is built
and how to extend it.

**Stack:** Python 3.11, FastAPI, PostgreSQL, SQLAlchemy, Jinja2, Anthropic
Claude API (or any model reachable through OpenRouter).

**Paired project:** CTM-FYP-2025-P2-BLUE (Blue Team Defence Engine). The two
form a purple team training range — this engine generates the attack telemetry
that one consumes.

## Design pattern

The engine implements **ReAct (Reasoning + Acting)**: an LLM alternates between
reasoning about the current state and taking an action, using the result of each
action as input to the next reasoning step.

The loop is implemented directly against the provider API in `agent/core.py`.
There is no LangChain runtime dependency — the agent needs a narrow, auditable
decision path (every step must be logged for FYP §8.1), which is easier to
guarantee without a framework in between.

## Layers

| Layer | Responsibility | Key files |
|---|---|---|
| **Orchestration** | LLM agent — reasons about attack phase, selects tools, interprets output, decides next action | `agent/core.py` |
| **Tool Integration** | Python wrappers exposing a uniform `execute(**params) -> ToolResult` interface | `tools/base.py`, `tools/registry.py` |
| **Context Memory** | PostgreSQL — Pentesting Task Tree plus entity tables (hosts, vulns, creds) | `memory/` |
| **Environment Manager** | Lab environment config: CIDR ranges, known targets, reachability probes | `environments/` |
| **Report Generator** | Jinja2 templates producing the structured pentest report | `reports/` |
| **API / UI** | FastAPI backend and HTMX dashboard | `api/` |

## The decision loop

`agent/core.py:_step()` runs one iteration:

1. **Build context** — `memory/task_tree.py:context_for_llm()` produces a compact
   snapshot of the task tree (in-progress node, top pending nodes, recent
   completions, dead ends, per-phase counts). `memory/queries.py:entity_snapshot()`
   adds discovered hosts and services, harvested credentials, and known
   vulnerabilities.
2. **Call the LLM** — system prompt (cached) plus the step prompt.
3. **Parse the action** — `agent/llm.py:_parse_json_action()` extracts a JSON
   object, tolerating fenced code blocks and surrounding prose.
4. **Log the decision** — `agent/decision_logger.py` persists context, proposed
   action, command, and result. Required by FYP §8.1; also feeds the report's
   audit appendix.
5. **Gate on approval** — in `human_in_loop` mode, block on the approval gateway.
6. **Check scope** — reject any target outside `ALLOWED_TARGET_RANGES`.
7. **Execute** — dispatch through the tool registry, retry transient failures
   (`settings.tool_retry_attempts`), update the tree node, and normalise findings
   into the entity tables.

The agent never replays raw database history to the model. Every step is framed
as *"given this tree state, what pending node should I execute next?"* — which
keeps the prompt bounded regardless of session length.

### Actions the LLM may return

| Action | Effect |
|---|---|
| `execute_tool` | Run a tool against an existing pending node, or a newly specified one |
| `expand_tree` | Add planning nodes without executing anything |
| `skip_node` | Mark a pending node skipped, with rationale |
| `complete_session` | No remaining work worth pursuing; triggers report generation |
| `abort` | Scope or safety violation; halt the session |

## Pentesting Task Tree (PTT)

The PTT is the agent's working memory: a hierarchical task tree in the
`task_nodes` table, manipulated exclusively through `memory/task_tree.py`.

It is bootstrapped with one root node per attack phase, and the agent expands
each into concrete, tool-bound child tasks as it learns about the target.

**Phases** (`AttackPhase`) map to MITRE ATT&CK tactics:

| Phase | Tactic | Typical tools |
|---|---|---|
| `recon` | TA0043 Reconnaissance | nmap, rustscan, theharvester |
| `enumeration` | TA0007 Discovery | gobuster, ffuf, nikto, enum4linux |
| `vuln_id` | TA0043 Reconnaissance | nuclei, openvas |
| `exploitation` | TA0001 Initial Access | metasploit, sqlmap |
| `post_exploit` | TA0004 Privilege Escalation | pwncat, linpeas |
| `lateral_movement` | TA0008 Lateral Movement | crackmapexec, impacket, bloodhound, rubeus |
| `objective` | TA0009 Collection | caldera, atomic_red_team |

**Node status transitions** (`NodeStatus`):

```
pending ─┬─> in_progress ─┬─> completed
         │                └─> failed
         ├─> skipped
         └─> awaiting_approval ─┬─> in_progress   (approved)
                                └─> rejected      (declined)
```

`awaiting_approval` and `rejected` occur only in `human_in_loop` mode.

**Tree operations** — `bootstrap_phases`, `add_root`, `expand`, `start`,
`complete`, `fail`, `skip`, `reject`, `mark_awaiting_approval`, `pick_next`,
`get_roots`, `all_nodes`, `context_for_llm`, `to_ascii`.

`to_ascii` renders the tree for the CLI and dashboard; `context_for_llm` renders
the compact JSON form the model actually reasons over.

## Tool Integration Layer

Every wrapper subclasses `OffensiveTool` (`tools/base.py`) and self-registers via
the `@register` decorator. Importing the `tools` package registers all of them;
the agent resolves them by name through `tools.registry.get(name)` and never
shells out directly.

**Contract:**

```python
@register
class MyTool(OffensiveTool):
    name = "mytool"
    phase = "recon"
    mitre_techniques = ["T1046"]
    description = "..."            # shown to the LLM

    def param_schema(self) -> dict:   # JSON Schema, shown to the LLM
        ...

    def execute(self, **params) -> ToolResult:
        ...
```

`ToolResult` carries a `ToolStatus` (`success`, `no_findings`, `partial`,
`timeout`, `error`), the exact command executed, raw output, a structured
`findings` dict, and duration.

**22 wrappers** are registered:

| Category | Wrappers |
|---|---|
| Recon | `nmap`, `rustscan`, `theharvester`, `enum4linux` |
| Web enumeration | `gobuster`, `ffuf`, `nikto` |
| Vulnerability scan | `nuclei`, `openvas` |
| Exploitation | `metasploit`, `sqlmap` |
| Credentials | `hydra`, `john`, `hashcat` |
| Post-exploitation | `pwncat`, `linpeas` |
| Lateral / AD | `crackmapexec`, `impacket`, `bloodhound`, `rubeus` |
| Simulation | `caldera`, `atomic_red_team` |

Most wrappers drive a CLI binary through `self._run(argv)` and parse its output.
Two talk to services instead: `metasploit` uses `pymetasploit3.MsfRpcClient` over
MSFRPC, and `caldera` uses the CALDERA v2 REST API.

`tools/recon/nmap.py` is the reference implementation for a new wrapper.

### How the LLM learns what tools exist

`agent/prompts.py:build_system_prompt()` walks the live registry, collects each
tool's name, phase, description, MITRE techniques, and parameter schema, and
embeds the whole catalogue as JSON in the system prompt (~35k characters).

Because the catalogue is generated from the registry, **registering a wrapper is
all that's needed to make the agent aware of it** — no prompt edits.

The system prompt is stable across a session, so it is sent with Anthropic prompt
caching (`"cache_control": {"type": "ephemeral"}`) to avoid re-tokenising the
catalogue on every step.

## Data model

Six tables, defined in `memory/models.py`, migrated with Alembic.

| Table | Purpose |
|---|---|
| `pentest_sessions` | One row per engagement — target, environment, mode, objective, status |
| `task_nodes` | The PTT — phase, status, priority, tool, params, findings, MITRE TTP, parent |
| `hosts` | Discovered IPs with ports and services (JSONB) |
| `vulnerabilities` | Findings with CVE, CVSS, severity, affected service |
| `credentials` | Recovered passwords, hashes, and tickets |
| `agent_decisions` | Full audit log: context, proposed action, command, result, token usage |

`agent/findings.py` is the normalisation layer: each wrapper returns a different
`findings` shape, and it maps them onto credential rows (`upsert_credential`) and
host compromise flags (`mark_host_compromised`). This is what makes credential
reuse and cross-host correlation possible — the agent sees a consolidated entity
view, not per-tool output.

Run `alembic revision --autogenerate` after changing models.

## Operation modes and approval

`OperationMode` is `autonomous` or `human_in_loop`. In human-in-the-loop mode the
agent blocks on an `ApprovalGateway` before every action. Two implementations
exist, and **which one is used depends on how the session was launched**:

| Launched from | Gateway | Behaviour |
|---|---|---|
| CLI (`main.py`) | `CLIGateway` | Prints the proposed action and blocks on terminal input; waits indefinitely |
| Dashboard | `DBPollingGateway` | Sets the node to `awaiting_approval`, polls the DB for a status change; **times out after 3600s** and auto-rejects |

The dashboard flips node status through `api/routes/approvals.py`
(`POST /api/approvals/{node_id}/approve|reject`), which may also modify
`tool_params` before approving — letting an analyst correct the agent rather than
only accept or refuse.

## Safety and scope

`agent/core.py:_target_in_scope()` is checked before every tool execution:

- Targets are matched against the `ALLOWED_TARGET_RANGES` CIDR list from `.env`.
- URLs are accepted; the host is extracted first.
- **Hostnames are rejected** when an allowlist is configured — only literal IPs
  pass, so scope cannot be widened through DNS.
- **CIDRs are rejected** as tool targets, so the agent cannot escalate a
  single-host engagement into a subnet sweep. Range scanning is an explicit
  operator action via `run-range`.
- An empty allowlist disables the check entirely and is treated as operator
  responsibility; the CLI warns on stderr.

An out-of-scope target fails that node and records `{"error": "out_of_scope"}` in
the decision log rather than aborting the session.

## Concurrency

`agent/orchestrator.py:run_targets()` fans a CIDR, comma list, or host file across
a thread pool — one DB session, `PentestSession`, and `RedTeamAgent` per host.

Threads are appropriate here because every step blocks on I/O: an LLM HTTP call or
a tool subprocess. `MAX_STEPS_PER_HOST` caps the per-host budget so one target
cannot consume the whole run.

The dashboard uses the same approach for single sessions, running the agent loop
in a daemon thread (`api/routes/sessions.py:_start_agent_thread`). A production
deployment would swap this for a worker queue.

## Reporting

`reports/generator.py:ReportGenerator.write()` renders
`reports/templates/pentest_report.html.j2` to `artefacts/reports/<session_id>.html`.

The template contains the seven sections required by FYP §3.3 — executive summary,
scope and rules of engagement, attack narrative, evidence table, vulnerability
register, ATT&CK coverage matrix, recommendations — plus appendices for
discovered hosts and the full decision log.

`reports/mitre_mapper.py:build_coverage_matrix()` derives tactic and technique
coverage from the `mitre_ttp` field of completed nodes, which is why every node
carries a TTP tag.

The output schema is fixed: update the template if model fields change.

## Benchmarking (FYP D5)

`benchmark/` scores a completed session against per-target ground truth.

- `benchmark/ground_truth/*.json` — manifests declaring known open ports, known
  CVEs, expected ATT&CK techniques, flag values, and an optional `manual_baseline`
  for the AI-vs-human comparison.
- `benchmark/scorer.py:score_session()` — port and CVE precision/recall, technique
  coverage, vulnerability false-positive rate, hosts compromised, flags captured,
  time-to-first-shell, agent step count, and estimated LLM cost.
- `benchmark/runner.py` — run and score, or `score_existing()` to re-score an old
  session. Artifacts land in `artefacts/benchmarks/<session_id>.{json,md}`.

## LLM client

`agent/llm.py` abstracts the provider behind `complete(system_prompt, user_prompt)
-> LLMResponse`.

- **anthropic** — official SDK, prompt caching on the system prompt.
- **openrouter** — gateway to many vendors over an OpenAI-compatible API.
  Added so the same target can be re-run under a different model and scored
  (FYP D5). Two opt-in settings cover provider variation:
  `OPENROUTER_CACHE_SYSTEM` sends the system prompt with an explicit
  `cache_control` breakpoint (some vendors need it, others cache
  automatically), and `OPENROUTER_JSON_MODE` requests guaranteed-JSON output
  for models that otherwise wrap their answer in prose.

The system prompt is ~35k characters and is re-sent every step, so whether
caching engages is the largest single factor in session cost — larger than the
choice of model. Verify it on the provider's dashboard after a first run.

**Model routing:** `get_llm_client(role=...)` sends planning to
`ANTHROPIC_PLANNER_MODEL` and high-volume output parsing to
`ANTHROPIC_PARSER_MODEL`, both falling back to `ANTHROPIC_MODEL`. This lets a
stronger model make decisions while a cheaper one handles bulk interpretation.

`estimate_cost_usd()` converts reported token usage into the cost figures the
benchmark reports. Its `MODEL_PRICING` table must be kept current — unknown models
silently cost `0.0`.

## Adding a tool

1. Create the module under the relevant `tools/<category>/` package.
2. Subclass `OffensiveTool`, set `name`, `phase`, `mitre_techniques`, and a
   `description` written for the LLM to read.
3. Implement `param_schema()` and `execute()`, returning a `ToolResult` with a
   structured `findings` dict.
4. Decorate with `@register` and import the module in the package `__init__.py`.
5. Extend `agent/findings.py` if the findings shape introduces new entity data.
6. Add tests — see `tests/test_tool_execution.py`, which mocks `_run` so no
   offensive binary is required.

The system prompt picks the tool up automatically on the next run.

## Design constraints

- Every agent decision must be logged (context, proposed action, command, result).
- All targets must fall within `ALLOWED_TARGET_RANGES`.
- Every action carries a MITRE ATT&CK technique tag, so coverage reporting works.
- Lab environments are isolated; target VMs have no internet access. Do not add
  routes or firewall rules that break that isolation.