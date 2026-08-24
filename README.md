# AI Red Team Engine

An LLM agent that plans and executes a penetration test end to end — reconnaissance, exploitation, post-exploitation — then writes the report.

Point it at a host and it decides what to run next at every step, reasoning over a task tree it builds and revises as it learns. It drives 24 real offensive tools (Nmap, Metasploit, Impacket, BloodHound, Nuclei, …), records every decision it makes, and produces a MITRE ATT&CK-mapped report from that record.

> **Lab use only.** Built for authorised testing in isolated environments. Never point it at a host you do not own or have explicit written authorisation to test. A CIDR allowlist is enforced on every action, not just at launch.

## What it actually does

A single autonomous run against Metasploitable 2, from the decision log:

```
1  recon          nmap -sV -sC -O -p- 192.168.163.131          T1046
2  exploitation   exploit/unix/ftp/vsftpd_234_backdoor         T1190   → session 1
3  post_exploit   session_run: id && whoami && uname -a        T1059.004
                  uid=0(root) gid=0(root)  metasploitable
4  complete_session
```

Four steps, ~7 minutes, and the resulting report opens with:

> **1 host compromised: 192.168.163.131.** Interactive access was obtained and verified.
>
> | Severity | Title | Host | CVE | Exploited |
> |---|---|---|---|---|
> | critical | VSFTPD 2.3.4 Backdoor Command Execution | 192.168.163.131:21 | CVE-2011-2523 | ✓ |

The CVE isn't hardcoded — it's read from the Metasploit module's own reference list at exploitation time, so the register can't drift from what the tooling actually knows.

## Design decisions worth explaining

**No agent framework.** The ReAct loop is ~200 lines in [`agent/core.py`](agent/core.py) talking directly to the provider API. No LangChain, no LlamaIndex — zero imports. Agent frameworks abstract exactly the part that needed to be inspectable here: the decision path. Every step is a row in `agent_decisions` with the prompt context, the proposed action, the tool result, and the token counts.

**The plan is the memory.** Rather than a scrolling message history, the agent reasons over a **Pentesting Task Tree** persisted in PostgreSQL — a hierarchical plan whose nodes carry status, findings and MITRE tags. Each step feeds the model a compact tree snapshot plus a consolidated view of everything discovered so far, so context stays roughly constant no matter how long the run goes.

**Findings are normalised, not just logged.** Every wrapper reports credentials in its own shape — `hydra` gives passwords, `secretsdump` gives NT hashes, Kerberos tools give tickets. [`agent/findings.py`](agent/findings.py) reduces all of them to one representation written into shared entity tables, which is what makes credential reuse across hosts possible rather than aspirational.

**Adding a tool is one class.** Wrappers implement a uniform interface and register themselves; the tool catalogue in the system prompt is generated from the registry at startup. Write the class, and the agent knows about it.

**Evidence over assertion.** The vulnerability register is populated from *confirmed* exploitation and scanner output — never from the agent's own claims. An agent that names a CVE while planning doesn't get a finding; a shell on the box does.

**168 tests**, with every offensive binary and RPC call mocked, so the suite runs anywhere without a lab.

## Stack

Python 3.13 · PostgreSQL (JSONB) + SQLAlchemy 2.0 + Alembic · Neo4j (BloodHound graphs) · FastAPI + HTMX · Jinja2 · Docker Compose · Kali Linux

Two LLM providers behind `LLM_PROVIDER`: `anthropic` (default) and `openrouter` (many vendors on one key, for cross-model comparison).

---

**`INSTRUCTIONS.txt` is the full setup and run guide.** The rest of this README is the overview; that file has the step-by-step, including target VM preparation and troubleshooting.

## Quick start (Kali Linux)

Kali is the supported runtime - every offensive tool the agent calls (nmap, metasploit, impacket, bloodhound-python, …) ships there natively.

**Before anything else:** put Kali and your target VM on the same isolated Host-Only network, give the target a static IP, and confirm `ping -c3 <target-ip>` works from Kali. Nothing below functions without that. See STEP 0 in `INSTRUCTIONS.txt`.

```bash
# 1. Clone
git clone https://github.com/benouahmane/AI-RedTeamEngine.git
cd AI-RedTeamEngine

# 2. One-shot install (OS deps, Python venv, CALDERA)
chmod +x setup_kali.sh
./setup_kali.sh

# 3. Configure
nano .env          # LLM_PROVIDER=anthropic  -> set ANTHROPIC_API_KEY
                   # LLM_PROVIDER=openrouter -> set OPENROUTER_API_KEY
                   #                            and OPENROUTER_MODEL
                   # check ALLOWED_TARGET_RANGES covers your target's IP

# 4. Start Postgres + Neo4j
docker compose up -d

# 5. Initialise the database
source .venv/bin/activate
alembic upgrade head

# 6. Smoke-test (offensive binaries are mocked — should pass anywhere)
pytest -v
```

Then start the two daemons, **each in its own terminal**, and leave them running:

```bash
./scripts/start_msfrpc.sh     # Metasploit RPC — required for exploitation
./scripts/start_caldera.sh    # CALDERA server — first start builds the UI, slow
```

Both can run as systemd services instead — see STEP 6 and 6B in `INSTRUCTIONS.txt`.

## Running a session

```bash
source .venv/bin/activate

# Supervised — approve each action (prompts in THIS terminal)
python main.py run --target 192.168.163.131 --mode human_in_loop

# Unattended — no gate, used for benchmarks
python main.py run --target 192.168.163.131 --mode autonomous

# Many hosts concurrently
python main.py run-range --targets 10.10.0.0/24 --env env2 --workers 8

# Results
python main.py list                        # past sessions
python main.py tree <session_id>           # the task tree
python main.py reconcile --dry-run         # sessions stuck in 'running'
python main.py reconcile                   # …mark them aborted
python main.py report <session_id>         # HTML report -> artefacts/reports/
python main.py report <session_id> --pdf   # …and a PDF beside it

# Score against ground truth
python main.py benchmark --manifest benchmark/ground_truth/metasploitable2.json
```

`192.168.163.131` is env1's Metasploitable 2 host — replace it with your target's actual IP. It must fall inside `ALLOWED_TARGET_RANGES` in `.env`, and must be a literal IP: with an allowlist configured the scope check rejects hostnames outright. Leaving `ALLOWED_TARGET_RANGES` empty disables the check for everything, hostnames included, and the CLI warns on stderr when it does.

PDF conversion needs one of `weasyprint` (best fidelity), `wkhtmltopdf`, or a headless Chromium; without one the HTML is still written and the command reports what to install.

Or drive it from the browser:

```bash
uvicorn api.main:app --reload    # http://localhost:8000
```

In the dashboard, creating a session and running it are two steps: submit the new-session form, then click **Start agent** in the panel that appears.

## Layout

| Path | Purpose |
|---|---|
| `agent/` | ReAct loop, prompt templates, findings normaliser, decision logger, multi-host orchestrator |
| `tools/` | Wrappers around Nmap, Gobuster, Nuclei, Metasploit, CALDERA, BloodHound, Rubeus, etc. |
| `memory/` | PostgreSQL context — sessions, hosts, vulns, **PTT (task tree)** |
| `environments/` | Lab env config (Metasploitable, VulnHub, GOAD) |
| `reports/` | Jinja2 pentest report generator |
| `benchmark/` | Ground-truth manifests and scoring — AI vs manual comparison |
| `api/` | FastAPI + HTMX dashboard |
| `scripts/` | msfrpcd + CALDERA start scripts and systemd units |
| `migrations/` | Alembic schema versions |
| `tests/` | Unit + integration tests |

## Operation modes

- **Autonomous** - agent completes the full pentest without intervention.
- **Human-in-the-loop** - every proposed action waits for analyst approval. *Where* it waits depends on how you launched it: sessions started from the CLI prompt in that terminal; sessions started from the dashboard wait on a browser click and time out after one hour.

## Reports

Seven sections, rendered from the database rather than assembled by the model: executive summary, scope, attack narrative, evidence, vulnerability register, MITRE ATT&CK coverage matrix, recommendations — plus appendices for discovered hosts and the full decision log with per-step token counts.

Coverage is measured against a 42-technique catalogue spanning 9 tactics, derived from what the registered tools can actually exercise. Techniques the agent uses that fall outside it are surfaced explicitly rather than silently dropped.

```bash
python main.py report <session_id> --pdf
```

## Architecture

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design — the ReAct loop, the task-tree contract, the tool-wrapper interface, the data model, and how to extend each.

## Documentation

| File | Contents |
|---|---|
| `INSTRUCTIONS.txt` | Setup and run guide - target VM prep, services, troubleshooting |
| `ARCHITECTURE.md` | Design, PTT, tool-wrapper contract, data model, extending it |