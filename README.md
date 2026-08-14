# AI Red Team Engine

Autonomous penetration testing framework - a ReAct-style agent driving offensive security tools against isolated lab environments. The reasoning loop is implemented directly against the provider API (no LangChain runtime dependency); see `agent/core.py`. Two providers are supported via `LLM_PROVIDER`: `anthropic` (default) and `openrouter` (many vendors behind one key, for benchmark comparisons).

> **Lab use only.** This system is designed exclusively for authorised testing in isolated environments. Never point it at a host you do not own or have explicit written authorisation to test.

**`INSTRUCTIONS.txt` is the full setup and run guide.** This README is the overview; that file has the step-by-step, including target VM preparation and troubleshooting.

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
python main.py report <session_id>         # HTML report -> artefacts/reports/
python main.py report <session_id> --pdf   # …and a PDF beside it

# Score against ground truth (FYP D5)
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
| `benchmark/` | Ground-truth manifests and scoring — AI vs manual comparison (D5) |
| `api/` | FastAPI + HTMX dashboard |
| `scripts/` | msfrpcd + CALDERA start scripts and systemd units |
| `migrations/` | Alembic schema versions |
| `tests/` | Unit + integration tests |

## Operation modes

- **Autonomous** - agent completes the full pentest without intervention.
- **Human-in-the-loop** - every proposed action waits for analyst approval. *Where* it waits depends on how you launched it: sessions started from the CLI prompt in that terminal; sessions started from the dashboard wait on a browser click and time out after one hour.

## Architecture

A multi-layer ReAct stack. An LLM agent reasons over a **Pentesting Task Tree** held in PostgreSQL - a hierarchical plan of attack tasks that doubles as the agent's working memory - and picks the next task to run at each step. Offensive tools sit behind a uniform wrapper interface and are exposed to the model as a generated catalogue, so registering a wrapper is all it takes to make the agent aware of it. Findings are normalised into shared entity tables (hosts, credentials, vulnerabilities), which is what enables credential reuse and cross-host correlation. Every decision is logged, every action carries a MITRE ATT&CK tag, and reports are rendered from that record.

See `ARCHITECTURE.md` for the full design.

## Documentation

| File | Contents |
|---|---|
| `INSTRUCTIONS.txt` | Setup and run guide - target VM prep, services, troubleshooting |
| `ARCHITECTURE.md` | Design, PTT, tool-wrapper contract, data model, extending it |