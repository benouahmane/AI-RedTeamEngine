# AI Red Team Engine

Autonomous penetration testing framework - a ReAct-style agent driving offensive security tools against isolated lab environments. The reasoning loop is implemented directly against the Anthropic/Ollama API (no LangChain runtime dependency); see `agent/core.py`.

> **Lab use only.** This system is designed exclusively for authorised testing in isolated environments. 

## Quick start (Kali Linux)

Kali is the supported runtime - every offensive tool the agent calls (nmap, metasploit, impacket, bloodhound-python, …) ships there natively.

```bash
# 1. Clone
git clone https://github.com/TheRamiB/AI-RedTeamEngine.git
cd AI-RedTeamEngine

# 2. One-shot install (OS deps + Python venv + Python deps)
chmod +x setup_kali.sh
./setup_kali.sh

# 3. Set your API key
nano .env          # set ANTHROPIC_API_KEY

# 4. Start Postgres + Neo4j
docker compose up -d

# 5. Initialise the database
source .venv/bin/activate
alembic upgrade head

# 6. Run a session
python main.py run --target 192.168.56.101 (or whatever it is assigned) --mode human_in_loop

# Or open the dashboard
uvicorn api.main:app --reload
```

## Layout

| Path | Purpose |
|---|---|
| `agent/` | ReAct loop, prompt templates, findings normaliser, decision logger, multi-host orchestrator |
| `tools/` | Wrappers around Nmap, Gobuster, Nuclei, Metasploit, BloodHound, Rubeus, etc. |
| `memory/` | PostgreSQL context — sessions, hosts, vulns, **PTT (task tree)** |
| `environments/` | Lab env config (Metasploitable, VulnHub, GOAD) |
| `reports/` | Jinja2 pentest report generator |
| `api/` | FastAPI + HTMX dashboard |
| `migrations/` | Alembic schema versions |
| `tests/` | Unit + integration tests |

See `AGENT.md` for architecture notes.

## Operation modes

- **Autonomous** — agent completes the full pentest without intervention.
- **Human-in-the-loop** — every proposed action waits for analyst approval via the dashboard.
