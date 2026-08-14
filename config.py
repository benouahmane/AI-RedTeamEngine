"""Centralised settings loaded from .env."""
from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://redteam:redteam@localhost:5432/redteam_engine"

    llm_provider: str = "anthropic"
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    # Model routing: a stronger model plans/decides; a cheaper one handles
    # high-volume parsing. Both default to `anthropic_model` if left unset so
    # existing single-model setups keep working.
    anthropic_planner_model: str | None = None
    anthropic_parser_model: str | None = None

    # OpenRouter gateway — used for cross-vendor benchmark runs (FYP D5).
    openrouter_api_key: str | None = None
    openrouter_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "qwen/qwen3.8-max"
    # Explicit cache breakpoint on the system prompt. Required by vendors that
    # don't cache automatically; harmless to leave off if they do.
    openrouter_cache_system: bool = False
    # Ask for guaranteed-JSON output. Not honoured by every model/provider.
    openrouter_json_mode: bool = False
    # Reasoning models spend most of their budget on chain-of-thought before
    # emitting the action, and get truncated mid-thought at the 4096 default —
    # which surfaces as "LLM returned malformed JSON" with prose in the dump.
    # Raise this when routing to one.
    openrouter_max_tokens: int = 4096
    openrouter_referer: str = "https://github.com/benouahmane/AI-RedTeamEngine"

    msf_rpc_host: str = "127.0.0.1"
    msf_rpc_port: int = 55553
    msf_rpc_user: str = "msf"
    msf_rpc_pass: str = "changeme"

    gvm_connection: str = "tls"               # "tls" | "socket"
    gvm_host: str = "127.0.0.1"
    gvm_port: int = 9390
    gvm_socket_path: str = "/run/gvmd/gvmd.sock"
    gvm_username: str = "admin"
    gvm_password: str = "admin"

    # CALDERA adversary-emulation server (REST API).
    caldera_url: str = "http://127.0.0.1:8888"
    caldera_api_key: str = "ADMIN123"

    default_mode: str = "human_in_loop"
    max_agent_steps: int = 200
    tool_execution_timeout_sec: int = 900

    # Transient-failure handling for tool execution.
    tool_retry_attempts: int = 1                 # extra attempts after the first
    tool_retry_backoff_sec: float = 3.0

    # Default per-host step budget when fanning out across a range.
    max_steps_per_host: int = 60

    allowed_target_ranges: str = ""

    @property
    def allowed_cidrs(self) -> list[str]:
        return [c.strip() for c in self.allowed_target_ranges.split(",") if c.strip()]

    @property
    def planner_model(self) -> str:
        return self.anthropic_planner_model or self.anthropic_model

    @property
    def parser_model(self) -> str:
        return self.anthropic_parser_model or self.anthropic_model


settings = Settings()
