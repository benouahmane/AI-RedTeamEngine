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

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:70b"

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
