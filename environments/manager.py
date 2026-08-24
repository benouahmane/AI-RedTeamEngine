"""Environment connectivity manager.

Currently lightweight — the bulk of the work (VPN tunnels, route table
swaps) is handled by the lab infrastructure. This class exists so the
agent has a single place to ask "am I currently connected to env3?".
"""
from __future__ import annotations

import socket
from dataclasses import dataclass

from environments.config import ENVIRONMENTS, EnvironmentSpec


@dataclass
class ReachabilityCheck:
    env_key: str
    ok: bool
    detail: str


class EnvironmentManager:
    def __init__(self) -> None:
        self.envs = ENVIRONMENTS

    def get(self, env_key: str) -> EnvironmentSpec:
        if env_key not in self.envs:
            raise KeyError(f"Unknown environment: {env_key}. Choose from {list(self.envs)}")
        return self.envs[env_key]

    # NOTE: there is deliberately no scope check here. Scope is enforced in one
    # place — `RedTeamAgent._target_in_scope`, reading ALLOWED_TARGET_RANGES —
    # and it is checked on every proposed action, not just at launch. A second,
    # never-called gate keyed on `network_cidr` used to live here; two sources
    # of truth for "is this target allowed" is exactly the kind of thing that
    # gets out of step. `main.warn_if_outside_environment` reports a mismatch
    # against the declared network without blocking.

    def check_reachability(self, env_key: str, *, port: int = 22, timeout: float = 2.0) -> ReachabilityCheck:
        """Quick TCP probe against a known host in the env to confirm routing."""
        spec = self.get(env_key)
        if not spec.targets:
            return ReachabilityCheck(env_key, False, "no static targets configured")
        host = spec.targets[0]
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return ReachabilityCheck(env_key, True, f"reached {host}:{port}")
        except OSError as exc:
            return ReachabilityCheck(env_key, False, f"unreachable: {exc}")
