"""Static configuration for the three lab environments described in the brief."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class EnvironmentSpec:
    key: str                         # env1, env2, env3
    name: str
    network_cidr: str
    description: str
    default_objective: str
    targets: list[str] = field(default_factory=list)
    requires_vpn: bool = False
    notes: str = ""


ENVIRONMENTS: dict[str, EnvironmentSpec] = {
    "env1": EnvironmentSpec(
        key="env1",
        name="Classic Vuln VMs",
        network_cidr="192.168.163.0/24",
        description="Metasploitable 2/3, DVWA, VulnOS, Kioptrix series. AI calibration baseline.",
        default_objective="Achieve root on every host and document each CVE exploited.",
        # VMware host-only subnet. The brief quotes 192.168.56.0/24 (VirtualBox's
        # default host-only range); this lab runs on VMware, which allocates
        # 192.168.163.0/24. Keep this in sync with ALLOWED_TARGET_RANGES in .env.
        targets=[
            "192.168.163.131",         # Metasploitable 2
        ],
    ),
    "env2": EnvironmentSpec(
        key="env2",
        name="VulnHub Range",
        network_cidr="10.10.0.0/16",
        description="50 VulnHub VMs of mixed difficulty — CTF-style flags.",
        default_objective="Capture root.txt and user.txt on as many targets as possible.",
        targets=[],   # populated dynamically by sweeping the CIDR
        notes="Allow Nmap ping sweep before any other action.",
    ),
    "env3": EnvironmentSpec(
        key="env3",
        name="GOAD Active Directory",
        network_cidr="10.20.0.0/16",
        description="Game of Active Directory + supplementary AD lab VMs.",
        default_objective="Reach Domain Admin on all forests and document the attack path.",
        targets=[],
        requires_vpn=True,
        notes="Always start with Kerberoast + AS-REP roast before brute force.",
    ),
}
