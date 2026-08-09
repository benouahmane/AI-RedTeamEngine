"""Ground-truth manifest schema + loader.

A manifest captures what a *correct* assessment of a target should find. The
scorer compares the agent's actual session against it to compute precision /
recall and coverage. Manifests live as JSON under
`benchmark/ground_truth/<target>.json`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ManualBaseline:
    """A human pentester's recorded result on the same target, for comparison."""
    time_to_first_shell_sec: float | None = None
    hosts_compromised: int | None = None
    technique_coverage: float | None = None       # 0..1 recall vs expected_techniques
    cve_recall: float | None = None               # 0..1
    analyst_hours: float | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "ManualBaseline":
        d = d or {}
        return cls(
            time_to_first_shell_sec=d.get("time_to_first_shell_sec"),
            hosts_compromised=d.get("hosts_compromised"),
            technique_coverage=d.get("technique_coverage"),
            cve_recall=d.get("cve_recall"),
            analyst_hours=d.get("analyst_hours"),
        )


@dataclass
class GroundTruth:
    target: str
    name: str
    environment: str = "env1"
    known_open_ports: list[int] = field(default_factory=list)
    known_cves: list[str] = field(default_factory=list)
    expected_techniques: list[str] = field(default_factory=list)   # MITRE ATT&CK ids
    flags: list[str] = field(default_factory=list)                 # values/paths to find
    objective: str | None = None
    manual_baseline: ManualBaseline = field(default_factory=ManualBaseline)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GroundTruth":
        return cls(
            target=d["target"],
            name=d.get("name", d["target"]),
            environment=d.get("environment", "env1"),
            known_open_ports=[int(p) for p in d.get("known_open_ports", [])],
            known_cves=[c.upper() for c in d.get("known_cves", [])],
            expected_techniques=[t.upper() for t in d.get("expected_techniques", [])],
            flags=list(d.get("flags", [])),
            objective=d.get("objective"),
            manual_baseline=ManualBaseline.from_dict(d.get("manual_baseline")),
        )


def load_manifest(path: str | Path) -> GroundTruth:
    data = json.loads(Path(path).read_text())
    return GroundTruth.from_dict(data)
