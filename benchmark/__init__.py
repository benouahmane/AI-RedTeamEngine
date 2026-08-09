"""Benchmark harness — score the agent against per-target ground truth.

Implements FYP deliverable D5 (Benchmark Study): a repeatable way to measure
the autonomous agent's coverage, accuracy, time-to-exploit, and cost, and to
compare it against a recorded manual-pentest baseline.

  - `manifest.GroundTruth`  — known facts about a target (ports, CVEs, ATT&CK
    techniques, flags) plus an optional manual baseline.
  - `scorer.score_session`  — turn a completed `PentestSession` + ground truth
    into a `BenchmarkScore` (precision/recall, coverage, time, cost).
  - `runner.run_benchmark`  — run a session and score it end to end.
"""
from benchmark.manifest import GroundTruth, ManualBaseline, load_manifest
from benchmark.scorer import BenchmarkScore, score_session

__all__ = [
    "GroundTruth",
    "ManualBaseline",
    "load_manifest",
    "BenchmarkScore",
    "score_session",
]
