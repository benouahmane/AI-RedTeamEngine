"""Report generator — Jinja2 templates rendered against session state."""
from reports.generator import ReportGenerator
from reports.mitre_mapper import build_coverage_matrix

__all__ = ["ReportGenerator", "build_coverage_matrix"]
