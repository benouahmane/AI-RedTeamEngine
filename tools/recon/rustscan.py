"""RustScan wrapper — fast port enumeration, typically chained into nmap.

Runs rustscan with `--greppable` so output is one
`ip -> [port,port,...]` line per host that's trivial to parse.
"""
from __future__ import annotations

import re
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


_GREP_LINE = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s*->\s*\[(?P<ports>[\d,]*)\]")


@register
class RustScanTool(OffensiveTool):
    name = "rustscan"
    phase = "recon"
    mitre_techniques = ["T1046"]
    description = """
    Ultra-fast TCP port scanner. Use as a precursor to nmap when scanning
    large port ranges; pipes discovered ports into a deeper nmap scan.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, CIDR, or hostname"},
                "batch_size": {"type": "integer", "default": 4500},
                "timeout_ms": {"type": "integer", "default": 1500},
                "ports": {
                    "type": "string",
                    "description": "comma-sep list or range, e.g. '1-65535' or '22,80,443'",
                },
                "ulimit": {"type": "integer", "default": 5000},
            },
            "required": ["target"],
        }

    def execute(self, **params: Any) -> ToolResult:
        target = params["target"]
        batch_size = params.get("batch_size", 4500)
        timeout_ms = params.get("timeout_ms", 1500)
        ports = params.get("ports")
        ulimit = params.get("ulimit", 5000)

        argv = [
            "rustscan",
            "-a", target,
            "-b", str(batch_size),
            "-t", str(timeout_ms),
            "--ulimit", str(ulimit),
            "--greppable",
            "--no-config",
            "--accessible",
        ]
        if ports:
            if "-" in ports:
                argv += ["-r", ports]
            else:
                argv += ["-p", ports]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(
                ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration,
            )

        hosts: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            m = _GREP_LINE.match(line.strip())
            if not m:
                continue
            raw_ports = m.group("ports").strip()
            ports_list = [int(p) for p in raw_ports.split(",") if p.strip().isdigit()]
            hosts.append({
                "ip": m.group("ip"),
                "ports": [{"port": p, "protocol": "tcp"} for p in ports_list],
                "open_ports": ports_list,
            })

        if rc != 0 and not hosts:
            return ToolResult(
                ToolStatus.ERROR, cmd, stdout + stderr,
                error=f"rustscan exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        status = ToolStatus.SUCCESS if hosts else ToolStatus.NO_FINDINGS
        return ToolResult(
            status=status,
            command=cmd,
            raw_output=stdout,
            findings={"hosts": hosts, "host_count": len(hosts)},
            duration_sec=duration,
        )
