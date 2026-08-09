"""BloodHound + bloodhound-python wrapper — AD attack-path graph collection."""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register

_BUILTIN_QUERIES: dict[str, str] = {
    "shortest_path_to_da": (
        "MATCH p=shortestPath((u:User)-[*1..]->(g:Group)) "
        "WHERE g.name =~ '(?i)domain admins.*' RETURN p LIMIT 10"
    ),
    "kerberoastable": (
        "MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true "
        "RETURN u.name, u.serviceprincipalnames LIMIT 50"
    ),
    "unconstrained_delegation": (
        "MATCH (c:Computer) WHERE c.unconstraineddelegation=true "
        "RETURN c.name, c.operatingsystem LIMIT 50"
    ),
    "as_rep_roastable": (
        "MATCH (u:User) WHERE u.dontreqpreauth=true AND u.enabled=true "
        "RETURN u.name LIMIT 50"
    ),
    "local_admins": (
        "MATCH p=(u:User)-[:AdminTo]->(c:Computer) "
        "RETURN u.name AS user, c.name AS computer LIMIT 50"
    ),
    "domain_trusts": (
        "MATCH p=(d:Domain)-[:TrustedBy]->(d2:Domain) "
        "RETURN d.name, d2.name LIMIT 20"
    ),
}

_STAT = re.compile(r"INFO:\s+Found\s+(\d+)\s+(\w+)", re.IGNORECASE)
_DONE = re.compile(r"INFO:\s+Done in", re.IGNORECASE)
_ZIP_PATH = re.compile(r"Compressing output into\s+(\S+\.zip)")


@register
class BloodHoundTool(OffensiveTool):
    name = "bloodhound"
    phase = "lateral_movement"
    mitre_techniques = ["T1087.002", "T1069.002", "T1482"]
    description = """
    Collects AD objects via bloodhound-python and queries the resulting graph
    (Neo4j) for attack paths. Two actions:

      - collect: run bloodhound-python against the DC to enumerate users,
        groups, computers, ACLs, sessions, and GPOs. Produces JSON/zip files
        ready for import into BloodHound/Neo4j.
      - query:   run a named Cypher query against a running Neo4j instance.
        Built-in names: shortest_path_to_da, kerberoastable,
        unconstrained_delegation, as_rep_roastable, local_admins,
        domain_trusts. Or supply custom_query with raw Cypher.
    """

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["collect", "query"]},
                "target_dc": {"type": "string", "description": "DC IP or hostname"},
                "domain": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "ntlm_hash": {"type": "string", "description": "LM:NT or :NT"},
                "collection_method": {
                    "type": "string",
                    "description": "bloodhound-python -c value (default: All)",
                    "default": "All",
                },
                "output_dir": {
                    "type": "string",
                    "description": "Directory to write JSON/zip output",
                },
                "query_name": {
                    "type": "string",
                    "enum": list(_BUILTIN_QUERIES),
                    "description": "Pre-built attack-path query name",
                },
                "custom_query": {
                    "type": "string",
                    "description": "Raw Cypher query (overrides query_name)",
                },
                "neo4j_uri": {
                    "type": "string",
                    "description": "Neo4j Bolt URI (default: bolt://localhost:7687)",
                },
                "neo4j_user": {"type": "string", "default": "neo4j"},
                "neo4j_password": {"type": "string"},
            },
            "required": ["action"],
        }

    def execute(self, **params: Any) -> ToolResult:
        action = params.get("action")
        if action == "collect":
            return self._collect(params)
        if action == "query":
            return self._query(params)
        return ToolResult(ToolStatus.ERROR, "", "", error=f"Unknown action: {action!r}")

    # ── collect ───────────────────────────────────────────────────────────────

    def _collect(self, p: dict[str, Any]) -> ToolResult:
        dc = p.get("target_dc")
        domain = p.get("domain")
        user = p.get("username")
        password = p.get("password")
        ntlm = p.get("ntlm_hash")

        if not dc or not domain or not user:
            return ToolResult(
                ToolStatus.ERROR, "", "",
                error="collect requires target_dc, domain, and username",
            )
        if not password and not ntlm:
            return ToolResult(
                ToolStatus.ERROR, "", "",
                error="collect requires password or ntlm_hash",
            )

        output_dir = p.get("output_dir") or tempfile.mkdtemp(prefix="bh_")
        collection = p.get("collection_method") or "All"

        argv = [
            "bloodhound-python",
            "-u", user,
            "-d", domain,
            "-ns", dc,
            "-c", collection,
            "--zip",
            "-o", output_dir,
            "--dns-tcp",
        ]
        if password:
            argv += ["-p", password]
        elif ntlm:
            argv += ["--hashes", ntlm]

        rc, stdout, stderr, duration = self._run(argv)
        cmd = self.quote(argv)

        if rc == -1:
            return ToolResult(ToolStatus.TIMEOUT, cmd, stdout,
                              error=stderr.strip() or "timeout", duration_sec=duration)

        combined = stdout + stderr
        if rc != 0 and not _DONE.search(combined):
            return ToolResult(
                ToolStatus.ERROR, cmd, combined,
                error=f"bloodhound-python exited {rc}: {stderr.strip()[:300]}",
                duration_sec=duration,
            )

        findings = _parse_collect(combined, output_dir)
        has_data = bool(findings.get("stats"))
        return ToolResult(
            status=ToolStatus.SUCCESS if has_data else ToolStatus.PARTIAL,
            command=cmd,
            raw_output=stdout,
            findings=findings,
            duration_sec=duration,
        )

    # ── query ─────────────────────────────────────────────────────────────────

    def _query(self, p: dict[str, Any]) -> ToolResult:
        cypher = p.get("custom_query")
        query_name = p.get("query_name")
        if not cypher:
            if not query_name or query_name not in _BUILTIN_QUERIES:
                return ToolResult(
                    ToolStatus.ERROR, "", "",
                    error=(
                        f"query requires query_name ({', '.join(_BUILTIN_QUERIES)}) "
                        "or custom_query"
                    ),
                )
            cypher = _BUILTIN_QUERIES[query_name]

        uri = p.get("neo4j_uri") or "bolt://localhost:7687"
        neo4j_user = p.get("neo4j_user") or "neo4j"
        neo4j_password = p.get("neo4j_password") or ""

        try:
            rows, error = self._neo4j_query(uri, neo4j_user, neo4j_password, cypher)
        except Exception as exc:
            return ToolResult(ToolStatus.ERROR, cypher, "", error=f"Neo4j error: {exc}")

        if error:
            return ToolResult(ToolStatus.ERROR, cypher, "", error=error)

        return ToolResult(
            status=ToolStatus.SUCCESS if rows else ToolStatus.NO_FINDINGS,
            command=cypher,
            raw_output=str(rows),
            findings={
                "query_name": query_name,
                "cypher": cypher,
                "results": rows,
                "result_count": len(rows),
            },
        )

    def _neo4j_query(
        self, uri: str, user: str, password: str, cypher: str
    ) -> tuple[list[dict[str, Any]], str | None]:
        try:
            from neo4j import GraphDatabase  # type: ignore[import]
        except ImportError:
            return [], "neo4j driver not installed — run: pip install neo4j"

        driver = GraphDatabase.driver(uri, auth=(user, password))
        try:
            with driver.session() as session:
                result = session.run(cypher)
                rows = [dict(record) for record in result]
        finally:
            driver.close()

        return rows, None


# ─────────────────────────────────────────────────────────────────────────────


def _parse_collect(output: str, output_dir: str) -> dict[str, Any]:
    stats: dict[str, int] = {}
    for m in _STAT.finditer(output):
        stats[m.group(2).lower()] = int(m.group(1))

    zip_match = _ZIP_PATH.search(output)
    zip_file = zip_match.group(1) if zip_match else None

    if not zip_file:
        zips = sorted(Path(output_dir).glob("*.zip"), key=lambda p: p.stat().st_mtime)
        zip_file = str(zips[-1]) if zips else None

    return {
        "output_dir": output_dir,
        "zip_file": zip_file,
        "stats": stats,
        "completed": bool(_DONE.search(output)),
    }
