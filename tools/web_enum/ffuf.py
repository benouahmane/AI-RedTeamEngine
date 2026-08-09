"""ffuf wrapper — fast web fuzzer (alternative to gobuster, supports param fuzzing).

Runs ffuf with `-of json -o <tmpfile>` and parses the JSON's `results` array.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from tools.base import OffensiveTool, ToolResult, ToolStatus
from tools.registry import register


@register
class FfufTool(OffensiveTool):
    name = "ffuf"
    phase = "enumeration"
    mitre_techniques = ["T1595.003"]
    description = """
    Fast web fuzzer. Pick over gobuster when you need parameter fuzzing,
    custom headers, or response filtering by size/word/line count.
    """

    DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

    def param_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ keyword"},
                "wordlist": {"type": "string"},
                "filter_size": {"type": "string", "description": "ffuf -fs"},
                "filter_words": {"type": "string", "description": "ffuf -fw"},
                "match_codes": {"type": "string", "default": "200,204,301,302,401,403"},
                "threads": {"type": "integer", "default": 40},
                "extensions": {"type": "string", "description": "comma-sep, e.g. 'php,html'"},
                "headers": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "header strings, e.g. 'Cookie: x=y'",
                },
            },
            "required": ["url"],
        }

    def execute(self, **params: Any) -> ToolResult:
        url = params["url"]
        if "FUZZ" not in url:
            return ToolResult(
                ToolStatus.ERROR, "", "",
                error="url must contain the FUZZ keyword (e.g. http://host/FUZZ)",
            )
        wordlist = params.get("wordlist") or self.DEFAULT_WORDLIST
        match_codes = params.get("match_codes", "200,204,301,302,401,403")
        threads = params.get("threads", 40)
        extensions = params.get("extensions")
        filter_size = params.get("filter_size")
        filter_words = params.get("filter_words")
        headers = params.get("headers") or []

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fp:
            outfile = Path(fp.name)

        try:
            argv = [
                "ffuf",
                "-u", url,
                "-w", wordlist,
                "-mc", match_codes,
                "-t", str(threads),
                "-of", "json",
                "-o", str(outfile),
                "-s",  # silent — suppress progress bar
            ]
            if extensions:
                argv += ["-e", "," + extensions if not extensions.startswith(",") else extensions]
            if filter_size:
                argv += ["-fs", filter_size]
            if filter_words:
                argv += ["-fw", filter_words]
            for h in headers:
                argv += ["-H", h]

            rc, stdout, stderr, duration = self._run(argv)
            cmd = self.quote(argv)

            if rc == -1:
                return ToolResult(
                    ToolStatus.TIMEOUT, cmd, stdout, error=stderr, duration_sec=duration,
                )

            results: list[dict[str, Any]] = []
            if outfile.exists() and outfile.stat().st_size > 0:
                try:
                    data = json.loads(outfile.read_text())
                    for r in data.get("results") or []:
                        results.append({
                            "url": r.get("url"),
                            "input": (r.get("input") or {}).get("FUZZ"),
                            "status": r.get("status"),
                            "length": r.get("length"),
                            "words": r.get("words"),
                            "lines": r.get("lines"),
                            "content_type": r.get("content-type"),
                        })
                except json.JSONDecodeError as exc:
                    return ToolResult(
                        ToolStatus.PARTIAL, cmd, stdout,
                        error=f"could not parse ffuf json: {exc}",
                        duration_sec=duration,
                    )

            if rc != 0 and not results:
                return ToolResult(
                    ToolStatus.ERROR, cmd, stdout + stderr,
                    error=f"ffuf exited {rc}: {stderr.strip()[:300]}",
                    duration_sec=duration,
                )

            status = ToolStatus.SUCCESS if results else ToolStatus.NO_FINDINGS
            return ToolResult(
                status=status,
                command=cmd,
                raw_output=stdout,
                findings={"url": url, "results": results, "count": len(results)},
                duration_sec=duration,
            )
        finally:
            outfile.unlink(missing_ok=True)
