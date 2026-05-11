"""nuclei — vulnerability scanning."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class NucleiTool(BaseTool):
    name = "nuclei"
    category = ToolCategory.VULN
    description = "Vulnerability scanning via nuclei templates (low–critical)"
    parallel_group = "vuln"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        alive_file = out_dir / "alive_urls.txt"
        if not alive_file.exists():
            return RunResult("", "No alive_urls.txt", 1, 0)
        outfile = out_dir / "nuclei_results.jsonl"
        return await self._exec([
            "nuclei", "-list", str(alive_file),
            "-severity", "low,medium,high,critical",
            "-json", "-o", str(outfile), "-silent",
        ], timeout=3600)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows = []
        for line in result.lines:
            try:
                f = json.loads(line)
                rows.append({
                    "template_id": f.get("template-id", ""),
                    "name":        f.get("info", {}).get("name", ""),
                    "severity":    f.get("info", {}).get("severity", f.get("severity", "unknown")),
                    "host":        f.get("host", ""),
                    "matched_at":  f.get("matched-at", ""),
                    "description": f.get("info", {}).get("description", ""),
                    "tags":        f.get("info", {}).get("tags", ""),
                    "request":     f.get("request", "")[:2000],
                    "response":    f.get("response", "")[:2000],
                    "curl":        f.get("curl-command", ""),
                    "timestamp":   f.get("timestamp", ""),
                    "source":      "nuclei",
                })
            except Exception:
                pass
        return rows
