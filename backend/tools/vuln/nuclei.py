"""nuclei — vulnerability scanning."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult


def parse_nuclei_jsonl(lines: list[str], source: str = "nuclei") -> list[dict[str, Any]]:
    """Normalize nuclei JSONL output into ShadowGrid result rows."""
    rows: list[dict[str, Any]] = []
    for line in lines:
        try:
            f = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(f, dict):
            continue
        info = f.get("info") if isinstance(f.get("info"), dict) else {}
        rows.append({
            "template_id": f.get("template-id", ""),
            "name":        info.get("name", ""),
            "severity":    info.get("severity", f.get("severity", "unknown")),
            "host":        f.get("host", ""),
            "matched_at":  f.get("matched-at", ""),
            "description": info.get("description", ""),
            "tags":        info.get("tags", ""),
            "request":     str(f.get("request", ""))[:2000],
            "response":    str(f.get("response", ""))[:2000],
            "curl":        f.get("curl-command", ""),
            "timestamp":   f.get("timestamp", ""),
            "source":      source,
        })
    return rows


class NucleiTool(BaseTool):
    name = "nuclei"
    category = ToolCategory.VULN
    description = "Vulnerability scanning via nuclei templates (low–critical)"
    parallel_group = "vuln"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        alive_file = out_dir / "alive_urls.txt"
        if not alive_file.exists():
            return RunResult("", "No alive_urls.txt", 0, 0)
        if not alive_file.read_text(errors="replace").strip():
            return RunResult("", "alive_urls.txt is empty — skipping nuclei", 0, 0)

        outfile = out_dir / "nuclei_results.jsonl"
        command = [
            "nuclei", "-list", str(alive_file),
            "-exclude-tags", "cve",
            "-severity", "low,medium,high,critical",
            "-jsonl", "-o", str(outfile), "-silent",
        ] + self._header_args(hosts=self._hosts_in(self._read_lines(alive_file)))
        result = await self._exec(command, timeout=3600)

        # Older nuclei used -json instead of -jsonl.
        if result.returncode != 0 and "unknown flag" in (result.stderr or "").lower():
            command = [
                "nuclei", "-list", str(alive_file),
                "-exclude-tags", "cve",
                "-severity", "low,medium,high,critical",
                "-json", "-o", str(outfile), "-silent",
            ] + self._header_args(hosts=self._hosts_in(self._read_lines(alive_file)))
            result = await self._exec(command, timeout=3600)
        return result

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = result.lines or self._read_lines(self.output_dir / domain / "nuclei_results.jsonl")
        return parse_nuclei_jsonl(lines)
