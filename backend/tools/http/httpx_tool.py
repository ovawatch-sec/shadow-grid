"""httpx — HTTP probing with tech detection."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class HttpxTool(BaseTool):
    name = "httpx"
    category = ToolCategory.HTTP
    description = "HTTP service detection with title, status, tech fingerprinting"
    parallel_group = "http"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        alive_file = out_dir / "alive_subdomains.txt"
        if not alive_file.exists():
            return RunResult("", "No alive_subdomains.txt", 1, 0)
        outfile = out_dir / "httpx.jsonl"
        return await self._exec([
            "httpx", "-silent", "-list", str(alive_file),
            "-title", "-status-code", "-follsg-redirects",
            "-tech-detect", "-json", "-o", str(outfile),
        ], timeout=900)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows = []
        for line in result.lines:
            try:
                obj = json.loads(line)
                techs = obj.get("tech") or obj.get("technologies") or []
                rows.append({
                    "url":    obj.get("url", ""),
                    "host":   obj.get("host", ""),
                    "status": obj.get("status-code") or obj.get("status_code"),
                    "title":  obj.get("title", ""),
                    "server": obj.get("webserver") or obj.get("web-server", ""),
                    "tech":   techs if isinstance(techs, list) else [techs],
                    "ip":     obj.get("host", obj.get("ip", "")),
                    "source": "httpx",
                })
            except Exception:
                pass
        return rows
