"""waybackurls."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class WaybackUrlsTool(BaseTool):
    name = "waybackurls"
    category = ToolCategory.URL
    description = "Historical URLs from the Wayback Machine"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        return await self._exec(["waybackurls", domain], timeout=180)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"url": l, "source": "waybackurls"} for l in result.lines if l.startswith("http")]
