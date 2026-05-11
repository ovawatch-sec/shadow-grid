"""urlfinder."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class UrlFinderTool(BaseTool):
    name = "urlfinder"
    category = ToolCategory.URL
    description = "URL discovery via urlfinder"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        return await self._exec(["urlfinder", "-d", domain, "-silent"], timeout=120)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"url": l, "source": "urlfinder"} for l in result.lines if l.startswith("http")]
