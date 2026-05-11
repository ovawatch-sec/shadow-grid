"""gau — GetAllURLs."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class GauTool(BaseTool):
    name = "gau"
    category = ToolCategory.URL
    description = "URL discovery: Wayback + CommonCrawl + OTX + URLScan"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        outfile = out_dir / "gau.txt"
        return await self._exec(["gau", "--subs", "--o", str(outfile), domain], timeout=300)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"url": l, "source": "gau"} for l in result.lines if l.startswith("http")]
