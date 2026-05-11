"""katana — active web crawler."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class KatanaTool(BaseTool):
    name = "katana"
    category = ToolCategory.URL
    description = "Active web crawling with JavaScript support"
    parallel_group = "urls"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        urls_file = out_dir / "alive_urls.txt"
        if not urls_file.exists():
            return RunResult("", "No alive_urls.txt", 1, 0)
        outfile = out_dir / "katana.txt"
        return await self._exec([
            "katana", "-list", str(urls_file),
            "-jsl", "-jc", "-d", "3", "-silent", "-o", str(outfile),
        ], timeout=900)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"url": l, "source": "katana"} for l in result.lines if l.startswith("http")]
