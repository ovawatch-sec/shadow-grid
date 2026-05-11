"""assetfinder — passive subdomain enum."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class AssetfinderTool(BaseTool):
    name = "assetfinder"
    category = ToolCategory.SUBDOMAIN
    description = "Passive subdomain discovery via assetfinder"
    parallel_group = "subdomain"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        return await self._exec(["assetfinder", "--subs-only", domain], timeout=120)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"host": l, "source": "assetfinder"} for l in result.lines
                if l == domain or l.endswith("." + domain)]
