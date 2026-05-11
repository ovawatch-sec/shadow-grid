"""whois."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class WhoisTool(BaseTool):
    name = "whois"
    category = ToolCategory.ASSET
    description = "WHOIS lookup for the root domain"
    parallel_group = "asset"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        r = await self._exec(["whois", domain], timeout=30)
        (out_dir / "whois.txt").write_text(r.stdout)
        return r

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        if not result.stdout:
            return []
        return [{"domain": domain, "whois": result.stdout[:8000], "source": "whois"}]
