"""subfinder — passive subdomain enum."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class SubfinderTool(BaseTool):
    name = "subfinder"
    category = ToolCategory.SUBDOMAIN
    description = "Passive subdomain discovery via subfinder (multiple sources)"
    parallel_group = "subdomain"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        outfile = out_dir / "subfinder.txt"
        r = await self._exec(["subfinder", "-silent", "-all", "-d", domain, "-o", str(outfile)], timeout=180)
        # Also capture stdout if -o didn't write
        if not outfile.exists():
            outfile.write_text(r.stdout)
        return r

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = result.lines or self._read_lines(self.output_dir / domain / "subfinder.txt")
        return [{"host": l, "source": "subfinder"} for l in lines
                if l == domain or l.endswith("." + domain)]
