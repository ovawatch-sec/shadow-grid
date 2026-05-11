"""shuffledns — active DNS bruteforce."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class ShuffledNSTool(BaseTool):
    name = "shuffledns"
    category = ToolCategory.SUBDOMAIN
    description = "Active DNS bruteforce via shuffledns"
    parallel_group = "subdomain"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        wl = wordlist or str(data_dir / "wordlists" / "dns.txt")
        resolvers = str(data_dir / "resolvers.txt")
        outfile = out_dir / "shuffledns.txt"
        return await self._exec([
            "shuffledns", "-silent", "-d", domain,
            "-w", wl, "-r", resolvers,
            "-mode", "bruteforce", "-o", str(outfile),
        ], timeout=900)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"host": l, "source": "shuffledns"} for l in result.lines
                if l == domain or l.endswith("." + domain)]
