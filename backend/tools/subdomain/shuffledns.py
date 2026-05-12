"""shuffledns — active DNS bruteforce."""
from __future__ import annotations
import shutil
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class ShuffledNSTool(BaseTool):
    name = "shuffledns"
    category = ToolCategory.SUBDOMAIN
    description = "Active DNS bruteforce via shuffledns"
    parallel_group = "subdomain"

    def availability_error(self) -> str | None:
        binary_error = super().availability_error()
        if binary_error:
            return binary_error
        if shutil.which("massdns") is None:
            return "Required dependency not found: massdns (needed by shuffledns)"
        return None

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        wl = wordlist or str(data_dir / "wordlists" / "dns.txt")
        resolvers = str(data_dir / "resolvers.txt")
        outfile = out_dir / "shuffledns.txt"
        return await self._exec([
            "shuffledns", "-silent", "-d", domain,
            "-w", wl, "-r", resolvers,
            "-mode", "bruteforce", "-o", str(outfile),
            "-m", shutil.which("massdns") or "massdns",
        ], timeout=900)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = result.lines or self._read_lines(self.output_dir / domain / "shuffledns.txt")
        return [{"host": l, "source": "shuffledns"} for l in lines
                if l == domain or l.endswith("." + domain)]
