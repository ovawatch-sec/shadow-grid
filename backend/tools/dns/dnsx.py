"""dnsx — DNS resolution of discovered hosts."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class DnsxTool(BaseTool):
    name = "dnsx"
    category = ToolCategory.DNS
    description = "Resolve and enumerate DNS records for alive subdomains"
    parallel_group = "dns"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        subdomains_file = out_dir / "subdomains_merged.txt"
        if not subdomains_file.exists():
            return RunResult("", "No merged subdomains file yet", 1, 0)
        outfile = out_dir / "dnsx.txt"
        return await self._exec([
            "dnsx", "-silent", "-l", str(subdomains_file),
            "-a", "-aaaa", "-cname", "-mx", "-txt", "-ns", "-resp",
            "-o", str(outfile),
        ], timeout=300)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows = []
        lines = result.lines or self._read_lines(self.output_dir / domain / "dnsx.txt")
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                rows.append({"host": parts[0], "record": " ".join(parts[1:]), "source": "dnsx"})
        return rows
