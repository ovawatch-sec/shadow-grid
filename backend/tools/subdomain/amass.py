"""amass — OWASP passive subdomain enumeration."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class AmassTool(BaseTool):
    name = "amass"
    category = ToolCategory.SUBDOMAIN
    description = "OWASP Amass passive subdomain enumeration"
    parallel_group = "subdomain"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        outfile = out_dir / "amass.txt"
        return await self._exec(
            ["amass", "enum", "-passive", "-silent", "-d", domain, "-o", str(outfile)],
            timeout=600,
        )

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        import re
        lines = result.lines or self._read_lines(self.output_dir / domain / "amass.txt")
        dom_re = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I)
        seen, rows = set(), []
        for line in lines:
            for m in dom_re.findall(line):
                h = m.lower()
                if h not in seen and (h == domain or h.endswith("." + domain)):
                    seen.add(h)
                    rows.append({"host": h, "source": "amass"})
        return rows
