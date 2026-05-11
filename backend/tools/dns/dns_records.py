"""dns_records — dig-based DNS record enumeration."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

RTYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

class DnsRecordsTool(BaseTool):
    name = "dns_records"
    category = ToolCategory.DNS
    description = "DNS record enumeration (A/AAAA/MX/TXT/NS/SOA/CNAME) via dig"
    parallel_group = "dns"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        all_output = []
        for rtype in RTYPES:
            r = await self._exec(["dig", "+noall", "+answer", domain, rtype], timeout=15)
            if r.stdout.strip():
                all_output.append(f"## {rtype}\n{r.stdout.strip()}")
        combined = "\n\n".join(all_output)
        (out_dir / "dns_records.txt").write_text(combined)
        return RunResult(combined, "", 0, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        rows, current = [], "OTHER"
        for line in result.lines:
            if line.startswith("## "):
                current = line[3:]
            elif line:
                rows.append({"type": current, "record": line, "domain": domain})
        return rows
