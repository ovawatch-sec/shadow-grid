"""zone_transfer — AXFR attempt on all nameservers."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class ZoneTransferTool(BaseTool):
    name = "zone_transfer"
    category = ToolCategory.DNS
    description = "AXFR zone transfer attempt against all nameservers"
    parallel_group = "dns"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        ns_r = await self._exec(["dig", "+short", domain, "NS"], timeout=10)
        nameservers = [ns.rstrip(".") for ns in ns_r.lines if ns.strip()]
        results = []
        for ns in nameservers:
            r = await self._exec(["dig", "axfr", domain, f"@{ns}"], timeout=15)
            if "XFR size" in r.stdout:
                results.append(f"=== SUCCESS via {ns} ===\n{r.stdout}")
            else:
                results.append(f"=== REFUSED by {ns} ===")
        combined = "\n".join(results) or "No nameservers found"
        (out_dir / "zone_transfer.txt").write_text(combined)
        return RunResult(combined, "", 0, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        vulnerable = "SUCCESS" in result.stdout
        return [{"domain": domain, "vulnerable": vulnerable, "detail": result.stdout[:4000]}]
