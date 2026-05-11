"""asnmap — ASN and IP range enumeration."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult

class AsnmapTool(BaseTool):
    name = "asnmap"
    category = ToolCategory.ASSET
    description = "ASN and IP range discovery via asnmap"
    parallel_group = "asset"

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        outfile = out_dir / "asn_ranges.txt"
        r = await self._exec(["asnmap", "-d", domain, "-silent"], timeout=60)
        (out_dir / "asn_ranges.txt").write_text(r.stdout)
        return r

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"cidr": l, "source": "asnmap"} for l in result.lines if l.strip()]
