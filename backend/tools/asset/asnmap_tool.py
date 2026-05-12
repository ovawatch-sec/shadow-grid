"""asnmap — ASN and IP range enumeration."""
from __future__ import annotations
import os
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult


class AsnmapTool(BaseTool):
    name = "asnmap"
    category = ToolCategory.ASSET
    description = "ASN and IP range discovery via ProjectDiscovery asnmap"
    parallel_group = "asset"

    def availability_error(self) -> str | None:
        binary_error = super().availability_error()
        if binary_error:
            return binary_error
        if not os.getenv("PDCP_API_KEY"):
            return "PDCP_API_KEY is not set; asnmap requires a ProjectDiscovery Cloud API key for non-interactive use"
        return None

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        outfile = out_dir / "asn_ranges.txt"
        r = await self._exec(["asnmap", "-domain", domain, "-silent", "-duc"], timeout=90)
        outfile.write_text(r.stdout)
        return r

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return [{"cidr": l, "source": "asnmap"} for l in result.lines if l.strip()]
