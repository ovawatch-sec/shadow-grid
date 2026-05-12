"""CRT.SH — certificate transparency, no binary required."""
from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any
import aiohttp
from models import ToolCategory
from tools.base import BaseTool, RunResult

DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b', re.I)

class CrtShTool(BaseTool):
    name = "crtsh"
    binary_name = None
    category = ToolCategory.SUBDOMAIN
    description = "Certificate Transparency via crt.sh (no binary required)"
    parallel_group = "subdomain"

    def is_available(self) -> bool:
        return True  # HTTP only

    async def run(self, domain, out_dir, data_dir, wordlist, extra) -> RunResult:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
                async with s.get(f"https://crt.sh/?q=%.{domain}&output=json",
                                 headers={"User-Agent": "ShadowGrid/3"}) as r:
                    text = await r.text()
            return RunResult(text, "", 0, 0)
        except Exception as e:
            return RunResult("", str(e), 1, 0)

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        if not result.stdout:
            return []
        seen = set()
        rows = []
        try:
            for entry in json.loads(result.stdout):
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name and (name == domain or name.endswith("." + domain)) and name not in seen:
                        seen.add(name)
                        rows.append({"host": name, "source": "crtsh"})
        except Exception:
            pass
        return rows
