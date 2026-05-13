"""Advanced Google dork generation.

This intentionally generates dork URLs only. It does not scrape Google.
"""
from __future__ import annotations
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from models import ToolCategory
from tools.base import BaseTool, RunResult


class GoogleDorksTool(BaseTool):
    name = "google_dorks"
    binary_name = None
    category = ToolCategory.DORK
    description = "Generate advanced Google dorks for manual attack-surface discovery"
    parallel_group = "analysis"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        hosts = self._read_lines(out_dir / "subdomains_merged.txt") or [domain]
        hosts = sorted({self._extract_host(h) for h in hosts if self._extract_host(h)})[:50]

        rows = self._build_dorks(domain, hosts)
        md = [f"# Google Dorks — {domain}", "", "> Use manually. Do not automate Google scraping.", ""]
        for row in rows:
            md.append(f"## {row['priority']} — {row['purpose']}")
            md.append(f"`{row['dork']}`")
            md.append(f"[Open search]({row['google_url']})")
            md.append("")
        (out_dir / "google_dorks.md").write_text("\n".join(md), encoding="utf-8")
        return RunResult("\n".join(row["dork"] for row in rows), "", 0, 0.0)

    def _row(self, priority: str, purpose: str, dork: str) -> dict[str, str]:
        return {
            "priority": priority,
            "purpose": purpose,
            "dork": dork,
            "google_url": f"https://www.google.com/search?q={quote_plus(dork)}",
            "source": "google_dorks",
        }

    def _build_dorks(self, domain: str, hosts: list[str]) -> list[dict[str, str]]:
        root = domain.strip().lower()
        dorks: list[dict[str, str]] = [
            self._row("P1", "Potential login/admin panels", f"site:{root} (inurl:admin OR inurl:login OR inurl:signin OR intitle:admin)"),
            self._row("P1", "Public config/secrets exposure", f"site:{root} (ext:env OR ext:ini OR ext:conf OR ext:config OR ext:yml OR ext:yaml)"),
            self._row("P1", "Database/backup leakage", f"site:{root} (ext:sql OR ext:db OR ext:bak OR ext:backup OR ext:old OR ext:zip OR ext:tar OR ext:gz)"),
            self._row("P1", "Stack traces and verbose errors", f"site:{root} (\"stack trace\" OR \"Traceback\" OR \"Unhandled exception\" OR \"System.NullReferenceException\")"),
            self._row("P1", "Cloud keys/tokens accidentally indexed", f"site:{root} (\"AKIA\" OR \"secret_key\" OR \"client_secret\" OR \"api_key\" OR \"access_token\")"),
            self._row("P2", "API docs and Swagger/OpenAPI", f"site:{root} (inurl:swagger OR inurl:openapi OR inurl:api-docs OR intitle:Swagger)"),
            self._row("P2", "Interesting files", f"site:{root} (filetype:pdf OR filetype:xls OR filetype:xlsx OR filetype:doc OR filetype:docx)"),
            self._row("P2", "Directory listings", f"site:{root} intitle:\"index of\""),
            self._row("P2", "Dev/staging/test surface", f"site:{root} (dev OR staging OR test OR qa OR sandbox OR preprod)"),
            self._row("P2", "Parameter-heavy endpoints", f"site:{root} inurl:?"),
            self._row("P2", "Upload/import/export functionality", f"site:{root} (inurl:upload OR inurl:import OR inurl:export OR inurl:file)"),
            self._row("P3", "Robots/sitemap/indexing clues", f"site:{root} (inurl:robots.txt OR inurl:sitemap.xml)"),
            self._row("P3", "Cached third-party mentions", f"\"{root}\" (password OR token OR secret OR leaked OR breached)"),
        ]

        for host in hosts[:15]:
            dorks.extend([
                self._row("P2", f"Host-specific admin/login: {host}", f"site:{host} (inurl:admin OR inurl:login OR inurl:signin)"),
                self._row("P2", f"Host-specific sensitive files: {host}", f"site:{host} (ext:env OR ext:sql OR ext:bak OR intitle:\"index of\")"),
            ])
        return dorks

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        return self._build_dorks(domain, self._read_lines(self.output_dir / domain / "subdomains_merged.txt") or [domain])
