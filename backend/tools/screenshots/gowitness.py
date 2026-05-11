"""gowitness — web screenshots (v2/v3 compatible)."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from models import ToolCategory
from tools.base import BaseTool, RunResult


class GowitnessTool(BaseTool):
    name = "gowitness"
    category = ToolCategory.SCREENSHOT
    description = "Web screenshots of alive HTTP services via gowitness"
    parallel_group = "screenshots"

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        urls_file = out_dir / "alive_urls.txt"
        if not urls_file.exists():
            return RunResult("", "No alive_urls.txt — skipping screenshots", 0, 0.0)

        ss_dir = out_dir / "screenshots"
        ss_dir.mkdir(parents=True, exist_ok=True)

        # gowitness v3+ uses:  gowitness scan file --file <path> --screenshot-path <dir>
        # gowitness v2  uses:  gowitness file -f <path> --screenshot-path <dir>
        # Try v3 syntax first; fall back to v2 on error.
        result = await self._exec([
            "gowitness", "scan", "file",
            "--file", str(urls_file),
            "--screenshot-path", str(ss_dir),
            "--timeout", "30",
        ], timeout=900)

        if result.returncode != 0 and "unknown command" in result.stderr.lower():
            # Fall back to v2 syntax
            result = await self._exec([
                "gowitness", "file",
                "-f", str(urls_file),
                "--screenshot-path", str(ss_dir),
                "--timeout", "30",
            ], timeout=900)

        return result

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        ss_dir = self.output_dir / domain / "screenshots"
        if not ss_dir.exists():
            return []
        files = list(ss_dir.glob("*.png")) + list(ss_dir.glob("*.jpg")) + list(ss_dir.glob("*.jpeg"))
        return [{"filename": f.name, "path": str(f.relative_to(self.output_dir)), "source": "gowitness"}
                for f in sorted(files)]
