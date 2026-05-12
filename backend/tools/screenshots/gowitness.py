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

    def _chrome_path(self) -> str | None:
        for path in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"):
            if Path(path).exists():
                return path
        return None

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        urls_file = out_dir / "alive_urls.txt"
        if not urls_file.exists():
            return RunResult("", "No alive_urls.txt — skipping screenshots", 0, 0.0)
        if not urls_file.read_text(errors="replace").strip():
            return RunResult("", "alive_urls.txt is empty — no screenshots to take", 0, 0.0)

        ss_dir = out_dir / "screenshots"
        ss_dir.mkdir(parents=True, exist_ok=True)

        chrome = self._chrome_path()
        base_cmd = [
            "gowitness", "scan", "file",
            "--file", str(urls_file),
            "--screenshot-path", str(ss_dir),
            "--timeout", "30",
        ]
        if chrome:
            base_cmd.extend(["--chrome-path", chrome])

        result = await self._exec(base_cmd, timeout=1200)

        stderr = (result.stderr or "").lower()
        if result.returncode != 0 and ("unknown command" in stderr or "unknown flag" in stderr or "unknown shorthand" in stderr):
            # Fall back to older v2 syntax.
            legacy_cmd = [
                "gowitness", "file",
                "-f", str(urls_file),
                "--screenshot-path", str(ss_dir),
                "--timeout", "30",
            ]
            if chrome:
                legacy_cmd.extend(["--chrome-path", chrome])
            result = await self._exec(legacy_cmd, timeout=1200)

        return result

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        ss_dir = self.output_dir / domain / "screenshots"
        if not ss_dir.exists():
            return []
        files = []
        for pattern in ("*.png", "*.jpg", "*.jpeg", "*.webp"):
            files.extend(ss_dir.rglob(pattern))
        return [
            {"filename": f.name, "path": str(f.relative_to(self.output_dir)), "source": "gowitness"}
            for f in sorted(set(files))
        ]
