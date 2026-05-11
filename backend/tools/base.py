"""
tools/base.py — BaseTool contract.

To add a new tool:
1. Create a file in the appropriate category folder.
2. Subclass BaseTool.
3. Set name, category, description, requires_root.
4. Implement run() — call self._exec() or self._exec_stdin().
5. Implement parse() — convert raw stdout/file lines → list[dict].
6. Register in tools/registry.py.

That's it. No other files need to change.
"""
from __future__ import annotations
import asyncio
import logging
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from models import ToolCategory, ToolResult

logger = logging.getLogger(__name__)


class RunResult:
    """Thin wrapper around subprocess output."""
    def __init__(self, stdout: str, stderr: str, returncode: int, elapsed: float):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.elapsed = elapsed
        self.lines = [l.strip() for l in stdout.splitlines() if l.strip()]


class BaseTool(ABC):
    name: str = ""
    category: ToolCategory = ToolCategory.SUBDOMAIN
    description: str = ""
    requires_root: bool = False
    parallel_group: str = ""   # tools with the same group run in parallel

    def __init__(self, output_dir: Path, data_dir: Path):
        self.output_dir = output_dir
        self.data_dir = data_dir

    # ── Public API ────────────────────────────────────────────────
    def is_available(self) -> bool:
        """Return True if the underlying binary exists in PATH."""
        return shutil.which(self.name) is not None

    async def execute(
        self,
        domain: str,
        scan_id: str,
        project_id: str,
        oos: list[str] | None = None,
        wordlist: str | None = None,
        extra: dict | None = None,
    ) -> ToolResult:
        """
        Top-level execute: calls run(), then parse(), then wraps in ToolResult.
        Handles timing, error capture, and OOS filtering automatically.
        """
        if not self.is_available():
            return ToolResult(
                scan_id=scan_id, project_id=project_id,
                tool=self.name, category=self.category, domain=domain,
                error=f"Tool not found in PATH: {self.name}",
            )

        domain_out = self.output_dir / domain
        domain_out.mkdir(parents=True, exist_ok=True)

        t0 = time.monotonic()
        try:
            run = await self.run(domain, domain_out, data_dir=self.data_dir,
                                 wordlist=wordlist, extra=extra or {})
            data = self.parse(run, domain)
            if oos:
                data = self._filter_oos(data, oos)
        except Exception as exc:
            logger.exception(f"{self.name} failed on {domain}")
            data, run = [], RunResult("", str(exc), 1, 0.0)

        elapsed = time.monotonic() - t0
        return ToolResult(
            scan_id=scan_id, project_id=project_id,
            tool=self.name, category=self.category, domain=domain,
            data=data, count=len(data), elapsed_s=round(elapsed, 2),
        )

    # ── Must implement ────────────────────────────────────────────
    @abstractmethod
    async def run(self, domain: str, out_dir: Path,
                  data_dir: Path, wordlist: str | None, extra: dict) -> RunResult:
        """Run the underlying tool and return raw output."""

    @abstractmethod
    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        """
        Convert raw tool output → list of dicts.
        Each dict must have at least one identifying key.
        Add as many fields as the tool provides — they are all stored.
        """

    # ── Helpers available to all tools ───────────────────────────
    async def _exec(self, cmd: list[str], timeout: int = 600) -> RunResult:
        logger.info(f"[{self.name}] {' '.join(str(c) for c in cmd)}")
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *[str(c) for c in cmd],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return RunResult(stdout.decode(errors="replace"),
                             stderr.decode(errors="replace"),
                             proc.returncode or 0,
                             time.monotonic() - t0)
        except asyncio.TimeoutError:
            logger.warning(f"{self.name} timed out after {timeout}s")
            return RunResult("", f"Timeout after {timeout}s", 1, timeout)
        except FileNotFoundError:
            return RunResult("", f"Binary not found: {cmd[0]}", 127, 0)

    async def _exec_stdin(self, cmd: list[str], stdin_text: str, timeout: int = 600) -> RunResult:
        logger.info(f"[{self.name}] (stdin) {' '.join(str(c) for c in cmd)}")
        t0 = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *[str(c) for c in cmd],
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_text.encode()), timeout=timeout
            )
            return RunResult(stdout.decode(errors="replace"),
                             stderr.decode(errors="replace"),
                             proc.returncode or 0,
                             time.monotonic() - t0)
        except asyncio.TimeoutError:
            return RunResult("", f"Timeout after {timeout}s", 1, timeout)
        except FileNotFoundError:
            return RunResult("", f"Binary not found: {cmd[0]}", 127, 0)

    def _write(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def _read_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return [l.strip() for l in path.read_text(errors="replace").splitlines() if l.strip()]

    @staticmethod
    def _filter_oos(data: list[dict], oos: list[str]) -> list[dict]:
        import fnmatch
        filtered = []
        for row in data:
            host = row.get("host") or row.get("domain") or row.get("url", "")
            if not any(fnmatch.fnmatch(host, pat) for pat in oos):
                filtered.append(row)
        return filtered
