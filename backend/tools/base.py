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
import re
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from models import ToolCategory, ToolResult

logger = logging.getLogger(__name__)

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def clean_tool_output(value: str) -> str:
    """Normalize CLI stderr/stdout snippets before showing them in the UI."""
    return ANSI_RE.sub("", value or "").strip()


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
    # Override when the registry name is not the executable name, e.g. dns_records -> dig.
    # Set to None only for tools that do not require a local binary.
    binary_name: str | None = ""
    category: ToolCategory = ToolCategory.SUBDOMAIN
    description: str = ""
    requires_root: bool = False
    parallel_group: str = ""   # tools with the same group run in parallel

    def __init__(self, output_dir: Path, data_dir: Path):
        self.output_dir = output_dir
        self.data_dir = data_dir

    # ── Public API ────────────────────────────────────────────────
    def availability_error(self) -> str | None:
        """Return None when runnable, otherwise a human-readable skip reason."""
        binary = self.binary_name if self.binary_name != "" else self.name
        if binary is None:
            return None
        if shutil.which(binary) is None:
            return f"Required binary not found: {binary}"
        return None

    def is_available(self) -> bool:
        """Return True if the tool and its required local dependencies exist."""
        return self.availability_error() is None

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
        error = ""
        if run.returncode != 0:
            error = clean_tool_output(run.stderr or f"{self.name} exited with code {run.returncode}")[:2000]

        return ToolResult(
            scan_id=scan_id, project_id=project_id,
            tool=self.name, category=self.category, domain=domain,
            data=data, count=len(data), elapsed_s=round(elapsed, 2),
            error=error,
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
    def _extract_host(value: str) -> str:
        value = (value or "").strip().lower().lstrip("*.")
        if not value:
            return ""
        if "://" in value:
            return (urlparse(value).hostname or "").strip(".")
        value = value.split("/", 1)[0].split("?", 1)[0]
        if value.count(":") == 1:
            value = value.rsplit(":", 1)[0]
        return value.strip(".")

    @classmethod
    def _is_oos(cls, value: str, oos: list[str]) -> bool:
        import fnmatch
        host = cls._extract_host(value)
        if not host:
            return False
        for raw in oos:
            pattern = (raw or "").strip().lower()
            clean = cls._extract_host(pattern)
            if not clean:
                continue
            if fnmatch.fnmatch(host, pattern):
                return True
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
            if host == clean or host.endswith(f".{clean}"):
                return True
        return False

    @classmethod
    def _filter_oos(cls, data: list[dict], oos: list[str]) -> list[dict]:
        filtered = []
        for row in data:
            host = str(row.get("host") or row.get("domain") or row.get("url", ""))
            if not cls._is_oos(host, oos):
                filtered.append(row)
        return filtered
