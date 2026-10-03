"""Active parameter fuzzing with nuclei's DAST engine.

Template matching asks "does this host look vulnerable?". DAST asks "does this
parameter mishandle this payload?" — the question that turns a URL list into
AppSec findings. It only works once ``param_miner`` has produced a
deduplicated parameter surface, because fuzzing a raw wayback dump means
thousands of requests against the same endpoint.

This tool sends attack payloads to the target. It is opt-in: it never runs
from a default tool selection and must be named explicitly for an assessment
the operator is authorised to test actively.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from models import ToolCategory
from tools.base import BaseTool, RunResult
from tools.vuln.nuclei import parse_nuclei_jsonl

#: Conservative defaults — DAST multiplies requests by template count.
REQUESTS_PER_SECOND = "20"
CONCURRENCY = "10"


class NucleiDastTool(BaseTool):
    """Fuzz discovered parameters with nuclei's DAST templates."""

    name = "nuclei_dast"
    binary_name = "nuclei"
    category = ToolCategory.VULN
    description = "Active DAST fuzzing of discovered parameters (opt-in, sends payloads)"
    parallel_group = "dast"
    #: Excluded from "all tools" selections — active testing is never implicit.
    opt_in = True

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        params_file = out_dir / "params.txt"
        targets = self._read_lines(params_file)
        if not targets:
            return RunResult(
                "", "No parameterised URLs — run param_miner first (nothing to fuzz)", 0, 0,
            )

        outfile = out_dir / "nuclei_dast.jsonl"
        command = [
            "nuclei", "-list", str(params_file), "-dast",
            "-severity", "low,medium,high,critical",
            "-rate-limit", REQUESTS_PER_SECOND, "-c", CONCURRENCY,
            "-timeout", "10", "-jsonl", "-o", str(outfile), "-silent",
        ] + self._header_args(hosts=self._hosts_in(targets))
        result = await self._exec(command, timeout=3600)

        stderr = (result.stderr or "").lower()
        unsupported = "flag provided but not defined" in stderr or "unknown flag" in stderr
        if result.returncode != 0 and unsupported:
            return RunResult(
                "", "Installed nuclei does not support -dast — upgrade to v3.2 or newer", 1, 0,
            )
        return result

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        lines = result.lines or self._read_lines(self.output_dir / domain / "nuclei_dast.jsonl")
        return parse_nuclei_jsonl(lines, source="nuclei_dast")
