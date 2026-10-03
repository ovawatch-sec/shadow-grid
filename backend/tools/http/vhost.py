"""Virtual host discovery against already-resolved service IPs.

Path fuzzing finds ``/admin`` on a host you already know. Host-header fuzzing
finds the staging application that shares the same IP and is never named in
DNS. Nothing else in the pipeline sees those.

Only IPs that a previous phase already resolved and verified are probed, so
this never widens the scan beyond the confirmed attack surface. It is opt-in:
every candidate name costs a request.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from models import ToolCategory
from tools.base import BaseTool, RunResult

MAX_IPS = 10
MAX_WORDS = 5_000


class VhostTool(BaseTool):
    """Fuzz the Host header against verified service IPs."""

    name = "vhost"
    binary_name = "ffuf"
    category = ToolCategory.HTTP
    description = "Virtual host discovery via Host-header fuzzing (opt-in)"
    parallel_group = "vhost"
    opt_in = True

    async def run(self, domain: str, out_dir: Path, data_dir: Path,
                  wordlist: str | None, extra: dict) -> RunResult:
        targets = self._service_targets(out_dir)
        if not targets:
            return RunResult("", "No resolved service IPs from the HTTP phase", 0, 0)

        words = Path(wordlist) if wordlist else data_dir / "wordlists" / "dns.txt"
        if not words.is_file():
            return RunResult("", f"Hostname wordlist is unavailable: {words}", 1, 0)
        words = self._bounded_wordlist(words, out_dir)

        combined: list[dict[str, Any]] = []
        errors: list[str] = []
        for index, (scheme, ip, port) in enumerate(targets[:MAX_IPS]):
            output = out_dir / f"vhost_{index}.json"
            netloc = f"{ip}:{port}" if port else ip
            command = [
                "ffuf", "-u", f"{scheme}://{netloc}/",
                "-H", f"Host: FUZZ.{domain}",
                "-w", str(words), "-of", "json", "-o", str(output),
                "-ac", "-mc", "all", "-fc", "400,404,421",
                "-rate", "25", "-t", "10", "-timeout", "8",
                "-maxtime", "180", "-noninteractive", "-s",
            ] + self._header_args(hosts=[ip])
            result = await self._exec(command, timeout=240)
            if output.is_file():
                try:
                    payload = json.loads(output.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    errors.append(f"Could not parse vhost output for {netloc}")
                    continue
                for entry in payload.get("results") or []:
                    candidate = str(entry.get("input", {}).get("FUZZ") or "").strip()
                    if not candidate:
                        continue
                    combined.append({
                        "host": f"{candidate}.{domain}",
                        "ip": ip,
                        "url": f"{scheme}://{netloc}/",
                        "status": entry.get("status"),
                        "length": entry.get("length"),
                        "words": entry.get("words"),
                        "source": "vhost",
                        "state": "vhost_discovered",
                    })
            elif result.returncode:
                errors.append(result.stderr[:300])

        serialized = json.dumps(combined)
        (out_dir / "vhost_results.json").write_text(serialized, encoding="utf-8")
        return RunResult(serialized, "; ".join(errors), 0 if combined or not errors else 1, 0)

    def _service_targets(self, out_dir: Path) -> list[tuple[str, str, str]]:
        """Return unique (scheme, ip, port) tuples from the HTTP inventory."""
        targets: dict[tuple[str, str, str], None] = {}
        for line in self._read_lines(out_dir / "httpx.jsonl"):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            ip = row.get("a") or row.get("ip") or ""
            ip = ip[0] if isinstance(ip, list) and ip else ip
            parsed = urlsplit(str(row.get("url") or ""))
            if not ip or parsed.scheme not in {"http", "https"}:
                continue
            port = str(parsed.port or "")
            targets.setdefault((parsed.scheme, str(ip), port), None)
        return list(targets)

    @staticmethod
    def _bounded_wordlist(source: Path, out_dir: Path) -> Path:
        """Cap the candidate list so one scan cannot issue unbounded requests."""
        lines = [line.strip() for line in source.read_text(errors="replace").splitlines() if line.strip()]
        if len(lines) <= MAX_WORDS:
            return source
        bounded = out_dir / "vhost_wordlist.txt"
        bounded.write_text("\n".join(lines[:MAX_WORDS]) + "\n", encoding="utf-8")
        return bounded

    def parse(self, result: RunResult, domain: str) -> list[dict[str, Any]]:
        try:
            rows = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return []
        return rows if isinstance(rows, list) else []
