"""
scan_engine.py — Orchestrates tool execution for a scan.

Parallel execution strategy:
  Phase 1 (ASSET):      whois, asnmap                   → parallel
  Phase 2 (SUBDOMAIN):  crtsh, assetfinder, subfinder, amass, shuffledns → parallel
  Phase 3 (DNS):        merge subdomains → dnsx, dns_records, zone_transfer → parallel
  Phase 4 (HTTP):       produce alive files → httpx, naabu → parallel
  Phase 5 (URLS):       produce alive_urls → waybackurls, gau, katana, urlfinder → parallel
  Phase 6 (VULN+SS):    nuclei, gowitness, whatweb → parallel

SSE events are broadcast via an asyncio.Queue per scan_id.
"""
from __future__ import annotations
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from models import Scan, ScanStatus, ToolResult, ScanProgress
from tools.registry import REGISTRY, get_tool
from storage import DualStorage

logger = logging.getLogger(__name__)

# scan_id → asyncio.Queue of SSE event dicts
_progress_queues: dict[str, asyncio.Queue] = {}


def get_progress_queue(scan_id: str) -> asyncio.Queue:
    if scan_id not in _progress_queues:
        _progress_queues[scan_id] = asyncio.Queue(maxsize=500)
    return _progress_queues[scan_id]


def drop_progress_queue(scan_id: str) -> None:
    _progress_queues.pop(scan_id, None)


async def _emit(scan_id: str, tool: str, status: str, message: str = "", count: int = 0) -> None:
    q = get_progress_queue(scan_id)
    event = {"tool": tool, "status": status, "message": message, "count": count,
             "ts": datetime.now(timezone.utc).isoformat()}
    try:
        q.put_nowait(event)
    except asyncio.QueueFull:
        pass
    logger.info(f"[{scan_id}] {tool}: {status} — {message}")


async def _run_tool(
    tool_name: str,
    domain: str,
    scan: Scan,
    oos: list[str],
    output_dir: Path,
    data_dir: Path,
    storage: DualStorage,
    wordlist: str | None,
) -> ToolResult | None:
    if tool_name not in scan.tools:
        return None

    tool = get_tool(tool_name, output_dir, data_dir)
    if tool is None:
        await _emit(scan.id, tool_name, "skipped", "Not in registry")
        return None
    if not tool.is_available():
        await _emit(scan.id, tool_name, "skipped", f"{tool_name} not installed")
        return None

    await _emit(scan.id, tool_name, "running")
    try:
        result = await tool.execute(domain, scan.id, scan.project_id, oos, wordlist)
        await storage.save_result(result)
        await _emit(scan.id, tool_name, "done",
                    result.error or f"{result.count} results", result.count)
        return result
    except Exception as exc:
        logger.exception(f"{tool_name} raised exception")
        await _emit(scan.id, tool_name, "error", str(exc))
        return None


def _write_merged_subdomains(domain: str, results: list[ToolResult | None], output_dir: Path) -> Path:
    """Merge all subdomain results into a single file for downstream tools."""
    merged = set()
    for r in results:
        if r and r.data:
            for row in r.data:
                h = row.get("host", "")
                if h:
                    merged.add(h)

    out = output_dir / domain / "subdomains_merged.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(sorted(merged)))
    return out


def _write_alive_files(domain: str, dns_results: list[ToolResult | None],
                       http_results: list[ToolResult | None], output_dir: Path) -> None:
    """Write alive_subdomains.txt and alive_urls.txt for downstream tools."""
    alive_hosts = set()
    for r in dns_results:
        if r and r.data:
            for row in r.data:
                h = row.get("host", "")
                if h:
                    alive_hosts.add(h.split()[0])  # strip record data

    out_subs = output_dir / domain / "alive_subdomains.txt"
    out_subs.write_text("\n".join(sorted(alive_hosts)))

    # Build alive_urls from httpx results
    alive_urls = set()
    for r in http_results:
        if r and r.data:
            for row in r.data:
                u = row.get("url", "")
                if u:
                    alive_urls.add(u)

    out_urls = output_dir / domain / "alive_urls.txt"
    out_urls.write_text("\n".join(sorted(alive_urls)))


async def run_scan(
    scan: Scan,
    domains: list[str],
    oos: list[str],
    output_dir: Path,
    data_dir: Path,
    storage: DualStorage,
) -> None:
    """Main scan coroutine — called as a background task."""
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    await storage.save_scan(scan)

    try:
        for domain in domains:
            await _emit(scan.id, "__domain__", "start", domain)

            wl = scan.wordlist

            # ── Phase 1: Asset ──────────────────────────────────────
            await _emit(scan.id, "__phase__", "running", "Phase 1: Asset Discovery")
            phase1 = await asyncio.gather(
                _run_tool("whois",  domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("asnmap", domain, scan, oos, output_dir, data_dir, storage, wl),
            )

            # ── Phase 2: Subdomain Enum (all parallel) ─────────────
            await _emit(scan.id, "__phase__", "running", "Phase 2: Subdomain Enumeration")
            phase2 = await asyncio.gather(
                _run_tool("crtsh",       domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("assetfinder", domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("subfinder",   domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("amass",       domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("shuffledns",  domain, scan, oos, output_dir, data_dir, storage, wl),
            )
            _write_merged_subdomains(domain, list(phase2), output_dir)

            # ── Phase 3: DNS Resolution ─────────────────────────────
            await _emit(scan.id, "__phase__", "running", "Phase 3: DNS Resolution")
            phase3 = await asyncio.gather(
                _run_tool("dnsx",         domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("dns_records",  domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("zone_transfer",domain, scan, oos, output_dir, data_dir, storage, wl),
            )

            # ── Phase 4: HTTP Probing ───────────────────────────────
            # First write alive_subdomains.txt (needed by httpx/naabu)
            _write_alive_files(domain, list(phase3), [], output_dir)
            await _emit(scan.id, "__phase__", "running", "Phase 4: HTTP Probing & Port Scanning")
            phase4 = await asyncio.gather(
                _run_tool("httpx", domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("naabu", domain, scan, oos, output_dir, data_dir, storage, wl),
            )

            # Update alive_urls.txt from httpx results
            _write_alive_files(domain, list(phase3), list(phase4), output_dir)

            # ── Phase 5: URL Discovery (all parallel) ───────────────
            await _emit(scan.id, "__phase__", "running", "Phase 5: URL Discovery")
            phase5 = await asyncio.gather(
                _run_tool("waybackurls", domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("gau",         domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("katana",      domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("urlfinder",   domain, scan, oos, output_dir, data_dir, storage, wl),
            )

            # ── Phase 6: Vuln + Screenshots (all parallel) ──────────
            await _emit(scan.id, "__phase__", "running", "Phase 6: Vuln Scan & Screenshots")
            await asyncio.gather(
                _run_tool("nuclei",    domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("gowitness", domain, scan, oos, output_dir, data_dir, storage, wl),
                _run_tool("whatweb",   domain, scan, oos, output_dir, data_dir, storage, wl),
            )

            await _emit(scan.id, "__domain__", "done", domain)

        scan.status = ScanStatus.COMPLETED
    except Exception as exc:
        logger.exception("Scan failed")
        scan.status = ScanStatus.FAILED
        scan.error = str(exc)

    scan.completed_at = datetime.now(timezone.utc)
    await storage.save_scan(scan)
    await _emit(scan.id, "__scan__", "done", scan.status.value)

    # Leave queue open for 60s so the frontend drains it, then clean up
    await asyncio.sleep(60)
    drop_progress_queue(scan.id)
