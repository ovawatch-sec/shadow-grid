#!/usr/bin/env python3
"""
recon.py — ShadowGrid v3 CLI
Terminal alternative to the web interface.
Uses the same tool classes and storage layer as the backend.

API keys live in a local .env file (copy .env.example) because the CLI has no
Settings UI. Search order: --env-file, $SHADOWGRID_ENV_FILE, ./.env, the
repository root, then ~/.config/shadowgrid/.env. Variables already exported in
the shell always win.

Usage:
  python3 recon.py -d example.com
  python3 recon.py -d example.com --tools crtsh,subfinder,httpx,nuclei
  python3 recon.py -d example.com --passive-only
  python3 recon.py -d example.com --oos "*.internal.example.com"
  python3 recon.py -d example.com --env-file ~/.shadowgrid.env
  python3 recon.py --show-config
"""
from __future__ import annotations
import argparse
import asyncio
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

# Make sure backend/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))

from env_file import ENV_FILE_VAR, candidate_paths, load_env_file
from models import Scan, ScanStatus, new_id
from storage import SqlStorage
from scan_engine import run_scan
from tool_secrets import KEY_ENV_MAP, MASK
from tools.registry import REGISTRY, get_tool

PASSIVE_TOOLS = [
    "crtsh","assetfinder","subfinder","amass",
    "dnsx","dns_records","zone_transfer",
    "waybackurls","gau","whois","asnmap",
]

BANNER = r"""
  ____              ___                _       _       _
 |  _ \            / _ \              | |     | |     | |
 | |_) |_   _  __ | | | |_   ______ _| |_ ___| |__   | |
 |  _ <| | | |/ _` | | \ \ / / _` | __/ __| '_ \    | |
 | |_) | |_| | (_| | |_| \ V / (_| | || (__| | | |   |_|
 |____/ \__,_|\__, |\___/ \_/ \__,_|\__\___|_| |_|   (_)
               __/ |
              |___/  v3.0  — Recon Framework
"""

GREEN, YELLOW, RED, DIM, RESET = "\033[92m", "\033[93m", "\033[91m", "\033[90m", "\033[0m"


def print_banner():
    print(GREEN + BANNER + RESET)


def load_credentials(args) -> None:
    """Apply the local credential file and report what it supplied."""
    if args.no_env_file:
        print(f"{DIM}[i]{RESET} Credential file disabled (--no-env-file)")
        return
    try:
        result = load_env_file(args.env_file)
    except (FileNotFoundError, OSError) as exc:
        print(f"{RED}[!]{RESET} {exc}")
        sys.exit(2)

    if not result.loaded:
        searched = ", ".join(str(path) for path in candidate_paths())
        print(f"{YELLOW}[!]{RESET} No credential file found — tools needing an API key will be skipped")
        print(f"{DIM}    Searched: {searched}")
        print(f"    Create one with: cp .env.example .env{RESET}")
        return

    print(f"{GREEN}[+]{RESET} Credentials: {result.path}")
    if result.applied:
        print(f"{DIM}    Loaded:   {', '.join(sorted(result.applied))}{RESET}")
    if result.overridden:
        print(f"{DIM}    Shell env already set (file ignored): {', '.join(sorted(result.overridden))}{RESET}")
    if not result.applied and not result.overridden:
        print(f"{YELLOW}    File contains no values — fill in the placeholders{RESET}")


def print_config() -> None:
    """Show which credentials the current environment exposes, masked."""
    print(f"\n{'Variable':<24} {'Status':<12} Setting field")
    print("-" * 64)
    for field, env_name in KEY_ENV_MAP.items():
        value = os.environ.get(env_name, "").strip()
        status = f"{GREEN}{MASK}{RESET}" if value else f"{DIM}not set{RESET}"
        padding = " " * max(0, 12 - (len(MASK) if value else len("not set")))
        print(f"  {env_name:<22} {status}{padding} {field}")
    configured = sum(1 for name in KEY_ENV_MAP.values() if os.environ.get(name, "").strip())
    print(f"\n{GREEN}[+]{RESET} {configured}/{len(KEY_ENV_MAP)} credential(s) configured")
    print(f"{DIM}    Values are never printed. Set them in .env (see .env.example) or ${ENV_FILE_VAR}.{RESET}\n")


def print_tool_table(output_dir: Path, data_dir: Path) -> None:
    """List every registered tool with its real availability reason."""
    print(f"\n{'Tool':<20} {'Category':<14} {'Available':<10} Description")
    print("-" * 80)
    for name in REGISTRY:
        tool = get_tool(name, output_dir, data_dir)
        reason = tool.availability_error() if tool else "Tool is not registered"
        mark = f"{GREEN}✓{RESET}" if reason is None else f"{RED}✗{RESET}"
        description = tool.description if tool else ""
        print(f"  {name:<18} {tool.category.value:<14} {mark:<19} {description}")
        if reason:
            print(f"{DIM}{'':<22}{reason}{RESET}")


def warn_unavailable(tools: list[str], output_dir: Path, data_dir: Path) -> None:
    """Flag selected tools that will be skipped, before the scan starts."""
    skipped: list[tuple[str, str]] = []
    for name in tools:
        tool = get_tool(name, output_dir, data_dir)
        reason = tool.availability_error() if tool else "Unknown tool — not in the registry"
        if reason:
            skipped.append((name, reason))
    if not skipped:
        return
    print(f"\n{YELLOW}[!]{RESET} {len(skipped)} selected tool(s) will be skipped:")
    for name, reason in skipped:
        print(f"{DIM}      {name:<18} {reason}{RESET}")


async def main():
    print_banner()

    parser = argparse.ArgumentParser(description="ShadowGrid recon framework CLI")
    parser.add_argument("-d", "--domain", nargs="+", help="Target domain(s)")
    parser.add_argument("--oos", nargs="*", default=[], help="Out-of-scope patterns")
    parser.add_argument("--tools", help="Comma-separated tool list (default: all)")
    parser.add_argument("--passive-only", action="store_true", help="Only run passive tools")
    parser.add_argument("--wordlist", help="Custom DNS wordlist path")
    parser.add_argument("--output-dir", default="./output", help="Output directory")
    parser.add_argument("--data-dir", default="./data", help="Data directory")
    parser.add_argument("--list-tools", action="store_true", help="List available tools and exit")
    parser.add_argument(
        "--env-file",
        help=f"Credential file to load (default: ${ENV_FILE_VAR}, ./.env, repo root, ~/.config/shadowgrid/.env)",
    )
    parser.add_argument(
        "--no-env-file", action="store_true",
        help="Ignore credential files and use only the current environment",
    )
    parser.add_argument(
        "--show-config", action="store_true",
        help="Show which API credentials are configured (masked) and exit",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    data_dir   = Path(args.data_dir)

    # Credentials must be in place before any availability check: several tools
    # report themselves unavailable purely because their API key is missing.
    load_credentials(args)

    if args.show_config:
        print_config()
        return

    if args.list_tools:
        print_tool_table(output_dir, data_dir)
        return

    if not args.domain:
        parser.error("-d/--domain is required (omit it only with --list-tools or --show-config)")

    # ── Resolve tool list ────────────────────────────────────────
    if args.tools:
        tools = [t.strip() for t in args.tools.split(",")]
    elif args.passive_only:
        tools = PASSIVE_TOOLS
    else:
        tools = list(REGISTRY.keys())

    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    warn_unavailable(tools, output_dir, data_dir)

    # ── Storage ──────────────────────────────────────────────────
    storage = SqlStorage(str(output_dir))

    # ── Create project + scan ────────────────────────────────────
    from models import Project, Target
    project = Project(name=f"CLI-{args.domain[0]}", description="CLI scan")
    await storage.save_project(project)
    for dom in args.domain:
        await storage.save_target(Target(project_id=project.id, domain=dom))
    for o in args.oos:
        await storage.save_target(Target(project_id=project.id, domain=o, is_oos=True))

    scan = Scan(project_id=project.id, tools=tools, wordlist=args.wordlist)
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    await storage.save_scan(scan)

    print(f"\n\033[92m[+]\033[0m Scan ID:  {scan.id}")
    print(f"\033[92m[+]\033[0m Targets:  {', '.join(args.domain)}")
    print(f"\033[92m[+]\033[0m OOS:      {', '.join(args.oos) or '(none)'}")
    print(f"\033[92m[+]\033[0m Tools:    {len(tools)} selected")
    print(f"\033[92m[+]\033[0m Output:   {output_dir}\n")

    # ── Progress display ─────────────────────────────────────────
    import threading

    from scan_engine import get_progress_queue
    queue = get_progress_queue(scan.id)

    async def show_progress():
        while True:
            try:
                ev = await asyncio.wait_for(queue.get(), timeout=5)
                tool, status, msg, count = ev["tool"], ev["status"], ev.get("message",""), ev.get("count",0)
                if tool.startswith("__"):
                    if tool == "__phase__":
                        print(f"\n\033[96m[Phase]\033[0m {msg}")
                    elif tool == "__scan__":
                        break
                    continue
                color = {"running":"\033[93m","done":"\033[92m","error":"\033[91m","skipped":"\033[90m"}.get(status,"\033[0m")
                icon  = {"running":"⟳","done":"✓","error":"✗","skipped":"—"}.get(status,"?")
                suffix = f" ({count} results)" if count else ""
                print(f"  {color}{icon}\033[0m  \033[1m{tool:<18}\033[0m {status:<8} {msg}{suffix}")
            except asyncio.TimeoutError:
                pass

    progress_task = asyncio.create_task(show_progress())

    await run_scan(
        scan=scan,
        domains=args.domain,
        oos=args.oos,
        output_dir=output_dir,
        data_dir=data_dir,
        storage=storage,
    )

    await progress_task

    print(f"\n\033[92m[+]\033[0m Scan {scan.status.value.upper()} — results in {output_dir}")
    print(f"\033[92m[+]\033[0m Open the web UI or check {output_dir} for output files\n")


if __name__ == "__main__":
    asyncio.run(main())
