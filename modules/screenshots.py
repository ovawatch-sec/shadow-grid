"""
modules/screenshots.py
Visual screenshots of alive HTTP services via gowitness.
"""
from pathlib import Path

from core.utils import run_command
from core.colors import RED, GREEN, RESET


def run_gowitness(alive_urls_file, output_dir) -> None:
    """
    Take screenshots of all alive URLs using gowitness.

    FIX from v1 — two bugs:
    1. http_proto parameter was referenced in recon.py as args.http_proto but
       that argparse argument was never defined → AttributeError at runtime.
       Parameter removed entirely; gowitness handles http/https from the URL itself.

    2. Missing comma in the command list between '--no-http' and '-s':
           "--timeout", "300",'--no-http'
           "-s", str(screenshots_dir)
       Python implicit string concatenation made this '--no-http-s' — a garbage
       flag that silently broke screenshot output paths.
       Also removed --no-http: we WANT both http and https screenshots.
    """
    output_dir = Path(output_dir)
    screenshots_dir = output_dir / 'screenshots'
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    alive_urls_file = Path(alive_urls_file)
    if not alive_urls_file.exists() or alive_urls_file.stat().st_size == 0:
        print(f"{RED}[-] gowitness: no alive URLs to screenshot{RESET}")
        return

    cmd = [
        'gowitness', 'scan', 'file',
        '-f', str(alive_urls_file),
        '--timeout', '30',
        '--screenshot-path', str(screenshots_dir),
    ]

    proc = run_command(cmd, timeout=900)
    if proc.returncode != 0:
        print(f"{RED}[-] gowitness failed: {proc.stderr.strip()}{RESET}")
