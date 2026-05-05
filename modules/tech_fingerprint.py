"""
modules/tech_fingerprint.py
Technology fingerprinting via whatweb.
All new in v2 — not present in v1.

Note: httpx already does tech detection (-tech-detect) in the alive_check phase.
whatweb gives a second opinion and catches things httpx misses (CMS versions,
specific plugin versions, WAF signatures, etc.).
"""
from pathlib import Path

from core.utils import run_command, read_lines
from core.colors import RED, GREEN, ORANGE, RESET


def run_whatweb(alive_urls_file, outfile) -> list:
    """
    Run whatweb against all alive URLs.
    Outputs JSON-lines to outfile.

    alive_urls_file must contain full URLs (http://... or https://...),
    not bare hostnames. Feed it the alive_urls.txt produced by the httpx phase.
    """
    alive_urls_file = Path(alive_urls_file)
    if not alive_urls_file.exists() or alive_urls_file.stat().st_size == 0:
        print(f"{RED}[-] whatweb: input file missing or empty{RESET}")
        return []

    run_command([
        'whatweb',
        '--input-file', str(alive_urls_file),
        '--log-json', str(outfile),
        '--quiet',
        '--no-errors',
    ], timeout=600)

    results = read_lines(outfile)
    if results:
        print(f"{GREEN}[+] whatweb: {len(results)} results saved → {outfile}{RESET}")
    else:
        print(f"{ORANGE}[!] whatweb produced no output{RESET}")

    return results
