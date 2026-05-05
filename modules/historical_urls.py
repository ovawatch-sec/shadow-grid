"""
modules/historical_urls.py
Passive URL discovery from archive sources.
"""
from pathlib import Path

from core.utils import run_command, save_to_file, read_lines
from core.colors import RED, GREEN, RESET


def run_waybackurls(domain: str, outfile) -> list:
    """Fetch URLs from the Wayback Machine."""
    result = run_command(['waybackurls', domain], timeout=180)
    urls = sorted(set(line for line in result.stdout.splitlines() if line.strip()))
    save_to_file(urls, outfile)
    return urls


def run_gau(domain: str, outfile) -> list:
    """
    Fetch URLs from multiple passive sources via gau:
    Wayback Machine, Common Crawl, OTX, URLScan.
    Better coverage than waybackurls alone.
    """
    outfile = Path(outfile)
    run_command([
        'gau',
        '--subs',           # include subdomains
        '--o', str(outfile),
        domain,
    ], timeout=300)
    return read_lines(outfile)


def run_urlfinder(domain: str, outfile) -> list:
    """
    Discover URLs using urlfinder.

    FIX from v1: v1 passed "urlfinder -d " as a SINGLE string in the cmd list
    → subprocess treated it as the binary name → FileNotFoundError.
    Fixed by splitting into proper list elements.
    """
    result = run_command([
        'urlfinder',
        '-d', domain,
        '-silent',
    ], timeout=120)

    urls = sorted(set(line for line in result.stdout.splitlines() if line.strip()))
    save_to_file(urls, outfile)
    return urls
