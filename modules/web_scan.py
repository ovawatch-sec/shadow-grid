"""
modules/web_scan.py
Port scanning (naabu), web crawling (katana), vulnerability scanning (nuclei).
"""
from pathlib import Path

from core.utils import run_command, read_lines
from core.colors import RED, GREEN, RESET, ORANGE


def run_naabu(infile, outfile) -> list:
    """
    Port scan a list of hosts using naabu.

    FIX from v1:
    - v1 used -host flag which expects a single host, not a file → replaced with -list
    - v1 had 'sudo naabu' hardcoded — naabu needs raw socket access for SYN scan,
      but falls back to CONNECT scan without sudo. Removed sudo; add it yourself
      if you want SYN scan performance.
    - v1 used -top-ports full (all 65535) which takes very long on large target lists.
      Changed to -top-ports 1000 by default. Pass a custom port range if needed.
    """
    infile = Path(infile)
    if not infile.exists() or infile.stat().st_size == 0:
        print(f"{RED}[-] naabu: input file missing or empty{RESET}")
        return []

    run_command([
        'naabu', '-silent',
        '-list', str(infile),
        '-top-ports', '1000',
        '-o', str(outfile),
    ], timeout=900)

    return read_lines(outfile)


def run_katana(alive_urls_file, output_dir) -> list:
    """
    Crawl alive URLs with katana for endpoint and JS discovery.

    FIX from v1:
    - v1 only read the first line of the input file and ran katana on one domain
    - v1 used -jsl but not -list; now uses -list to process all URLs in one pass
    """
    alive_urls_file = Path(alive_urls_file)
    output_dir = Path(output_dir)

    if not alive_urls_file.exists() or alive_urls_file.stat().st_size == 0:
        print(f"{RED}[-] katana: input file missing or empty{RESET}")
        return []

<<<<<<< dev
    outfile = output_dir / 'katana.txt'

    run_command([
        'katana',
        '-list', str(alive_urls_file),
        '-jsl',          # JavaScript link extraction
        '-jc',           # JavaScript crawling
        '-d', '3',       # crawl depth
        '-silent',
        '-o', str(outfile),
    ], timeout=900)
=======
def run_naabu(infile, output_dir):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []
    outfile = output_dir / 'naabu.txt'
    run_command(['sudo',"naabu", '-top-ports','full',"-host",str(infile) ,"-o",str(outfile)])
>>>>>>> main

    return read_lines(outfile)


def run_nuclei(infile, outfile) -> list:
    """
    Run nuclei against alive URLs, outputting JSON-lines for dashboard consumption.

    FIX from v1:
    - v1 used -json-export which outputs a JSON array — fails to parse if nuclei
      crashes mid-run. Using -json (JSON-lines) is safer: each finding is a
      self-contained line and partial output is still readable.
    - Dashboard expects output at raw/nuclei_results.json — we write JSON-lines
      to that path to keep compatibility.
    """
    infile = Path(infile)
    if not infile.exists() or infile.stat().st_size == 0:
        print(f"{RED}[-] nuclei: input file missing or empty{RESET}")
        return []

    outfile = Path(outfile)
    outfile.parent.mkdir(parents=True, exist_ok=True)

    run_command([
        'nuclei',
        '-list', str(infile),
        '-severity', 'low,medium,high,critical',
        '-json',
        '-o', str(outfile),
        '-silent',
    ], timeout=3600)

    return read_lines(outfile)
