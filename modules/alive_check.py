"""
modules/alive_check.py
DNS resolution and HTTP probing of discovered subdomains.
"""
from pathlib import Path

from core.utils import run_command, save_to_file, read_lines, extract_domains
from core.colors import RED, GREEN, RESET


def run_dnsx(infile, outfile=None) -> list:
    """
    Resolve subdomains via dnsx using -l (list) flag.

    FIX from v1: v1 used stdin piping and called extract_domains on dnsx output,
    which works but dnsx -a -resp output includes IP addresses that polluted
    the domain list. Now we use -o directly and read back clean hostnames.
    """
    infile = Path(infile)
    cmd = [
        'dnsx', '-silent',
        '-l', str(infile),
        '-a', '-resp',
    ]
    if outfile:
        cmd += ['-o', str(outfile)]

    result = run_command(cmd, timeout=300)

    if outfile and Path(outfile).exists():
        # dnsx -a -resp format: "sub.domain.com [1.2.3.4]"
        # Extract just the hostnames
        raw = read_lines(outfile)
        domains = sorted(extract_domains(raw))
        save_to_file(domains, outfile)
        return domains

    return sorted(extract_domains(result.stdout.splitlines()))


def run_httpx(infile, outfile=None):
    """
    Probe alive HTTP services with httpx.
    Outputs JSON-lines to outfile (one JSON object per live host).

    FIX from v1:
    - v1 used '-location fr' which is not a valid httpx flag → replaced with -follow-redirects
    - v1 passed output through extract_domains which mangled JSON
    - v1 used stdin piping; now uses -list flag for clarity
    - Added -tech-detect for technology fingerprinting in one pass
    """
    infile = Path(infile)
    cmd = [
        'httpx', '-silent',
        '-list', str(infile),
        '-title',
        '-status-code',
        '-follow-redirects',
        '-tech-detect',
        '-json',
    ]
    if outfile:
        cmd += ['-o', str(outfile)]

    run_command(cmd, timeout=900)

    if outfile:
        return read_lines(outfile)
    return []
