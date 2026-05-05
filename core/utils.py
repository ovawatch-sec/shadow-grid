import re
import json
import subprocess
import fnmatch
from pathlib import Path
from typing import List, Optional

from .colors import RED, GREEN, RESET, ORANGE

DOMAIN_RE = re.compile(
    r'\b(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b',
    re.IGNORECASE
)


# ─────────────────────────────────────────────────────────
# Command runners
# ─────────────────────────────────────────────────────────

def run_command(
    cmd: List[str],
    outfile=None,
    show: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """
    Run a command, capturing stdout/stderr.
    Gracefully handles missing binaries and timeouts.
    """
    if show:
        extra = f' → {outfile}' if (outfile and '-o' not in cmd and '--output' not in cmd) else ''
        print(f"{GREEN}[+] Running: {' '.join(str(c) for c in cmd)}{extra}{RESET}")
    try:
        return subprocess.run(
            [str(c) for c in cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        print(f"{RED}[-] Tool not found: {cmd[0]} — is it installed and in PATH?{RESET}")
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr=f'not found: {cmd[0]}')
    except subprocess.TimeoutExpired:
        print(f"{ORANGE}[!] Timed out after {timeout}s: {cmd[0]}{RESET}")
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='timeout')


def run_stdin_command(
    cmd: List[str],
    infile: Path,
    outfile=None,
    show: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """
    Run a command with stdin piped from a file.
    Used for tools that read targets from stdin (alterx, dnsx, httprobe, etc.).
    """
    infile = Path(infile)
    if not infile.exists() or infile.stat().st_size == 0:
        print(f"{RED}[-] Input file missing or empty: {infile}{RESET}")
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='no input')

    if show:
        extra = f' → {outfile}' if outfile else ''
        print(f"{GREEN}[+] Running: {' '.join(str(c) for c in cmd)} < {infile}{extra}{RESET}")
    try:
        with open(infile, 'r') as f:
            return subprocess.run(
                [str(c) for c in cmd],
                stdin=f,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
    except FileNotFoundError:
        print(f"{RED}[-] Tool not found: {cmd[0]}{RESET}")
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr=f'not found: {cmd[0]}')
    except subprocess.TimeoutExpired:
        print(f"{ORANGE}[!] Timed out after {timeout}s: {cmd[0]}{RESET}")
        return subprocess.CompletedProcess(cmd, 1, stdout='', stderr='timeout')


# ─────────────────────────────────────────────────────────
# File I/O helpers
# ─────────────────────────────────────────────────────────

def save_to_file(lines, outfile):
    """Write a list of strings to a file, one per line. Creates parent dirs."""
    outfile = Path(outfile)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    with open(outfile, 'w') as f:
        f.write('\n'.join(str(line) for line in lines if line))


def read_lines(filepath) -> List[str]:
    """Return non-empty stripped lines from a file. Returns [] if file missing."""
    p = Path(filepath)
    if not p.exists():
        return []
    with open(p, 'r', errors='replace') as f:
        return [line.strip() for line in f if line.strip()]


def phase_done(output_file) -> bool:
    """True if output file already exists and is non-empty (used with --resume)."""
    p = Path(output_file)
    return p.exists() and p.stat().st_size > 0


# ─────────────────────────────────────────────────────────
# Domain / URL processing
# ─────────────────────────────────────────────────────────

def extract_domains(lines: List[str]) -> List[str]:
    """
    Pull unique domain names out of arbitrary text lines.
    Strips ANSI colour escapes first.
    """
    domains: List[str] = []
    seen: set = set()
    for line in lines:
        clean = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line)
        for match in DOMAIN_RE.findall(clean):
            d = match.lower()
            if d not in seen:
                seen.add(d)
                domains.append(d)
    return domains


def extract_urls_from_httpx(httpx_jsonl_file) -> List[str]:
    """
    Parse httpx JSON-lines output and return the list of URLs.
    Falls back to treating lines as plain URLs if JSON parse fails.
    """
    urls: List[str] = []
    for line in read_lines(httpx_jsonl_file):
        try:
            obj = json.loads(line)
            url = obj.get('url', '')
            if url:
                urls.append(url)
        except (json.JSONDecodeError, TypeError):
            if line.startswith('http://') or line.startswith('https://'):
                urls.append(line)
    return urls


# ─────────────────────────────────────────────────────────
# Scope filtering
# ─────────────────────────────────────────────────────────

def filter_out_of_scope(domains, oos_list) -> List[str]:
    if not oos_list:
        return list(domains)
    return [d for d in domains if not any(fnmatch.fnmatch(d, pat) for pat in oos_list)]


def load_out_of_scope(filepath) -> List[str]:
    if not filepath or not Path(filepath).exists():
        return []
    return read_lines(filepath)


# ─────────────────────────────────────────────────────────
# Misc
# ─────────────────────────────────────────────────────────

def check_tool(name: str) -> bool:
    """Return True if binary is available in PATH."""
    import shutil
    return shutil.which(name) is not None
