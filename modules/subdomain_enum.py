"""
modules/subdomain_enum.py
Passive and active subdomain discovery.
"""
import subprocess
import requests
from pathlib import Path

from core.utils import run_command, save_to_file, read_lines, extract_domains
from core.colors import RED, GREEN, ORANGE, RESET


# ─────────────────────────────────────────────────────────
# Passive: Certificate Transparency (no tool required)
# ─────────────────────────────────────────────────────────

def run_crtsh(domain: str, outfile=None) -> list:
    """
    Query crt.sh for certificate transparency records.
    Returns subdomains found. No external tool required — uses requests.
    """
    print(f"{GREEN}[+] Querying crt.sh for *.{domain}{RESET}")
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
            headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Bug-Ovawatch/2.0'},
        )
        resp.raise_for_status()
        entries = resp.json()
    except requests.exceptions.Timeout:
        print(f"{ORANGE}[!] crt.sh timed out — skipping{RESET}")
        return []
    except Exception as e:
        print(f"{RED}[-] crt.sh failed: {e}{RESET}")
        return []

    found = set()
    for entry in entries:
        for name in entry.get('name_value', '').splitlines():
            name = name.strip().lstrip('*.')
            if name and (name.endswith(f'.{domain}') or name == domain):
                found.add(name.lower())

    results = sorted(found)
    if outfile:
        save_to_file(results, outfile)
    print(f"{GREEN}[+] crt.sh: {len(results)} subdomains{RESET}")
    return results


# ─────────────────────────────────────────────────────────
# Passive: Tool-based enumeration
# ─────────────────────────────────────────────────────────

def run_assetfinder(domain: str, outfile=None) -> list:
    result = run_command(['assetfinder', '--subs-only', domain])
    domains = sorted(extract_domains(result.stdout.splitlines()))
    if outfile:
        save_to_file(domains, outfile)
    return domains


def run_subfinder(domain: str, outfile=None) -> list:
    outfile = Path(outfile)
    run_command(['subfinder', '-silent', '-all', '-d', domain, '-o', str(outfile)])
    return read_lines(outfile)


def run_amass(domain: str, raw_dir: Path, outfile=None) -> list:
    """
    Run amass in passive mode.
    Saves raw output to raw_dir/amass_raw.txt, then extracts clean domain list.

    FIX from v1: v1 passed outfile to run_command but amass was writing to
    raw_outfile — the outfile parameter was never actually written to.
    """
    raw_dir = Path(raw_dir)
    raw_outfile = raw_dir / 'amass_raw.txt'

    run_command(
        ['amass', 'enum', '-passive', '-silent', '-d', domain, '-o', str(raw_outfile)],
        timeout=600,
    )

    domains = sorted(extract_domains(read_lines(raw_outfile)))
    if outfile:
        save_to_file(domains, outfile)
    return domains


# ─────────────────────────────────────────────────────────
# Active: DNS bruteforce
# ─────────────────────────────────────────────────────────

def run_shuffledns(domain: str, data_dir: Path, wordlist=None, outfile=None) -> list:
    data_dir = Path(data_dir)
    resolver_file = data_dir / 'resolvers.txt'
    wordlist = Path(wordlist) if wordlist else data_dir / 'wordlists' / 'dns.txt'

    run_command([
        'shuffledns', '-silent',
        '-d', domain,
        '-w', str(wordlist),
        '-r', str(resolver_file),
        '-mode', 'bruteforce',
        '-o', str(outfile),
    ])
    return read_lines(outfile)


# ─────────────────────────────────────────────────────────
# Active: Permutation generation
# ─────────────────────────────────────────────────────────

def run_alterx(infile, outfile=None) -> list:
    """
    Generate subdomain permutations via alterx (reads from stdin).

    FIX from v1: v1 fed alterx the file but then called extract_domains on
    stdout — no save_to_file was ever called, so the file was empty on some
    code paths.
    """
    infile = Path(infile)
    if not infile.exists() or infile.stat().st_size == 0:
        print(f"{RED}[-] alterx: input file missing or empty — {infile}{RESET}")
        return []

    print(f"{GREEN}[+] Running alterx on {infile} → {outfile}{RESET}")
    try:
        with infile.open('r') as f:
            proc = subprocess.run(
                ['alterx', '-silent'],
                stdin=f,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=180,
            )
    except FileNotFoundError:
        print(f"{RED}[-] alterx not found{RESET}")
        return []
    except subprocess.TimeoutExpired:
        print(f"{ORANGE}[!] alterx timed out{RESET}")
        return []

    if proc.returncode != 0 and not proc.stdout.strip():
        print(f"{RED}[-] alterx failed: {proc.stderr.strip()}{RESET}")
        return []

    domains = sorted(extract_domains(proc.stdout.splitlines()))
    if outfile:
        save_to_file(domains, outfile)
    return domains
