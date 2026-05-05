"""
modules/asset_discovery.py
WHOIS lookup and ASN / IP-range enumeration.
All new in v2 — not present in v1.

Why this matters:
- WHOIS reveals registrar, registration dates, name servers, abuse contacts.
- ASN enumeration via asnmap reveals all IP ranges owned by the target org,
  which you can feed into naabu directly for infrastructure-level scanning.
"""
from pathlib import Path

from core.utils import run_command, save_to_file
from core.colors import RED, GREEN, ORANGE, RESET


def run_whois(domain: str, outfile) -> str:
    """Run WHOIS lookup on the root domain."""
    result = run_command(['whois', domain], timeout=30)
    if result.stdout:
        outfile = Path(outfile)
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text(result.stdout)
        print(f"{GREEN}[+] WHOIS saved → {outfile}{RESET}")
    else:
        print(f"{ORANGE}[!] WHOIS returned no data for {domain}{RESET}")
    return result.stdout


def run_asnmap(domain: str, outfile) -> list:
    """
    Enumerate ASN numbers and associated CIDR ranges via asnmap.
    Output is a list of IP ranges (e.g. 192.0.2.0/24) for further scanning.
    """
    result = run_command(['asnmap', '-d', domain, '-silent'], timeout=60)
    lines = [l for l in result.stdout.splitlines() if l.strip()]

    if lines:
        save_to_file(lines, outfile)
        print(f"{GREEN}[+] ASN/IP ranges ({len(lines)} entries) saved → {outfile}{RESET}")
    else:
        print(f"{ORANGE}[!] asnmap found no ASN data for {domain}{RESET}")

    return lines
