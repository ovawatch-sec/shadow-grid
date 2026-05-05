"""
modules/dns_recon.py
DNS record enumeration, zone transfer attempts, and dnsx full-record scan.
All new in v2 — not present in v1.
"""
from pathlib import Path

from core.utils import run_command, save_to_file, read_lines, extract_domains
from core.colors import RED, GREEN, ORANGE, RESET

DNS_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']


def run_dns_records(domain: str, outfile) -> list:
    """
    Query all common DNS record types for the root domain using dig.
    Useful for identifying mail servers, SPF/DMARC, CDN usage, etc.
    """
    lines = [f'# DNS Records for {domain}', '']

    for rtype in DNS_RECORD_TYPES:
        result = run_command(
            ['dig', '+noall', '+answer', domain, rtype],
            show=False, timeout=10,
        )
        if result.stdout.strip():
            lines.append(f'## {rtype}')
            lines.append(result.stdout.strip())
            lines.append('')

    save_to_file(lines, outfile)
    print(f"{GREEN}[+] DNS records saved → {outfile}{RESET}")
    return lines


def attempt_zone_transfer(domain: str, outfile) -> list:
    """
    Attempt AXFR zone transfer on each authoritative NS.
    Almost always fails on properly configured domains but worth checking.
    A successful transfer leaks the entire zone.
    """
    ns_result = run_command(['dig', '+short', domain, 'NS'], show=False, timeout=10)
    nameservers = [ns.rstrip('.') for ns in ns_result.stdout.splitlines() if ns.strip()]

    if not nameservers:
        print(f"{ORANGE}[!] No NS records found for {domain} — skipping zone transfer{RESET}")
        return []

    results = []
    for ns in nameservers:
        print(f"{GREEN}[+] Zone transfer attempt: {domain} @ {ns}{RESET}")
        axfr = run_command(['dig', 'axfr', domain, f'@{ns}'], show=False, timeout=15)

        if axfr.returncode == 0 and 'XFR size' in axfr.stdout:
            results.append(f'=== Zone Transfer via {ns} ===')
            results.append(axfr.stdout)
            print(f"{GREEN}[+] Zone transfer SUCCESSFUL via {ns}!{RESET}")
        else:
            print(f"{RED}[-] Zone transfer refused by {ns}{RESET}")

    if results:
        save_to_file(results, outfile)
        print(f"{GREEN}[+] Zone transfer data saved → {outfile}{RESET}")

    return results


def run_dnsx_full(infile, outfile) -> list:
    """
    Run dnsx with multiple record types across all alive subdomains.
    Captures A, AAAA, CNAME, MX, TXT, NS with resolved values.
    Useful for finding interesting CNAME targets, SPF misconfigs, etc.
    """
    infile = Path(infile)
    if not infile.exists() or infile.stat().st_size == 0:
        print(f"{RED}[-] dnsx full: input file missing or empty{RESET}")
        return []

    run_command([
        'dnsx', '-silent',
        '-l', str(infile),
        '-a', '-aaaa', '-cname', '-mx', '-txt', '-ns',
        '-resp',
        '-o', str(outfile),
    ], timeout=300)

    return read_lines(outfile)
