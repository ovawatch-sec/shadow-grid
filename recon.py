#!/usr/bin/env python3
"""
Bug-Ovawatch Recon Automation Framework v2
Author: theblxckcicada
"""
import sys
import argparse
from pathlib import Path

from core.banner import banner
from core.colors import RED, GREEN, BLUE, PURPLE, ORANGE, RESET
from core.utils import (
    load_out_of_scope, filter_out_of_scope,
    save_to_file, run_command, read_lines,
    phase_done, extract_urls_from_httpx,
)
from core.dependency_check import check_dependencies

import modules.subdomain_enum as enum_mod
import modules.alive_check as alive_mod
import modules.web_scan as web_mod
import modules.screenshots as ss_mod
import modules.historical_urls as hist_mod
import modules.dns_recon as dns_mod
import modules.asset_discovery as asset_mod
import modules.tech_fingerprint as tech_mod


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def phase_header(number: int, name: str) -> None:
    bar = '─' * 62
    print(f"\n{PURPLE}┌{bar}┐{RESET}")
    print(f"{PURPLE}│  Phase {number:<2}  {name:<51} │{RESET}")
    print(f"{PURPLE}└{bar}┘{RESET}")


def skip(tool: str, skip_set: set) -> bool:
    return tool in skip_set


def should_run(outfile, resume: bool) -> bool:
    """False means skip because resume mode and output already exists."""
    return not (resume and phase_done(outfile))


# ─────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────

def main() -> None:
    banner()

    parser = argparse.ArgumentParser(
        description='Bug-Ovawatch Recon Automation Framework v2',
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument('-t', '--target', required=True,
                        help='Single domain OR path to a file with one domain per line')
    parser.add_argument('--oos',
                        help='File with out-of-scope patterns (supports wildcards, e.g. *.internal.example.com)')
    parser.add_argument('-w', '--wordlist', default=None,
                        help='Custom DNS wordlist for shuffledns (default: data/wordlists/dns.txt)')
    parser.add_argument('-p', '--port', type=int, default=8000,
                        help='Dashboard HTTP port (default: 8000)')
    parser.add_argument('--skip-tools', default='',
                        help='Comma-separated tool names to skip\n'
                             '  e.g. --skip-tools amass,gowitness,nuclei')
    parser.add_argument('--skip-check', action='store_true',
                        help='Skip dependency check at startup')
    parser.add_argument('--resume', action='store_true',
                        help='Skip any phase whose output file already exists (resume interrupted run)')
    parser.add_argument('--passive-only', action='store_true',
                        help='Stop after Phase 4 (HTTP probing) — no active scanning')
    parser.add_argument('--no-dashboard', action='store_true',
                        help='Do not launch the web dashboard after recon')
    parser.add_argument('-l', '--list', action='store_true',
                        help='List all tools this framework uses and exit')
    args = parser.parse_args()

    ALL_TOOLS = [
        'assetfinder', 'subfinder', 'amass', 'shuffledns', 'alterx',
        'dnsx', 'httpx', 'naabu', 'nuclei', 'katana', 'gowitness',
        'waybackurls', 'gau', 'urlfinder', 'asnmap', 'whatweb', 'dig', 'whois',
    ]

    if args.list:
        print(f"{PURPLE}[Tools used]{RESET}")
        for t in ALL_TOOLS:
            print(f"  • {t}")
        sys.exit(0)

    skip_set = {t.strip().lower() for t in args.skip_tools.split(',') if t.strip()}

    if not args.skip_check:
        missing = check_dependencies(skip_tools=skip_set)
        if missing:
            print(f"{ORANGE}[!] Continuing with missing tools — affected phases will be skipped{RESET}")

    # ── Resolve target list ──────────────────────────────
    target_path = Path(args.target)
    domains = read_lines(target_path) if target_path.exists() else [args.target]

    oos_list = load_out_of_scope(args.oos)
    if oos_list:
        print(f"{ORANGE}[!] Out-of-scope patterns loaded: {len(oos_list)}{RESET}")

    # ─────────────────────────────────────────────────────
    # Per-domain pipeline
    # ─────────────────────────────────────────────────────
    for domain in domains:
        print(f"\n{PURPLE}{'═' * 66}{RESET}")
        print(f"{PURPLE}  Target: {domain}{RESET}")
        print(f"{PURPLE}{'═' * 66}{RESET}")

        # Directory layout
        data_dir       = Path('data')
        out            = Path('output') / domain
        raw_dir        = out / 'raw'
        wayback_dir    = out / 'waybackurls'
        gau_dir        = out / 'gau'
        katana_dir     = out / 'katana'
        urlfinder_dir  = out / 'urlfinder'

        for d in [data_dir, out, raw_dir, wayback_dir, gau_dir, katana_dir, urlfinder_dir]:
            d.mkdir(parents=True, exist_ok=True)

        # ── Phase 1: Passive Recon ────────────────────────────────────
        phase_header(1, 'Passive Recon — WHOIS / ASN / DNS Records')

        whois_file  = out / 'whois.txt'
        asn_file    = out / 'asn_ranges.txt'
        dns_file    = out / 'dns_records.txt'
        zone_file   = out / 'zone_transfer.txt'

        if not skip(  'whois', skip_set) and should_run(whois_file, args.resume):
            asset_mod.run_whois(domain, whois_file)

        if not skip(  'asnmap', skip_set) and should_run(asn_file, args.resume):
            asset_mod.run_asnmap(domain, asn_file)

        if not skip(  'dig', skip_set):
            if should_run(dns_file, args.resume):
                dns_mod.run_dns_records(domain, dns_file)
            if should_run(zone_file, args.resume):
                dns_mod.attempt_zone_transfer(domain, zone_file)

        # ── Phase 2: Subdomain Enumeration ───────────────────────────
        phase_header(2, 'Subdomain Enumeration')

        subdomains: set = set()

        # crt.sh — no tool dependency, always runs unless skipped
        crtsh_file = out / 'crt.sh.txt'
        if should_run(crtsh_file, args.resume):
            enum_mod.run_crtsh(domain, crtsh_file)
        subdomains.update(read_lines(crtsh_file))

        if not skip('assetfinder', skip_set):
            af_file = out / 'assetfinder.txt'
            if should_run(af_file, args.resume):
                enum_mod.run_assetfinder(domain, af_file)
            subdomains.update(read_lines(af_file))

        if not skip('subfinder', skip_set):
            sf_file = out / 'subfinder.txt'
            if should_run(sf_file, args.resume):
                enum_mod.run_subfinder(domain, sf_file)
            subdomains.update(read_lines(sf_file))

        if not skip('amass', skip_set):
            am_file = out / 'amass.txt'
            if should_run(am_file, args.resume):
                enum_mod.run_amass(domain, raw_dir, am_file)
            subdomains.update(read_lines(am_file))

        if not skip('shuffledns', skip_set):
            sdns_file = out / 'shuffledns.txt'
            if should_run(sdns_file, args.resume):
                enum_mod.run_shuffledns(domain, data_dir, args.wordlist, sdns_file)
            subdomains.update(read_lines(sdns_file))

        subdomains_file = out / 'subdomains.txt'
        save_to_file(sorted(subdomains), subdomains_file)
        print(f"{GREEN}[+] Total unique subdomains: {len(subdomains)}{RESET}")

        # ── Phase 3: Permutations + DNS Resolution ───────────────────
        phase_header(3, 'Permutations → DNS Resolution → OOS Filter')

        if not skip('alterx', skip_set):
            alterx_file = out / 'alterx.txt'
            if should_run(alterx_file, args.resume):
                enum_mod.run_alterx(subdomains_file, alterx_file)
            # Merge permutations into master list
            merged = set(read_lines(subdomains_file))
            merged.update(read_lines(alterx_file))
            save_to_file(sorted(merged), subdomains_file)
            print(f"{GREEN}[+] After alterx permutations: {len(merged)} candidates{RESET}")

        alive_file   = out / 'alive_subdomains.txt'
        dnsx_full    = out / 'dnsx_records.txt'

        if not skip('dnsx', skip_set):
            if should_run(alive_file, args.resume):
                alive_mod.run_dnsx(subdomains_file, alive_file)
            if should_run(dnsx_full, args.resume):
                dns_mod.run_dnsx_full(alive_file, dnsx_full)
        else:
            # No dnsx — fall back to unresolved list
            alive_file = subdomains_file

        # Apply OOS filter in-place
        alive_domains = filter_out_of_scope(read_lines(alive_file), oos_list)
        save_to_file(sorted(alive_domains), alive_file)
        print(f"{GREEN}[+] Alive subdomains (post-OOS): {len(alive_domains)}{RESET}")

        if not alive_domains:
            print(f"{RED}[-] No alive subdomains — skipping remaining phases for {domain}{RESET}")
            continue

        # ── Phase 4: HTTP Probing ─────────────────────────────────────
        phase_header(4, 'HTTP Probing (httpx)')

        httpx_file     = out / 'httpx.jsonl'
        alive_urls_file = out / 'alive_urls.txt'

        if not skip('httpx', skip_set):
            if should_run(httpx_file, args.resume):
                alive_mod.run_httpx(alive_file, httpx_file)

            http_urls = extract_urls_from_httpx(httpx_file)
            save_to_file(http_urls, alive_urls_file)
            print(f"{GREEN}[+] Alive URLs (HTTP/S): {len(http_urls)}{RESET}")
        else:
            # No httpx — use bare hostnames; tools that need full URLs will degrade
            alive_urls_file = alive_file

        if args.passive_only:
            print(f"{ORANGE}[!] --passive-only: stopping here for {domain}{RESET}")
            continue

        # ── Phase 5: Port Scanning ────────────────────────────────────
        phase_header(5, 'Port Scanning (naabu)')

        naabu_file = out / 'naabu.txt'
        if not skip('naabu', skip_set) and should_run(naabu_file, args.resume):
            web_mod.run_naabu(alive_file, naabu_file)

        # ── Phase 6: Screenshots + Tech Fingerprinting ───────────────
        phase_header(6, 'Screenshots + Tech Fingerprinting')

        if not skip('gowitness', skip_set):
            ss_mod.run_gowitness(alive_urls_file, out)

        whatweb_file = out / 'whatweb.jsonl'
        if not skip('whatweb', skip_set) and should_run(whatweb_file, args.resume):
            tech_mod.run_whatweb(alive_urls_file, whatweb_file)

        # ── Phase 7: URL Discovery ────────────────────────────────────
        phase_header(7, 'URL Discovery — waybackurls / gau / katana / urlfinder')

        if not skip('waybackurls', skip_set):
            for sub in alive_domains:
                wb_file = wayback_dir / f'{sub}_wayback.txt'
                if should_run(wb_file, args.resume):
                    hist_mod.run_waybackurls(sub, wb_file)

        if not skip('gau', skip_set):
            for sub in alive_domains:
                gau_file = gau_dir / f'{sub}_gau.txt'
                if should_run(gau_file, args.resume):
                    hist_mod.run_gau(sub, gau_file)

        if not skip('katana', skip_set):
            katana_out = katana_dir / 'katana.txt'
            if should_run(katana_out, args.resume):
                web_mod.run_katana(alive_urls_file, katana_dir)

        if not skip('urlfinder', skip_set):
            for sub in alive_domains:
                uf_file = urlfinder_dir / f'{sub}_urlfinder.txt'
                if should_run(uf_file, args.resume):
                    hist_mod.run_urlfinder(sub, uf_file)

        # ── Phase 8: Vulnerability Scanning ──────────────────────────
        phase_header(8, 'Vulnerability Scanning (nuclei)')

        nuclei_file = raw_dir / 'nuclei_results.json'
        if not skip('nuclei', skip_set) and should_run(nuclei_file, args.resume):
            web_mod.run_nuclei(alive_urls_file, nuclei_file)

        # ── Summary ───────────────────────────────────────────────────
        print(f"""
{GREEN}{'═' * 66}
  Recon complete: {domain}
  Results → output/{domain}/
{'═' * 66}{RESET}""")

    # ── Dashboard ─────────────────────────────────────────────────────
    if not args.no_dashboard:
        print(f"\n{GREEN}[+] Launching dashboard on http://localhost:{args.port}/app{RESET}")
        print(f"{GREEN}[+] Press Ctrl+C to stop{RESET}\n")
        run_command(['python3', '-m', 'http.server', str(args.port)])


# ─────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{ORANGE}[!] Interrupted — partial results are in output/{RESET}")
        sys.exit(0)
    except Exception as exc:
        import traceback
        print(f"\n{RED}[!] Fatal: {exc}{RESET}")
        traceback.print_exc()
        sys.exit(1)
