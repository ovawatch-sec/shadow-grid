# Bug-Ovawatch Recon Framework v2

Automated recon pipeline for bug bounty and pentest engagements.

## Quick Start

```bash
# Install all tools
chmod +x setup.sh && ./setup.sh

# Basic run
python3 recon.py -t example.com

# Multiple targets from file
python3 recon.py -t targets.txt

# Passive only (no active scanning)
python3 recon.py -t example.com --passive-only

# Skip specific tools
python3 recon.py -t example.com --skip-tools amass,gowitness,nuclei

# Resume interrupted run
python3 recon.py -t example.com --resume

# With out-of-scope list and custom wordlist
python3 recon.py -t example.com --oos oos.txt -w /path/to/wordlist.txt
```

## Pipeline

| Phase | What runs | Tools |
|-------|-----------|-------|
| 1 | Passive recon | whois, asnmap, dig (records + zone transfer) |
| 2 | Subdomain enumeration | crt.sh, assetfinder, subfinder, amass, shuffledns |
| 3 | DNS resolution + OOS filter | alterx, dnsx |
| 4 | HTTP probing | httpx (title, status, tech-detect) |
| 5 | Port scanning | naabu (top 1000) |
| 6 | Screenshots + tech fingerprint | gowitness, whatweb |
| 7 | URL discovery | waybackurls, gau, katana, urlfinder |
| 8 | Vulnerability scanning | nuclei (low–critical) |

## Output Structure

```
output/
└── example.com/
    ├── whois.txt              # WHOIS record
    ├── asn_ranges.txt         # IP ranges owned by target
    ├── dns_records.txt        # A/AAAA/MX/TXT/NS/SOA/CNAME
    ├── zone_transfer.txt      # AXFR results (if vulnerable)
    ├── crt.sh.txt             # Certificate transparency hits
    ├── assetfinder.txt
    ├── subfinder.txt
    ├── amass.txt
    ├── shuffledns.txt
    ├── subdomains.txt         # Merged unique subdomains
    ├── alterx.txt             # Permutation candidates
    ├── alive_subdomains.txt   # DNS-resolved alive hosts
    ├── dnsx_records.txt       # Multi-record DNS dump of alive hosts
    ├── httpx.jsonl            # Full httpx JSON output
    ├── alive_urls.txt         # Clean URL list for downstream tools
    ├── naabu.txt              # Open ports (host:port)
    ├── whatweb.jsonl          # Technology fingerprints
    ├── waybackurls/           # Historical URLs per subdomain
    ├── gau/                   # GetAllURLs per subdomain
    ├── katana/                # Active crawl results
    ├── urlfinder/             # urlfinder results per subdomain
    ├── screenshots/           # gowitness screenshots
    └── raw/
        ├── amass_raw.txt
        └── nuclei_results.json
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | required | Domain or file of domains |
| `--oos` | — | Out-of-scope patterns file (wildcards OK) |
| `-w, --wordlist` | data/wordlists/dns.txt | DNS brute-force wordlist |
| `-p, --port` | 8000 | Dashboard port |
| `--skip-tools` | — | Comma-separated tools to skip |
| `--skip-check` | off | Skip startup dependency check |
| `--resume` | off | Skip phases with existing output |
| `--passive-only` | off | Stop after httpx (phase 4) |
| `--no-dashboard` | off | Don't launch the web dashboard |
| `-l, --list` | — | Print all tools and exit |

## Tools Required

All installed by `setup.sh`. Requires Go 1.21+.

| Tool | Source |
|------|--------|
| assetfinder | tomnomnom/assetfinder |
| subfinder | projectdiscovery/subfinder |
| amass | owasp-amass/amass |
| shuffledns | projectdiscovery/shuffledns |
| alterx | projectdiscovery/alterx |
| dnsx | projectdiscovery/dnsx |
| httpx | projectdiscovery/httpx |
| naabu | projectdiscovery/naabu |
| nuclei | projectdiscovery/nuclei |
| katana | projectdiscovery/katana |
| gowitness | sensepost/gowitness |
| waybackurls | tomnomnom/waybackurls |
| gau | lc/gau |
| urlfinder | projectdiscovery/urlfinder |
| asnmap | projectdiscovery/asnmap |
| whatweb | system package |
| dig / whois | dnsutils / whois system package |

## Notes

- naabu runs without `sudo` by default (CONNECT scan mode). Add `sudo` for SYN
  scan if you need speed on large target lists.
- nuclei timeout is 1 hour. For large targets consider `--skip-tools nuclei`
  and run it separately.
- The dashboard is served by Python's `http.server` from the project root.
  Visit `http://localhost:8000/app` after recon completes.

## Disclaimer

Only test systems you have explicit written permission to test.
