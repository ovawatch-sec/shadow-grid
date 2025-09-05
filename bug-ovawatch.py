import os
import subprocess
import fnmatch
from pathlib import Path
import shutil

# =========================
# Configuration
# =========================
USERNAME = "theblxckcicada"
CUSTOM_UA = f"Intigriti-{USERNAME}- Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
DEFAULT_HEADER = f"X-Bug-Bounty: {USERNAME}"

BASE_OUTPUT = Path("recon_output")
BASE_OUTPUT.mkdir(exist_ok=True)

TOOLS = {
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "amass": "go install github.com/owasp-amass/amass/v4/...@master",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gowitness": "go install github.com/sensepost/gowitness@latest"
}

# =========================
# Banner
# =========================
def banner():
    print("""
=======================================
      Recon Automation Framework
      Author: theblxckcicada
=======================================
    """)

# =========================
# Tool Check & Installer
# =========================
def check_and_install_tools():
    print("[*] Checking required tools...")
    for tool, install_cmd in TOOLS.items():
        if shutil.which(tool) is None:
            print(f"[!] {tool} not found. Installing...")
            try:
                subprocess.run(install_cmd, shell=True, check=True)
                print(f"[+] {tool} installed successfully.")
            except subprocess.CalledProcessError:
                print(f"[!] Failed to install {tool}. Please install manually: {install_cmd}")
        else:
            print(f"[+] {tool} is installed.")

# =========================
# Utility Functions
# =========================
def run_command(cmd, outfile=None):
    """Run a system command and optionally write output to file."""
    print(f"[+] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    if outfile:
        with open(outfile, "w") as f:
            f.write(result.stdout)
    return result.stdout.splitlines()


def load_out_of_scope(filepath):
    """Load out-of-scope domains/wildcards from file."""
    if not filepath or not Path(filepath).exists():
        return []
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip()]


def filter_out_of_scope(domains, oos_list):
    """Filter domains that match any out-of-scope entry."""
    filtered = []
    for d in domains:
        if not any(fnmatch.fnmatch(d, pattern) for pattern in oos_list):
            filtered.append(d)
    return list(set(filtered))

# =========================
# Recon Steps
# =========================
def run_assetfinder(domain):
    return run_command(["assetfinder", "--subs-only", domain])


def run_subfinder(domain):
    return run_command(["subfinder", "-silent", "-d", domain])


def run_amass(domain):
    return run_command(["amass", "enum", "-passive", "-d", domain])


def run_httpx(domains, output_dir, rate_limit, custom_headers):
    alive_file = output_dir / "alive.txt"
    input_file = output_dir / "all_subs.txt"

    with open(input_file, "w") as f:
        f.write("\n".join(domains))

    cmd = [
        "httpx",
        "-silent",
        "-l", str(input_file),
        "-user-agent", CUSTOM_UA,
        "-rate-limit", str(rate_limit),
        "-o", str(alive_file)
    ]

    # Add custom headers
    for header in custom_headers:
        cmd.extend(["-H", header])

    run_command(cmd)

    return [line.strip() for line in open(alive_file)]


def run_gowitness(alive_domains, output_dir):
    input_file = output_dir / "alive.txt"
    run_command(["gowitness", "file", "-f", str(input_file), "--timeout", "10", "--disable-verify", "-P", str(output_dir / "screenshots")])

# =========================
# Main Workflow
# =========================
def recon(domain, out_of_scope_file=None, rate_limit=20, custom_headers=None):
    print(f"[*] Starting recon for {domain}")
    
    if custom_headers is None:
        custom_headers = [DEFAULT_HEADER]

    # Prepare domain-specific folder
    output_dir = BASE_OUTPUT / domain
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load out-of-scope
    oos_list = load_out_of_scope(out_of_scope_file)

    # Run tools
    subs = []
    subs += run_assetfinder(domain)
    subs += run_subfinder(domain)
    subs += run_amass(domain)

    # Filter OOS
    subs = filter_out_of_scope(subs, oos_list)

    # Save raw subdomains
    all_file = output_dir / "all_subs.txt"
    with open(all_file, "w") as f:
        f.write("\n".join(subs))

    print(f"[+] Found {len(subs)} unique subdomains (after filtering)")

    # Alive check
    alive = run_httpx(subs, output_dir, rate_limit, custom_headers)
    print(f"[+] {len(alive)} alive subdomains")

    # Screenshots
    if alive:
        run_gowitness(alive, output_dir)

    print(f"[+] Recon finished for {domain}. Results saved in {output_dir}/")


if __name__ == "__main__":
    import argparse

    banner()

    parser = argparse.ArgumentParser(description="Recon automation script")
    parser.add_argument("target", help="Target domain or file with domains")
    parser.add_argument("--oos", help="File with out-of-scope domains/wildcards")
    parser.add_argument("--rate", type=int, default=20, help="Max requests per second (default 20)")
    parser.add_argument("--header", action="append", help="Custom header(s) to add (can be used multiple times)")
    parser.add_argument("--skip-install", action="store_true", help="Skip tool installation check")
    args = parser.parse_args()

    if not args.skip_install:
        check_and_install_tools()

    target_path = Path(args.target)
    domains = []

    if target_path.exists():
        with open(target_path) as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        domains = [args.target]

    for d in domains:
        recon(d, args.oos, args.rate, args.header)