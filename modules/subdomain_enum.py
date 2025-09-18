import requests
import subprocess
from core.utils import run_command,save_to_file,extract_domains

from core.colors import RED, GREEN, RESET
def run_assetfinder(domain, outfile=None):
    result = run_command(["assetfinder", "--subs-only", domain],outfile)
    save_to_file(extract_domains(result.stdout.splitlines()),outfile)


def run_subfinder(domain, outfile=None):
    result =  run_command(["subfinder", "-silent", "-d", domain],outfile)
    save_to_file(extract_domains(result.stdout.splitlines()),outfile)


def run_sublist3r(domain, outfile=None):
    result =  run_command(["sublist3r", "-d", domain],outfile)
    save_to_file(extract_domains(result.stdout.splitlines()),outfile)


def run_amass(domain, output_dir,outfile):
    raw_outfile = output_dir / 'amass_raw.txt'
    result =  run_command(["amass", "enum","-passive","-d", domain,"-o",str(raw_outfile)],outfile)
    save_to_file(extract_domains(result.stdout.splitlines()),outfile)


def run_crt(domain, outfile=None):
    
    url = f"https://crt.sh?q={domain}&output=json"
    print(f"{GREEN}[+] Quering {url} , output file = {outfile}{RESET}")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"{RED}[-] Error fetching data: {e}{RESET}")
        return []

    try:
        data = resp.json()
    except ValueError:
        print(f"{RED}[-] Error parsing JSON response{RESET}")
        return []

    # Collect all unique certificate names
    names = sorted({entry["name_value"] for entry in data if "name_value" in entry})

    # Save to file if requested
    save_to_file(names,outfile)

    return names
