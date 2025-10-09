import subprocess
from pathlib import Path
from core.colors import RED,GREEN,RESET
from core.utils import extract_domains, run_command,save_to_file

def run_httprobe(infile, outfile=None):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []

    # run httprobe, feeding the file into stdin
    print(f"{GREEN}[+] Running: httprobe on {infile} to fetch alive subdomains, output file {outfile}{RESET}")
    with infile.open("r") as f:
        proc = subprocess.run(
            ["httprobe"],
            stdin=f,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    if proc.returncode != 0 and not proc.stdout:
        print(f"{RED}[-] httprobe failed: {proc.stderr.strip()}{RESET}")
        return []
    urls = proc.stdout.splitlines()
    results = sorted({url for url in urls if url.startswith("https://")})
    save_to_file(results,outfile)

    return results


    
def run_dnsx(infile, outfile=None):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []

    # run alterx, feeding the file into stdin
    print(f"{GREEN}[+] Running: dnsx on {infile} to fetch alive subdomains, output file {outfile}{RESET}")
    with infile.open("r") as f:
        proc = subprocess.run(
            ["dnsx",'-silent'],
            stdin=f,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    if proc.returncode != 0 and not proc.stdout:
        print(f"{RED}[-] dnsx failed: {proc.stderr.strip()}{RESET}")
        return []
    urls = proc.stdout.splitlines()
    results = sorted(extract_domains(urls))
    save_to_file(results,outfile)

def run_httpx(infile, outfile=None):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []

    # run alterx, feeding the file into stdin
    print(f"{GREEN}[+] Running: httpx on {infile} to fetch alive subdomains, output file {outfile}{RESET}")
    with infile.open("r") as f:
        proc = subprocess.run(
            ["httpx",'-silent','-title','-sc','-location','fr'],
            stdin=f,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    if proc.returncode != 0 and not proc.stdout:
        print(f"{RED}[-] httpx failed: {proc.stderr.strip()}{RESET}")
        return []
    urls = proc.stdout.splitlines()
    results = sorted(extract_domains(urls))
    save_to_file(results,outfile)