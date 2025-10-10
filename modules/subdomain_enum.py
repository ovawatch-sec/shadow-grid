from pathlib import Path
import requests
import subprocess
from core.utils import run_command,save_to_file,extract_domains

from core.colors import RED, GREEN, RESET
def run_assetfinder(domain, outfile=None):
    result = run_command(["assetfinder", "--subs-only", domain],outfile)
    save_to_file(extract_domains(result.stdout.splitlines()),outfile)

def run_subfinder(domain, outfile=None):
    run_command(["subfinder", "-silent", "-d", domain,'-all','-o',str(outfile)])

def run_chaos_client(domain, key=None, outfile=None):
    if key is not None:
        run_command(["chaos-client", '-key',key,"-silent", "-d", domain,'-o',str(outfile)])

def run_amass(domain, output_dir,outfile):
    raw_outfile = output_dir / 'amass_raw.txt'
    run_command(["amass", "enum",'-silent',"-d", domain,"-o",str(raw_outfile)],outfile)

def run_shuffledns(domain, data_dir=None, wordlist=None,outfile=None):
    resolver_file = data_dir/'resolvers.txt'
    wordlist = wordlist or data_dir/'wordlists/dns.txt' 
    run_command(["shuffledns",'-silent', "-d", domain,'-w',str(wordlist),'-r',str(resolver_file),'-mode','bruteforce','-o',str(outfile)],outfile)
    
def run_alterx(infile, outfile=None):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []

    # run alterx, feeding the file into stdin
    print(f"{GREEN}[+] Running: alterx on {infile} to get subdomain permutations, output file {outfile}{RESET}")
    with infile.open("r") as f:
        proc = subprocess.run(
            ["alterx",'-silent'],
            stdin=f,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

    if proc.returncode != 0 and not proc.stdout:
        print(f"{RED}[-] alterx failed: {proc.stderr.strip()}{RESET}")
        return []
    urls = proc.stdout.splitlines()
    results = sorted(extract_domains(urls))
    save_to_file(results,outfile)


def load_existing_subdomains(output_dir:None):
    subdomains = set()
    af_file = output_dir / "assetfinder.txt"
    # read the content of the file
    if  Path(af_file).exists():
        with open(af_file, 'r') as f:
            subdomains.update(line.strip() for line in f)

    sf_file = output_dir / "subfinder.txt"
    # read the content of the file
    if  Path(sf_file).exists():
        with open(sf_file, 'r') as f:
            subdomains.update(line.strip() for line in f)

    sdns_file = output_dir / "shuffledns.txt"

    # read the content of the file
    if  Path(sdns_file).exists():
        with open(sdns_file, 'r') as f:
            subdomains.update(line.strip() for line in f)

    chaos_file = output_dir / "chaos-client.txt"

    # read the content of the file
    if  Path(chaos_file).exists():
        with open(chaos_file, 'r') as f:
            subdomains.update(line.strip() for line in f)

    am_file = output_dir / "amass.txt"

    # read the content of the file
    if  Path(am_file).exists():
        with open(am_file, 'r') as f:
            subdomains.update(line.strip() for line in f)
    return subdomains