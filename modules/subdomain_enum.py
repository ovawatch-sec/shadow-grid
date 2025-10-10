from pathlib import Path
import requests
import subprocess
from core.utils import run_command,save_to_file,extract_domains

from core.colors import RED, GREEN, RESET
def run_assetfinder(domain, outfile=None):
    result = run_command(["assetfinder", "--subs-only", domain],outfile)
    save_to_file(extract_domains(result.stdout.splitlines()),outfile)

def run_subfinder(domain, outfile=None):
    result =  run_command(["subfinder", "-silent", "-d", domain,'-all','-o',str(outfile)])

def run_amass(domain, output_dir,outfile):
    raw_outfile = output_dir / 'amass_raw.txt'
    result =  run_command(["amass", "enum",'-silent',"-d", domain,"-o",str(raw_outfile)],outfile)

def run_shuffledns(domain, data_dir=None, wordlist=None,outfile=None):
    resolver_file = data_dir/'resolvers.txt'
    wordlist = wordlist or data_dir/'wordlists/dns.txt' 
    result =  run_command(["shuffledns",'-silent', "-d", domain,'-w',str(wordlist),'-r',str(resolver_file),'-mode','bruteforce','-o',str(outfile)],outfile)
    
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