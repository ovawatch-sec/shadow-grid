from pathlib import Path
from core.colors import RED,RESET
from core.utils import run_command

def run_dnsx(infile, outfile):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []
    run_command(['dnsx', '-silent',"-list",str(infile) ,"-o",str(outfile)])

def run_httpx(infile, outfile):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []
    run_command(['httpx', '-silent', '-title' ,'-sc','-location', 'fr',"-list",str(infile) ,"-o",str(outfile)])
    
