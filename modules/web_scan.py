# modules/web_scan.py
import subprocess
from pathlib import Path
import shutil
from core.colors import RED,GREEN,RESET
from core.utils import save_to_file, run_command

def run_fuzzing(domain, output_dir,rate_limit=0,wordlist=None, headers=None, http_proto=443):
    outfile = output_dir / f'{domain}_fuzz.json'
    url =''
    if http_proto == 80:
        url= f'http://{domain}'
    else:
        url = f'https://{domain}'

    cmd = f'feroxbuster -u {url} -o {outfile} --rate-limit {rate_limit} --protocol {http_proto}'
    
    if headers is not None:
        cmd = f'{cmd} -H "{headers}"'
    if wordlist is not None:
        cmd = f'{cmd} -w {wordlist}'
    try:
        run_command(cmd.split(' '))
    except subprocess.TimeoutExpired:
        print(f"{RED}[-] feroxbuster timed out{RESET}")
    
def run_nuclei(input_file, output_dir: Path, timeout=300):
    """
    Run nuclei on a list of targets from input_file.
    Saves results in JSON format to output_dir/nuclei_results.json.
    """

    output_dir.mkdir(parents=True, exist_ok=True)
    input_file = Path(input_file)
    output_file = output_dir / "nuclei_results.json"

    if not input_file.exists():
        print(f"{RED}[-] Input file not found: {input_file}{RESET}")
        return []

    cmd = [
        "nuclei",
        "-list", str(input_file),
        "-json-export", str(output_file)
    ]

    try:
        proc = run_command(cmd)
    except subprocess.TimeoutExpired:
        print(f"{RED}[-] nuclei timed out{RESET}")
        return []

    if proc.returncode != 0:
        print(f"{RED}[-] nuclei failed: {proc.stderr.strip()}{RESET}")
        return []

    # nuclei writes JSON to file; read it back
    if output_file.exists():
        import json
        try:
            with output_file.open() as f:
                results = json.load(f)
        except json.JSONDecodeError:
            print(f"{RED}[-] Failed to parse nuclei JSON output{RESET}")
            results = []
        return results
    else:
        print(f"{RED}[-] nuclei did not produce output file{RESET}")
        return []

    
