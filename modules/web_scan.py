# modules/web_scan.py
import subprocess
from pathlib import Path
from core.colors import RED,RESET
from core.utils import run_command
    
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

def run_naabu(infile, output_dir):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []
    outfile = output_dir / 'naabu.txt'
    run_command(["naabu", '-top-ports','full',"-host",str(infile) ,"-o",str(outfile)])

def run_katana(infile, output_dir):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []
    with open(infile,'r') as file:
        domain = file.readline().strip()
        outfile = output_dir / f'{domain}_katana.txt'
        run_command(["katana", '-u',domain,"-jsl","-o",str(outfile)])
