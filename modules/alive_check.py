import subprocess
from pathlib import Path
from core.colors import RED,GREEN,RESET

def run_httprobe(infile, outfile=None):
    infile = Path(infile)
    if not infile.exists():
        print(f"{RED}[-] Input file not found: {infile}{RESET}")
        return []

    # run httprobe, feeding the file into stdin
    print(f"{GREEN}[+] Running httprobe on {infile} to fetch alive subdomains, output file {outfile}{RESET}")
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

    results = sorted(set(proc.stdout.splitlines()))

    if outfile:
        with open(outfile, "w") as f:
            f.write("\n".join(set(results)))

    return results
