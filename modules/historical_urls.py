# modules/historical_urls.py
from core.utils import run_command,save_to_file
from pathlib import Path

def run_waybackurls(domain, output_dir: Path):
    output_file = output_dir / f"{domain}_wayback_urls.txt"
    result = run_command(["waybackurls", domain], outfile=output_file)
    save_to_file(set(result.stdout.splitlines()),output_file)
    return [line.strip() for line in open(output_file)]

def run_urlfinder(infile, output_dir: Path):
    if Path(infile).exists():
        with open(infile) as f:
            domains = sorted(set(line.strip() for line in f if line.strip()))
            for domain in domains:
                output_file = output_dir / f"{domain}_urlfinder.txt"
                run_command(['urlfinder','-d', domain,'-o',str(output_file)], outfile=output_file)


